"""Offline, stateful validator for CMP (RFC 4210) registration transactions.

The validator is deliberately scope-limited to the four messages of an
initialization registration and its polling sub-protocol:

``ir`` (Initialization Request), ``ip`` (Initialization Response),
``pollReq``/``pollRep`` (Polling), ``certConf`` (Certificate Confirmation)
and ``pkiconf`` (PKI Confirmation).

The caller is expected to have already verified the outer PKIMessage
protection (RFC 4210 section 5.1.3).  Input is the raw DER encoding of a
:class:`pyasn1_modules.rfc4210.PKIMessage`.  Every validation decision is
deterministic and all-or-nothing: a rejected message never mutates
transaction state, so a correct follow-up message can always be processed
afterwards.

All wall-clock decisions (polling ``checkAfter`` deadlines, ``messageTime``
skew) are taken from a clock callable supplied by the caller; the validator
itself never sleeps or performs any I/O.
"""

import copy
import hashlib
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum

from pyasn1.codec.der import decoder as der_decoder
from pyasn1.codec.der import encoder as der_encoder

from pyasn1_modules import rfc2459
from pyasn1_modules import rfc4210

#: Body types that make up the supported part of an initialization flow.
SUPPORTED_BODY_NAMES = frozenset(
    ("ir", "ip", "pollReq", "pollRep", "certConf", "pkiconf")
)

#: PKIBody choices sent by the end entity (client -> CA).
EE_TO_CA_BODIES = frozenset(("ir", "pollReq", "certConf"))

#: PKIBody choices sent by the PKI (CA -> client).
CA_TO_EE_BODIES = frozenset(("ip", "pollRep", "pkiconf"))

#: PKIStatus values that carry an issued certificate (RFC 4210 5.3.4).
_GRANTED_STATUSES = frozenset(
    (int(rfc4210.PKIStatus.namedValues.getValue("accepted")),
     int(rfc4210.PKIStatus.namedValues.getValue("grantedWithMods")))
)
_WAITING_STATUS = int(rfc4210.PKIStatus.namedValues.getValue("waiting"))
_REJECTION_STATUS = int(rfc4210.PKIStatus.namedValues.getValue("rejection"))

_GENERALIZED_TIME_RE = re.compile(
    r"^(\d{4})(\d{2})(\d{2})(\d{2})(?:(\d{2})(?:(\d{2}))?)?"
    r"(?:[.,](\d+))?(Z|[+-]\d{2}(?::?\d{2})?)?$"
)


class RejectReason(str, Enum):
    """Stable, deterministic rejection codes."""

    MALFORMED_DER = "malformed-der"
    UNSUPPORTED_VERSION = "unsupported-version"
    UNSUPPORTED_BODY = "unsupported-body"
    MISSING_TRANSACTION_ID = "missing-transaction-id"
    MISSING_SENDER_NONCE = "missing-sender-nonce"
    BAD_RECIPIENT_NONCE = "bad-recipient-nonce"
    BAD_SENDER_NONCE = "bad-sender-nonce"
    DUPLICATE_MESSAGE = "duplicate-message"
    UNKNOWN_TRANSACTION_ID = "unknown-transaction-id"
    TRANSACTION_ID_IN_USE = "transaction-id-in-use"
    TRANSACTION_TERMINATED = "transaction-terminated"
    WRONG_PARTIES = "wrong-sender-recipient"
    BAD_MESSAGE_TIME = "bad-message-time"
    BAD_CERT_ID = "bad-cert-id"
    MISSING_CERT_RESPONSE = "missing-cert-response"
    UNEXPECTED_STATUS = "unexpected-pki-status"
    ENCRYPTED_CERT_UNSUPPORTED = "encrypted-cert-unsupported"
    MESSAGE_OUT_OF_ORDER = "message-out-of-order"
    POLL_TOO_EARLY = "poll-too-early"
    LATE_POLL_REP = "late-poll-rep"
    BAD_CERT_HASH = "bad-cert-hash"
    CERT_DOES_NOT_MATCH_REQUEST = "cert-does-not-match-request"
    INVALID_CONTENT = "invalid-content"


class TransactionPhase(str, Enum):
    OPEN = "open"
    COMPLETED = "completed"


class CertReqState(str, Enum):
    """Per-``certReqId`` state machine."""

    REQUESTED = "requested"
    WAITING = "waiting"
    ISSUED = "issued"
    CONFIRMED = "confirmed"
    REJECTED_BY_CA = "rejected-by-ca"
    REJECTED_BY_CLIENT = "rejected-by-client"


class _Reject(Exception):
    def __init__(self, reason, detail):
        super().__init__(f"{reason.value}: {detail}")
        self.reason = reason
        self.detail = detail


def _untagged_der(value, base_type):
    """Encode a context-tagged value using the base type's plain tag."""
    return der_encoder.encode(value.clone(
        tagSet=base_type().tagSet, cloneValueFlag=True))


def _parse_generalized_time(value):
    """Parse an ASN.1 GeneralizedTime value into an aware ``datetime``."""
    match = _GENERALIZED_TIME_RE.match(str(value))
    if match is None:
        raise ValueError("not a GeneralizedTime value: %r" % (value,))
    year, month, day, hour, minute, second, fraction, zone = match.groups()
    microsecond = 0
    if fraction:
        microsecond = int((fraction + "000000")[:6])
    parsed = datetime(
        int(year), int(month), int(day), int(hour),
        int(minute or 0), int(second or 0), microsecond,
    )
    if zone is None or zone == "Z":
        return parsed.replace(tzinfo=timezone.utc)
    sign = 1 if zone[0] == "+" else -1
    digits = zone[1:].replace(":", "")
    offset_hours = int(digits[:2])
    offset_minutes = int(digits[2:]) if len(digits) > 2 else 0
    return parsed.replace(
        tzinfo=timezone(sign * timedelta(hours=offset_hours,
                                         minutes=offset_minutes))
    )


@dataclass
class CertRecord:
    cert_req_id: int
    state: CertReqState = CertReqState.REQUESTED
    cert_der: bytes = None
    cert_hash: bytes = None
    #: Subject Name requested in the ir CertTemplate (bare DER), if present.
    expected_subject_der: bytes = None
    #: SubjectPublicKeyInfo requested in the ir CertTemplate (bare DER).
    expected_spki_der: bytes = None
    #: Earliest time at which the next pollReq for this id is acceptable.
    poll_not_before: datetime = None


@dataclass
class TransactionRecord:
    transaction_id: bytes
    client_name_der: bytes
    ca_name_der: bytes
    phase: TransactionPhase = TransactionPhase.OPEN
    certs: dict = field(default_factory=dict)
    used_sender_nonces: set = field(default_factory=set)
    #: recipNonce the *next* message must carry (last senderNonce seen).
    expected_recip_nonce: bytes = None
    #: certReqIds covered by the currently outstanding pollReq.
    pending_poll_ids: set = field(default_factory=set)
    last_message_time: datetime = None
    history: list = field(default_factory=list)
    #: certReqId -> DER of certificates confirmed and installed.
    installed_certs: dict = field(default_factory=dict)

    @property
    def key(self):
        return self.client_name_der, self.transaction_id


@dataclass(frozen=True)
class ValidationResult:
    accepted: bool
    body_name: str
    reason: RejectReason = None
    detail: str = ""
    transaction: TransactionRecord = None
    #: certReqId -> DER of certs installed by *this* message.
    installed_certs: dict = field(default_factory=dict)

    @property
    def rejected(self):
        return not self.accepted


class CMPTransactionValidator:
    """Validate a stream of protected CMP messages for one or more clients.

    Transactions are keyed by the ``(client GeneralName, transactionID)``
    tuple, as recommended by RFC 4210 section 5.1.1, so several clients and
    several transactions may be interleaved on one validator instance.

    Parameters
    ----------
    clock: zero-argument callable returning a timezone-aware ``datetime``;
        defaults to UTC wall-clock time.  Injected by the caller so tests
        and offline processing are fully deterministic.
    max_skew: ``timedelta`` tolerance for the header ``messageTime`` field.
    cert_hash_alg: hash algorithm used for the ``certConf`` ``certHash``
        comparison (RFC 4210 5.2.8); SHA-256 by default.
    """

    def __init__(self, clock=None, max_skew=timedelta(minutes=5),
                 cert_hash_alg=hashlib.sha256):
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._max_skew = max_skew
        self._hash = cert_hash_alg
        self._records = {}
        self._seen_der = set()

    @property
    def records(self):
        return self._records

    def get_transaction(self, client_name_der, transaction_id):
        return self._records.get((client_name_der, transaction_id))

    def validate(self, message_der):
        """Validate one DER-encoded PKIMessage.

        Returns a :class:`ValidationResult`.  Rejection never mutates any
        transaction state.
        """
        if not isinstance(message_der, (bytes, bytearray)):
            return self._reject(RejectReason.MALFORMED_DER,
                                "input must be raw DER bytes", None)
        try:
            message, rest = der_decoder.decode(
                bytes(message_der), asn1Spec=rfc4210.PKIMessage())
            if rest:
                raise _Reject(RejectReason.MALFORMED_DER,
                              "%d trailing bytes after PKIMessage" % len(rest))
            header = message.getComponentByName("header")
            body = message.getComponentByName("body")
            body_name = body.getName()
            if body_name not in SUPPORTED_BODY_NAMES:
                raise _Reject(RejectReason.UNSUPPORTED_BODY,
                              "PKIBody choice %r is outside the supported "
                              "initialization flow" % body_name)
            if int(header.getComponentByName("pvno")) != 2:
                raise _Reject(RejectReason.UNSUPPORTED_VERSION,
                              "only CMP 2000 (pvno=2) is supported")

            sender_der = der_encoder.encode(
                header.getComponentByName("sender"))
            recipient_der = der_encoder.encode(
                header.getComponentByName("recipient"))

            txn_id_field = header.getComponentByName("transactionID")
            if not txn_id_field.hasValue():
                raise _Reject(RejectReason.MISSING_TRANSACTION_ID,
                              "header.transactionID is required")
            transaction_id = bytes(txn_id_field)

            sender_nonce_field = header.getComponentByName("senderNonce")
            if not sender_nonce_field.hasValue():
                raise _Reject(RejectReason.MISSING_SENDER_NONCE,
                              "header.senderNonce is required")
            sender_nonce = bytes(sender_nonce_field)
            recip_nonce_field = header.getComponentByName("recipNonce")
            recip_nonce = (bytes(recip_nonce_field)
                           if recip_nonce_field.hasValue() else None)

            message_time = None
            message_time_field = header.getComponentByName("messageTime")
            if message_time_field.hasValue():
                try:
                    message_time = _parse_generalized_time(message_time_field)
                except ValueError as exc:
                    raise _Reject(RejectReason.BAD_MESSAGE_TIME, str(exc))

            # Full-DER replay detection comes before any state lookup so a
            # replayed message is always classified deterministically.
            if message_der in self._seen_der:
                raise _Reject(RejectReason.DUPLICATE_MESSAGE,
                              "identical DER message was already processed")

            if body_name == "ir":
                record = self._open_transaction(
                    body, transaction_id, sender_der, recipient_der,
                    sender_nonce, recip_nonce, message_time)
            else:
                record = self._lookup_transaction(
                    body_name, transaction_id, sender_der, recipient_der)
                snapshot = copy.deepcopy(record)
                try:
                    self._check_common_header(
                        record, body_name, sender_nonce, recip_nonce,
                        message_time)
                    self._dispatch(
                        record, body_name, body, sender_nonce, message_time)
                except _Reject:
                    self._records[record.key] = snapshot
                    raise
                record = self._records[record.key]

            self._seen_der.add(bytes(message_der))
            record.history.append((self._clock(), body_name, True))
            installed = dict(
                record.installed_certs if body_name == "certConf" else {})
            return ValidationResult(
                accepted=True, body_name=body_name,
                transaction=record, installed_certs=installed)

        except _Reject as exc:
            return self._reject(exc.reason, exc.detail,
                                locals().get("body_name"))
        except Exception as exc:  # decoder/encoder/type errors
            return self._reject(RejectReason.MALFORMED_DER, str(exc),
                                locals().get("body_name"))

    def _reject(self, reason, detail, body_name=None):
        return ValidationResult(
            accepted=False, body_name=body_name or "",
            reason=reason, detail=detail)

    def _open_transaction(self, body, transaction_id, client_der, ca_der,
                          sender_nonce, recip_nonce, message_time):
        if recip_nonce is not None:
            raise _Reject(RejectReason.BAD_RECIPIENT_NONCE,
                          "the first message (ir) must not carry recipNonce")
        key = (client_der, transaction_id)
        existing = self._records.get(key)
        if existing is not None:
            if existing.phase is TransactionPhase.COMPLETED:
                raise _Reject(RejectReason.TRANSACTION_TERMINATED,
                              "transactionID already completed for client")
            raise _Reject(RejectReason.TRANSACTION_ID_IN_USE,
                          "an open transaction already uses this "
                          "transactionID for this client")

        cert_requests = body.getComponentByName("ir")
        requested_ids = []
        seen_ids = set()
        templates = {}
        for cert_req_msg in cert_requests:
            cert_request = cert_req_msg.getComponentByName("certReq")
            cert_req_id = int(cert_request.getComponentByName("certReqId"))
            if cert_req_id < 0 or cert_req_id in seen_ids:
                raise _Reject(RejectReason.BAD_CERT_ID,
                              "duplicate or negative certReqId %d in ir"
                              % cert_req_id)
            seen_ids.add(cert_req_id)
            requested_ids.append(cert_req_id)
            templates[cert_req_id] = cert_request.getComponentByName(
                "certTemplate")
        if not requested_ids:
            raise _Reject(RejectReason.INVALID_CONTENT,
                          "ir contains no CertReqMsg")

        record = TransactionRecord(
            transaction_id=transaction_id,
            client_name_der=client_der,
            ca_name_der=ca_der)
        self._check_message_time(record, message_time)
        for cert_req_id in requested_ids:
            cert_record = CertRecord(cert_req_id)
            template = templates[cert_req_id]
            subject = template.getComponentByName("subject")
            if subject.hasValue():
                # subject is implicitly [5]; compare on the bare Name DER.
                cert_record.expected_subject_der = _untagged_der(
                    subject, rfc2459.Name)
            public_key = template.getComponentByName("publicKey")
            if public_key.hasValue():
                cert_record.expected_spki_der = _untagged_der(
                    public_key, rfc2459.SubjectPublicKeyInfo)
            record.certs[cert_req_id] = cert_record
        record.used_sender_nonces.add(sender_nonce)
        record.expected_recip_nonce = sender_nonce
        record.last_message_time = message_time
        self._records[key] = record
        return record

    def _lookup_transaction(self, body_name, transaction_id,
                            sender_der, recipient_der):
        if body_name in EE_TO_CA_BODIES:
            client_der, ca_der = sender_der, recipient_der
        else:
            client_der, ca_der = recipient_der, sender_der
        record = self._records.get((client_der, transaction_id))
        if record is None:
            # Distinguish a genuinely unknown transaction from an attempt to
            # ride another client's transaction at the same CA.
            for candidate in self._records.values():
                if (candidate.transaction_id == transaction_id
                        and candidate.ca_name_der == ca_der):
                    raise _Reject(
                        RejectReason.WRONG_PARTIES,
                        "transactionID belongs to a different client")
            raise _Reject(RejectReason.UNKNOWN_TRANSACTION_ID,
                          "no open transaction for (client, transactionID)")
        if record.ca_name_der != ca_der:
            raise _Reject(RejectReason.WRONG_PARTIES,
                          "message is addressed to/from the wrong CA")
        if record.phase is TransactionPhase.COMPLETED:
            raise _Reject(RejectReason.TRANSACTION_TERMINATED,
                          "transaction already reached its terminal state")
        return record

    def _check_common_header(self, record, body_name, sender_nonce,
                             recip_nonce, message_time):
        if recip_nonce is None:
            raise _Reject(RejectReason.BAD_RECIPIENT_NONCE,
                          "%s must echo the previous senderNonce" % body_name)
        if recip_nonce != record.expected_recip_nonce:
            raise _Reject(RejectReason.BAD_RECIPIENT_NONCE,
                          "recipNonce does not match the last senderNonce "
                          "of this transaction")
        if sender_nonce in record.used_sender_nonces:
            raise _Reject(RejectReason.BAD_SENDER_NONCE,
                          "senderNonce was already used in this transaction")

        self._check_message_time(record, message_time)

    def _check_message_time(self, record, message_time):
        if message_time is None:
            return
        now = self._clock()
        if abs(now - message_time) > self._max_skew:
            raise _Reject(
                RejectReason.BAD_MESSAGE_TIME,
                "messageTime %s outside clock skew window (now %s)"
                % (message_time.isoformat(), now.isoformat()))
        if (record.last_message_time is not None
                and message_time < record.last_message_time):
            raise _Reject(RejectReason.BAD_MESSAGE_TIME,
                          "messageTime goes backwards within the "
                          "transaction")

    def _dispatch(self, record, body_name, body, sender_nonce, message_time):
        handler = {
            "ip": self._handle_ip,
            "pollReq": self._handle_poll_req,
            "pollRep": self._handle_poll_rep,
            "certConf": self._handle_cert_conf,
            "pkiconf": self._handle_pki_conf,
        }[body_name]
        handler(record, body)
        # Commit nonce/time progression only after content validation.
        record.used_sender_nonces.add(sender_nonce)
        record.expected_recip_nonce = sender_nonce
        record.last_message_time = message_time

    def _handle_ip(self, record, body):
        cert_rep = body.getComponentByName("ip")
        responses = list(cert_rep.getComponentByName("response"))
        if not responses:
            raise _Reject(RejectReason.INVALID_CONTENT,
                          "ip contains no CertResponse")

        response_ids = [int(rsp.getComponentByName("certReqId"))
                        for rsp in responses]
        if len(set(response_ids)) != len(response_ids):
            raise _Reject(RejectReason.BAD_CERT_ID,
                          "duplicate certReqId in ip")

        initial = all(cert.state is CertReqState.REQUESTED
                      for cert in record.certs.values())
        if initial:
            expected_ids = set(record.certs)
        else:
            # A later ip is only legal as the answer to an outstanding
            # pollReq and may only address the ids that were polled.
            if not record.pending_poll_ids:
                raise _Reject(RejectReason.MESSAGE_OUT_OF_ORDER,
                              "unexpected ip: no pollReq is outstanding")
            expected_ids = set(record.pending_poll_ids)

        unknown = [rid for rid in response_ids if rid not in record.certs]
        if unknown:
            raise _Reject(RejectReason.BAD_CERT_ID,
                          "ip references unknown certReqId %r" % unknown)
        if set(response_ids) != expected_ids:
            raise _Reject(
                RejectReason.MISSING_CERT_RESPONSE,
                "ip must answer exactly certReqId %r, got %r"
                % (sorted(expected_ids), sorted(response_ids)))
        if not initial:
            not_waiting = [
                rid for rid in response_ids
                if record.certs[rid].state is not CertReqState.WAITING]
            if not_waiting:
                raise _Reject(RejectReason.MESSAGE_OUT_OF_ORDER,
                              "ip re-answers non-waiting certReqId %r"
                              % not_waiting)

        for response in responses:
            self._apply_cert_response(record, response)
        record.pending_poll_ids.clear()

    def _apply_cert_response(self, record, response):
        cert_req_id = int(response.getComponentByName("certReqId"))
        cert_record = record.certs[cert_req_id]
        status_info = response.getComponentByName("status")
        status = int(status_info.getComponentByName("status"))

        if status in _GRANTED_STATUSES:
            if not response.getComponentByName("certifiedKeyPair").hasValue():
                raise _Reject(RejectReason.INVALID_CONTENT,
                              "granted CertResponse for certReqId %d carries "
                              "no certifiedKeyPair" % cert_req_id)
            certified = response.getComponentByName("certifiedKeyPair")
            choice = certified.getComponentByName("certOrEncCert")
            if choice.getName() != "certificate":
                raise _Reject(RejectReason.ENCRYPTED_CERT_UNSUPPORTED,
                              "only the plain certificate choice is "
                              "supported for certReqId %d" % cert_req_id)
            tagged_cert = choice.getComponentByName("certificate")
            # certHash (RFC 4210 5.2.8) is over the bare Certificate DER,
            # not the implicit [0] tag of the CertOrEncCert CHOICE.
            bare_cert = tagged_cert.clone(
                tagSet=rfc4210.CMPCertificate().tagSet,
                cloneValueFlag=True)
            cert_der = der_encoder.encode(bare_cert)
            self._check_cert_binding(cert_record, bare_cert, cert_req_id)
            cert_record.cert_der = cert_der
            cert_record.cert_hash = self._hash(cert_der).digest()
            cert_record.state = CertReqState.ISSUED
            cert_record.poll_not_before = None
        elif status == _WAITING_STATUS:
            if response.getComponentByName("certifiedKeyPair").hasValue():
                raise _Reject(RejectReason.INVALID_CONTENT,
                              "waiting CertResponse for certReqId %d must "
                              "not carry a certificate" % cert_req_id)
            cert_record.state = CertReqState.WAITING
        elif status == _REJECTION_STATUS:
            cert_record.state = CertReqState.REJECTED_BY_CA
            cert_record.poll_not_before = None
        else:
            raise _Reject(RejectReason.UNEXPECTED_STATUS,
                          "PKIStatus %d is not valid in an ip for "
                          "certReqId %d" % (status, cert_req_id))

    def _check_cert_binding(self, cert_record, bare_cert, cert_req_id):
        """Bind an issued certificate to the original ir CertTemplate.

        A response that is otherwise well-formed (right transactionID,
        nonces, parties) must still carry the subject and public key the
        client actually requested.  This is what stops a cryptographically
        valid certificate minted for a different transaction from being
        installed here.
        """
        if cert_record.expected_subject_der is not None:
            issued_subject = der_encoder.encode(
                bare_cert.getComponentByName("tbsCertificate")
                .getComponentByName("subject"))
            if issued_subject != cert_record.expected_subject_der:
                raise _Reject(
                    RejectReason.CERT_DOES_NOT_MATCH_REQUEST,
                    "issued certificate subject for certReqId %d does not "
                    "match the ir template" % cert_req_id)
        if cert_record.expected_spki_der is not None:
            issued_spki = der_encoder.encode(
                bare_cert.getComponentByName("tbsCertificate")
                .getComponentByName("subjectPublicKeyInfo"))
            if issued_spki != cert_record.expected_spki_der:
                raise _Reject(
                    RejectReason.CERT_DOES_NOT_MATCH_REQUEST,
                    "issued certificate public key for certReqId %d does "
                    "not match the ir template" % cert_req_id)

    def _handle_poll_req(self, record, body):
        poll_req = body.getComponentByName("pollReq")
        polled_ids = []
        for entry in poll_req:
            cert_req_id = int(entry.getComponentByName("certReqId"))
            if cert_req_id in polled_ids:
                raise _Reject(RejectReason.BAD_CERT_ID,
                              "duplicate certReqId %d in pollReq"
                              % cert_req_id)
            polled_ids.append(cert_req_id)
        if not polled_ids:
            raise _Reject(RejectReason.INVALID_CONTENT,
                          "empty pollReq")
        unknown = [rid for rid in polled_ids if rid not in record.certs]
        if unknown:
            raise _Reject(RejectReason.BAD_CERT_ID,
                          "pollReq references unknown certReqId %r" % unknown)
        not_waiting = [
            rid for rid in polled_ids
            if record.certs[rid].state is not CertReqState.WAITING]
        if not_waiting:
            raise _Reject(RejectReason.MESSAGE_OUT_OF_ORDER,
                          "pollReq for certReqId not in waiting state: %r"
                          % not_waiting)
        now = self._clock()
        premature = [
            rid for rid in polled_ids
            if record.certs[rid].poll_not_before is not None
            and now < record.certs[rid].poll_not_before]
        if premature:
            raise _Reject(
                RejectReason.POLL_TOO_EARLY,
                "pollReq before checkAfter deadline for certReqId %r"
                % premature)
        record.pending_poll_ids = set(polled_ids)

    def _handle_poll_rep(self, record, body):
        if not record.pending_poll_ids:
            raise _Reject(RejectReason.LATE_POLL_REP,
                          "pollRep without an outstanding pollReq")
        poll_rep = body.getComponentByName("pollRep")
        entries = list(poll_rep)
        if not entries:
            raise _Reject(RejectReason.INVALID_CONTENT, "empty pollRep")
        rep_ids = []
        now = self._clock()
        for entry in entries:
            cert_req_id = int(entry.getComponentByName("certReqId"))
            check_after = int(entry.getComponentByName("checkAfter"))
            if check_after < 0:
                raise _Reject(RejectReason.INVALID_CONTENT,
                              "negative checkAfter for certReqId %d"
                              % cert_req_id)
            rep_ids.append(cert_req_id)
            if cert_req_id not in record.pending_poll_ids:
                raise _Reject(RejectReason.BAD_CERT_ID,
                              "pollRep answers certReqId %d that was not "
                              "polled" % cert_req_id)
            cert_record = record.certs[cert_req_id]
            if cert_record.state is not CertReqState.WAITING:
                raise _Reject(RejectReason.LATE_POLL_REP,
                              "pollRep for certReqId %d in state %s"
                              % (cert_req_id, cert_record.state.value))
            cert_record.poll_not_before = now + timedelta(seconds=check_after)
        if set(rep_ids) != record.pending_poll_ids:
            raise _Reject(RejectReason.MISSING_CERT_RESPONSE,
                          "pollRep must answer exactly %r"
                          % sorted(record.pending_poll_ids))
        record.pending_poll_ids.clear()

    def _handle_cert_conf(self, record, body):
        cert_conf = body.getComponentByName("certConf")
        entries = list(cert_conf)
        if not entries:
            raise _Reject(RejectReason.INVALID_CONTENT,
                          "empty certConf: omission means rejection of all "
                          "certificates and is not supported")
        conf_ids = []
        for cert_status in entries:
            cert_req_id = int(cert_status.getComponentByName("certReqId"))
            cert_hash = bytes(cert_status.getComponentByName("certHash"))
            conf_ids.append(cert_req_id)
            if cert_req_id not in record.certs:
                raise _Reject(RejectReason.BAD_CERT_ID,
                              "certConf references unknown certReqId %d"
                              % cert_req_id)
            cert_record = record.certs[cert_req_id]
            if cert_record.state is not CertReqState.ISSUED:
                raise _Reject(RejectReason.MESSAGE_OUT_OF_ORDER,
                              "certConf for certReqId %d in state %s"
                              % (cert_req_id, cert_record.state.value))
            if cert_hash != cert_record.cert_hash:
                raise _Reject(RejectReason.BAD_CERT_HASH,
                              "certHash mismatch for certReqId %d"
                              % cert_req_id)
            status_info = cert_status.getComponentByName("statusInfo")
            client_rejects = (
                status_info.hasValue()
                and int(status_info.getComponentByName("status"))
                == _REJECTION_STATUS)
            if client_rejects:
                cert_record.state = CertReqState.REJECTED_BY_CLIENT
            else:
                cert_record.state = CertReqState.CONFIRMED
                record.installed_certs[cert_req_id] = cert_record.cert_der

        if len(set(conf_ids)) != len(conf_ids):
            raise _Reject(RejectReason.BAD_CERT_ID,
                          "duplicate certReqId in certConf")
        issued_ids = {
            rid for rid, cert in record.certs.items()
            if cert.state is CertReqState.ISSUED}
        if issued_ids:
            raise _Reject(RejectReason.MISSING_CERT_RESPONSE,
                          "certConf must cover every issued certReqId, "
                          "missing %r" % sorted(issued_ids))

    def _handle_pki_conf(self, record, body):
        body.getComponentByName("pkiconf")  # NULL content, choice must exist
        unfinished = [
            rid for rid, cert in record.certs.items()
            if cert.state in (CertReqState.REQUESTED,
                              CertReqState.WAITING,
                              CertReqState.ISSUED)]
        if unfinished:
            raise _Reject(RejectReason.MESSAGE_OUT_OF_ORDER,
                          "pkiconf before all certificates settled, "
                          "certReqId %r still open" % unfinished)
        record.phase = TransactionPhase.COMPLETED
