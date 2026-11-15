"""Policy engine for RADIUS CoA / Disconnect requests (RFC 5176).

The engine only runs *after* the RADIUS shared-secret authenticator (and any
Message-Authenticator) has been verified. It adds the authorization layer on
top of that cryptographic check:

* a sender may only address NASes and operations it was granted;
* a target session must be located with an explicit identifier combination
  (User-Name alone is never enough and must not cause a broadcast);
* all validation happens before any session state changes, so a NAK never
  leaves a partially modified session;
* repeated requests return the original result without touching state again.
"""

import hashlib
import socket
import time
from collections import OrderedDict, deque
from dataclasses import dataclass

from .constants import (
    ACCT_SESSION_ID,
    ADMINISTRATIVELY_PROHIBITED,
    CALLED_STATION_ID,
    CALLING_STATION_ID,
    DISCONNECT_NAK,
    COA_NAK,
    DISCONNECT_REQUEST,
    FRAMED_IP_ADDRESS,
    INVALID_ATTRIBUTE_VALUE,
    LOCATOR_CODES,
    MESSAGE_AUTHENTICATOR,
    MISSING_ATTRIBUTE,
    NAS_IP_ADDRESS,
    SESSION_CONTEXT_NOT_FOUND,
    SESSION_CONTEXT_NOT_REMOVABLE,
    SESSION_TIMEOUT,
    SUPPORTED_CHANGE_CODES,
    UNSUPPORTED_EXTENSION,
    USER_NAME,
)
from .session_store import SessionStore


class PolicyError(Exception):
    """A policy refusal carrying the RFC 5176 Error-Cause value."""

    def __init__(self, error_cause, message):
        super().__init__(message)
        self.error_cause = error_cause
        self.message = message


@dataclass(frozen=True)
class SenderPolicy:
    """Authorization granted to one authenticated sender.

    ``allowed_nas`` maps the NAS-IP-Address the sender may put in a request
    to the set of permitted packet codes. A request for another NAS or
    operation is refused with Administratively-Prohibited.
    """

    sender_id: str
    allowed_nas: dict
    name: str = ""

    def permits(self, nas_ip, code):
        return code in self.allowed_nas.get(nas_ip, ())


@dataclass
class AuditEntry:
    """One processed request, including before/after session state."""

    ts: float
    sender_id: str
    code: int
    identifier: int
    nas_ip: object
    locator: dict
    decision: str
    error_cause: object
    reason: str
    replayed: bool
    before: object
    after: object

    def as_dict(self):
        return {
            "ts": self.ts,
            "sender_id": self.sender_id,
            "code": self.code,
            "identifier": self.identifier,
            "nas_ip": self.nas_ip,
            "locator": self.locator,
            "decision": self.decision,
            "error_cause": self.error_cause,
            "reason": self.reason,
            "replayed": self.replayed,
            "before": self.before,
            "after": self.after,
        }


class AuditLog:
    """Append-only audit trail recording every decision and state delta."""

    def __init__(self):
        self.entries = deque()

    def record(self, entry):
        self.entries.append(entry)

    def all(self):
        return list(self.entries)


@dataclass
class Decision:
    """Result of handling a request: the reply packet and audit metadata."""

    reply: object
    audit: AuditEntry
    replayed: bool = False


class IdempotencyCache:
    """Caches the original :class:`Decision` of an accepted request.

    Keyed by sender and the packet Identifier plus a hash of the raw request,
    so a retransmission returns the exact original reply. Entries expire after
    ``ttl`` seconds and the cache is bounded to ``max_entries``.
    """

    def __init__(self, ttl=300.0, max_entries=4096):
        self.ttl = ttl
        self.max_entries = max_entries
        self._entries = OrderedDict()

    def _key(self, sender_id, pkt, raw):
        digest = hashlib.md5(raw).digest()
        return sender_id, pkt.id, digest

    def get(self, sender_id, pkt, raw):
        key = self._key(sender_id, pkt, raw)
        item = self._entries.get(key)
        if item is None:
            return None
        stored_at, decision = item
        if time.monotonic() - stored_at > self.ttl:
            self._entries.pop(key, None)
            return None
        self._entries.move_to_end(key)
        return decision

    def put(self, sender_id, pkt, raw, decision):
        self._entries[self._key(sender_id, pkt, raw)] = \
            (time.monotonic(), decision)
        self._entries.move_to_end(self._key(sender_id, pkt, raw))
        while len(self._entries) > self.max_entries:
            self._entries.popitem(last=False)


class PolicyEngine:
    """Stateless policy decisions over a :class:`SessionStore`."""

    def __init__(self, store, sender_policies, audit=None, cache=None,
                 radius_dictionary=None):
        self.store = store if isinstance(store, SessionStore) \
            else SessionStore(store)
        self.sender_policies = sender_policies
        self.audit = audit or AuditLog()
        self.cache = cache or IdempotencyCache()
        self.dictionary = radius_dictionary

    def _decode(self, code, raw_value):
        """Decode a raw attribute value according to the dictionary type."""
        if self.dictionary is None or \
                not self.dictionary.attrindex.HasBackward(code):
            if isinstance(raw_value, bytes):
                return raw_value.decode("utf-8", "replace")
            return raw_value
        name = self.dictionary.attrindex.GetBackward(code)
        attr_type = self.dictionary.attributes[name].type
        if attr_type == "ipaddr":
            return normalize_ip(raw_value)
        if attr_type == "integer":
            from pyrad import tools
            return tools.DecodeInteger(raw_value)
        if attr_type in ("string", "octets"):
            if isinstance(raw_value, bytes):
                return raw_value.decode("utf-8", "replace")
        return raw_value

    def handle(self, pkt, raw, sender_id):
        """Handle an already authenticated CoA / Disconnect request.

        :param pkt: decoded request, with the sender's secret attached
        :param raw: exact bytes received, used for replay detection
        :param sender_id: identity resolved from the packet source address
        :return: a :class:`Decision` whose reply is ready to send
        """
        cached = self.cache.get(sender_id, pkt, raw)
        if cached is not None:
            replayed = self._replayed_audit(cached, sender_id, pkt)
            self.audit.record(replayed)
            return Decision(cached.reply, replayed, replayed=True)

        before = None
        try:
            self._authorize_sender(sender_id, pkt)
            nas_ip = self._require_nas(pkt)
            locator = self._build_locator(pkt)
            session, matches = self.store.locate(nas_ip, locator)
            before = session.snapshot() if session is not None else None

            if len(matches) > 1:
                raise PolicyError(
                    SESSION_CONTEXT_NOT_REMOVABLE if
                    pkt.code == DISCONNECT_REQUEST else SESSION_CONTEXT_NOT_FOUND,
                    "locator matches %d sessions on NAS %s; refusing an "
                    "ambiguous target" % (len(matches), nas_ip))
            if session is None:
                raise PolicyError(
                    SESSION_CONTEXT_NOT_FOUND,
                    "no active session matches the locator on NAS %s" % nas_ip)

            if pkt.code == DISCONNECT_REQUEST:
                self._disconnect(session)
                decision_name = "Disconnect-ACK"
            else:
                self._apply_coa(session, pkt)
                decision_name = "CoA-ACK"

            reply = self._ack(pkt)
            after = session.snapshot()
            entry = self._entry(
                sender_id, pkt, nas_ip, locator, decision_name, None,
                "applied", False, before, after)
        except PolicyError as err:
            reply = self._nak(pkt, err)
            entry = self._entry(
                sender_id, pkt, getattr(pkt, "_nas_ip", None),
                getattr(pkt, "_locator", {}),
                "Disconnect-NAK" if pkt.code == DISCONNECT_REQUEST
                else "CoA-NAK",
                err.error_cause, err.message, False, before, before)

        decision = Decision(reply, entry)
        self.cache.put(sender_id, pkt, raw, decision)
        self.audit.record(entry)
        return decision

    # -- authorization -----------------------------------------------------

    def _authorize_sender(self, sender_id, pkt):
        policy = self.sender_policies.get(sender_id)
        if policy is None:
            raise PolicyError(
                ADMINISTRATIVELY_PROHIBITED,
                "sender %r has no Dynamic Authorization policy" % sender_id)
        nas_ip = self._require_nas(pkt)
        if not policy.permits(nas_ip, pkt.code):
            operation = "Disconnect" if pkt.code == DISCONNECT_REQUEST \
                else "CoA"
            raise PolicyError(
                ADMINISTRATIVELY_PROHIBITED,
                "sender %r may not run %s against NAS %s"
                % (sender_id, operation, nas_ip))
        return policy

    @staticmethod
    def _require_nas(pkt):
        value = pkt.get(NAS_IP_ADDRESS)
        if not value:
            raise PolicyError(
                MISSING_ATTRIBUTE,
                "NAS-IP-Address is required to scope the target NAS")
        nas_ip = normalize_ip(value[0])
        pkt._nas_ip = nas_ip
        return nas_ip

    def _build_locator(self, pkt):
        locator = {}
        for code in (ACCT_SESSION_ID, FRAMED_IP_ADDRESS,
                     CALLING_STATION_ID, CALLED_STATION_ID, USER_NAME):
            values = pkt.get(code)
            if values:
                locator[code] = self._decode(code, values[0])
        pkt._locator = locator
        # An explicit session-level identifier is mandatory. User-Name alone
        # must never be used to broadcast a disconnect.
        if not locator.keys() - {USER_NAME}:
            raise PolicyError(
                MISSING_ATTRIBUTE,
                "an explicit session identifier (Acct-Session-Id, "
                "Framed-IP-Address or Calling-Station-Id) is required; "
                "User-Name alone is ambiguous")
        return locator

    # -- mutations ---------------------------------------------------------

    @staticmethod
    def _disconnect(session):
        session.active = False

    def _apply_coa(self, session, pkt):
        changes = self._validate_changes(pkt)
        # Validation is fully finished before the single state update, so a
        # NAK cannot have modified part of the session.
        for code, value in changes.items():
            session.attributes[self._attribute_name(code)] = value

    def _attribute_name(self, code):
        if self.dictionary is not None and \
                self.dictionary.attrindex.HasBackward(code):
            return self.dictionary.attrindex.GetBackward(code)
        return code

    def _validate_changes(self, pkt):
        changes = {}
        for code, values in pkt.items():
            if not isinstance(code, int) or code in LOCATOR_CODES or \
                    code == MESSAGE_AUTHENTICATOR:
                continue
            if code not in SUPPORTED_CHANGE_CODES:
                raise PolicyError(
                    UNSUPPORTED_EXTENSION,
                    "CoA attribute code %s is not supported" % code)
            if len(values) != 1:
                raise PolicyError(
                    INVALID_ATTRIBUTE_VALUE,
                    "attribute code %s must appear exactly once" % code)
            changes[code] = self._decode(code, values[0])
        if not changes:
            raise PolicyError(
                MISSING_ATTRIBUTE,
                "CoA-Request carries no authorization change attribute")
        if SESSION_TIMEOUT in changes and \
                not isinstance(changes[SESSION_TIMEOUT], int):
            raise PolicyError(
                INVALID_ATTRIBUTE_VALUE, "Session-Timeout must be an integer")
        return changes

    # -- replies / audit ---------------------------------------------------

    @staticmethod
    def _ack(pkt):
        return pkt.CreateReply()

    @staticmethod
    def _nak(pkt, err):
        reply = pkt.CreateReply()
        reply.code = DISCONNECT_NAK if pkt.code == DISCONNECT_REQUEST \
            else COA_NAK
        reply.AddAttribute("Error-Cause", err.error_cause)
        return reply

    def _replayed_audit(self, original, sender_id, pkt):
        base = original.audit
        return AuditEntry(
            ts=time.time(), sender_id=sender_id, code=pkt.code,
            identifier=pkt.id, nas_ip=base.nas_ip, locator=dict(base.locator),
            decision=base.decision, error_cause=base.error_cause,
            reason="replayed request: original result returned",
            replayed=True, before=base.before, after=base.after)

    @staticmethod
    def _entry(sender_id, pkt, nas_ip, locator, decision, error_cause,
               reason, replayed, before, after):
        return AuditEntry(
            ts=time.time(), sender_id=sender_id, code=pkt.code,
            identifier=pkt.id, nas_ip=nas_ip, locator=dict(locator),
            decision=decision, error_cause=error_cause, reason=reason,
            replayed=replayed, before=before, after=after)


def normalize_ip(value):
    """Return the dotted-string form of a RADIUS ipaddr attribute value."""
    if isinstance(value, (bytes, bytearray)):
        return socket.inet_ntoa(bytes(value))
    return str(value)
