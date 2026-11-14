"""ASN.1 decoding for CMS SignedData and ESS receipts.

The decoder is deliberately strict: every field that later takes part in a
correlation decision is kept as raw bytes and accompanied by its exact
location in the ASN.1 structure.  Nothing here verifies a signature.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Dict, List, Mapping, Optional, Sequence, Tuple

from pyasn1.codec.der.decoder import decode as der_decoder
from pyasn1.codec.der.encoder import encode as der_encoder
from pyasn1.error import PyAsn1Error
from pyasn1.type import char
from pyasn1_modules import rfc2634, rfc4055, rfc5280, rfc5652

MAX_LAYERS = 8

STATUS_VALID = "valid"
STATUS_INVALID = "invalid"
STATUS_UNKNOWN = "unknown"

TRUST_TRUSTED = "trusted"
TRUST_UNTRUSTED = "untrusted"
TRUST_UNKNOWN = "unknown"

_STATUS_ALIASES = {
    "valid": STATUS_VALID,
    "verified": STATUS_VALID,
    "invalid": STATUS_INVALID,
    "failed": STATUS_INVALID,
    "unknown": STATUS_UNKNOWN,
    "unverified": STATUS_UNKNOWN,
    "not_checked": STATUS_UNKNOWN,
    "not checked": STATUS_UNKNOWN,
    "absent": STATUS_UNKNOWN,
}

_TRUST_ALIASES = {
    "trusted": TRUST_TRUSTED,
    "untrusted": TRUST_UNTRUSTED,
    "distrusted": TRUST_UNTRUSTED,
    "unknown": TRUST_UNKNOWN,
    "not_checked": TRUST_UNKNOWN,
    "not checked": TRUST_UNKNOWN,
}

DIGEST_ALGORITHMS = {
    str(rfc4055.id_sha1): "sha1",
    str(rfc4055.id_sha224): "sha224",
    str(rfc4055.id_sha256): "sha256",
    str(rfc4055.id_sha384): "sha384",
    str(rfc4055.id_sha512): "sha512",
    "1.2.840.113549.2.5": "md5",
}


class DecodeError(ValueError):
    """Raised when an archive object cannot be decoded as claimed."""


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def hex_bytes(data: Optional[bytes]) -> Optional[str]:
    return None if data is None else data.hex()


def digest_for_oid(oid: str, data: bytes) -> Tuple[Optional[bytes], Optional[str]]:
    """Return ``(digest, error)`` for a CMS digest algorithm identifier."""

    name = DIGEST_ALGORITHMS.get(str(oid))
    if name is None:
        return None, "unsupported digest algorithm %s" % (oid,)
    try:
        return hashlib.new(name, data).digest(), None
    except ValueError as exc:  # pragma: no cover - depends on OpenSSL
        return None, "digest algorithm %s unavailable: %s" % (oid, exc)


def set_of_der(context_tagged_der: bytes) -> bytes:
    """Return the DER SET OF encoding used for SignedAttributes digests.

    RFC 5652 section 5.4 requires the digest over the EXPLICIT SET OF
    encoding of the signed attributes, not the IMPLICIT [0] form found on the
    wire.  Only the identifier octet changes; the content octets are kept
    byte-for-byte.
    """

    if not context_tagged_der:
        raise DecodeError("empty SignedAttributes encoding")
    first = context_tagged_der[0]
    if first & 0x1F == 0x1F:
        raise DecodeError("high-tag-number SignedAttributes are not supported")
    if first & 0x20 == 0:
        raise DecodeError("SignedAttributes must be constructed")
    index = 1
    if index >= len(context_tagged_der):
        raise DecodeError("truncated SignedAttributes length")
    length_octet = context_tagged_der[index]
    index += 1
    if length_octet & 0x80:
        count = length_octet & 0x7F
        if count == 0:
            raise DecodeError("indefinite length SignedAttributes are not supported")
        if index + count > len(context_tagged_der):
            raise DecodeError("truncated SignedAttributes length")
        length = int.from_bytes(context_tagged_der[index:index + count], "big")
        index += count
    else:
        length = length_octet
    header = context_tagged_der[:index]
    body = context_tagged_der[index:]
    if len(body) != length:
        raise DecodeError("SignedAttributes length mismatch")
    # Keep the original length octets so the digest input differs from
    # the wire encoding only in the identifier octet, as RFC 5652 requires.
    return bytes((0x31,)) + header[1:] + body


def _decode(data: bytes, spec, what: str):
    if data is None:
        raise DecodeError("%s is absent" % (what,))
    try:
        value, rest = der_decoder(data, asn1Spec=spec)
    except PyAsn1Error as exc:
        raise DecodeError("%s does not decode: %s" % (what, exc))
    if rest:
        raise DecodeError("%s has %d trailing octets" % (what, len(rest)))
    return value


def _optional_value(sequence, name: str):
    """Return a decoded OPTIONAL component or None when it is absent."""

    try:
        component = sequence.getComponentByName(name)
    except PyAsn1Error:
        return None
    if component is None or not component.isValue:
        return None
    return component


def _dn_string(name) -> str:
    parts: List[str] = []
    try:
        rdns = name["rdnSequence"]
    except (PyAsn1Error, KeyError):
        return ""
    for rdn in rdns:
        for atv in rdn:
            oid = str(atv["type"])
            raw = bytes(atv["value"])
            text = None
            if oid == str(rfc5280.id_at_commonName):
                try:
                    decoded = _decode(raw, rfc5280.X520CommonName(), "commonName")
                    kind = decoded.getName()
                    text = str(decoded[kind])
                except DecodeError:
                    text = None
            elif oid == str(rfc5280.id_emailAddress):
                try:
                    text = str(_decode(raw, char.IA5String(), "emailAddress"))
                except DecodeError:
                    text = None
            if text is None:
                text = "0x" + raw.hex()
            parts.append("%s=%s" % (oid, text))
    return ", ".join(parts)


def _general_name_text(general_name) -> Tuple[str, str]:
    """Return ``(kind, printable value)`` for a GeneralName."""

    kind = general_name.getName()
    value = general_name[kind]
    if kind in ("rfc822Name", "dNSName", "uniformResourceIdentifier"):
        text = bytes(value).decode("ascii", "backslashreplace")
    elif kind == "directoryName":
        text = _dn_string(value)
    elif kind == "iPAddress":
        text = bytes(value).hex()
    else:
        text = "0x" + bytes(value).hex()
    return kind, text


def canonical_name(kind: str, value: str) -> str:
    """Canonical form used only for recipient matching.

    Email local parts are technically case sensitive.  Archives in practice
    contain case variations, so matching is case-insensitive and the report
    states that normalization explicitly.
    """

    if kind in ("rfc822Name", "dNSName"):
        return "%s:%s" % (kind, value.strip().lower())
    return "%s:%s" % (kind, value.strip())


@dataclass(frozen=True)
class CertificateInfo:
    der: bytes
    subject: str
    issuer_der: bytes
    serial: int
    subject_key_identifier: Optional[bytes]
    emails: Tuple[str, ...]
    names: Tuple[Tuple[str, str], ...]
    parse_issues: Tuple[str, ...] = ()


@dataclass(frozen=True)
class Attribute:
    oid: str
    values: Tuple[bytes, ...]
    der: bytes


@dataclass(frozen=True)
class SignerRecord:
    index: int
    layer_index: int
    signature: bytes
    digest_algorithm: str
    signature_algorithm: str
    sid_kind: str
    sid_issuer_der: Optional[bytes]
    sid_serial: Optional[int]
    sid_subject_key_identifier: Optional[bytes]
    attributes: Tuple[Attribute, ...]
    signed_attributes_der: Optional[bytes]
    certificate: Optional[CertificateInfo]
    message_digest: Optional[bytes]
    content_type: Optional[str]
    content_identifier: Optional[bytes]
    receipt_request: Optional[rfc2634.ReceiptRequest]
    receipt_request_der: Optional[bytes]
    msg_sig_digest: Optional[bytes]
    ml_expansion_history: Optional[rfc2634.MLExpansionHistory]
    ml_expansion_history_der: Optional[bytes]
    parse_issues: Tuple[str, ...] = ()

    @property
    def path(self) -> str:
        return "layers[%d].signerInfos[%d]" % (self.layer_index, self.index)

    def attr_der(self, oid) -> Optional[bytes]:
        for attribute in self.attributes:
            if attribute.oid == str(oid):
                return attribute.der
        return None

    def attr_values(self, oid) -> Tuple[bytes, ...]:
        found: List[bytes] = []
        for attribute in self.attributes:
            if attribute.oid == str(oid):
                found.extend(attribute.values)
        return tuple(found)

    @property
    def emails(self) -> Tuple[str, ...]:
        return () if self.certificate is None else self.certificate.emails


@dataclass(frozen=True)
class Envelope:
    layer_index: int
    content_info_der: bytes
    signed_data_der: bytes
    econtent_type: str
    econtent: Optional[bytes]
    signers: Tuple[SignerRecord, ...]
    certificates: Tuple[CertificateInfo, ...]
    receipt: Optional[rfc2634.Receipt]
    nested: Optional["Envelope"]
    parse_issues: Tuple[str, ...] = ()

    @property
    def path(self) -> str:
        return "layers[%d]" % (self.layer_index,)


@dataclass(frozen=True)
class MessageRecord:
    name: str
    der: bytes
    der_sha256: str
    layers: Tuple[Envelope, ...]
    parse_issues: Tuple[str, ...] = ()

    @property
    def outer(self) -> Envelope:
        return self.layers[0]

    @property
    def body(self) -> Optional[bytes]:
        return self.layers[-1].econtent

    @property
    def body_sha256(self) -> Optional[str]:
        body = self.body
        return None if body is None else sha256_hex(body)

    @property
    def signers(self) -> Tuple[SignerRecord, ...]:
        return tuple(s for layer in self.layers for s in layer.signers)


@dataclass(frozen=True)
class ReceiptRecord:
    name: str
    der: bytes
    der_sha256: str
    envelope: Envelope
    receipt: rfc2634.Receipt
    receipt_content_der: bytes
    parse_issues: Tuple[str, ...] = ()

    @property
    def version(self) -> int:
        return int(self.receipt["version"])

    @property
    def content_type(self) -> str:
        return str(self.receipt["contentType"])

    @property
    def signed_content_identifier(self) -> bytes:
        return bytes(self.receipt["signedContentIdentifier"])

    @property
    def originator_signature_value(self) -> bytes:
        return bytes(self.receipt["originatorSignatureValue"])

    @property
    def signer(self) -> SignerRecord:
        if len(self.envelope.signers) != 1:
            raise DecodeError(
                "signedData/Receipt must contain exactly one SignerInfo, found %d"
                % (len(self.envelope.signers),)
            )
        return self.envelope.signers[0]


@dataclass(frozen=True)
class SignerAttestation:
    status: str = STATUS_UNKNOWN
    reason: str = ""
    signer_names: Tuple[str, ...] = ()
    signature_sha256: Optional[str] = None

    def normalized(self) -> "SignerAttestation":
        status = _STATUS_ALIASES.get(str(self.status).strip().lower())
        if status is None:
            raise ValueError(
                "unrecognised signer verification status %r; use valid, invalid or unknown"
                % (self.status,)
            )
        digest = self.signature_sha256
        if digest is not None:
            digest = str(digest).strip().lower()
            if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
                raise ValueError("signatureSha256 must be 64 hex characters")
        return SignerAttestation(
            status=status,
            reason=self.reason,
            signer_names=tuple(self.signer_names),
            signature_sha256=digest,
        )


@dataclass(frozen=True)
class ReceiptAttestation:
    signature_status: str = STATUS_UNKNOWN
    certificate_trust: str = TRUST_UNKNOWN
    reason: str = ""
    signer_names: Tuple[str, ...] = ()

    def normalized(self) -> "ReceiptAttestation":
        status = _STATUS_ALIASES.get(str(self.signature_status).strip().lower())
        if status is None:
            raise ValueError(
                "unrecognised receipt signature status %r; use valid, invalid or unknown"
                % (self.signature_status,)
            )
        trust = _TRUST_ALIASES.get(str(self.certificate_trust).strip().lower())
        if trust is None:
            raise ValueError(
                "unrecognised certificate trust %r; use trusted, untrusted or unknown"
                % (self.certificate_trust,)
            )
        return ReceiptAttestation(
            signature_status=status,
            certificate_trust=trust,
            reason=self.reason,
            signer_names=tuple(self.signer_names),
        )


@dataclass(frozen=True)
class Attestations:
    """Explicit verification inputs; absent entries are unknown."""

    message_signers: Mapping[str, Tuple[Tuple[SignerAttestation, ...], ...]] = field(
        default_factory=dict
    )
    receipts: Mapping[str, ReceiptAttestation] = field(default_factory=dict)

    def message_signer(self, message: str, layer: int, signer: int, signature: bytes = b"") -> SignerAttestation:
        layers = self.message_signers.get(message, ())
        digest = sha256_hex(signature)
        matches = [
            entry
            for entries in layers
            for entry in entries
            if entry.signature_sha256 == digest
        ]
        if len(matches) == 1:
            return matches[0]
        if len(matches) > 1:
            return SignerAttestation(
                status=STATUS_UNKNOWN,
                reason="multiple attestations share signatureSha256 %s" % (digest,),
            )
        # Any hash-keyed entry means the manifest opted out of positional
        # addressing; do not silently fall back to positions.
        if any(entry.signature_sha256 is not None for entries in layers for entry in entries):
            return SignerAttestation(
                status=STATUS_UNKNOWN,
                reason="no attestation matches signatureSha256 %s" % (digest,),
            )
        if layer >= len(layers) or signer >= len(layers[layer]):
            return SignerAttestation()
        return layers[layer][signer]

    def receipt(self, receipt: str) -> ReceiptAttestation:
        return self.receipts.get(receipt, ReceiptAttestation())


def _parse_signer_attestation(raw) -> SignerAttestation:
    if raw is None:
        return SignerAttestation()
    if isinstance(raw, str):
        return SignerAttestation(status=raw).normalized()
    if not isinstance(raw, Mapping):
        raise ValueError("signer attestation must be a string or object")
    return SignerAttestation(
        status=raw.get("status", STATUS_UNKNOWN),
        reason=str(raw.get("reason", "")),
        signer_names=tuple(raw.get("signerNames", ()) or ()),
        signature_sha256=raw.get("signatureSha256"),
    ).normalized()


def attestations_from_mapping(document: Mapping) -> Attestations:
    """Build attestations from the archive manifest.

    Expected shape::

        {
          "messages": {
            "MSG-A": {"layers": [{"signers": [{"status": "valid"}]}]}
          },
          "receipts": {
            "RECEIPT-A": {"signatureStatus": "valid",
                           "certificateTrust": "trusted",
                           "signerNames": ["bob@example.com"]}
          }
        }

    Any missing message, layer or signer entry stays ``unknown``.  No value
    is inferred, and unrecognised status words raise instead of being
    silently treated as valid.
    """

    messages = document.get("messages", {}) if document else {}
    receipts = document.get("receipts", {}) if document else {}
    parsed_messages: Dict[str, Tuple[Tuple[SignerAttestation, ...], ...]] = {}
    for message, raw_message in messages.items():
        layers_raw = raw_message.get("layers", ()) if isinstance(raw_message, Mapping) else ()
        layers: List[Tuple[SignerAttestation, ...]] = []
        for raw_layer in layers_raw:
            signers_raw = raw_layer.get("signers", ()) if isinstance(raw_layer, Mapping) else ()
            layers.append(tuple(_parse_signer_attestation(item) for item in signers_raw))
        parsed_messages[str(message)] = tuple(layers)

    parsed_receipts: Dict[str, ReceiptAttestation] = {}
    for receipt, raw_receipt in receipts.items():
        if not isinstance(raw_receipt, Mapping):
            raise ValueError("receipt attestation for %s must be an object" % (receipt,))
        parsed_receipts[str(receipt)] = ReceiptAttestation(
            signature_status=raw_receipt.get("signatureStatus", STATUS_UNKNOWN),
            certificate_trust=raw_receipt.get("certificateTrust", TRUST_UNKNOWN),
            reason=str(raw_receipt.get("reason", "")),
            signer_names=tuple(raw_receipt.get("signerNames", ()) or ()),
        ).normalized()
    return Attestations(message_signers=parsed_messages, receipts=parsed_receipts)


def _parse_certificate(cert) -> CertificateInfo:
    issues: List[str] = []
    tbs = cert["tbsCertificate"]
    emails: List[str] = []
    names: List[Tuple[str, str]] = []
    ski = None
    try:
        subject_text = _dn_string(tbs["subject"])
    except (PyAsn1Error, KeyError):
        subject_text = ""

    for rdn in tbs["subject"]["rdnSequence"]:
        for atv in rdn:
            if str(atv["type"]) == str(rfc5280.id_emailAddress):
                try:
                    email = str(_decode(bytes(atv["value"]), char.IA5String(), "emailAddress"))
                except DecodeError as exc:
                    issues.append(str(exc))
                    continue
                emails.append(email)
                names.append(("rfc822Name", email))

    extensions = _optional_value(tbs, "extensions")
    if extensions is not None:
        for extension in extensions:
            oid = str(extension["extnID"])
            value = bytes(extension["extnValue"])
            if oid == str(rfc5280.id_ce_subjectKeyIdentifier):
                try:
                    ski = bytes(_decode(value, rfc5280.SubjectKeyIdentifier(), "subjectKeyIdentifier"))
                except DecodeError as exc:
                    issues.append(str(exc))
            elif oid == str(rfc5280.id_ce_subjectAltName):
                try:
                    sans = _decode(value, rfc5280.SubjectAltName(), "subjectAltName")
                except DecodeError as exc:
                    issues.append(str(exc))
                    continue
                for general_name in sans:
                    kind, text = _general_name_text(general_name)
                    names.append((kind, text))
                    if kind == "rfc822Name" and text not in emails:
                        emails.append(text)

    return CertificateInfo(
        der=der_encoder(cert),
        subject=subject_text,
        issuer_der=der_encoder(tbs["issuer"]),
        serial=int(tbs["serialNumber"]),
        subject_key_identifier=ski,
        emails=tuple(emails),
        names=tuple(names),
        parse_issues=tuple(issues),
    )


def _signer_certificate(signer, certificates: Sequence[CertificateInfo]) -> Optional[CertificateInfo]:
    for certificate in certificates:
        if signer.sid_kind == "issuerAndSerialNumber":
            if (
                certificate.issuer_der == signer.sid_issuer_der
                and certificate.serial == signer.sid_serial
            ):
                return certificate
        elif signer.sid_kind == "subjectKeyIdentifier":
            if (
                signer.sid_subject_key_identifier is not None
                and certificate.subject_key_identifier == signer.sid_subject_key_identifier
            ):
                return certificate
    return None


def _decode_attribute(attribute) -> Attribute:
    values = tuple(bytes(value) for value in attribute["attrValues"])
    return Attribute(
        oid=str(attribute["attrType"]),
        values=values,
        der=der_encoder(attribute),
    )


def _decode_signed_value(
    signer: SignerRecord,
    oid,
    spec,
    label: str,
    issues: List[str],
):
    values = signer.attr_values(oid)
    if not values:
        return None, None
    if len(values) != 1:
        issues.append(
            "%s: expected exactly one %s attribute value, found %d"
            % (signer.path, label, len(values))
        )
        return None, None
    try:
        decoded = _decode(values[0], spec, "%s %s" % (signer.path, label))
    except DecodeError as exc:
        issues.append(str(exc))
        return None, None
    return decoded, values[0]


def _parse_signers(sd, layer_index: int, certificates: Sequence[CertificateInfo]):
    signers: List[SignerRecord] = []
    issues: List[str] = []
    for index, signer in enumerate(sd["signerInfos"]):
        signer_issues: List[str] = []
        sid = signer["sid"]
        sid_kind = sid.getName()
        sid_issuer_der = None
        sid_serial = None
        sid_ski = None
        if sid_kind == "issuerAndSerialNumber":
            sid_issuer_der = der_encoder(sid["issuerAndSerialNumber"]["issuer"])
            sid_serial = int(sid["issuerAndSerialNumber"]["serialNumber"])
        else:
            sid_ski = bytes(sid["subjectKeyIdentifier"])

        attributes: Tuple[Attribute, ...] = ()
        signed_attributes_der = None
        signed_attrs = _optional_value(signer, "signedAttrs")
        if signed_attrs is not None:
            attributes = tuple(_decode_attribute(item) for item in signed_attrs)
            seen_oids = set()
            for attribute in attributes:
                if attribute.oid in seen_oids:
                    signer_issues.append(
                        "%s: duplicate attribute type %s; ESS permits at most one"
                        % ("layers[%d].signerInfos[%d]" % (layer_index, index), attribute.oid)
                    )
                seen_oids.add(attribute.oid)
                if len(attribute.values) != 1:
                    signer_issues.append(
                        "%s: attribute %s has %d values; ESS permits exactly one"
                        % (
                            "layers[%d].signerInfos[%d]" % (layer_index, index),
                            attribute.oid,
                            len(attribute.values),
                        )
                    )
            try:
                signed_attributes_der = set_of_der(der_encoder(signed_attrs))
            except DecodeError as exc:
                signer_issues.append(str(exc))

        record = SignerRecord(
            index=index,
            layer_index=layer_index,
            signature=bytes(signer["signature"]),
            digest_algorithm=str(signer["digestAlgorithm"]["algorithm"]),
            signature_algorithm=str(signer["signatureAlgorithm"]["algorithm"]),
            sid_kind=sid_kind,
            sid_issuer_der=sid_issuer_der,
            sid_serial=sid_serial,
            sid_subject_key_identifier=sid_ski,
            attributes=attributes,
            signed_attributes_der=signed_attributes_der,
            certificate=None,
            message_digest=None,
            content_type=None,
            content_identifier=None,
            receipt_request=None,
            receipt_request_der=None,
            msg_sig_digest=None,
            ml_expansion_history=None,
            ml_expansion_history_der=None,
            parse_issues=(),
        )

        content_type, _ = _decode_signed_value(
            record, rfc5652.id_contentType, rfc5652.ContentType(), "contentType", signer_issues
        )
        content_identifier, _ = _decode_signed_value(
            record,
            rfc2634.id_aa_contentIdentifier,
            rfc2634.ContentIdentifier(),
            "contentIdentifier",
            signer_issues,
        )
        receipt_request, receipt_request_der = _decode_signed_value(
            record,
            rfc2634.id_aa_receiptRequest,
            rfc2634.ReceiptRequest(),
            "receiptRequest",
            signer_issues,
        )
        msg_sig_digest, _ = _decode_signed_value(
            record,
            rfc2634.id_aa_msgSigDigest,
            rfc2634.MsgSigDigest(),
            "msgSigDigest",
            signer_issues,
        )
        message_digest, _ = _decode_signed_value(
            record,
            rfc5652.id_messageDigest,
            rfc5652.MessageDigest(),
            "messageDigest",
            signer_issues,
        )
        history, history_der = _decode_signed_value(
            record,
            rfc2634.id_aa_mlExpandHistory,
            rfc2634.MLExpansionHistory(),
            "mlExpansionHistory",
            signer_issues,
        )

        record = SignerRecord(
            index=record.index,
            layer_index=record.layer_index,
            signature=record.signature,
            digest_algorithm=record.digest_algorithm,
            signature_algorithm=record.signature_algorithm,
            sid_kind=record.sid_kind,
            sid_issuer_der=record.sid_issuer_der,
            sid_serial=record.sid_serial,
            sid_subject_key_identifier=record.sid_subject_key_identifier,
            attributes=record.attributes,
            signed_attributes_der=record.signed_attributes_der,
            certificate=_signer_certificate(record, certificates),
            message_digest=None if message_digest is None else bytes(message_digest),
            content_type=None if content_type is None else str(content_type),
            content_identifier=None if content_identifier is None else bytes(content_identifier),
            receipt_request=receipt_request,
            receipt_request_der=receipt_request_der,
            msg_sig_digest=None if msg_sig_digest is None else bytes(msg_sig_digest),
            ml_expansion_history=history,
            ml_expansion_history_der=history_der,
            parse_issues=tuple(signer_issues),
        )
        if len(record.attr_values(rfc5652.id_messageDigest)) > 1:
            signer_issues.append(
                "%s: multiple messageDigest attribute values" % (record.path,)
            )
        signers.append(record)
    return tuple(signers), tuple(issues)


def _load_envelope(data: bytes, layer_index: int = 0) -> Envelope:
    if layer_index >= MAX_LAYERS:
        raise DecodeError("nesting exceeds %d layers" % (MAX_LAYERS,))
    issues: List[str] = []
    content_info = None
    try:
        content_info = _decode(data, rfc5652.ContentInfo(), "ContentInfo")
    except DecodeError:
        signed_data = _decode(data, rfc5652.SignedData(), "SignedData")
        content_info = content_info_of(signed_data)
        wrapped = True
    else:
        wrapped = False
    if str(content_info["contentType"]) != str(rfc5652.id_signedData):
        raise DecodeError(
            "ContentInfo.contentType is %s, not id-signedData" % (content_info["contentType"],)
        )
    if wrapped:
        content_info_der = der_encoder(content_info)
    else:
        content_info_der = der_encoder(content_info)
    content_bytes = bytes(content_info["content"])
    signed_data = _decode(content_bytes, rfc5652.SignedData(), "SignedData")
    if der_encoder(signed_data) != content_bytes:
        issues.append("SignedData does not round-trip through DER")

    certificates: List[CertificateInfo] = []
    certificate_set = _optional_value(signed_data, "certificates")
    if certificate_set is not None:
        for choice in certificate_set:
            if choice.getName() != "certificate":
                issues.append("ignored non-X.509 certificate choice %s" % (choice.getName(),))
                continue
            certificates.append(_parse_certificate(choice["certificate"]))

    signers, signer_issues = _parse_signers(signed_data, layer_index, certificates)
    issues.extend(signer_issues)

    econtent_info = signed_data["encapContentInfo"]
    econtent_type = str(econtent_info["eContentType"])
    econtent_component = _optional_value(econtent_info, "eContent")
    econtent = None if econtent_component is None else bytes(econtent_component)

    receipt = None
    nested = None
    if econtent_type == str(rfc2634.id_ct_receipt):
        if econtent is None:
            issues.append("Receipt content is detached (eContent absent)")
        else:
            try:
                receipt = _decode(econtent, rfc2634.Receipt(), "Receipt")
                if der_encoder(receipt) != econtent:
                    issues.append("Receipt content does not round-trip through DER")
            except DecodeError as exc:
                issues.append(str(exc))
    elif econtent_type in (str(rfc5652.id_signedData), str(rfc5652.id_ct_contentInfo)):
        if econtent is None:
            issues.append("nested SignedData content is detached (eContent absent)")
        else:
            try:
                nested = _load_envelope(econtent, layer_index + 1)
            except DecodeError as exc:
                issues.append("nested layer: %s" % (exc,))
    elif econtent_type == str(rfc5652.id_envelopedData):
        issues.append("EnvelopedData layer is opaque; encrypted inner content is not analysed")
    elif econtent_type in (
        str(rfc5652.id_data),
        str(rfc5652.id_ct_authData),
        str(rfc5652.id_digestedData),
        str(rfc5652.id_encryptedData),
    ):
        pass
    else:
        issues.append("unrecognised encapsulated content type %s" % (econtent_type,))

    return Envelope(
        layer_index=layer_index,
        content_info_der=content_info_der,
        signed_data_der=der_encoder(signed_data),
        econtent_type=econtent_type,
        econtent=econtent,
        signers=signers,
        certificates=tuple(certificates),
        receipt=receipt,
        nested=nested,
        parse_issues=tuple(issues),
    )


def content_info_of(signed_data) -> rfc5652.ContentInfo:
    content_info = rfc5652.ContentInfo()
    content_info["contentType"] = rfc5652.id_signedData
    content_info["content"] = der_encoder(signed_data)
    return content_info


def _flatten(envelope: Envelope) -> Tuple[Envelope, ...]:
    layers = [envelope]
    current = envelope
    while current.nested is not None:
        layers.append(current.nested)
        current = current.nested
    return tuple(layers)


def decode_message(name: str, der: bytes) -> MessageRecord:
    envelope = _load_envelope(der)
    layers = _flatten(envelope)
    return MessageRecord(
        name=name,
        der=der,
        der_sha256=sha256_hex(der),
        layers=layers,
        parse_issues=envelope.parse_issues,
    )


def decode_receipt(name: str, der: bytes) -> ReceiptRecord:
    """Decode a ``signedData/Receipt`` object.

    The outer ``encapContentInfo.eContentType`` is checked later by the
    analysis so that a receipt delivered under the wrong content type can be
    reported field by field rather than rejected at decode time.
    """

    envelope = _load_envelope(der)
    if envelope.nested is not None:
        raise DecodeError("Receipt is nested inside another SignedData layer")
    if envelope.econtent is None:
        raise DecodeError("Receipt content is detached")
    issues = list(envelope.parse_issues)
    if envelope.econtent_type != str(rfc2634.id_ct_receipt):
        issues.append(
            "outer encapContentInfo.eContentType is %s, not id-ct-receipt"
            % (envelope.econtent_type,)
        )
    try:
        receipt = _decode(envelope.econtent, rfc2634.Receipt(), "Receipt content")
    except DecodeError as exc:
        raise DecodeError("not a Receipt object: %s" % (exc,))
    return ReceiptRecord(
        name=name,
        der=der,
        der_sha256=sha256_hex(der),
        envelope=envelope,
        receipt=receipt,
        receipt_content_der=envelope.econtent,
        parse_issues=tuple(issues),
    )


def receipt_request_names(request: rfc2634.ReceiptRequest) -> Tuple[Tuple[str, str], ...]:
    """Flatten ``receiptsFrom.receiptList`` GeneralNames."""

    names: List[Tuple[str, str]] = []
    choice = request["receiptsFrom"]
    if choice.getName() != "receiptList":
        return ()
    for general_names in choice["receiptList"]:
        for general_name in general_names:
            names.append(_general_name_text(general_name))
    return tuple(names)


def general_names_texts(general_names) -> Tuple[Tuple[str, str], ...]:
    return tuple(_general_name_text(item) for item in general_names)


def receipts_to_names(request: rfc2634.ReceiptRequest) -> Tuple[Tuple[Tuple[str, str], ...], ...]:
    entries: List[Tuple[Tuple[str, str], ...]] = []
    for general_names in request["receiptsTo"]:
        entries.append(general_names_texts(general_names))
    return tuple(entries)


def ml_data_summary(history: rfc2634.MLExpansionHistory) -> Tuple[Dict, ...]:
    entries: List[Dict] = []
    for data in history:
        identifier = data["mailListIdentifier"]
        kind = identifier.getName()
        if kind == "issuerAndSerialNumber":
            issuer = identifier["issuerAndSerialNumber"]["issuer"]
            serial = int(identifier["issuerAndSerialNumber"]["serialNumber"])
            identifier_text = "issuer=%s, serial=%d" % (_dn_string(issuer), serial)
        else:
            identifier_text = "subjectKeyIdentifier=0x%s" % (
                bytes(identifier["subjectKeyIdentifier"]).hex(),
            )
        policy = _optional_value(data, "mlReceiptPolicy")
        policy_entry: Dict = {"kind": None, "names": []}
        if policy is not None:
            policy_kind = policy.getName()
            policy_entry["kind"] = policy_kind
            if policy_kind in ("insteadOf", "inAdditionTo"):
                policy_names: List[Dict] = []
                for general_names in policy[policy_kind]:
                    for name_kind, value in general_names_texts(general_names):
                        policy_names.append({"kind": name_kind, "value": value})
                policy_entry["names"] = policy_names
        entries.append(
            {
                "mailListIdentifier": identifier_text,
                "expansionTime": str(data["expansionTime"]),
                "mlReceiptPolicy": policy_entry,
            }
        )
    return tuple(entries)


def layer_history(layer: Envelope):
    """Return ``(history, der, conflict)`` for the layer's signerInfos."""

    histories = [
        (signer.ml_expansion_history, signer.ml_expansion_history_der)
        for signer in layer.signers
        if signer.ml_expansion_history is not None
    ]
    if not histories:
        return None, None, False
    first_value, first_der = histories[0]
    conflict = any(der != first_der for _, der in histories[1:])
    return first_value, first_der, conflict


def effective_history(message: MessageRecord):
    """Topmost layer carrying mlExpansionHistory, as RFC 2634 section 2.3 uses."""

    for layer in message.layers:
        history, der, conflict = layer_history(layer)
        if history is not None:
            return layer, history, der, conflict
    return None, None, None, False


def parse_status(value: Optional[str]) -> str:
    if value is None:
        return STATUS_UNKNOWN
    status = _STATUS_ALIASES.get(str(value).strip().lower())
    if status is None:
        raise ValueError("unrecognised verification status %r" % (value,))
    return status


__all__ = [
    "Attestations",
    "Attribute",
    "CertificateInfo",
    "DecodeError",
    "Envelope",
    "MessageRecord",
    "ReceiptAttestation",
    "ReceiptRecord",
    "SignerAttestation",
    "SignerRecord",
    "STATUS_INVALID",
    "STATUS_UNKNOWN",
    "STATUS_VALID",
    "TRUST_TRUSTED",
    "TRUST_UNKNOWN",
    "TRUST_UNTRUSTED",
    "attestations_from_mapping",
    "canonical_name",
    "decode_message",
    "decode_receipt",
    "digest_for_oid",
    "effective_history",
    "general_names_texts",
    "hex_bytes",
    "layer_history",
    "ml_data_summary",
    "receipt_request_names",
    "receipts_to_names",
    "set_of_der",
    "sha256_hex",
]
