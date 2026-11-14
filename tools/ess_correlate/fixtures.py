"""Deterministic ESS/CMS fixtures for the correlation prototype.

Signature values below are placeholders.  They are stable, non-empty octet
strings so that the receipt fields can reference them exactly, but they are
not real cryptographic signatures.  Every verification outcome is supplied
separately by ``attestations()``; the fixtures themselves never assert that
anything is valid.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Tuple

from pyasn1.codec.der.decoder import decode as der_decoder
from pyasn1.codec.der.encoder import encode as der_encoder
from pyasn1.type import char, tag, univ
from pyasn1_modules import rfc2634, rfc4055, rfc5280, rfc5652

from .model import set_of_der

SHA256 = rfc4055.id_sha256

HASH_NAMES = {
    str(rfc4055.id_sha1): "sha1",
    str(rfc4055.id_sha224): "sha224",
    str(rfc4055.id_sha256): "sha256",
    str(rfc4055.id_sha384): "sha384",
    str(rfc4055.id_sha512): "sha512",
}


def _body(subject: str, text: str, message_id: str) -> bytes:
    return (
        "From: alice@example.com\r\n"
        "To: bob@example.com\r\n"
        "Subject: %s\r\n"
        "Date: Fri, 13 Nov 2026 09:00:00 +0000\r\n"
        "Message-ID: <%s>\r\n"
        "\r\n"
        "%s\r\n" % (subject, message_id, text)
    ).encode("utf-8")


BODY_PRIMARY = _body("Q4 report", "The quarterly report is attached.", "q4-primary@example.com")
BODY_MULTI = _body("Two signatures", "Two signers, only one asks for a receipt.", "multi@example.com")
BODY_LIST = _body("List expansion", "Delivered through a mailing list.", "list@example.com")
BODY_NO_RR = _body("No receipt requested", "This message never asked for a receipt.", "no-rr@example.com")


@dataclass(frozen=True)
class SignerSpec:
    """Metadata for one fabricated SignerInfo."""

    signature: bytes
    certificate_email: str
    signed_attributes_der: bytes
    content_type: str
    signed_content_identifier: Optional[bytes]
    receipt_request_der: Optional[bytes]
    layer_index: int
    index: int

    @property
    def label(self) -> str:
        return "layers[%d].signerInfos[%d]" % (self.layer_index, self.index)


@dataclass(frozen=True)
class FixtureMessage:
    name: str
    der: bytes
    signed_data_der: bytes
    body: Optional[bytes]
    signers: Tuple[SignerSpec, ...]
    description: str

    def signer_at(self, layer: int, index: int) -> SignerSpec:
        for signer in self.signers:
            if signer.layer_index == layer and signer.index == index:
                return signer
        raise KeyError((layer, index))

    def signer_by_signature(self, signature: bytes) -> SignerSpec:
        for signer in self.signers:
            if signer.signature == signature:
                return signer
        raise KeyError(signature)


@dataclass(frozen=True)
class FixtureReceipt:
    name: str
    der: bytes
    target_message: str
    target_signer: SignerSpec
    receipt_signer_email: str
    description: str


@dataclass(frozen=True)
class Corpus:
    messages: Tuple[FixtureMessage, ...]
    receipts: Tuple[FixtureReceipt, ...]
    notes: Tuple[str, ...] = ()

    def message(self, name: str) -> FixtureMessage:
        for message in self.messages:
            if message.name == name:
                return message
        raise KeyError(name)

    def receipt(self, name: str) -> FixtureReceipt:
        for receipt in self.receipts:
            if receipt.name == name:
                return receipt


# --------------------------------------------------------------------------
# ASN.1 construction helpers


def _name(common_name: str, email: str) -> rfc5280.Name:
    name = rfc5280.Name()
    sequence = rfc5280.RDNSequence()
    for oid, value in (
        (rfc5280.id_at_commonName, common_name),
        (rfc5280.id_emailAddress, email),
    ):
        if oid == rfc5280.id_at_commonName:
            encoded = rfc5280.X520CommonName()
            encoded["printableString"] = value
        else:
            encoded = rfc5280.EmailAddress(value)
        atv = rfc5280.AttributeTypeAndValue()
        atv["type"] = oid
        atv["value"] = rfc5280.AttributeValue(der_encoder(encoded))
        rdn = rfc5280.RelativeDistinguishedName()
        rdn.append(atv)
        sequence.append(rdn)
    name["rdnSequence"] = sequence
    return name


def _certificate(common_name: str, email: str, serial: int) -> rfc5280.Certificate:
    certificate = rfc5280.Certificate()
    tbs = certificate["tbsCertificate"]
    tbs["version"] = "v3"
    tbs["serialNumber"] = serial
    tbs["signature"]["algorithm"] = SHA256
    subject = _name(common_name, email)
    tbs["issuer"] = subject
    tbs["subject"] = subject
    tbs["validity"]["notBefore"]["utcTime"] = "260101000000Z"
    tbs["validity"]["notAfter"]["utcTime"] = "270101000000Z"
    tbs["subjectPublicKeyInfo"]["algorithm"]["algorithm"] = univ.ObjectIdentifier("1.2.840.10045.2.1")
    tbs["subjectPublicKeyInfo"]["subjectPublicKey"] = univ.BitString(hexValue="00")

    names = rfc5280.GeneralNames()
    general_name = rfc5280.GeneralName()
    general_name["rfc822Name"] = email
    names.append(general_name)
    extension = rfc5280.Extension()
    extension["extnID"] = rfc5280.id_ce_subjectAltName
    extension["critical"] = False
    extension["extnValue"] = der_encoder(names)
    extensions = rfc5280.Extensions()
    extensions.append(extension)
    tbs["extensions"] = extensions.subtype(
        explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 3)
    )
    certificate["signatureAlgorithm"]["algorithm"] = SHA256
    certificate["signature"] = univ.BitString(hexValue="00")
    return certificate


def _general_names(email: str) -> rfc5280.GeneralNames:
    names = rfc5280.GeneralNames()
    general_name = rfc5280.GeneralName()
    general_name["rfc822Name"] = email
    names.append(general_name)
    return names


def _attribute(oid, value) -> rfc5652.Attribute:
    attribute = rfc5652.Attribute()
    attribute["attrType"] = oid
    attribute["attrValues"].append(univ.Any(der_encoder(value)))
    return attribute


def _tagged(attributes: rfc5652.SignedAttributes):
    spec = rfc5652.SignerInfo.componentType.getTypeByPosition(3)
    tagged = spec.clone()
    for attribute in attributes:
        tagged.append(attribute)
    return tagged


def _signed_attributes(content_type, content, digest_oid, extras):
    attributes = rfc5652.SignedAttributes()
    attributes.append(_attribute(rfc5652.id_contentType, rfc5652.ContentType(content_type)))
    digest = hashlib.new(HASH_NAMES[str(digest_oid)], content).digest()
    attributes.append(_attribute(rfc5652.id_messageDigest, rfc5652.MessageDigest(digest)))
    for oid, value in extras:
        attributes.append(_attribute(oid, value))
    return attributes, set_of_der(der_encoder(_tagged(attributes)))


def _receipt_request(signed_content_identifier, receipts_from, receipts_to):
    request = rfc2634.ReceiptRequest()
    request["signedContentIdentifier"] = signed_content_identifier
    if isinstance(receipts_from, str):
        values = {"allReceipts": 0, "firstTierRecipients": 1}
        if receipts_from not in values:
            raise ValueError(receipts_from)
        request["receiptsFrom"]["allOrFirstTier"] = rfc2634.AllOrFirstTier(
            values[receipts_from]
        ).subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0))
    else:
        entries = rfc2634.ReceiptsFrom.componentType.getTypeByPosition(1).clone()
        for email in receipts_from:
            entries.append(_general_names(email))
        request["receiptsFrom"]["receiptList"] = entries
    for email in receipts_to:
        request["receiptsTo"].append(_general_names(email))
    return request


def _ml_history(certificate, expansion_time, policy_kind, policy_names=()):
    data = rfc2634.MLData()
    identifier = data["mailListIdentifier"]
    identifier["issuerAndSerialNumber"]["issuer"] = certificate["tbsCertificate"]["issuer"]
    identifier["issuerAndSerialNumber"]["serialNumber"] = (
        certificate["tbsCertificate"]["serialNumber"]
    )
    data["expansionTime"] = expansion_time
    if policy_kind == "none":
        data["mlReceiptPolicy"]["none"] = univ.Null("").subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0)
        )
    elif policy_kind is not None:
        number = {"insteadOf": 1, "inAdditionTo": 2}[policy_kind]
        entries = rfc2634.MLReceiptPolicy.componentType.getTypeByPosition(number).clone()
        for email in policy_names:
            entries.append(_general_names(email))
        data["mlReceiptPolicy"][policy_kind] = entries
    history = rfc2634.MLExpansionHistory()
    history.append(data)
    return history


@dataclass
class _LayerSpec:
    econtent_type: str
    econtent: Optional[bytes]
    certificates: List[object] = field(default_factory=list)
    # Each signer: (signature bytes, certificate, extras, content_type, sci)
    signers: List[dict] = field(default_factory=list)


def _build_signed_data(layer: _LayerSpec, layer_index: int):
    signed_data = rfc5652.SignedData()
    signed_data["version"] = 1
    algorithms = rfc5652.DigestAlgorithmIdentifiers()
    identifier = rfc5652.DigestAlgorithmIdentifier()
    identifier["algorithm"] = SHA256
    algorithms.append(identifier)
    signed_data["digestAlgorithms"] = algorithms
    signed_data["encapContentInfo"]["eContentType"] = layer.econtent_type
    if layer.econtent is not None:
        signed_data["encapContentInfo"]["eContent"] = layer.econtent

    certificate_set = rfc5652.CertificateSet()
    for certificate in layer.certificates:
        choice = rfc5652.CertificateChoices()
        choice["certificate"] = certificate
        certificate_set.append(choice)
    # Build the [0] tag on the schema object first, then append: applying
    # the implicit tag to an already-populated SetOf discards its components.
    signed_data["certificates"] = certificate_set.subtype(
        implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0)
    ).clone()
    for choice in certificate_set:
        signed_data["certificates"].append(choice)

    signer_infos = rfc5652.SignerInfos()
    specs: List[SignerSpec] = []
    for index, spec in enumerate(layer.signers):
        certificate = spec["certificate"]
        attributes, attributes_der = _signed_attributes(
            spec["content_type"], layer.econtent or b"", SHA256, spec["extras"]
        )
        signer = rfc5652.SignerInfo()
        signer["version"] = 1
        ias = rfc5652.IssuerAndSerialNumber()
        ias["issuer"] = certificate["tbsCertificate"]["issuer"]
        ias["serialNumber"] = certificate["tbsCertificate"]["serialNumber"]
        signer["sid"]["issuerAndSerialNumber"] = ias
        signer["digestAlgorithm"]["algorithm"] = SHA256
        signer["signedAttrs"] = _tagged(attributes)
        signer["signatureAlgorithm"]["algorithm"] = univ.ObjectIdentifier(
            "1.2.840.10045.4.3.2"
        )
        signer["signature"] = spec["signature"]
        signer_infos.append(signer)
        specs.append(
            SignerSpec(
                signature=spec["signature"],
                certificate_email=spec["certificate_email"],
                signed_attributes_der=attributes_der,
                content_type=spec["content_type"],
                signed_content_identifier=spec.get("sci"),
                receipt_request_der=spec.get("receipt_request_der"),
                layer_index=layer_index,
                index=index,
            )
        )
    signed_data["signerInfos"] = signer_infos
    return signed_data, tuple(specs)


def _content_info(signed_data) -> rfc5652.ContentInfo:
    content_info = rfc5652.ContentInfo()
    content_info["contentType"] = rfc5652.id_signedData
    content_info["content"] = der_encoder(signed_data)
    return content_info


def _assemble(name, layer_specs, description) -> Tuple[FixtureMessage, List[Tuple[object, Tuple[SignerSpec, ...]]]]:
    """Build from innermost to outermost and return the message plus layers."""

    built = []
    total = len(layer_specs)
    for position, layer in enumerate(layer_specs):
        layer_index = total - 1 - position
        signed_data, specs = _build_signed_data(layer, layer_index)
        built.append((layer, signed_data, specs))
        der = der_encoder(signed_data)
        if position + 1 < total:
            layer_specs[position + 1].econtent = der
    outer_signed_data = built[-1][1]
    inner_body = built[0][0].econtent
    message = FixtureMessage(
        name=name,
        der=der_encoder(_content_info(outer_signed_data)),
        signed_data_der=der_encoder(outer_signed_data),
        body=inner_body,
        signers=tuple(spec for _, _, specs in reversed(built) for spec in specs),
        description=description,
    )
    return message, built


def single_signer_message(
    name: str,
    body: bytes,
    certificate,
    signature: bytes,
    signed_content_identifier: Optional[bytes],
    description: str,
    receipts_from="allReceipts",
    receipts_to=("alice@example.com",),
    include_receipt_request: bool = True,
) -> FixtureMessage:
    extras = []
    if signed_content_identifier is not None:
        extras.append(
            (
                rfc2634.id_aa_contentIdentifier,
                rfc2634.ContentIdentifier(signed_content_identifier),
            )
        )
    if include_receipt_request:
        request = _receipt_request(signed_content_identifier, receipts_from, receipts_to)
        extras.append((rfc2634.id_aa_receiptRequest, request))
    layer = _LayerSpec(
        econtent_type=str(rfc5652.id_data),
        econtent=body,
        certificates=[certificate],
        signers=[
            {
                "signature": signature,
                "certificate": certificate,
                "certificate_email": _email_of(certificate),
                "extras": extras,
                "content_type": str(rfc5652.id_data),
                "sci": signed_content_identifier,
            }
        ],
    )
    message, _ = _assemble(name, [layer], description)
    return message


def _email_of(certificate) -> str:
    for rdn in certificate["tbsCertificate"]["subject"]["rdnSequence"]:
        for atv in rdn:
            if str(atv["type"]) == str(rfc5280.id_emailAddress):
                value, _ = der_decoder(bytes(atv["value"]), asn1Spec=char.IA5String())
                return str(value)
    return ""


def multi_signer_message(
    name: str,
    body: bytes,
    primary_certificate,
    secondary_certificate,
    primary_signature: bytes,
    secondary_signature: bytes,
    description: str,
) -> FixtureMessage:
    """Two parallel signatures; only the first carries a ReceiptRequest."""

    request = _receipt_request(b"SCI-MULTI-PRIMARY", "allReceipts", ["alice@example.com"])
    primary_extras = [
        (rfc2634.id_aa_receiptRequest, request),
        (
            rfc2634.id_aa_contentIdentifier,
            rfc2634.ContentIdentifier(b"SCI-MULTI-PRIMARY"),
        ),
    ]
    layer = _LayerSpec(
        econtent_type=str(rfc5652.id_data),
        econtent=body,
        certificates=[primary_certificate, secondary_certificate],
        signers=[
            {
                "signature": primary_signature,
                "certificate": primary_certificate,
                "certificate_email": _email_of(primary_certificate),
                "extras": primary_extras,
                "content_type": str(rfc5652.id_data),
                "sci": b"SCI-MULTI-PRIMARY",
                "receipt_request_der": der_encoder(request),
            },
            {
                "signature": secondary_signature,
                "certificate": secondary_certificate,
                "certificate_email": _email_of(secondary_certificate),
                "extras": [
                    (
                        rfc2634.id_aa_contentIdentifier,
                        rfc2634.ContentIdentifier(b"SCI-MULTI-SECONDARY"),
                    )
                ],
                "content_type": str(rfc5652.id_data),
                "sci": b"SCI-MULTI-SECONDARY",
            },
        ],
    )
    message, _ = _assemble(name, [layer], description)
    return message


def list_message(
    name: str,
    body: bytes,
    originator_certificate,
    list_certificate,
    originator_signature: bytes,
    signed_content_identifier: bytes,
    receipts_from,
    receipts_to,
    description: str,
    policy_kind: Optional[str] = None,
    policy_names=(),
) -> FixtureMessage:
    """Inner originator signature wrapped by a mailing-list outer signature."""

    inner_request = _receipt_request(signed_content_identifier, receipts_from, receipts_to)
    inner_layer = _LayerSpec(
        econtent_type=str(rfc5652.id_data),
        econtent=body,
        certificates=[originator_certificate],
        signers=[
            {
                "signature": originator_signature,
                "certificate": originator_certificate,
                "certificate_email": _email_of(originator_certificate),
                "extras": [
                    (rfc2634.id_aa_receiptRequest, inner_request),
                    (
                        rfc2634.id_aa_contentIdentifier,
                        rfc2634.ContentIdentifier(signed_content_identifier),
                    ),
                ],
                "content_type": str(rfc5652.id_data),
                "sci": signed_content_identifier,
            }
        ],
    )
    outer_layer = _LayerSpec(
        econtent_type=str(rfc5652.id_signedData),
        econtent=None,
        certificates=[list_certificate],
        signers=[
            {
                "signature": b"LIST-OUTER-SIGNATURE",
                "certificate": list_certificate,
                "certificate_email": _email_of(list_certificate),
                "extras": [
                    (
                        rfc2634.id_aa_mlExpandHistory,
                        _ml_history(
                            list_certificate,
                            "20261113090000Z",
                            policy_kind,
                            policy_names,
                        ),
                    )
                ],
                "content_type": str(rfc5652.id_signedData),
                "sci": None,
            }
        ],
    )
    message, _ = _assemble(name, [inner_layer, outer_layer], description)
    return message


def forwarded_message(
    name: str,
    inner_message: FixtureMessage,
    forwarder_certificate,
    forwarder_signature: bytes,
    description: str,
) -> FixtureMessage:
    """Wrap an existing SignedData inside a new outer signature.

    The inner SignedData is reused byte-for-byte, so the inner signature and
    its signed attributes are unchanged and remain individually verifiable.
    """

    outer_layer = _LayerSpec(
        econtent_type=str(rfc5652.id_signedData),
        econtent=inner_message.signed_data_der,
        certificates=[forwarder_certificate],
        signers=[
            {
                "signature": forwarder_signature,
                "certificate": forwarder_certificate,
                "certificate_email": _email_of(forwarder_certificate),
                "extras": [],
                "content_type": str(rfc5652.id_signedData),
                "sci": None,
            }
        ],
    )
    message, _ = _assemble(name, [outer_layer], description)
    return message


def _receipt_attributes(receipt_der, target: SignerSpec, include_msg_sig_digest: bool):
    extras = []
    if include_msg_sig_digest:
        digest = hashlib.new(
            HASH_NAMES[str(SHA256)], target.signed_attributes_der
        ).digest()
        extras.append((rfc2634.id_aa_msgSigDigest, rfc2634.MsgSigDigest(digest)))
    return _signed_attributes(rfc2634.id_ct_receipt, receipt_der, SHA256, extras)


def build_receipt(
    name: str,
    target: FixtureSigner,
    target_message: str,
    receipt_signer_certificate,
    receipt_signature: bytes,
    description: str,
    include_msg_sig_digest: bool = True,
    tamper_originator_signature: bool = False,
    wrong_content_type=None,
) -> FixtureReceipt:
    receipt = rfc2634.Receipt()
    receipt["version"] = 1
    receipt["contentType"] = wrong_content_type or target.content_type
    receipt["signedContentIdentifier"] = target.signed_content_identifier or b""
    signature = target.signature
    if tamper_originator_signature:
        signature = bytes([signature[0] ^ 0x01]) + signature[1:]
    receipt["originatorSignatureValue"] = signature
    receipt_der = der_encoder(receipt)

    attributes, _ = _receipt_attributes(receipt_der, target, include_msg_sig_digest)
    layer = _LayerSpec(
        econtent_type=str(rfc2634.id_ct_receipt),
        econtent=receipt_der,
        certificates=[receipt_signer_certificate],
        signers=[
            {
                "signature": receipt_signature,
                "certificate": receipt_signer_certificate,
                "certificate_email": _email_of(receipt_signer_certificate),
                "extras": [],
                "content_type": str(rfc2634.id_ct_receipt),
                "sci": None,
            }
        ],
    )
    # Bypass _assemble's receipt-attribute generation by building directly,
    # then injecting the pre-computed signed attributes.
    signed_data = rfc5652.SignedData()
    signed_data["version"] = 1
    algorithms = rfc5652.DigestAlgorithmIdentifiers()
    identifier = rfc5652.DigestAlgorithmIdentifier()
    identifier["algorithm"] = SHA256
    algorithms.append(identifier)
    signed_data["digestAlgorithms"] = algorithms
    signed_data["encapContentInfo"]["eContentType"] = rfc2634.id_ct_receipt
    signed_data["encapContentInfo"]["eContent"] = receipt_der
    certificate_set = rfc5652.CertificateSet()
    choice = rfc5652.CertificateChoices()
    choice["certificate"] = receipt_signer_certificate
    certificate_set.append(choice)
    # Build the [0] tag on the schema object first, then append: applying
    # the implicit tag to an already-populated SetOf discards its components.
    signed_data["certificates"] = certificate_set.subtype(
        implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0)
    ).clone()
    for choice in certificate_set:
        signed_data["certificates"].append(choice)
    signer = rfc5652.SignerInfo()
    signer["version"] = 1
    ias = rfc5652.IssuerAndSerialNumber()
    ias["issuer"] = receipt_signer_certificate["tbsCertificate"]["issuer"]
    ias["serialNumber"] = receipt_signer_certificate["tbsCertificate"]["serialNumber"]
    signer["sid"]["issuerAndSerialNumber"] = ias
    signer["digestAlgorithm"]["algorithm"] = SHA256
    signer["signedAttrs"] = _tagged(attributes)
    signer["signatureAlgorithm"]["algorithm"] = univ.ObjectIdentifier("1.2.840.10045.4.3.2")
    signer["signature"] = receipt_signature
    signers = rfc5652.SignerInfos()
    signers.append(signer)
    signed_data["signerInfos"] = signers
    content_info = _content_info(signed_data)
    return FixtureReceipt(
        name=name,
        der=der_encoder(content_info),
        target_message=target_message,
        target_signer=target,
        receipt_signer_email=_email_of(receipt_signer_certificate),
        description=description,
    )


def build_corpus() -> Corpus:
    """Assemble the forensic archive used by tests, CLI and the report.

    Messages
        MSG-A, MSG-B
            Byte-identical bodies, different signatures and different
            signedContentIdentifier values.  RECEIPT-B covers MSG-B only.
        MSG-RESIGN
            The same body re-signed as a brand new message with a fresh
            signedContentIdentifier.
        MSG-FWD
            MSG-A's SignedData wrapped, byte-for-byte, inside a new outer
            signature by Bob.  The inner signature and signed attributes are
            unchanged.
        MSG-MULTI
            Two parallel signers on one body; only signer 0 carries a
            ReceiptRequest.
        MSG-LIST-NONE / MSG-LIST-ADD / MSG-LIST-FIRST
            Mailing-list expansion with mlReceiptPolicy none, inAdditionTo
            dave@example.com, and an inner request restricted to first-tier
            recipients.
        MSG-NO-RR
            Signed with contentIdentifier but no ReceiptRequest.

    Receipts
        RECEIPT-B
            Covers MSG-B signer 0 (signedContentIdentifier and
            originatorSignatureValue both match; msgSigDigest matches the
            signer's SignedAttributes digest).
        RECEIPT-A
            Copies MSG-A's identifiers but its msgSigDigest is computed over
            MSG-B's signed attributes, modelling a spliced receipt.
        RECEIPT-NO-MSGDIGEST
            Structurally complete receipt with the msgSigDigest attribute
            removed.
        RECEIPT-SIG-MISMATCH
            originatorSignatureValue altered after signing.
        RECEIPT-WRONG-CT
            Receipt.contentType names id-data while the originator's
            content-type attribute named id-data as well; used to show the
            three-field check is co-equal, not decorative.
    """

    alice = _certificate("Alice", "alice@example.com", 1001)
    bob = _certificate("Bob", "bob@example.com", 2002)
    carol = _certificate("Carol", "carol@example.com", 2003)
    dave = _certificate("Dave", "dave@example.com", 2004)
    list_agent = _certificate("Announce List", "announce@example.com", 3003)

    msg_a = single_signer_message(
        "MSG-A",
        BODY_PRIMARY,
        alice,
        b"PRIMARY-SIGNATURE-A",
        b"SCI-PRIMARY-A",
        "Identical body to MSG-B; signature A; receipt RECEIPT-B does not name it.",
    )
    msg_b = single_signer_message(
        "MSG-B",
        BODY_PRIMARY,
        alice,
        b"PRIMARY-SIGNATURE-B",
        b"SCI-PRIMARY-B",
        "Identical body to MSG-A; signature B; the genuine receipt covers it.",
    )
    resign = single_signer_message(
        "MSG-RESIGN",
        BODY_PRIMARY,
        alice,
        b"RESIGNED-SIGNATURE-A2",
        b"SCI-RESIGN-A2",
        "Same body re-signed as a new message with a new identifier.",
    )
    forwarded = forwarded_message(
        "MSG-FWD",
        msg_a,
        bob,
        b"FORWARD-SIGNATURE-BOB",
        "MSG-A wrapped verbatim inside Bob's outer signature.",
    )
    multi = multi_signer_message(
        "MSG-MULTI",
        BODY_MULTI,
        alice,
        carol,
        b"MULTI-SIGNATURE-ALICE",
        b"MULTI-SIGNATURE-CAROL",
        "Two signers, ReceiptRequest only on signer 0.",
    )
    list_none = list_message(
        "MSG-LIST-NONE",
        BODY_LIST,
        alice,
        list_agent,
        b"LIST-NONE-SIGNATURE",
        b"SCI-LIST-NONE",
        "allReceipts",
        ["alice@example.com"],
        "List expansion whose mlReceiptPolicy is none.",
        policy_kind="none",
    )
    list_add = list_message(
        "MSG-LIST-ADD",
        BODY_LIST,
        alice,
        list_agent,
        b"LIST-ADD-SIGNATURE",
        b"SCI-LIST-ADD",
        ["dave@example.com"],
        ["alice@example.com"],
        "List expansion whose mlReceiptPolicy adds dave@example.com.",
        policy_kind="inAdditionTo",
        policy_names=["dave@example.com"],
    )
    list_first = list_message(
        "MSG-LIST-FIRST",
        BODY_LIST,
        alice,
        list_agent,
        b"LIST-FIRST-SIGNATURE",
        b"SCI-LIST-FIRST",
        "firstTierRecipients",
        ["alice@example.com"],
        "Inner request is firstTierRecipients but ML expansion occurred.",
        policy_kind=None,
    )
    no_request = single_signer_message(
        "MSG-NO-RR",
        BODY_NO_RR,
        alice,
        b"NO-REQUEST-SIGNATURE",
        b"SCI-NO-RR",
        "contentIdentifier present, ReceiptRequest absent.",
        include_receipt_request=False,
    )

    receipt_b = build_receipt(
        "RECEIPT-B",
        msg_b.signers[0],
        "MSG-B",
        bob,
        b"RECEIPT-SIGNATURE-B",
        "Genuine receipt naming MSG-B signer 0.",
    )

    # Spliced receipt: receipt fields are those of MSG-B, but msgSigDigest is
    # computed over MSG-A's signed attributes.  The two bodies are equal, so a
    # body-only comparison would wrongly accept it.
    spliced = _build_receipt_with_digest(
        "RECEIPT-SPLICED",
        target=msg_b.signers[0],
        digest_source=msg_a.signers[0],
        receipt_signer_certificate=dave,
        receipt_signature=b"RECEIPT-DAVE-SPLICED",
        description="MSG-B identifiers with a msgSigDigest taken from MSG-A.",
    )

    no_digest = build_receipt(
        "RECEIPT-NO-MSGDIGEST",
        msg_b.signers[0],
        "MSG-B",
        bob,
        b"RECEIPT-SIGNATURE-NO-DIGEST",
        "Genuine identifiers, msgSigDigest attribute absent.",
        include_msg_sig_digest=False,
    )
    sig_mismatch = build_receipt(
        "RECEIPT-SIG-MISMATCH",
        msg_b.signers[0],
        "MSG-B",
        bob,
        b"RECEIPT-SIGNATURE-CORRUPTED",
        "originatorSignatureValue altered after the Receipt was formed.",
        tamper_originator_signature=True,
    )

    multi_carol = build_receipt(
        "RECEIPT-MULTI-CAROL",
        multi.signer_at(0, 1),
        "MSG-MULTI",
        carol,
        b"RECEIPT-MULTI-CAROL-SIG",
        "Claims the non-requesting second signer of MSG-MULTI.",
    )
    no_request_receipt = build_receipt(
        "RECEIPT-NO-RR",
        no_request.signers[0],
        "MSG-NO-RR",
        bob,
        b"RECEIPT-NO-RR-SIG",
        "Claims a message that carried no ReceiptRequest.",
    )
    resign_receipt = build_receipt(
        "RECEIPT-RESIGN",
        resign.signers[0],
        "MSG-RESIGN",
        bob,
        b"RECEIPT-RESIGN-SIG",
        "Genuine receipt whose originator signature status is unknown.",
    )
    unattested_copy = build_receipt(
        "RECEIPT-B-UNATTESTED",
        msg_b.signers[0],
        "MSG-B",
        bob,
        b"RECEIPT-SIGNATURE-B",
        "Same receipt as RECEIPT-B but omitted from the attestation manifest.",
    )
    list_none_receipt = build_receipt(
        "RECEIPT-LIST-NONE",
        list_none.signer_by_signature(b"LIST-NONE-SIGNATURE"),
        "MSG-LIST-NONE",
        bob,
        b"RECEIPT-LIST-NONE-SIG",
        "Receipt returned despite mlReceiptPolicy none.",
    )
    list_add_receipt = build_receipt(
        "RECEIPT-LIST-ADD",
        list_add.signer_by_signature(b"LIST-ADD-SIGNATURE"),
        "MSG-LIST-ADD",
        dave,
        b"RECEIPT-LIST-ADD-SIG",
        "Receipt from dave@example.com, listed in receiptsFrom and policy inAdditionTo.",
    )
    list_unexpected_receipt = build_receipt(
        "RECEIPT-LIST-UNEXPECTED",
        list_add.signer_by_signature(b"LIST-ADD-SIGNATURE"),
        "MSG-LIST-ADD",
        carol,
        b"RECEIPT-LIST-UNEXPECTED-SIG",
        "Receipt from carol@example.com, who is not in the receiptList.",
    )
    list_first_receipt = build_receipt(
        "RECEIPT-LIST-FIRST",
        list_first.signer_by_signature(b"LIST-FIRST-SIGNATURE"),
        "MSG-LIST-FIRST",
        bob,
        b"RECEIPT-LIST-FIRST-SIG",
        "Receipt for a firstTierRecipients request after list expansion.",
    )

    return Corpus(
        messages=(msg_a, msg_b, resign, forwarded, multi, list_none, list_add, list_first, no_request),
        receipts=(
            receipt_b,
            spliced,
            no_digest,
            sig_mismatch,
            multi_carol,
            no_request_receipt,
            resign_receipt,
            unattested_copy,
            list_none_receipt,
            list_add_receipt,
            list_unexpected_receipt,
            list_first_receipt,
        ),
        notes=(
            "No fixture signature is cryptographically real.",
            "BODY_PRIMARY is shared by MSG-A, MSG-B and MSG-RESIGN.",
            "MSG-FWD embeds MSG-A's SignedData verbatim.",
        ),
    )


def _build_receipt_with_digest(
    name,
    target: FixtureSigner,
    digest_source: FixtureSigner,
    receipt_signer_certificate,
    receipt_signature: bytes,
    description: str,
) -> FixtureReceipt:
    receipt = rfc2634.Receipt()
    receipt["version"] = 1
    receipt["contentType"] = target.content_type
    receipt["signedContentIdentifier"] = target.signed_content_identifier
    receipt["originatorSignatureValue"] = target.signature
    receipt_der = der_encoder(receipt)
    extras = [
        (
            rfc2634.id_aa_msgSigDigest,
            rfc2634.MsgSigDigest(
                hashlib.new(
                    HASH_NAMES[str(SHA256)], digest_source.signed_attributes_der
                ).digest()
            ),
        )
    ]
    attributes, _ = _signed_attributes(rfc2634.id_ct_receipt, receipt_der, SHA256, extras)
    signed_data = rfc5652.SignedData()
    signed_data["version"] = 1
    algorithms = rfc5652.DigestAlgorithmIdentifiers()
    identifier = rfc5652.DigestAlgorithmIdentifier()
    identifier["algorithm"] = SHA256
    algorithms.append(identifier)
    signed_data["digestAlgorithms"] = algorithms
    signed_data["encapContentInfo"]["eContentType"] = rfc2634.id_ct_receipt
    signed_data["encapContentInfo"]["eContent"] = receipt_der
    certificate_set = rfc5652.CertificateSet()
    choice = rfc5652.CertificateChoices()
    choice["certificate"] = receipt_signer_certificate
    certificate_set.append(choice)
    # Build the [0] tag on the schema object first, then append: applying
    # the implicit tag to an already-populated SetOf discards its components.
    signed_data["certificates"] = certificate_set.subtype(
        implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0)
    ).clone()
    for choice in certificate_set:
        signed_data["certificates"].append(choice)
    signer = rfc5652.SignerInfo()
    signer["version"] = 1
    ias = rfc5652.IssuerAndSerialNumber()
    ias["issuer"] = receipt_signer_certificate["tbsCertificate"]["issuer"]
    ias["serialNumber"] = receipt_signer_certificate["tbsCertificate"]["serialNumber"]
    signer["sid"]["issuerAndSerialNumber"] = ias
    signer["digestAlgorithm"]["algorithm"] = SHA256
    signer["signedAttrs"] = _tagged(attributes)
    signer["signatureAlgorithm"]["algorithm"] = univ.ObjectIdentifier("1.2.840.10045.4.3.2")
    signer["signature"] = receipt_signature
    signers = rfc5652.SignerInfos()
    signers.append(signer)
    signed_data["signerInfos"] = signers
    return FixtureReceipt(
        name=name,
        der=der_encoder(_content_info(signed_data)),
        target_message="MSG-B",
        target_signer=target,
        receipt_signer_email=_email_of(receipt_signer_certificate),
        description=description,
    )


def attestations() -> Dict:
    """Explicit verification inputs for the corpus.

    Message signer entries are addressed by ``signatureSha256`` rather than by
    position: CMS encodes signerInfos as a SET OF, so DER canonical ordering
    can move signers between archives.  Hash addressing keeps the manifest
    stable and makes any missing entry visibly unknown.

    Choices that make the three evidence levels separable:

    * MSG-B's signer is ``valid``; MSG-FWD's outer forwarder has no entry.
    * RECEIPT-B is ``valid`` + ``trusted`` => reaches level 3.
    * RECEIPT-SPLICED is ``valid`` + ``trusted`` but its msgSigDigest points
      at MSG-A, so it stops at level 1.
    * RECEIPT-SIG-MISMATCH is ``invalid`` and must never become trusted.
    * RECEIPT-NO-MSGDIGEST is ``valid`` but lacks the linkage attribute.
    * MSG-MULTI's second signer is ``invalid``; its receipt still reaches
      level 2 because the receipt binds to SignedAttributes, not to a
      successful original signature, but stops before level 3.
    """

    message_signatures = {
        "MSG-A": b"PRIMARY-SIGNATURE-A",
        "MSG-B": b"PRIMARY-SIGNATURE-B",
        "MSG-FWD": b"FORWARD-SIGNATURE-BOB",
        "MSG-MULTI": b"MULTI-SIGNATURE-ALICE",
        "MSG-LIST-NONE": b"LIST-OUTER-SIGNATURE",
        "MSG-LIST-ADD": b"LIST-OUTER-SIGNATURE",
        "MSG-LIST-FIRST": b"LIST-OUTER-SIGNATURE",
        "MSG-NO-RR": b"NO-REQUEST-SIGNATURE",
    }

    import hashlib as _hashlib

    def entry(signature: bytes, status: str, reason: str) -> Dict:
        return {
            "signatureSha256": _hashlib.sha256(signature).hexdigest(),
            "status": status,
            "reason": reason,
        }

    messages: Dict[str, Dict] = {}
    for name, signature in message_signatures.items():
        messages[name] = {
            "layers": [
                {"signers": [entry(signature, "valid", "fixture")]},
            ]
        }
    # MSG-MULTI has two signers; the second signature fails verification.
    messages["MSG-MULTI"]["layers"][0]["signers"] = [
        entry(b"MULTI-SIGNATURE-ALICE", "valid", "fixture"),
        entry(b"MULTI-SIGNATURE-CAROL", "invalid", "second signature fails"),
    ]
    # List messages: outer list signature valid, inner originator signature
    # valid, but the inner signer is a different signature value.
    messages["MSG-LIST-NONE"]["layers"] = [
        {"signers": [entry(b"LIST-OUTER-SIGNATURE", "valid", "list agent")]},
        {"signers": [entry(b"LIST-NONE-SIGNATURE", "valid", "originator")]},
    ]
    messages["MSG-LIST-ADD"]["layers"] = [
        {"signers": [entry(b"LIST-OUTER-SIGNATURE", "valid", "list agent")]},
        {"signers": [entry(b"LIST-ADD-SIGNATURE", "valid", "originator")]},
    ]
    messages["MSG-LIST-FIRST"]["layers"] = [
        {"signers": [entry(b"LIST-OUTER-SIGNATURE", "valid", "list agent")]},
        {"signers": [entry(b"LIST-FIRST-SIGNATURE", "valid", "originator")]},
    ]
    # Forwarded message: outer forwarder attestation deliberately omitted.
    messages["MSG-FWD"]["layers"] = [
        {"signers": []},
        {"signers": [entry(b"PRIMARY-SIGNATURE-A", "valid", "inner signature retained")]},
    ]

    messages["MSG-RESIGN"] = {
        "layers": [{"signers": [{"status": "unknown", "reason": "verification not performed"}]}]
    }

    return {
        "messages": messages,
        "receipts": {
            "RECEIPT-B": {
                "signatureStatus": "valid",
                "certificateTrust": "trusted",
                "signerNames": ["bob@example.com"],
                "reason": "fixture",
            },
            "RECEIPT-SPLICED": {
                "signatureStatus": "valid",
                "certificateTrust": "trusted",
                "signerNames": ["dave@example.com"],
                "reason": "signature internally consistent but digest points elsewhere",
            },
            "RECEIPT-NO-MSGDIGEST": {
                "signatureStatus": "valid",
                "certificateTrust": "trusted",
                "signerNames": ["bob@example.com"],
            },
            "RECEIPT-SIG-MISMATCH": {
                "signatureStatus": "invalid",
                "certificateTrust": "untrusted",
                "signerNames": ["bob@example.com"],
            },
            "RECEIPT-MULTI-CAROL": {
                "signatureStatus": "valid",
                "certificateTrust": "trusted",
                "signerNames": ["carol@example.com"],
                "reason": "internally valid receipt for a signer that requested nothing",
            },
            "RECEIPT-NO-RR": {
                "signatureStatus": "valid",
                "certificateTrust": "trusted",
                "signerNames": ["bob@example.com"],
                "reason": "internally valid receipt for a message with no ReceiptRequest",
            },
            "RECEIPT-RESIGN": {
                "signatureStatus": "valid",
                "certificateTrust": "trusted",
                "signerNames": ["bob@example.com"],
                "reason": "receipt is sound but the originator signature was never verified",
            },
            "RECEIPT-LIST-NONE": {
                "signatureStatus": "valid",
                "certificateTrust": "trusted",
                "signerNames": ["bob@example.com"],
                "reason": "receipt is genuine; list policy forbids creating it",
            },
            "RECEIPT-LIST-ADD": {
                "signatureStatus": "valid",
                "certificateTrust": "trusted",
                "signerNames": ["dave@example.com"],
                "reason": "receipt is genuine",
            },
            "RECEIPT-LIST-UNEXPECTED": {
                "signatureStatus": "valid",
                "certificateTrust": "trusted",
                "signerNames": ["carol@example.com"],
                "reason": "receipt is genuine but carol is outside the receiptList",
            },
            "RECEIPT-LIST-FIRST": {
                "signatureStatus": "valid",
                "certificateTrust": "trusted",
                "signerNames": ["bob@example.com"],
                "reason": "receipt is genuine; list expansion blocks first-tier response",
            },
        },
    }
