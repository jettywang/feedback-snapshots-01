"""Parse and build ESSSecurityLabel values using pyasn1_modules.rfc2634.

Only the label structure is handled here.  CMS signature validation, envelope
decryption and signer-certificate path building are deliberately outside this
module; the caller supplies their results as explicit attestations.
"""

from dataclasses import dataclass
from typing import Iterable, Optional, Tuple

from pyasn1.codec.der.decoder import decode as der_decoder
from pyasn1.codec.der.encoder import encode as der_encoder
from pyasn1.error import PyAsn1Error
from pyasn1.type import char, tag, univ

from pyasn1_modules import rfc2634

from .mapping import CATEGORY_SYNTAX


class LabelParseError(ValueError):
    """Raised when bytes are not a single, structurally valid ESS label."""


class LabelConsistencyError(LabelParseError):
    """Raised when authenticated labels disagree across signers or attributes."""


@dataclass(frozen=True)
class ParsedCategory:
    oid: str
    raw: bytes
    syntax: Optional[str]
    value: Optional[str]
    known: bool


@dataclass(frozen=True)
class ParsedLabel:
    policy_oid: str
    classification: Optional[int]
    privacy_mark: Optional[str]
    privacy_mark_choice: Optional[str]
    categories: Tuple[ParsedCategory, ...]
    der: bytes

    def category_map(self):
        return tuple(sorted(
            (cat.oid, cat.value) for cat in self.categories
            if cat.value is not None
        ))

    def category_display(self):
        if not self.categories:
            return "(none)"
        parts = []
        for cat in self.categories:
            value = cat.value if cat.known else f"<unknown raw {cat.raw.hex()}>"
            parts.append(f"{cat.oid}={value}")
        return ", ".join(parts)


def _oid_text(value) -> str:
    return ".".join(str(part) for part in value)


def _decode_category_value(raw: bytes,
                           syntax: Optional[str]) -> Tuple[Optional[str], bool]:
    if syntax is None:
        return None, False
    specs = {
        "utf8": char.UTF8String(),
        "ia5": char.IA5String(),
        "integer": univ.Integer(),
    }
    try:
        decoded, rest = der_decoder(raw, asn1Spec=specs[syntax])
    except (KeyError, PyAsn1Error):
        return None, False
    if rest:
        return None, False
    if syntax == "integer":
        return str(int(decoded)), True
    return str(decoded), True


def parse_label(substrate: bytes, category_syntax=None) -> ParsedLabel:
    """Decode one ESS label.  Raises LabelParseError on malformed input.

    Category syntax comes only from a local table (``category_syntax`` or the
    built-in ``CATEGORY_SYNTAX``); it is never inferred from the message.
    """

    syntax_table = CATEGORY_SYNTAX if category_syntax is None else category_syntax

    try:
        label, rest = der_decoder(substrate, asn1Spec=rfc2634.ESSSecurityLabel())
    except PyAsn1Error as exc:
        raise LabelParseError(f"DER decode failed: {exc}") from exc

    if rest:
        raise LabelParseError(f"{len(rest)} trailing bytes after ESS label")
    if not label['security-policy-identifier'].isValue:
        raise LabelParseError("missing security-policy-identifier")

    classification = None
    if label['security-classification'].isValue:
        classification = int(label['security-classification'])

    privacy_mark = None
    privacy_choice = None
    if label['privacy-mark'].isValue:
        privacy_choice = label['privacy-mark'].getName()
        privacy_mark = str(label['privacy-mark'][privacy_choice])

    categories = []
    if label['security-categories'].isValue:
        for cat in label['security-categories']:
            cat_oid = _oid_text(cat['type'])
            raw = bytes(cat['value'].asOctets())
            syntax = syntax_table.get(cat_oid)
            value, known = _decode_category_value(raw, syntax)
            categories.append(ParsedCategory(
                oid=cat_oid, raw=raw, syntax=syntax, value=value, known=known))

    return ParsedLabel(
        policy_oid=_oid_text(label['security-policy-identifier']),
        classification=classification,
        privacy_mark=privacy_mark,
        privacy_mark_choice=privacy_choice,
        categories=tuple(categories),
        der=bytes(substrate),
    )


def _tagged_oid(oid: str):
    return univ.ObjectIdentifier(oid).subtype(
        implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0))


def _tagged_any(raw: bytes):
    return univ.Any(raw).subtype(
        implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1))


def _encode_category_value(oid: str, value, category_syntax=None) -> bytes:
    syntax_table = CATEGORY_SYNTAX if category_syntax is None else category_syntax
    syntax = syntax_table.get(oid)
    if syntax is None:
        raise LabelParseError(
            f"category {oid} has no locally configured syntax; refusing to encode")
    if syntax == "integer":
        spec = univ.Integer(int(value))
    elif syntax == "utf8":
        spec = char.UTF8String(value)
    elif syntax == "ia5":
        spec = char.IA5String(value)
    else:
        raise LabelParseError(f"unsupported local syntax {syntax!r}")
    return der_encoder(spec)


def build_label(policy_oid: str, classification: Optional[int] = None,
                privacy_mark=None, categories: Iterable = (),
                raw_categories: Iterable = (),
                category_syntax=None) -> bytes:
    """Build a DER-encoded ESS label for tests and demos.

    ``categories`` is an iterable of ``(category_oid, value)`` pairs whose
    syntax must already exist in the local table.  ``raw_categories`` allows a
    deliberately unknown ``(oid, der_bytes)`` pair so tests can exercise the
    unknown-category path.
    """

    label = rfc2634.ESSSecurityLabel()
    label['security-policy-identifier'] = univ.ObjectIdentifier(policy_oid)

    if classification is not None:
        label['security-classification'] = int(classification)

    if privacy_mark is not None:
        mark = rfc2634.ESSPrivacyMark()
        if isinstance(privacy_mark, tuple):
            choice, text = privacy_mark
            mark[choice] = text
        else:
            mark['utf8String'] = privacy_mark
        label['privacy-mark'] = mark

    encoded_categories = [
        (oid, _encode_category_value(oid, value, category_syntax))
        for oid, value in categories
    ]
    encoded_categories.extend((oid, bytes(raw)) for oid, raw in raw_categories)

    if encoded_categories:
        category_set = rfc2634.SecurityCategories()
        for position, (oid, raw) in enumerate(encoded_categories):
            category = rfc2634.SecurityCategory()
            category['type'] = _tagged_oid(oid)
            category['value'] = _tagged_any(raw)
            category_set.setComponentByPosition(position, category)
        label['security-categories'] = category_set

    return der_encoder(label)


def build_equivalent_labels(label_ders: Iterable[bytes],
                            category_syntax=None) -> bytes:
    """Build the DER payload of an EquivalentLabels attribute."""

    labels = rfc2634.EquivalentLabels()
    for position, label_der in enumerate(label_ders):
        parse_label(label_der, category_syntax=category_syntax)
        asn1_label, rest = der_decoder(
            label_der, asn1Spec=rfc2634.ESSSecurityLabel())
        if rest:
            raise LabelParseError("trailing bytes in equivalent label")
        labels.setComponentByPosition(position, asn1_label)
    return der_encoder(labels)


def extract_from_signer(signer_info) -> Tuple[Tuple[bytes, ...],
                                              Tuple[bytes, ...]]:
    """Pull security-label and equivalent-labels DER from signed attributes.

    Returns ``(security_label_payloads, equivalent_labels_payloads)``.  Duplicate
    attributes are returned so the caller can reject them; unsigned attributes
    are intentionally not inspected.
    """

    labels = []
    equivalents = []
    attrs = signer_info['signedAttrs']
    if not attrs.isValue:
        return (), ()
    for attr in attrs:
        attr_type = attr['attrType']
        if attr_type not in (rfc2634.id_aa_securityLabel,
                             rfc2634.id_aa_equivalentLabels):
            continue
        values = attr['attrValues']
        # RFC 2634 section 3.1: an ESS attribute, when present, must contain
        # exactly one AttributeValue.  Silently taking [0] would ignore a
        # second, possibly contradictory value.
        if not values.isValue or len(values) != 1:
            raise LabelConsistencyError(
                f"attribute {attr_type} must contain exactly one "
                f"AttributeValue; found {len(values) if values.isValue else 0}")
        payload = bytes(values[0].asOctets())
        if attr_type == rfc2634.id_aa_securityLabel:
            labels.append(payload)
        else:
            equivalents.append(payload)
    if len(labels) > 1:
        raise LabelConsistencyError(
            "signerInfo contains multiple securityLabel attributes")
    if len(equivalents) > 1:
        raise LabelConsistencyError(
            "signerInfo contains multiple equivalentLabels attributes")
    return tuple(labels), tuple(equivalents)


def collect_signed_labels(signed_data, category_syntax=None):
    """Require one consistent ESS label across every signerInfo.

    RFC 2634 section 3.4.1: if an ESSSecurityLabel is present in a signerInfo,
    every signerInfo MUST contain one and they MUST all be identical.  This
    helper enforces that at the CMS layer, so a later decision never picks one
    of several authenticated labels.  EquivalentLabels payloads are gathered
    from every signer and passed through; the checker refuses to merge more
    than one such attribute.
    """

    signer_infos = signed_data['signerInfos']
    if not signer_infos.isValue or len(signer_infos) == 0:
        raise LabelParseError("SignedData has no signerInfos")

    extracted = [extract_from_signer(si) for si in signer_infos]
    labels_per_signer = [labels for labels, _ in extracted]

    if not any(labels_per_signer):
        raise LabelParseError("no ESSSecurityLabel signed attribute is present")

    counts = [len(labels) for labels in labels_per_signer]
    if any(count != 1 for count in counts):
        raise LabelConsistencyError(
            "when any signerInfo carries an ESSSecurityLabel, every "
            f"signerInfo must carry exactly one; found counts {counts}")

    unique = {labels[0] for labels in labels_per_signer}
    if len(unique) != 1:
        raise LabelConsistencyError(
            "signerInfos carry different ESSSecurityLabel values; RFC 2634 "
            "requires all of them to be identical")

    equivalents = []
    for _, payloads in extracted:
        equivalents.extend(payloads)
    return unique.pop(), tuple(equivalents)
