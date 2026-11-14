# This file is being contributed to pyasn1-modules software.
#
# Trust Anchor Format (RFC 5914) -- import adapter
#
# Copyright (c) 2024, Vigil Security, LLC
# License: http://snmplabs.com/pyasn1/license.html
#
# This module turns a DER-decoded TrustAnchorList (RFC 5914) into immutable
# TrustAnchorConstraints objects that a path validator can consume.  It does
# NOT collapse a list entry down to "public key + display name": every path
# control carried by the chosen alternative (certificate, tbsCert, or taInfo)
# is retained, entries with the same key but different controls are never
# silently merged, and unsupported critical controls are rejected rather than
# dropped.  The caller must state explicitly that the source of the list is
# trusted; successful decoding or a self-signed signature never establishes
# that trust.

from dataclasses import dataclass
from typing import Dict, FrozenSet, List, Optional, Tuple

from pyasn1.type import univ
from pyasn1.codec.der.decoder import decode as der_decoder
from pyasn1.codec.der.encoder import encode as der_encoder

from pyasn1_modules import rfc5280
from pyasn1_modules import rfc5914
# Importing rfc3779 registers the IP/AS resource extension OIDs
# (id_pe_ipAddrBlocks, id_pe_autonomousSysIds) into rfc5280's shared extension
# map so they are recognised as supported critical controls.
from pyasn1_modules import rfc3779  # noqa: F401


MAX = float('inf')

# ---------------------------------------------------------------------------
# Diagnostics
# ---------------------------------------------------------------------------


class TrustAnchorImportError(Exception):
    """Base class for every failure raised while importing a trust list."""


class UntrustedSourceError(TrustAnchorImportError):
    """The caller did not explicitly vouch for the source of the list."""


class UnsupportedCriticalControlError(TrustAnchorImportError):
    """A critical control is present that this adapter cannot honour."""


class TrustAnchorConflictError(TrustAnchorImportError):
    """Controls inside one trust anchor contradict each other."""


# ---------------------------------------------------------------------------
# Immutable constraint objects
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ExtensionControl:
    """One X.509 extension, retained verbatim so no control is dropped.

    ``value_der`` is the DER encoding of the extnValue inner value.  The full
    extension (including its critical flag) is therefore reconstructable.
    """

    extn_id: str
    critical: bool
    value_der: bytes


@dataclass(frozen=True)
class TrustAnchorConstraints:
    """The complete, lossless set of controls carried by one list entry.

    Two entries that share ``public_key_der`` but differ in any name or policy
    control are distinct objects with a distinct ``fingerprint``.  Nothing here
    is mutable, so a validator cannot widen the authorisation after import.
    """

    anchor_form: str                      # 'certificate' | 'tbsCert' | 'taInfo'
    public_key_der: bytes                 # DER of SubjectPublicKeyInfo
    key_id: Optional[bytes]
    name_der: Optional[bytes]             # DER of the anchor Name (taName/subject)
    name_constraints_der: Optional[bytes]  # DER of effective NameConstraints
    certificate_policies_der: Optional[bytes]  # DER of effective CertificatePolicies
    path_len_constraint: Optional[int]
    policy_flags: FrozenSet[str]          # named CertPolicyFlags bits
    extensions: Tuple[ExtensionControl, ...]
    source_der: bytes                     # DER of the whole TrustAnchorChoice
    fingerprint: str                      # stable identity over ALL controls

    def has_same_key(self, other: 'TrustAnchorConstraints') -> bool:
        return self.public_key_der == other.public_key_der


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Critical extensions whose semantics this adapter understands.  Every
# extension is retained verbatim in ``TrustAnchorConstraints.extensions``; the
# point of this set is to ensure a critical control the validator machinery does
# not know about is rejected rather than silently ignored.  The accepted set is
# exactly the X.509 extensions pyasn1's rfc5280 module already defines.
_SUPPORTED_CRITICAL_EXTNS = frozenset(
    str(oid) for oid in rfc5280.certificateExtensionsMap.keys()
)


def _has(value):
    return value is not None and value.hasValue()


def _der(value):
    return der_encoder(value)


def _encode_length(length):
    if length < 0x80:
        return bytes((length,))
    body = length.to_bytes((length.bit_length() + 7) // 8, 'big')
    return bytes((0x80 | len(body),)) + body


def _implicit_to_base_der(raw, base_universal_tag):
    """Rewrite an implicit context-tagged TLV as its base universal type.

    CertPathControls fields such as nameConstr [3] and policySet [1] carry an
    implicit context tag over an underlying SEQUENCE.  A path validator wants
    the base NameConstraints / CertificatePolicies DER, so only the leading tag
    is rewritten; the length and content octets are preserved exactly.
    """
    if not raw or not (raw[0] & 0x80):
        return raw
    position = 1
    length = raw[position]
    position += 1
    if length & 0x80:
        count = length & 0x7F
        length = int.from_bytes(raw[position:position + count], 'big')
        position += count
    content = raw[position:position + length]
    if len(content) != length:
        raise TrustAnchorImportError('truncated implicit-tagged control value')
    return bytes((base_universal_tag,)) + _encode_length(length) + content


def _base_type_der(tagged_value, base_spec, base_universal_tag):
    """Encode an implicit-tagged field as the DER of its base ASN.1 type."""
    if not _has(tagged_value):
        return None
    raw = _implicit_to_base_der(der_encoder(tagged_value), base_universal_tag)
    decoded, rest = der_decoder(raw, asn1Spec=base_spec)
    if rest:
        raise TrustAnchorImportError(
            'trailing bytes while normalising a path-control value')
    return der_encoder(decoded)


def _policy_flag_names(bit_string):
    if not _has(bit_string):
        return frozenset()
    by_position = {
        position: name for name, position in
        rfc5914.CertPolicyFlags.namedValues.items()
    }
    return frozenset(
        name for position, name in by_position.items()
        if len(bit_string) > position and bit_string[position]
    )


def _octet_content(extn_value):
    """Return the content octets of an Extension.extnValue OctetString."""
    octet_string, rest = der_decoder(
        der_encoder(extn_value), univ.OctetString())
    if rest:
        raise TrustAnchorImportError('trailing bytes in extension value')
    return octet_string.asOctets()


def _retain_extensions(extensions, index):
    """Decode and retain every extension; reject unsupported critical ones."""
    retained = []
    if not _has(extensions):
        return tuple(retained)
    for extension in extensions:
        extn_id = str(extension['extnID'])
        critical = bool(extension['critical'])
        value_der = _octet_content(extension['extnValue'])
        if critical and extn_id not in _SUPPORTED_CRITICAL_EXTNS:
            raise UnsupportedCriticalControlError(
                'entry %d: critical extension %s is not supported; refusing to '
                'drop it and continue' % (index, extn_id)
            )
        retained.append(ExtensionControl(extn_id, critical, value_der))
    return tuple(retained)


def _extension_value(extensions, oid):
    """Return the inner content octets of one extension's extnValue."""
    if not _has(extensions):
        return None
    wanted = str(oid)
    for extension in extensions:
        if str(extension['extnID']) == wanted:
            return _octet_content(extension['extnValue'])
    return None


def _decode_name_constraints(value_der):
    if value_der is None:
        return None
    nc, rest = der_decoder(value_der, rfc5280.NameConstraints())
    if rest:
        raise TrustAnchorImportError('trailing bytes in nameConstraints value')
    return nc


def _extract_cert_path_controls(cert_path, index):
    """Pull the dedicated CertPathControls fields without losing the rest."""
    controls = {
        'name_der': None,
        'name_constraints_der': None,
        'certificate_policies_der': None,
        'path_len_constraint': None,
        'policy_flags': frozenset(),
        'embedded_certificate': None,
    }
    if not _has(cert_path):
        return controls

    if _has(cert_path['taName']):
        controls['name_der'] = _der(cert_path['taName'])
    if _has(cert_path['nameConstr']):
        controls['name_constraints_der'] = _base_type_der(
            cert_path['nameConstr'], rfc5280.NameConstraints(), 0x30)
    if _has(cert_path['policySet']):
        controls['certificate_policies_der'] = _base_type_der(
            cert_path['policySet'], rfc5280.CertificatePolicies(), 0x30)
    if _has(cert_path['pathLenConstraint']):
        controls['path_len_constraint'] = int(cert_path['pathLenConstraint'])
    controls['policy_flags'] = _policy_flag_names(cert_path['policyFlags'])
    if _has(cert_path['certificate']):
        controls['embedded_certificate'] = cert_path['certificate']
    return controls


def _fingerprint(anchor_form, public_key_der, key_id, name_der,
                 name_constraints_der, certificate_policies_der,
                 path_len_constraint, policy_flags, extensions):
    import hashlib

    digest = hashlib.sha256()
    digest.update(anchor_form.encode('ascii'))
    digest.update(b'\x00')
    digest.update(public_key_der)
    digest.update(b'\x00')
    digest.update(key_id or b'')
    digest.update(b'\x00')
    digest.update(name_der or b'')
    digest.update(b'\x00')
    digest.update(name_constraints_der or b'')
    digest.update(b'\x00')
    digest.update(certificate_policies_der or b'')
    digest.update(b'\x00')
    digest.update(repr(path_len_constraint).encode('ascii'))
    digest.update(b'\x00')
    for flag in sorted(policy_flags):
        digest.update(flag.encode('ascii'))
    digest.update(b'\x00')
    for extension in extensions:
        digest.update(extension.extn_id.encode('ascii'))
        digest.update(b'\x01' if extension.critical else b'\x00')
        digest.update(extension.value_der)
    digest.update(b'\x00')
    return digest.hexdigest()


def _build_constraints(index, anchor_form, public_key_der, key_id, name_der,
                       name_constraints_der, certificate_policies_der,
                       path_len_constraint, policy_flags, extensions,
                       source_der):
    fingerprint = _fingerprint(
        anchor_form, public_key_der, key_id, name_der, name_constraints_der,
        certificate_policies_der, path_len_constraint, policy_flags, extensions
    )
    return TrustAnchorConstraints(
        anchor_form=anchor_form,
        public_key_der=public_key_der,
        key_id=key_id,
        name_der=name_der,
        name_constraints_der=name_constraints_der,
        certificate_policies_der=certificate_policies_der,
        path_len_constraint=path_len_constraint,
        policy_flags=policy_flags,
        extensions=extensions,
        source_der=source_der,
        fingerprint=fingerprint,
    )


def _check_embedded_certificate_conflicts(ta_info, path_controls,
                                          outer_spki_der, outer_key_id, index):
    """RFC 5914 section 3.2.3: an embedded cert must match the outer fields."""
    embedded = path_controls.get('embedded_certificate')
    if embedded is None:
        return

    tbs = embedded['tbsCertificate']
    embedded_spki_der = _der(tbs['subjectPublicKeyInfo'])
    if embedded_spki_der != outer_spki_der:
        raise TrustAnchorConflictError(
            'entry %d: taInfo.certPath.certificate public key does not match '
            'taInfo.pubKey' % index
        )

    # A self-signature on the embedded certificate never establishes trust on
    # its own; the caller must still confirm the list source out of band.

    embedded_exts = tbs['extensions'] if _has(tbs['extensions']) else None
    if outer_key_id is not None and embedded_exts is not None:
        ski_value = _extension_value(embedded_exts,
                                     rfc5280.id_ce_subjectKeyIdentifier)
        if ski_value is not None:
            ski, rest = der_decoder(ski_value, rfc5280.KeyIdentifier())
            if not rest and ski.asOctets() != outer_key_id:
                raise TrustAnchorConflictError(
                    'entry %d: embedded certificate subjectKeyIdentifier does '
                    'not match taInfo.keyId' % index
                )

    if path_controls.get('name_der') is not None and _has(tbs['subject']):
        if _der(tbs['subject']) != path_controls['name_der']:
            raise TrustAnchorConflictError(
                'entry %d: embedded certificate subject does not match '
                'certPath.taName' % index
            )

    embedded_nc = None
    if embedded_exts is not None:
        embedded_nc = _extension_value(embedded_exts,
                                       rfc5280.id_ce_nameConstraints)
    path_nc = path_controls.get('name_constraints_der')
    if embedded_nc is not None and path_nc is not None and embedded_nc != path_nc:
        raise TrustAnchorConflictError(
            'entry %d: embedded certificate nameConstraints conflict with '
            'certPath.nameConstr' % index
        )


def _import_one(choice, index):
    form = choice.getName()
    source_der = _der(choice)

    if form == 'certificate':
        return _import_certificate(choice.getComponent(), index, source_der)
    if form == 'tbsCert':
        return _import_tbs_cert(choice.getComponent(), index, source_der)
    if form == 'taInfo':
        return _import_ta_info(choice.getComponent(), index, source_der)
    raise TrustAnchorImportError(
        'entry %d: unknown TrustAnchorChoice alternative %r' % (index, form)
    )


def _import_certificate(certificate, index, source_der):
    tbs = certificate['tbsCertificate']
    public_key_der = _der(tbs['subjectPublicKeyInfo'])
    extensions = tbs['extensions'] if _has(tbs['extensions']) else None
    retained = _retain_extensions(extensions, index)

    key_id = None
    ski_value = _extension_value(extensions, rfc5280.id_ce_subjectKeyIdentifier)
    if ski_value is not None:
        ski, rest = der_decoder(ski_value, rfc5280.KeyIdentifier())
        if not rest:
            key_id = bytes(ski)

    name_der = _der(tbs['subject']) if _has(tbs['subject']) else None
    nc_der = _extension_value(extensions, rfc5280.id_ce_nameConstraints)
    policies_der = _extension_value(extensions,
                                    rfc5280.id_ce_certificatePolicies)

    path_len = None
    bc_value = _extension_value(extensions, rfc5280.id_ce_basicConstraints)
    if bc_value is not None:
        bc, rest = der_decoder(bc_value, rfc5280.BasicConstraints())
        if not rest and _has(bc['pathLenConstraint']):
            path_len = int(bc['pathLenConstraint'])

    return _build_constraints(
        index, 'certificate', public_key_der, key_id, name_der, nc_der,
        policies_der, path_len, frozenset(), retained, source_der
    )


def _import_tbs_cert(tbs, index, source_der):
    public_key_der = _der(tbs['subjectPublicKeyInfo'])
    extensions = tbs['extensions'] if _has(tbs['extensions']) else None
    retained = _retain_extensions(extensions, index)

    key_id = None
    ski_value = _extension_value(extensions, rfc5280.id_ce_subjectKeyIdentifier)
    if ski_value is not None:
        ski, rest = der_decoder(ski_value, rfc5280.KeyIdentifier())
        if not rest:
            key_id = bytes(ski)

    name_der = _der(tbs['subject']) if _has(tbs['subject']) else None
    nc_der = _extension_value(extensions, rfc5280.id_ce_nameConstraints)
    policies_der = _extension_value(extensions,
                                    rfc5280.id_ce_certificatePolicies)

    path_len = None
    bc_value = _extension_value(extensions, rfc5280.id_ce_basicConstraints)
    if bc_value is not None:
        bc, rest = der_decoder(bc_value, rfc5280.BasicConstraints())
        if not rest and _has(bc['pathLenConstraint']):
            path_len = int(bc['pathLenConstraint'])

    return _build_constraints(
        index, 'tbsCert', public_key_der, key_id, name_der, nc_der,
        policies_der, path_len, frozenset(), retained, source_der
    )


def _import_ta_info(ta_info, index, source_der):
    public_key_der = _der(ta_info['pubKey'])
    outer_key_id = bytes(ta_info['keyId']) if _has(ta_info['keyId']) else None

    path_controls = _extract_cert_path_controls(ta_info['certPath'], index)

    _check_embedded_certificate_conflicts(
        ta_info, path_controls, public_key_der, outer_key_id, index
    )

    extensions = ta_info['exts'] if _has(ta_info['exts']) else None
    retained = _retain_extensions(extensions, index)

    # certPath controls take the dedicated slots; extension-based controls are
    # still retained verbatim above and surface in a conflict if both appear.
    name_der = path_controls['name_der']
    nc_der = path_controls['name_constraints_der']
    policies_der = path_controls['certificate_policies_der']
    path_len = path_controls['path_len_constraint']
    flags = path_controls['policy_flags']

    ext_nc = _extension_value(extensions, rfc5280.id_ce_nameConstraints)
    if ext_nc is not None:
        if nc_der is not None and ext_nc != nc_der:
            raise TrustAnchorConflictError(
                'entry %d: certPath.nameConstr conflicts with the taInfo exts '
                'nameConstraints' % index
            )
        if nc_der is None:
            nc_der = ext_nc

    ext_policies = _extension_value(extensions,
                                    rfc5280.id_ce_certificatePolicies)
    if ext_policies is not None and policies_der is not None \
            and ext_policies != policies_der:
        raise TrustAnchorConflictError(
            'entry %d: certPath.policySet conflicts with the taInfo exts '
            'certificatePolicies' % index
        )
    if policies_der is None:
        policies_der = ext_policies

    return _build_constraints(
        index, 'taInfo', public_key_der, outer_key_id, name_der, nc_der,
        policies_der, path_len, flags, retained, source_der
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def import_trust_anchor_list(trust_anchor_list, source_trusted):
    """Convert a decoded RFC 5914 TrustAnchorList into constraints.

    Parameters
    ----------
    trust_anchor_list : rfc5914.TrustAnchorList
        A TrustAnchorList that has already been DER-decoded.  Decoding only
        proves the bytes are well formed; it never establishes trust.
    source_trusted : bool
        Must be ``True`` and supplied explicitly by the caller to confirm that
        the origin of the list has been authenticated through an out-of-band
        mechanism.  A self-signed signature or a successful decode is not a
        substitute.

    Returns
    -------
    tuple of TrustAnchorConstraints
        One immutable object per input entry, in order.  Entries with the same
        public key but different controls are kept as separate objects and are
        never merged.
    """
    if source_trusted is not True:
        raise UntrustedSourceError(
            'refusing to import a trust anchor list whose source has not been '
            'explicitly confirmed as trusted by the caller'
        )

    anchors = []
    for index, choice in enumerate(trust_anchor_list):
        anchors.append(_import_one(choice, index))
    return tuple(anchors)


def import_trust_anchor_list_der(substrate, source_trusted):
    """Decode DER bytes and then run :func:`import_trust_anchor_list`."""
    trust_anchor_list, rest = der_decoder(substrate, rfc5914.TrustAnchorList())
    if rest:
        raise TrustAnchorImportError(
            'trailing bytes after TrustAnchorList: %d octet(s)' % len(rest)
        )
    return import_trust_anchor_list(trust_anchor_list, source_trusted)


def group_by_public_key(anchors):
    """Map each public key to the distinct anchors that carry it.

    The mapping never collapses distinct constraints: the value is a tuple of
    every anchor (same key, possibly different name or policy controls).
    """
    grouped = {}  # type: Dict[bytes, List[TrustAnchorConstraints]]
    for anchor in anchors:
        grouped.setdefault(anchor.public_key_der, []).append(anchor)
    return {key: tuple(value) for key, value in grouped.items()}


def export_trust_anchor_list_der(anchors):
    """Re-serialise anchors back into a DER TrustAnchorList.

    Each entry is rebuilt from the exact ``source_der`` captured at import, so
    the round trip cannot add or widen any control.
    """
    choices = []
    for anchor in anchors:
        choice, rest = der_decoder(anchor.source_der, rfc5914.TrustAnchorChoice())
        if rest:
            raise TrustAnchorImportError('trailing bytes in stored anchor DER')
        choices.append(choice)

    trust_anchor_list = rfc5914.TrustAnchorList()
    for position, choice in enumerate(choices):
        trust_anchor_list.setComponentByPosition(position, choice)
    return der_encoder(trust_anchor_list)


def authorisation_is_within(exported_der, original_der):
    """Confirm an exported list grants no more than the original list.

    A faithful export is byte-identical entry-for-entry, which is the strongest
    possible guarantee that the authorisation scope has not widened.
    """
    original = import_trust_anchor_list_der(original_der, source_trusted=True)
    re_imported = import_trust_anchor_list_der(exported_der, source_trusted=True)
    if len(original) != len(re_imported):
        return False
    for before, after in zip(original, re_imported):
        if before.fingerprint != after.fingerprint:
            return False
    return True
