""" merge.py

Non-destructive merging of different copies of the same OpenPGP certificate.

A public key directory regularly receives multiple, independently observed copies
of the same certificate.  They can arrive out of order, be truncated, contain
duplicate packets, or even carry forged material (such as a bogus revocation or a
signature that only matches a short key id).  This module provides a merge entry
point that:

* never mutates the certificate objects handed to it (a fresh object is returned);
* only combines material after confirming that the primary key packets carry the
  exact same identity (full fingerprint *and* identical key material) - a short
  key id collision is never enough;
* keeps every accepted packet at most once (duplicate material is idempotent);
* distinguishes raw observations from cryptographically verified facts: a packet
  is only treated as a verified fact after its signature verifies against the
  primary key material of the certificate;
* never lets an unverified update erase history that was previously verifiable;
* quarantines conflicting material instead of silently dropping or merging it,
  and records enough provenance to locate the source of the conflict.
"""
from __future__ import absolute_import

import copy
import hashlib
import warnings
from collections import OrderedDict

from .constants import SignatureType
from .errors import PGPError
from .pgp import PGPKey
from .pgp import PGPSignature

__all__ = ['MergeConflict',
           'MergeResult',
           'merge_certificates',
           'merge', ]


# certification types that another key may legitimately place on a UID/attribute.
# Such signatures cannot be verified from this certificate alone, so they are kept
# as observations rather than treated as verified facts
_THIRD_PARTY_ALLOWED_TYPES = {
    SignatureType.Generic_Cert,
    SignatureType.Persona_Cert,
    SignatureType.Casual_Cert,
    SignatureType.Positive_Cert,
}

# signature types that live directly on a primary key rather than on a UID
_DIRECT_PRIMARY_TYPES = {
    SignatureType.DirectlyOnKey,
    SignatureType.KeyRevocation,
}


def _packet_bytes(obj):
    """Stable byte rendering of a packet-bearing object, used for identity checks."""
    return bytes(obj.__bytearray__())


def _packet_digest(obj):
    """A stable content identifier for a packet; identical packets share a digest."""
    return hashlib.sha256(_packet_bytes(obj)).hexdigest().upper()


def _sig_digest(sig):
    # canonical_bytes covers the signed portion; the full packet also contains the
    # unhashed area and the MPI signature, which together uniquely identify the packet
    return hashlib.sha256(bytes(sig._signature.__bytearray__())).hexdigest().upper()


def _uid_digest(uid):
    return hashlib.sha256(_packet_bytes(uid._uid)).hexdigest().upper()


def _key_digest(key):
    # the public portion of the key packet, independent of private key material
    pub = key._key if key.is_public else key._key.pubkey()
    return hashlib.sha256(bytes(pub.__bytearray__())).hexdigest().upper()


class MergeConflict(object):
    """
    A single piece of material that could not be merged automatically.

    A conflict is never dropped: it is held here, together with the reason it was
    quarantined and enough provenance to locate the source copy it came from.
    """

    __slots__ = ('reason', 'location', 'packet_type', 'digest', 'signer',
                 'signature_type', 'source', 'detail')

    def __init__(self, reason, location, packet, source, detail=''):
        self.reason = reason
        self.location = location
        self.packet_type = packet.__class__.__name__
        self.digest = _packet_digest(packet)
        self.signer = getattr(packet, 'signer', None)
        sigtype = getattr(packet, 'type', None)
        self.signature_type = sigtype.name if sigtype is not None else None
        self.source = source
        self.detail = detail

    def __repr__(self):
        return '<MergeConflict [{:s}] {:s} at {:s} (source={:s})>'.format(
            self.reason, self.packet_type, self.location, str(self.source))

    def __eq__(self, other):
        if not isinstance(other, MergeConflict):
            return NotImplemented
        return (self.reason, self.location, self.digest, self.source) == \
               (other.reason, other.location, other.digest, other.source)

    def __hash__(self):
        return hash((self.reason, self.location, self.digest, self.source))

    def as_dict(self):
        return {
            'reason': self.reason,
            'location': self.location,
            'packet_type': self.packet_type,
            'digest': self.digest,
            'signer': self.signer,
            'signature_type': self.signature_type,
            'source': self.source,
            'detail': self.detail,
        }


class MergeResult(object):
    """
    The outcome of merging one or more certificate copies.

    Attributes:

    * ``merged``: the resulting :py:obj:`~pgpy.PGPKey`. It is a freshly built object;
      none of the input certificates were modified.
    * ``verified``: digests of signature packets that were accepted because their
      cryptographic verification succeeded. These are the *verified facts*.
    * ``observations``: digests of packets that were retained as raw observations
      (for example, third-party certifications this certificate cannot verify).
    * ``conflicts``: a list of :py:obj:`MergeConflict` objects holding quarantined
      material and the reason it could not be merged.
    * ``sources``: the labels of every certificate copy that contributed material.
    """

    def __init__(self, merged):
        self.merged = merged
        self.verified = set()
        self.observations = set()
        self.conflicts = []
        self.sources = []
        # internal indexes used to keep the merge idempotent
        self._sig_index = set()
        self._conflict_index = set()

    @property
    def quarantined(self):
        """All conflict records, in the order they were quarantined."""
        return list(self.conflicts)

    def _quarantine(self, reason, location, packet, source, detail=''):
        conflict = MergeConflict(reason, location, packet, source, detail)
        fingerprint = (conflict.reason, conflict.location, conflict.digest, conflict.source)
        if fingerprint not in self._conflict_index:
            self._conflict_index.add(fingerprint)
            self.conflicts.append(conflict)
        return conflict

    def conflict_locations(self):
        """Return a mapping of packet digest -> conflict records, to locate a quarantined source."""
        locations = OrderedDict()
        for conflict in self.conflicts:
            locations.setdefault(conflict.digest, []).append(conflict)
        return locations

    def __repr__(self):
        return '<MergeResult sources={:d} verified={:d} observations={:d} conflicts={:d}>'.format(
            len(self.sources), len(self.verified), len(self.observations), len(self.conflicts))

    def as_dict(self):
        """Serialise the report (not the key material) for auditing and export."""
        return {
            'fingerprint': str(self.merged.fingerprint),
            'sources': list(self.sources),
            'verified': sorted(self.verified),
            'observations': sorted(self.observations),
            'conflicts': [conflict.as_dict() for conflict in self.conflicts],
        }


def _same_primary_identity(base, candidate):
    """Confirm two certificates are copies of the same primary key identity."""
    if base.fingerprint != candidate.fingerprint:
        return False
    # the fingerprint comparison alone is deliberately not trusted: require the
    # rendered public key packets to be byte-identical as well
    return _key_digest(base) == _key_digest(candidate)


def _verify_signature(primary, sig, subject):
    """
    Verify a single signature against the primary key material.

    Returns ``True`` only when the cryptographic check succeeds. Any failure
    (including an unsupported algorithm or malformed packet) is treated as
    "not verified", never as an exception, because unverified input must not be
    able to abort the merge of otherwise valid history.
    """
    with warnings.catch_warnings():
        warnings.simplefilter('ignore')
        try:
            result = primary.verify(subject, sig)
        except Exception:
            return False
    return bool(result)


def _is_self_issued(primary, sig):
    """
    Decide whether a signature claims to be issued by the certificate's primary key.

    The full issuer fingerprint is preferred whenever present; the 16-character
    key id is only a fallback. A bare 8-character short id is never used to make
    merging decisions by itself.
    """
    issuer_fp = sig.signer_fingerprint
    if issuer_fp:
        return issuer_fp == primary.fingerprint
    return sig.signer == primary.fingerprint.keyid


class _MergeEngine(object):
    def __init__(self, base, result):
        self.primary = base
        self.result = result

    # ------------------------------------------------------------------
    # signature handling
    # ------------------------------------------------------------------
    def _accept_signature(self, target, sig, verified):
        digest = _sig_digest(sig)
        if digest in self.result._sig_index:
            # identical packet already incorporated: duplicates are idempotent
            return digest, False

        target |= copy.copy(sig)
        self.result._sig_index.add(digest)
        if verified:
            self.result.verified.add(digest)
        else:
            self.result.observations.add(digest)
        return digest, True

    def _classify_signature(self, sig, subject, location, source):
        """
        Decide the fate of one signature packet.

        The signer identity is checked first: signature *types* such as generic
        certifications are also used by third parties, so a type alone can never
        prove a signature is self-issued. Self-issued signatures are then verified
        against the primary key material, and only a cryptographically valid one
        becomes a verified fact. Third-party signatures are retained as unverified
        observations (they may be verifiable once the certifier's key is available),
        while a signature of a primary-key-only type that names another issuer is
        quarantined as an impersonation or short-id collision attempt.
        """
        if not isinstance(sig, PGPSignature):
            self.result._quarantine('unparseable_packet', location, sig, source)
            return None

        self_issued = _is_self_issued(self.primary, sig)

        if not self_issued:
            if sig.type in _THIRD_PARTY_ALLOWED_TYPES:
                # a certification this certificate cannot verify itself: keep it as
                # an observation, never as a verified fact
                return False

            self.result._quarantine(
                'issuer_identity_mismatch', location, sig, source,
                'signature type {:s} names issuer {:s}, not the primary key'.format(
                    sig.type.name, sig.signer))
            return None

        if not _verify_signature(self.primary, sig, subject):
            self.result._quarantine(
                'signature_verification_failed', location, sig, source,
                'self-issued {:s} signature did not verify'.format(sig.type.name))
            return None

        return True

    # ------------------------------------------------------------------
    # primary-key level signatures (direct key signatures and key revocations)
    # ------------------------------------------------------------------
    def merge_primary_signatures(self, candidate, source):
        for sig in candidate._signatures:
            if sig.embedded:
                # embedded primary key binding signatures travel with their parent
                # subkey binding signature and are handled there
                continue
            if sig.type not in _DIRECT_PRIMARY_TYPES:
                # unknown/unexpected placement is quarantined rather than guessed at
                self.result._quarantine('unexpected_signature_placement', 'primary', sig, source)
                continue

            verdict = self._classify_signature(sig, self.primary, 'primary', source)
            if verdict is None:
                continue
            self._accept_signature(self.primary, sig, verdict)

    # ------------------------------------------------------------------
    # user ids / user attributes and their signatures
    # ------------------------------------------------------------------
    def merge_uids(self, candidate, source):
        for incoming_uid in candidate._uids:
            target_uid = self._find_matching_uid(incoming_uid)

            if target_uid is None:
                target_uid = copy.copy(incoming_uid)
                # drop copied signatures; they are re-evaluated individually below
                target_uid._signatures.clear()
                target_uid._parent = self.primary
                self.primary |= target_uid

            location = 'uid:{:s}'.format(target_uid.userid or '<attribute>')
            for sig in incoming_uid._signatures:
                verdict = self._classify_signature(sig, target_uid, location, source)
                if verdict is None:
                    continue
                self._accept_signature(target_uid, sig, verdict)

    def _find_matching_uid(self, incoming_uid):
        incoming_digest = _uid_digest(incoming_uid)
        for existing_uid in self.primary._uids:
            if _uid_digest(existing_uid) == incoming_digest:
                return existing_uid
        return None

    # ------------------------------------------------------------------
    # subkeys and their binding / revocation signatures
    # ------------------------------------------------------------------
    def merge_subkeys(self, candidate, source):
        for incoming_subkey in candidate.subkeys.values():
            target_subkey, reason = self._match_subkey(incoming_subkey, source)

            if reason is not None:
                # the whole subkey packet is conflicting; quarantine it and every
                # signature that depended on it, so nothing is silently discarded
                self.result._quarantine(reason, 'subkeys', incoming_subkey._key, source)
                for sig in incoming_subkey._signatures:
                    if not sig.embedded:
                        self.result._quarantine(reason, 'subkeys', sig, source,
                                                'belongs to quarantined subkey {:s}'.format(
                                                    incoming_subkey.fingerprint.keyid))
                continue

            if target_subkey is None:
                target_subkey = self._admit_new_subkey(incoming_subkey, source)
                if target_subkey is None:
                    continue

            location = 'subkey:{:s}'.format(target_subkey.fingerprint.keyid)
            for sig in incoming_subkey._signatures:
                if sig.embedded:
                    continue
                self._merge_subkey_signature(target_subkey, sig, incoming_subkey, location, source)

    def _match_subkey(self, incoming_subkey, source):
        """
        Match an incoming subkey by full fingerprint.

        Returns ``(subkey, reason)``: ``(existing_subkey, None)`` when it is already
        present, ``(None, None)`` when it is genuinely new, or ``(None, reason)``
        when it conflicts (for example a short-id collision with different material).
        """
        incoming_fp = incoming_subkey.fingerprint
        for existing in self.primary.subkeys.values():
            if existing.fingerprint == incoming_fp:
                if _key_digest(existing) != _key_digest(incoming_subkey):
                    return None, 'subkey_material_conflict'
                return existing, None

        # same 16-char key id but a different full fingerprint: a collision, never a merge
        if incoming_fp.keyid in self.primary.subkeys:
            return None, 'keyid_collision'
        return None, None

    def _admit_new_subkey(self, incoming_subkey, source):
        # a previously unseen subkey is only admitted once at least one valid
        # primary-key binding signature verifies; otherwise it stays quarantined
        binding = next((sig for sig in incoming_subkey._signatures
                        if not sig.embedded and sig.type == SignatureType.Subkey_Binding), None)
        if binding is None or not _is_self_issued(self.primary, binding) or \
                not _verify_signature(self.primary, binding, incoming_subkey):
            for sig in incoming_subkey._signatures:
                if not sig.embedded:
                    self.result._quarantine(
                        'unverified_subkey_binding', 'subkeys', sig, source,
                        'subkey {:s} has no valid primary key binding signature'.format(
                            incoming_subkey.fingerprint.keyid))
            self.result._quarantine(
                'unverified_subkey_binding', 'subkeys', incoming_subkey._key, source)
            return None

        new_subkey = copy.copy(incoming_subkey)
        new_subkey._signatures.clear()
        new_subkey._parent = self.primary
        self.primary._children[new_subkey.fingerprint.keyid] = new_subkey
        return new_subkey

    def _merge_subkey_signature(self, target_subkey, sig, incoming_subkey, location, source):
        if sig.type == SignatureType.PrimaryKey_Binding:
            # an embedded cross-signature: verify with the subkey material itself
            if not self._verify_embedded_binding(target_subkey, sig):
                self.result._quarantine('signature_verification_failed', location, sig, source,
                                        'embedded primary key binding signature did not verify')
                return
            self._accept_signature(target_subkey, sig, True)
            return

        verdict = self._classify_signature(sig, target_subkey, location, source)
        if verdict is not None:
            self._accept_signature(target_subkey, sig, verdict)

    def _verify_embedded_binding(self, target_subkey, sig):
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            try:
                result = target_subkey.verify(self.primary, sig)
            except Exception:
                return False
        return bool(result)


def _label(certificate, index, labels):
    if labels is not None and index < len(labels) and labels[index] is not None:
        return labels[index]
    return 'copy-{:d}'.format(index)


def merge_certificates(certificates, labels=None):
    """
    Merge several copies of the same OpenPGP certificate without modifying any of them.

    :param certificates: an ordered iterable of :py:obj:`~pgpy.PGPKey` objects. Order
                         represents the order in which the copies were observed; it is
                         used only for provenance, never for trust decisions.
    :param labels: optional labels (one per certificate) used to identify the source
                   copy of any quarantined material in the resulting report.
    :returns: a :py:obj:`MergeResult` whose ``merged`` attribute is a new, independent
              :py:obj:`~pgpy.PGPKey`.
    :raises: :py:exc:`~pgpy.errors.PGPError` if the inputs are not all primary keys of
             the same public half (full fingerprint and identical key material), or if
             less than one certificate is supplied.

    The first certificate is used only as the structural base for the output; its
    material is copied, so the input objects are never altered. Missing packets in an
    older or newer copy are never interpreted as revocations, and later-arriving
    packets are not treated as more trustworthy than earlier ones.
    """
    certificates = list(certificates)
    if len(certificates) == 0:
        raise PGPError('at least one certificate is required to merge')

    for index, certificate in enumerate(certificates):
        if not isinstance(certificate, PGPKey):
            raise PGPError('merge input #{:d} is not a PGPKey'.format(index))
        if not certificate.is_primary:
            raise PGPError('merge input #{:d} is not a primary key'.format(index))

    is_public = certificates[0].is_public
    for index, certificate in enumerate(certificates[1:], start=1):
        if certificate.is_public != is_public:
            raise PGPError(
                'cannot merge a mix of public and private key halves (input #{:d} '
                'is {:s})'.format(index, 'public' if certificate.is_public else 'private'))

    base_input = certificates[0]
    for index, candidate in enumerate(certificates[1:], start=1):
        if not _same_primary_identity(base_input, candidate):
            raise PGPError(
                'cannot merge certificates with different primary key identities: '
                '{:s} != {:s}'.format(base_input.fingerprint, candidate.fingerprint))

    # build the output as an independent deep copy of the first certificate
    merged = copy.deepcopy(base_input)
    merged._sibling = None
    result = MergeResult(merged)

    # material already present in the base copy is recorded as observed/verified
    # history so that later input can never erase it
    _index_base_history(merged, result)

    engine = _MergeEngine(merged, result)

    for index, candidate in enumerate(certificates):
        source = _label(candidate, index, labels)
        if source not in result.sources:
            result.sources.append(source)

        if index == 0:
            # the base was copied wholesale; still scan it for unverifiable junk so
            # the report reflects its quality, without removing anything
            _audit_base(merged, engine, source)
            continue

        engine.merge_primary_signatures(candidate, source)
        engine.merge_uids(candidate, source)
        engine.merge_subkeys(candidate, source)

    return result


def _index_base_history(merged, result):
    """Record every packet the base certificate starts out with."""
    for sig in merged._signatures:
        if not sig.embedded:
            result._sig_index.add(_sig_digest(sig))
    for uid in merged._uids:
        for sig in uid._signatures:
            result._sig_index.add(_sig_digest(sig))
    for subkey in merged.subkeys.values():
        for sig in subkey._signatures:
            if not sig.embedded:
                result._sig_index.add(_sig_digest(sig))


def _audit_base(merged, engine, source):
    """
    Classify the base certificate's material for the report.

    The base itself is never modified and nothing is quarantined from it (callers
    already trust it enough to use it as the base). Self-issued signatures that
    cryptographically verify are recorded as verified facts; everything else (for
    example third-party certifications) is recorded as an observation, so the report
    accurately distinguishes facts from observations after a round trip.
    """
    def _classify(sig, subject):
        digest = _sig_digest(sig)
        if _is_self_issued(merged, sig) and _verify_signature(merged, sig, subject):
            engine.result.verified.add(digest)
        else:
            engine.result.observations.add(digest)

    for sig in merged._signatures:
        if not sig.embedded:
            _classify(sig, merged)

    for uid in merged._uids:
        for sig in uid._signatures:
            _classify(sig, uid)

    for subkey in merged.subkeys.values():
        for sig in subkey._signatures:
            if not sig.embedded:
                _classify(sig, subkey)


def merge(base, other, label=None):
    """
    Merge two copies of the same certificate.

    Convenience wrapper around :py:func:`merge_certificates`. Neither input is
    modified; the merged certificate is available as ``MergeResult.merged``.
    """
    labels = [None, label] if label is not None else None
    return merge_certificates([base, other], labels=labels)
