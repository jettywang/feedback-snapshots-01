"""
certprune.py
============

Targeted pruning of OpenPGP certificates.

This module produces a *minimal* transferable public key that still carries
every packet required to evaluate a specific signature, while stripping
unrelated identity material (extra User IDs, photos, third-party
certifications) and every packet that is not needed for that verification.

Design rules (see RFC 4880 sections 5.2.1, 5.2.3, 11.1 and RFC 4880bis
"OpenPGP Certificate Filtering"):

* Only public packets are ever emitted.  A private key input is reduced to
  its public half first, and the output is asserted to contain no
  Secret-Key / Secret-Subkey packets or private key material.
* The primary key packet, the actual signing (sub)key, its binding
  signatures (including the embedded primary-key binding for signing
  subkeys) and every piece of revocation evidence that affects validity
  are retained.  Revocation packets are never dropped to make a revoked
  key look usable.
* No packet is re-issued or re-signed.  The output is assembled from
  ``copy.copy`` of the original packets only, so every retained signature
  stays byte-identical to the source.
* If the primary key derives its expiration (or another validity-affecting
  property) from a User ID self-signature, a User ID must be kept; the
  report records that identity disclosure is unavoidable rather than
  silently producing a certificate whose verification result differs.
* The source key object is never mutated.
"""

from __future__ import print_function

import argparse
import collections
import copy
import warnings

from .constants import PacketTag
from .constants import SignatureType
from .errors import PGPError
from .packet import Packet
from .packet.packets import PrivKey
from .packet.packets import PrivSubKey
from .pgp import PGPKey
from .pgp import PGPSignature


# Signature types that directly affect the validity of the certificate or
# of a retained component.  Anything outside these sets is identity or
# advisory material that can be removed without changing the answer to
# "does the target signature verify?".
_PRIMARY_VALIDITY_SIGS = {
    SignatureType.KeyRevocation,
    SignatureType.DirectlyOnKey,
}
_UID_VALIDITY_SIGS = {
    SignatureType.Generic_Cert,
    SignatureType.Persona_Cert,
    SignatureType.Casual_Cert,
    SignatureType.Positive_Cert,
    SignatureType.CertRevocation,
}
_SUBKEY_VALIDITY_SIGS = {
    SignatureType.Subkey_Binding,
    SignatureType.SubkeyRevocation,
}

# Human readable names for the packet categories used in the report.
_PACKET_LABELS = {
    PacketTag.PublicKey: 'primary public key packet',
    PacketTag.SecretKey: 'secret key packet (private material)',
    PacketTag.PublicSubKey: 'public subkey packet',
    PacketTag.SecretSubKey: 'secret subkey packet (private material)',
    PacketTag.UserID: 'User ID packet',
    PacketTag.UserAttribute: 'User Attribute packet (photo/image)',
    PacketTag.Signature: 'signature packet',
}


class PruneReport(object):
    """
    An auditable record of a pruning run.

    ``kept`` and ``removed`` are lists of ``(category, detail, reason)``
    tuples describing every packet class that was retained or dropped.
    ``notes`` carries disclosures that the operator must read, in
    particular cases where identity material could not be removed without
    changing the verification result.
    """

    _entry = collections.namedtuple('PruneReportEntry', ['category', 'detail', 'reason'])

    def __init__(self):
        self.kept = []
        self.removed = []
        self.notes = []

    def _record(self, bucket, category, detail, reason):
        bucket.append(self._entry(category, detail, reason))

    def keep(self, category, detail, reason):
        self._record(self.kept, category, detail, reason)

    def drop(self, category, detail, reason):
        self._record(self.removed, category, detail, reason)

    def note(self, text):
        if text not in self.notes:
            self.notes.append(text)

    def format_text(self):
        """Return a human readable rendering of the report."""
        lines = ['Certificate pruning report',
                 '===========================',
                 '',
                 'Kept packets:']
        lines += ['  - {:s}: {:s} — {:s}'.format(cat, detail, reason)
                  for cat, detail, reason in self.kept]
        lines.append('')
        lines.append('Removed packets:')
        lines += ['  - {:s}: {:s} — {:s}'.format(cat, detail, reason)
                  for cat, detail, reason in self.removed]
        lines.append('')
        lines.append('Notes:')
        if self.notes:
            lines += ['  - {:s}'.format(n) for n in self.notes]
        else:
            lines.append('  - none')
        lines.append('')
        return '\n'.join(lines)


def _sig_type_name(sig):
    try:
        return SignatureType(sig.type).name
    except ValueError:  # pragma: no cover - defensive against unknown types
        return '0x{:02X}'.format(int(sig.type))


def _label(packet_tag):
    try:
        return _PACKET_LABELS[PacketTag(packet_tag)]
    except (ValueError, KeyError):  # pragma: no cover - defensive
        return 'packet tag 0x{:02X}'.format(int(packet_tag))


def _is_private(key):
    """True if this PGPKey or any of its subkeys still carries private material."""
    if isinstance(key._key, (PrivKey, PrivSubKey)):
        return True
    return any(isinstance(sk._key, (PrivKey, PrivSubKey)) for sk in key.subkeys.values())


def _assert_no_private_material(key):
    """Defensive guard: the output must never contain a private packet."""
    tags = [pkt.header.tag for pkt in _iter_packets(key)]
    forbidden = {PacketTag.SecretKey, PacketTag.SecretSubKey}
    leaked = [t for t in tags if t in forbidden]
    if leaked or not key.is_public or _is_private(key):
        raise PGPError(
            "Refusing to export pruned certificate: private key material is present "
            "(tags={:s})".format(', '.join(hex(int(t)) for t in leaked)))
    return tags


def _iter_packets(key):
    """
    Yield the low-level packets of a PGPKey in transfer order, mirroring
    ``PGPKey.__bytearray__`` so the audit sees exactly what gets exported.
    """
    yield key._key
    for sig in key._signatures:
        if not sig.embedded and sig.exportable:
            yield sig._signature
    for uid in key._uids:
        yield uid._uid
        for sig in uid._signatures:
            if sig.exportable:
                yield sig._signature
    for subkey in key.subkeys.values():
        yield subkey._key
        for sig in subkey._signatures:
            if not sig.embedded and sig.exportable:
                yield sig._signature


def _packet_counts(key):
    """Count exported packets by tag."""
    counts = {}
    for pkt in _iter_packets(key):
        tag = int(pkt.header.tag)
        counts[tag] = counts.get(tag, 0) + 1
    return counts


def _signing_key_id(key, signature):
    """
    Identify the key id that must perform the cryptographic check for
    ``signature``: a subkey id when the signer is a bound subkey, otherwise
    the primary key id.  Raises ``PGPError`` when the candidate certificate
    does not contain the issuer at all.
    """
    issuer = signature.signer
    if issuer == key.fingerprint.keyid:
        return issuer, False
    if issuer in key.subkeys:
        return issuer, True
    raise PGPError(
        "Candidate certificate 0x{:s} does not contain signature issuer 0x{:s}".format(
            key.fingerprint.keyid, issuer))


def _latest_self_cert(uid, key):
    """
    Return the most recent self-certification (not a certification
    revocation) on ``uid``.

    ``PGPUID.selfsig`` simply returns the newest self-issued signature,
    which can be a ``CertRevocation`` that never carries a key expiration
    subpacket.  Validity data such as key expiration lives on the newest
    non-revocation certification, so filter explicitly.
    """
    keyid = key.fingerprint.keyid
    candidates = [
        sig for sig in uid._signatures
        if sig.signer == keyid
        and sig.type in _UID_VALIDITY_SIGS
        and sig.type != SignatureType.CertRevocation
    ]
    return candidates[-1] if candidates else None


def _primary_needs_uid(key):
    """
    Determine whether validity information about the primary key is only
    available through a User ID self-signature.

    PGPy derives primary key expiration from User ID self-signatures; a
    direct-key signature carrying a key expiration can carry the same fact
    without exposing an identity.  When neither exists the primary never
    expires and no User ID is required.
    """
    has_expiring_self_cert = any(
        (lambda cert: cert is not None and cert.key_expiration is not None)(
            _latest_self_cert(uid, key))
        for uid in key.userids)
    if not has_expiring_self_cert:
        return False

    has_direct_expiration = any(
        sig.type == SignatureType.DirectlyOnKey
        and sig.signer == key.fingerprint.keyid
        and sig.key_expiration is not None
        for sig in key._signatures)
    return not has_direct_expiration


def _verify(key, subject, signature):
    """Run a verification and return the boolean result and issue flags."""
    with warnings.catch_warnings():
        warnings.simplefilter('ignore')
        result = key.verify(subject, signature)
    issues = tuple(sorted(int(s.issues) for s in result._subjects))
    return bool(result), issues


def prune_certificate(candidate, signature, subject):
    """
    Build a minimal public certificate capable of evaluating ``signature``
    over ``subject``.

    :param candidate: The candidate certificate, public or private.
    :type candidate: :py:obj:`~pgpy.PGPKey`
    :param signature: The target signature the output must be able to verify.
    :type signature: :py:obj:`~pgpy.PGPSignature`
    :param subject: The signed data: ``bytes``/``str`` for a detached
                    signature, or the original :py:obj:`~pgpy.PGPMessage`.
    :returns: A tuple of ``(pruned_key, report)`` where ``pruned_key`` is a
              new, public-only :py:obj:`~pgpy.PGPKey` and ``report`` is a
              :py:obj:`PruneReport`.
    :raises: :py:exc:`~pgpy.errors.PGPError` if the candidate does not hold
             the signature issuer.
    """
    if not isinstance(candidate, PGPKey):
        raise TypeError("candidate must be a PGPKey")
    if not isinstance(signature, PGPSignature):
        raise TypeError("signature must be a PGPSignature")

    report = PruneReport()

    # 1. Never operate on (or export) private packets.  Reduce to the public
    #    half first; the source object itself is left untouched.
    source = candidate.pubkey if not candidate.is_public else candidate
    if source is not candidate:
        report.note(
            "Input was a private key; only its public half was used. No private "
            "key material is present in the output.")

    issuer_id, issuer_is_subkey = _signing_key_id(source, signature)

    # 2. Establish the baseline verification conclusion before pruning.
    before_ok, before_issues = _verify(source, subject, signature)

    # 3. A fresh shell that will only ever receive public packets.
    pruned = PGPKey()
    pruned._key = copy.copy(source._key)
    report.keep(_label(PacketTag.PublicKey),
                '0x{:s} ({:s})'.format(source.fingerprint.keyid, source.key_algorithm.name),
                'primary key packet anchors the certificate and its fingerprint/key IDs')

    # 4. Primary-level packets: self-issued direct-key signatures and key
    #    revocations are validity evidence and must survive.  Everything
    #    else (third-party direct signatures, confirmations, timestamps)
    #    is irrelevant to verifying the target signature.
    for sig in source._signatures:
        if not sig.exportable or sig.embedded:
            report.drop(_label(PacketTag.Signature),
                        '{:s} (primary level)'.format(_sig_type_name(sig)),
                        'non-exportable or embedded signature is not part of the transferable key')
            continue
        is_self_issued = sig.signer == source.fingerprint.keyid
        if is_self_issued and sig.type in _PRIMARY_VALIDITY_SIGS:
            pruned |= copy.copy(sig)
            if sig.type == SignatureType.KeyRevocation:
                reason = 'key revocation evidence must be retained so a revoked primary key cannot be made to appear valid'
            else:
                reason = 'direct-key self-signature carries validity information (expiration, flags, revocation keys) about the primary key'
            report.keep(_label(PacketTag.Signature),
                        '{:s} by 0x{:s}'.format(_sig_type_name(sig), sig.signer), reason)
        else:
            report.drop(_label(PacketTag.Signature),
                        '{:s} by 0x{:s} (primary level)'.format(_sig_type_name(sig), sig.signer),
                        'not required to evaluate the target signature and carries no self-issued validity evidence')

    # 5. Decide whether a User ID must be kept to preserve the primary key
    #    validity conclusion.
    keep_uid = _primary_needs_uid(source)
    retained_uid = None
    if keep_uid:
        # Prefer the primary UID, then the first UID with an expiring
        # non-revocation self-signature, then simply the first UID.
        retained_uid = next((u for u in source.userids if u.is_primary), None)
        if retained_uid is None:
            retained_uid = next(
                (u for u in source.userids
                 if (lambda cert: cert is not None and cert.key_expiration is not None)(
                     _latest_self_cert(u, source))),
                None)
        if retained_uid is None:
            retained_uid = next(iter(source.userids), None)
        report.note(
            "The primary key expiration is only asserted by a User ID self-signature; "
            "a User ID ('{:s}') must be retained to preserve the original validity "
            "conclusion. Removing all identities would change the verification result, "
            "so no equivalent certificate was synthesized.".format(
                retained_uid.userid if retained_uid is not None else ''))

    for uid in source._uids:
        category = _label(PacketTag.UserID) if uid.is_uid else _label(PacketTag.UserAttribute)
        detail = uid.userid if uid.is_uid else 'image attribute'
        if uid is retained_uid:
            pruned |= copy.copy(uid)
            # keep only self certifications and certification revocations
            # issued by the primary key; third-party certifications leak
            # relationships without affecting this verification.
            for sig in uid._signatures:
                if not sig.exportable:
                    report.drop(_label(PacketTag.Signature),
                                '{:s} on retained User ID'.format(_sig_type_name(sig)),
                                'non-exportable signature is not part of the transferable key')
                    continue
                is_self = sig.signer == source.fingerprint.keyid
                if is_self and sig.type in _UID_VALIDITY_SIGS:
                    pruned |= copy.copy(sig)
                    if sig.type == SignatureType.CertRevocation:
                        reason = 'certification revocation must be retained with its User ID so revocation evidence is not hidden'
                    else:
                        reason = 'self-certification binds the retained User ID and carries primary key validity data'
                    report.keep(_label(PacketTag.Signature),
                                '{:s} by 0x{:s} on retained User ID'.format(_sig_type_name(sig), sig.signer),
                                reason)
                else:
                    report.drop(_label(PacketTag.Signature),
                                '{:s} by 0x{:s} on retained User ID'.format(_sig_type_name(sig), sig.signer),
                                'third-party or non-validity certification is not needed to verify the target signature')
            report.keep(category, detail,
                        'required to preserve primary key validity information that exists nowhere else')
        else:
            reason = ('unrelated identity: not needed to verify the target signature'
                      if uid.is_uid else
                      'photo/attribute is identity material unrelated to the target signature')
            report.drop(category, detail, reason)
            for sig in uid._signatures:
                report.drop(_label(PacketTag.Signature),
                            '{:s} by 0x{:s} on removed identity'.format(_sig_type_name(sig), sig.signer),
                            'certification of an identity that was removed')

    # 6. Subkeys: retain only the actual signing subkey (plus its binding
    #    and revocation signatures).  Encryption-only or otherwise unused
    #    subkeys are dropped entirely.  A signing subkey that was revoked
    #    stays in the output *with* its revocation signature.
    for sub_id, subkey in source.subkeys.items():
        if not issuer_is_subkey or sub_id != issuer_id:
            report.drop(_label(PacketTag.PublicSubKey),
                        '0x{:s} ({:s})'.format(sub_id, subkey.key_algorithm.name),
                        'subkey did not create the target signature')
            for sig in subkey._signatures:
                if not sig.embedded and sig.exportable:
                    report.drop(_label(PacketTag.Signature),
                                '{:s} on removed subkey 0x{:s}'.format(_sig_type_name(sig), sub_id),
                                'belongs to a subkey that was removed')
            continue

        pruned |= copy.copy(subkey)
        report.keep(_label(PacketTag.PublicSubKey),
                    '0x{:s} ({:s})'.format(sub_id, subkey.key_algorithm.name),
                    'this subkey cryptographically created the target signature')

        for sig in subkey._signatures:
            if sig.embedded:
                # embedded primary-key binding travels inside the binding
                # signature packet; __bytearray__ never emits it standalone
                report.keep(_label(PacketTag.Signature),
                            '{:s} (embedded in binding)'.format(_sig_type_name(sig)),
                            'embedded primary-key binding proves the signing subkey is authorized to sign')
                continue
            if not sig.exportable:
                report.drop(_label(PacketTag.Signature),
                            '{:s} on signing subkey'.format(_sig_type_name(sig)),
                            'non-exportable signature is not part of the transferable key')
                continue
            if sig.type in _SUBKEY_VALIDITY_SIGS:
                pruned |= copy.copy(sig)
                if sig.type == SignatureType.SubkeyRevocation:
                    reason = 'subkey revocation evidence must be retained so a revoked signing subkey cannot be made to appear valid'
                else:
                    reason = 'subkey binding signature (and its embedded primary-key binding) authorizes this subkey'
                report.keep(_label(PacketTag.Signature),
                            '{:s} by 0x{:s}'.format(_sig_type_name(sig), sig.signer), reason)
            else:
                report.drop(_label(PacketTag.Signature),
                            '{:s} by 0x{:s} on signing subkey'.format(_sig_type_name(sig), sig.signer),
                            'not required to evaluate the target signature')

    # When the primary key itself signed, there is nothing subkey-related
    # to keep; record that fact explicitly for the audit trail.
    if not issuer_is_subkey:
        report.note(
            "The target signature was issued by the primary key 0x{:s}; no subkey is required.".format(
                issuer_id))

    # 7. Hard security gate: the assembled certificate must be strictly public.
    _assert_no_private_material(pruned)

    # 8. Re-verify with the pruned certificate and require an identical
    #    conclusion.  Any divergence is reported rather than papered over.
    after_ok, after_issues = _verify(pruned, subject, signature)
    report.verification_before = (before_ok, before_issues)
    report.verification_after = (after_ok, after_issues)
    if before_ok != after_ok or before_issues != after_issues:
        report.note(
            "WARNING: verification conclusion changed after pruning "
            "(before={!r}/{:r}, after={!r}/{:r}). The pruned certificate is "
            "still exported for inspection but must not be treated as equivalent.".format(
                before_ok, before_issues, after_ok, after_issues))
    else:
        report.note(
            "Verification conclusion unchanged by pruning: {:s} (issues={!r}).".format(
                'valid' if after_ok else 'invalid', after_issues))

    return pruned, report


def audit_removal(original, pruned):
    """
    Compare the packet inventories of the original and pruned certificates
    and return a dict mapping packet-tag ints to ``(before, after)`` counts.
    Used to prove that unrelated identity material was actually removed.
    """
    before = _packet_counts(original)
    after = _packet_counts(pruned)
    all_tags = set(before) | set(after)
    return {tag: (before.get(tag, 0), after.get(tag, 0)) for tag in sorted(all_tags)}


def assert_identities_removed(pruned, forbidden_uids=None, no_attributes=True):
    """
    Assert that the pruned certificate contains no User Attribute packets
    and none of the ``forbidden_uids`` strings.  Returns the remaining User
    ID strings (normally empty, or exactly the one unavoidable UID).
    """
    if no_attributes and pruned.userattributes:
        raise AssertionError(
            "pruned certificate still contains {:d} User Attribute packet(s)".format(
                len(pruned.userattributes)))
    remaining = [u.userid for u in pruned.userids]
    if forbidden_uids:
        leaked = [uid for uid in remaining if uid in set(forbidden_uids)]
        if leaked:
            raise AssertionError("pruned certificate still contains forbidden identities: {!r}".format(leaked))
    return remaining


def load_signature(blob_or_path):
    """
    Load a :py:obj:`PGPSignature` from an armored signature block or a
    standalone revocation-certificate style block containing one signature
    packet.  Accepts bytes/str content or a filesystem path.
    """
    data = _read(blob_or_path)
    try:
        return PGPSignature.from_blob(data)
    except ValueError:
        unarmored = PGPKey.ascii_unarmor(data)
        pkt = Packet(unarmored['body'])
        if pkt.header.tag != PacketTag.Signature:
            raise
        return PGPSignature() | pkt


def _read(value):
    if isinstance(value, (bytes, bytearray)):
        return bytearray(value)
    if isinstance(value, str):
        try:
            with open(value, 'rb') as fh:
                return bytearray(fh.read())
        except (IOError, OSError):
            return bytearray(value, 'latin-1')
    raise TypeError("expected path or blob, got {:s}".format(type(value).__name__))


def _build_arg_parser():
    parser = argparse.ArgumentParser(
        prog='python -m pgpy',
        description='Prune an OpenPGP certificate down to the public material needed to verify one signature.')
    parser.add_argument('--signature', '-s', required=True,
                        help='armored target signature (detached signature block or a file containing one signature packet)')
    parser.add_argument('--subject', '-f', required=True,
                        help='the signed data file (the exact bytes covered by the detached signature)')
    parser.add_argument('--candidate', '-k', required=True, action='append',
                        help='candidate certificate file; may be repeated to provide multiple candidates')
    parser.add_argument('--output', '-o',
                        help='write the pruned armored public key here (default: stdout)')
    parser.add_argument('--report', '-r',
                        help='write the human-readable pruning report here (default: stderr)')
    return parser


def main(argv=None):
    args = _build_arg_parser().parse_args(argv)

    with open(args.subject, 'rb') as fh:
        subject = fh.read()
    signature = load_signature(args.signature)

    reports = []
    pruned_for_export = None
    for candidate_path in args.candidate:
        candidate = PGPKey.from_file(candidate_path)[0]
        try:
            pruned, report = prune_certificate(candidate, signature, subject)
        except PGPError as exc:
            reports.append("Candidate {:s}: skipped ({!s})".format(candidate_path, exc))
            continue

        inventory = audit_removal(candidate, pruned)
        reports.append("Candidate {:s} (0x{:s})".format(candidate_path, candidate.fingerprint.keyid))
        reports.append(_format_inventory(inventory))
        reports.append(report.format_text())
        pruned_for_export = pruned
        break

    report_text = '\n'.join(reports)
    if pruned_for_export is None:
        if args.report:
            with open(args.report, 'w') as fh:
                fh.write(report_text)
        else:  # pragma: no cover - exercised via CLI manually
            import sys
            sys.stderr.write(report_text + '\n')
        raise SystemExit("No candidate certificate contained the issuer of the target signature.")

    if args.output:
        with open(args.output, 'w') as fh:
            fh.write(str(pruned_for_export))
    else:
        print(str(pruned_for_export))

    if args.report:
        with open(args.report, 'w') as fh:
            fh.write(report_text)
    else:  # pragma: no cover - exercised via CLI manually
        import sys
        sys.stderr.write(report_text + '\n')


def _format_inventory(inventory):
    lines = ['Packet inventory (tag: before -> after):']
    for tag, (before, after) in inventory.items():
        lines.append('  - 0x{:02X} {:s}: {:d} -> {:d}'.format(
            tag, _label(tag), before, after))
    return '\n'.join(lines)


if __name__ == '__main__':  # pragma: no cover
    main()
