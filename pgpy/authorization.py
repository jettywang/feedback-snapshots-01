"""
authorization.py
================

Historical, point-in-time authorization views of OpenPGP keys.

The boolean properties on :py:class:`~pgpy.PGPKey` (such as
:py:attr:`~pgpy.PGPKey.is_expired`) answer questions about *right now*.
Archive verification instead asks a different question:

    "At a specific moment in the past, was this key (or one of its
    subkeys, or one of its User IDs) authorized to make a signature?"

That question cannot be answered by reusing a present-tense boolean.  A
key that is expired or revoked today may have been perfectly valid at
the time an archived document was signed, and a self-signature that is
older, expired or superseded today may have been the governing
certification back then.

This module therefore reconstructs the authorization state of a
:py:class:`~pgpy.PGPKey` as it was at an explicit evaluation time.  It:

* cryptographically verifies the self-signatures and primary/subkey
  binding signatures that could govern the requested moment,
* derives the validity period and usage flags of the primary key, each
  User ID and each subkey from the *effective* signature at that moment,
* processes revocations issued by the key holder themselves, keeping the
  different scopes of key, subkey and certification revocations apart,
* reports evidence produced by externally designated revokers as
  requiring an external authorization decision, without inferring the
  authority of such a revoker, and
* returns an explicit ``unknown`` verdict whenever the available
  material does not permit a definite answer, instead of guessing.

Every conclusion carries the concrete, valid signature(s) it was derived
from, so an auditor can trace each decision back to the packet that
actually determined it.

The low-level :py:meth:`~pgpy.PGPKey.verify` interface is intentionally
left untouched; this module is an additional, time-aware layer on top of
the same key material.
"""

import enum
import collections

from datetime import datetime, timezone

from cryptography.hazmat.primitives import hashes

from .constants import KeyFlags
from .constants import SignatureType
from .pgp import PGPKey
from .pgp import PGPSignature


__all__ = ['AuthorizationState',
           'EvidenceState',
           'SignatureEvidence',
           'AuthorizationDecision',
           'KeyAuthorizationView']


class AuthorizationState(enum.Enum):
    """The tri-state result of a point-in-time authorization question."""

    #: The key material was definitely authorized for the requested use
    #: at the evaluation time.
    authorized = 'authorized'

    #: The key material was definitely *not* authorized at the evaluation
    #: time (expired, revoked by the holder, lacking the required flag,
    #: bound only in the future, ...).
    not_authorized = 'not_authorized'

    #: The available material does not permit a definite answer.  The
    #: accompanying :py:class:`SignatureEvidence` list explains what is
    #: missing or what requires an external decision.
    unknown = 'unknown'

    def __bool__(self):
        return self is AuthorizationState.authorized

    __nonzero__ = __bool__


class EvidenceState(enum.Enum):
    """How a particular signature packet was treated by the evaluation."""

    #: The signature was cryptographically valid and admissible at the
    #: evaluation time; it is eligible to govern the conclusion.
    valid = 'valid'

    #: The signature was created after the evaluation time and therefore
    #: could not yet have had any effect at that moment.
    future = 'future'

    #: The signature carried its own signature-expiration that had already
    #: elapsed at the evaluation time.
    expired = 'expired'

    #: Cryptographic verification failed.  This includes forged
    #: revocations and forged self-signature updates: they are rejected and
    #: can never alter a historical conclusion.
    bad_signature = 'bad_signature'

    #: Cryptographic verification could not be completed (for example, an
    #: unsupported public key algorithm).  No conclusion may be drawn from
    #: this signature.
    unverifiable = 'unverifiable'

    #: The signature is a revocation issued by someone other than the key
    #: holder.  Its authority depends on a Revocation Key designation that
    #: is evaluated externally; it is recorded as evidence but never
    #: treated as a holder revocation here.
    external_revocation = 'external_revocation'


#: A single auditable fact about a signature packet considered during an
#: evaluation.
#:
#: ``signature``      - the :py:class:`~pgpy.PGPSignature` packet itself
#: ``state``          - an :py:class:`EvidenceState` classification
#: ``detail``         - a short, stable, human-readable explanation
SignatureEvidence = collections.namedtuple('SignatureEvidence',
                                           ['signature', 'state', 'detail'])


class AuthorizationDecision(collections.namedtuple(
        'AuthorizationDecision',
        ['subject', 'usage', 'at', 'state', 'reason', 'evidence'])):
    """The outcome of one point-in-time authorization question.

    ``subject``  - the :py:class:`~pgpy.PGPKey` primary key or subkey, or
                   the :py:class:`~pgpy.PGPUID` the decision is about
    ``usage``    - the :py:class:`~pgpy.constants.KeyFlags` capability
                   that was asked about (``None`` for identity questions)
    ``at``       - the evaluation time as a timezone-aware
                   :py:class:`~datetime.datetime`
    ``state``    - an :py:class:`AuthorizationState`
    ``reason``   - a short, stable, human-readable explanation of why the
                   decision is what it is
    ``evidence`` - the ordered list of :py:class:`SignatureEvidence`
                   packets actually considered, with the effective
                   signature first when one governs the conclusion
    """

    __slots__ = ()

    def __bool__(self):
        return bool(self.state)

    __nonzero__ = __bool__

    def __repr__(self):
        subject = self.subject.fingerprint.keyid if isinstance(self.subject, PGPKey) \
            else '{}'.format(self.subject)
        usage = self.usage.name if self.usage is not None else 'identity'
        return 'AuthorizationDecision(subject={}, usage={}, at={}, state={})'.format(
            subject, usage, self.at.isoformat(), self.state.name)

    @property
    def effective_signature(self):
        """The valid, governing signature for this decision, if any.

        This is the packet that actually supplied the validity period,
        usage flags or revocation that the conclusion rests on.  It is
        ``None`` when no admissible, cryptographically valid signature
        governs the decision, in which case ``state`` is never
        :py:attr:`AuthorizationState.authorized`.
        """
        # every code path keeps the packet that governs the conclusion at
        # the head of the evidence list, so the first valid entry is the
        # effective signature even when older valid self-signatures remain
        # in the list as supporting evidence.
        valid = [ev.signature for ev in self.evidence
                 if ev.state is EvidenceState.valid]
        return valid[0] if valid else None

    @property
    def requires_external_authorization(self):
        """``True`` if a third-party revocation was encountered.

        Such evidence is never interpreted here; the caller has to
        determine separately whether the external revoker was authorized
        through a Revocation Key designation.
        """
        return any(ev.state is EvidenceState.external_revocation
                   for ev in self.evidence)


class KeyAuthorizationView(object):
    """A point-in-time authorization view of a :py:class:`~pgpy.PGPKey`.

    :param key: the primary key to evaluate (a subkey may be passed, in
                which case its parent primary key is used)
    :param at:  the evaluation time as a timezone-aware
                :py:class:`~datetime.datetime`
    """

    def __init__(self, key, at):
        if not isinstance(key, PGPKey):
            raise TypeError("KeyAuthorizationView expects a PGPKey, not {:s}".format(
                type(key).__name__))

        if not isinstance(at, datetime):
            raise TypeError("the evaluation time must be a datetime")

        if at.tzinfo is None:
            raise ValueError("the evaluation time must be timezone-aware")

        if not key.is_primary:
            if key.parent is None:  # pragma: no cover - defensive
                raise ValueError("cannot evaluate an orphaned subkey")
            key = key.parent

        self._key = key
        self._at = at

    @property
    def key(self):
        """The primary key this view evaluates."""
        return self._key

    @property
    def at(self):
        """The evaluation time of this view."""
        return self._at

    # ------------------------------------------------------------------
    # low-level, purely historical helpers
    # ------------------------------------------------------------------
    def _crypto_check(self, signer, signature, subject):
        """Verify a signature cryptographically, without any present-tense
        boolean such as ``is_expired``.

        Returns ``True`` for a valid signature, ``False`` for one that
        fails verification, and ``None`` when verification could not be
        performed at all (e.g. an unsupported algorithm).
        """
        try:
            verified = signer._key.verify(
                signature.hashdata(subject),
                signature.__sig__,
                getattr(hashes, signature.hash_algorithm.name)())
        except NotImplementedError:
            return None
        except Exception:
            return False

        if verified is NotImplemented:
            return None
        return bool(verified)

    @staticmethod
    def _issued_by(signature, key):
        """Whether ``signature`` claims to have been issued by ``key``."""
        if signature.signer_fingerprint:
            return signature.signer_fingerprint == key.fingerprint
        return signature.signer == key.fingerprint.keyid

    def _admissible(self, signature):
        """Filter purely on the signature's own timing relative to the
        evaluation time.  Cryptographic validity is checked separately."""
        if signature.created > self._at:
            return EvidenceState.future, 'signature created after the evaluation time'

        expires_at = signature.expires_at
        if expires_at is not None and expires_at != signature.created and expires_at <= self._at:
            return EvidenceState.expired, \
                'the signature itself had expired at the evaluation time'

        return EvidenceState.valid, ''

    def _evaluate(self, signatures, signer, subject):
        """Classify every supplied signature, preserving packet order.

        Returns a list of :py:class:`SignatureEvidence` sorted so that
        admissible, cryptographically valid signatures (most recent
        first) come first, followed by all rejected packets.
        """
        valid = []
        rejected = []

        for signature in signatures:
            timing, detail = self._admissible(signature)
            if timing is not EvidenceState.valid:
                rejected.append(SignatureEvidence(signature, timing, detail))
                continue

            crypto = self._crypto_check(signer, signature, subject)
            if crypto is None:
                rejected.append(SignatureEvidence(
                    signature, EvidenceState.unverifiable,
                    'the signature could not be cryptographically verified'))
            elif not crypto:
                rejected.append(SignatureEvidence(
                    signature, EvidenceState.bad_signature,
                    'cryptographic verification failed'))
            else:
                valid.append(SignatureEvidence(
                    signature, EvidenceState.valid,
                    'cryptographically valid and admissible'))

        # signatures are stored sorted by creation time; newest first
        valid.sort(key=lambda ev: ev.signature.created, reverse=True)
        return valid + rejected

    # ------------------------------------------------------------------
    # primary key
    # ------------------------------------------------------------------
    def _evaluate_primary_self_signatures(self):
        """Evaluate every holder self-signature that may govern the primary
        key at the evaluation time: direct-key signatures and holder
        certifications of the primary's own User IDs and User Attributes.

        Each family is verified against its own hash subject: direct-key
        signatures against the primary key and certifications against the
        User ID / Attribute they bind.
        """
        evaluated = []
        primary_id = self._key.fingerprint.keyid

        direct = [signature for signature in self._key._signatures
                  if not signature.embedded
                  and signature.type is SignatureType.DirectlyOnKey
                  and signature.signer == primary_id]
        evaluated.extend(self._evaluate(direct, self._key, self._key))

        cert_types = {
            SignatureType.Generic_Cert,
            SignatureType.Persona_Cert,
            SignatureType.Casual_Cert,
            SignatureType.Positive_Cert,
        }
        for uid in self._key._uids:
            uid_sigs = [signature for signature in uid._signatures
                        if signature.type in cert_types
                        and self._issued_by(signature, self._key)]
            evaluated.extend(self._evaluate(uid_sigs, self._key, uid))

        # _evaluate already sorts each batch newest-first; merge them while
        # keeping every valid signature ahead of every rejected one
        valid = [ev for ev in evaluated if ev.state is EvidenceState.valid]
        rejected = [ev for ev in evaluated if ev.state is not EvidenceState.valid]
        valid.sort(key=lambda ev: ev.signature.created, reverse=True)
        return valid + rejected

    def _primary_revocations(self, evidence):
        """Split key-revocation packets on the primary key into holder
        revocations and externally issued ones.

        Only holder revocations can revoke the key here.  Third-party
        revocations are recorded as requiring an external decision and
        never determine the conclusion.

        Every inspected packet is appended to ``evidence``; the returned
        list contains only admissible, cryptographically valid holder
        revocations, newest first.
        """
        holder = []
        for signature in self._key._signatures:
            if signature.type is not SignatureType.KeyRevocation:
                continue

            if not self._issued_by(signature, self._key):
                evidence.append(SignatureEvidence(
                    signature, EvidenceState.external_revocation,
                    'key revocation issued by a third party; its authority '
                    'must be established externally via a Revocation Key '
                    'designation and is not inferred here'))
                continue

            timing, detail = self._admissible(signature)
            if timing is not EvidenceState.valid:
                evidence.append(SignatureEvidence(signature, timing, detail))
                continue

            crypto = self._crypto_check(self._key, signature, self._key)
            if crypto is None:
                evidence.append(SignatureEvidence(
                    signature, EvidenceState.unverifiable,
                    'the revocation could not be cryptographically verified'))
            elif not crypto:
                evidence.append(SignatureEvidence(
                    signature, EvidenceState.bad_signature,
                    'forged key revocation; cryptographic verification failed, '
                    'so it cannot revoke the key'))
            else:
                holder.append(SignatureEvidence(
                    signature, EvidenceState.valid,
                    'cryptographically valid holder key revocation'))

        holder.sort(key=lambda ev: ev.signature.created, reverse=True)
        evidence[0:0] = holder
        return [ev.signature for ev in holder]

    def primary_decision(self):
        """Evaluate the primary key itself at the view's evaluation time.

        Validity, validity period and usage are derived from the most
        recent admissible, cryptographically valid holder
        self-signature.  Holder key revocations are applied with their
        key-wide scope; third-party revocations are only reported as
        requiring external authorization.

        :rtype: :py:class:`AuthorizationDecision`
        """
        evidence = []

        if self._at < self._key.created:
            evidence.append(SignatureEvidence(
                None, EvidenceState.future,
                'the evaluation time predates creation of the primary key'))
            return AuthorizationDecision(
                self._key, None, self._at, AuthorizationState.not_authorized,
                'the primary key did not yet exist', evidence)

        evaluated = self._evaluate_primary_self_signatures()
        evidence.extend(evaluated)
        effective = evaluated[0].signature if evaluated and \
            evaluated[0].state is EvidenceState.valid else None

        if effective is None:
            has_unverifiable = any(ev.state is EvidenceState.unverifiable
                                   for ev in evaluated)
            if has_unverifiable:
                reason = 'no admissible self-signature could be verified'
            else:
                reason = 'no admissible, valid holder self-signature governs ' \
                         'the primary key at this time'
            return AuthorizationDecision(
                self._key, None, self._at, AuthorizationState.unknown,
                reason, evidence)

        # holder key revocation: key-wide scope, effective at its creation
        # time.  Revocation is evaluated before expiration so that a key
        # which is both expired and revoked reports the revocation as the
        # governing event.
        holder_revocations = self._primary_revocations(evidence)
        effective_revocation = next(
            (sig for sig in holder_revocations if sig.created <= self._at), None)
        if effective_revocation is not None:
            return AuthorizationDecision(
                self._key, None, self._at, AuthorizationState.not_authorized,
                'the primary key was revoked by its holder', evidence)

        # validity period derived from the *effective* self-signature
        key_expiration = effective.key_expiration
        expires_at = None
        if key_expiration is not None and key_expiration.total_seconds() != 0:
            expires_at = self._key.created + key_expiration

        if expires_at is not None and self._at >= expires_at:
            evidence.append(SignatureEvidence(
                effective, EvidenceState.valid,
                'the effective self-signature set a key expiration of '
                '{}'.format(expires_at.isoformat())))
            return AuthorizationDecision(
                self._key, None, self._at, AuthorizationState.not_authorized,
                'the primary key had expired at the evaluation time', evidence)

        return AuthorizationDecision(
            self._key, None, self._at, AuthorizationState.authorized,
            'the primary key was valid and not revoked by its holder', evidence)

    def primary_can_sign(self):
        """Whether the *primary* key itself was authorized to sign at the
        evaluation time, taking both validity and the Sign usage flag
        into account.

        :rtype: :py:class:`AuthorizationDecision`
        """
        decision = self.primary_decision()
        if decision.state is not AuthorizationState.authorized:
            return decision

        effective = decision.effective_signature
        flags = effective.key_flags
        if not flags:
            return AuthorizationDecision(
                self._key, KeyFlags.Sign, self._at, AuthorizationState.unknown,
                'the effective self-signature specifies no Key Flags, so the '
                'Sign capability cannot be established', decision.evidence)

        if KeyFlags.Sign not in flags:
            return AuthorizationDecision(
                self._key, KeyFlags.Sign, self._at,
                AuthorizationState.not_authorized,
                'the effective self-signature does not grant the Sign flag',
                decision.evidence)

        return AuthorizationDecision(
            self._key, KeyFlags.Sign, self._at, AuthorizationState.authorized,
            'the primary key held the Sign flag and was valid',
            decision.evidence)

    # ------------------------------------------------------------------
    # User IDs
    # ------------------------------------------------------------------
    def uid_decision(self, uid):
        """Evaluate whether a User ID was bound to the primary key and not
        revoked at the evaluation time.

        A holder certification revocation (0x30) revokes only the User
        ID certification and therefore only this identity; it never
        revokes the whole key.

        :rtype: :py:class:`AuthorizationDecision`
        """
        evidence = []

        if self._at < self._key.created:
            evidence.append(SignatureEvidence(
                None, EvidenceState.future,
                'the evaluation time predates creation of the primary key'))
            return AuthorizationDecision(
                uid, None, self._at, AuthorizationState.not_authorized,
                'the primary key did not yet exist', evidence)

        cert_types = {
            SignatureType.Generic_Cert,
            SignatureType.Persona_Cert,
            SignatureType.Casual_Cert,
            SignatureType.Positive_Cert,
        }
        certifications = [sig for sig in uid._signatures
                          if sig.type in cert_types and self._issued_by(sig, self._key)]
        evaluated = self._evaluate(certifications, self._key, uid)
        evidence.extend(evaluated)
        effective = evaluated[0].signature if evaluated and \
            evaluated[0].state is EvidenceState.valid else None

        if effective is None:
            return AuthorizationDecision(
                uid, None, self._at, AuthorizationState.unknown,
                'no admissible, valid holder certification binds this User ID '
                'at the evaluation time', evidence)

        # certification revocations have User-ID scope only
        cert_revocations = [sig for sig in uid._signatures
                            if sig.type is SignatureType.CertRevocation]
        for revocation in cert_revocations:
            if not self._issued_by(revocation, self._key):
                evidence.append(SignatureEvidence(
                    revocation, EvidenceState.external_revocation,
                    'certification revocation issued by a third party; its '
                    'authority must be established externally and is not '
                    'inferred here'))
                continue

            timing, detail = self._admissible(revocation)
            if timing is not EvidenceState.valid:
                evidence.append(SignatureEvidence(revocation, timing, detail))
                continue

            crypto = self._crypto_check(self._key, revocation, uid)
            if crypto is None:
                evidence.append(SignatureEvidence(
                    revocation, EvidenceState.unverifiable,
                    'the certification revocation could not be verified'))
            elif not crypto:
                evidence.append(SignatureEvidence(
                    revocation, EvidenceState.bad_signature,
                    'forged certification revocation; cryptographic '
                    'verification failed, so the User ID remains bound'))
            elif revocation.created <= self._at:
                evidence.insert(0, SignatureEvidence(
                    revocation, EvidenceState.valid,
                    'cryptographically valid holder certification revocation '
                    'in effect at the evaluation time'))
                return AuthorizationDecision(
                    uid, None, self._at, AuthorizationState.not_authorized,
                    'this User ID certification was revoked by its holder',
                    evidence)
            else:
                evidence.append(SignatureEvidence(
                    revocation, EvidenceState.future,
                    'the holder certification revocation was created after '
                    'the evaluation time'))

        return AuthorizationDecision(
            uid, None, self._at, AuthorizationState.authorized,
            'the User ID was bound by a valid holder certification and not '
            'revoked', evidence)

    # ------------------------------------------------------------------
    # subkeys
    # ------------------------------------------------------------------
    @staticmethod
    def _embedded_primary_binding(binding):
        for subpacket in binding._signature.subpackets['EmbeddedSignature']:
            embedded = PGPSignature() | subpacket
            # wire the parent exactly as parsing does, otherwise the
            # embedded-signature hash trailer is computed incorrectly
            embedded._parent = binding
            if embedded.type is SignatureType.PrimaryKey_Binding:
                return embedded
        return None

    def subkey_decision(self, subkey):
        """Evaluate a subkey's binding at the evaluation time.

        Binding validity, validity period and usage flags are derived
        from the most recent admissible, cryptographically valid
        subkey binding signature.  Holder subkey revocations are applied
        with subkey-only scope.  Third-party revocations are reported as
        requiring an external decision.

        :rtype: :py:class:`AuthorizationDecision`
        """
        evidence = []

        if subkey not in self._key.subkeys.values():
            raise ValueError('the given subkey is not bound to this primary key')

        if self._at < subkey.created:
            evidence.append(SignatureEvidence(
                None, EvidenceState.future,
                'the evaluation time predates creation of the subkey'))
            return AuthorizationDecision(
                subkey, None, self._at, AuthorizationState.not_authorized,
                'the subkey did not yet exist', evidence)

        bindings = [sig for sig in subkey._signatures
                    if sig.type is SignatureType.Subkey_Binding]
        evaluated = self._evaluate(bindings, self._key, subkey)
        evidence.extend(evaluated)
        effective = evaluated[0].signature if evaluated and \
            evaluated[0].state is EvidenceState.valid else None

        if effective is None:
            if any(ev.state is EvidenceState.unverifiable for ev in evaluated):
                reason = 'no admissible subkey binding could be verified'
                state = AuthorizationState.unknown
            else:
                reason = 'no admissible, valid subkey binding existed at the ' \
                         'evaluation time'
                state = AuthorizationState.not_authorized
            return AuthorizationDecision(
                subkey, None, self._at, state, reason, evidence)

        # holder subkey revocation: subkey-only scope.  Like the primary
        # key, revocation is evaluated ahead of expiration so that it
        # remains the governing event once the subkey has also expired.
        effective_revocation = None
        for revocation in subkey._signatures:
            if revocation.type is not SignatureType.SubkeyRevocation:
                continue

            if not self._issued_by(revocation, self._key):
                evidence.append(SignatureEvidence(
                    revocation, EvidenceState.external_revocation,
                    'subkey revocation issued by a third party; its authority '
                    'must be established externally and is not inferred here'))
                continue

            timing, detail = self._admissible(revocation)
            if timing is not EvidenceState.valid:
                evidence.append(SignatureEvidence(revocation, timing, detail))
                continue

            crypto = self._crypto_check(self._key, revocation, subkey)
            if crypto is None:
                evidence.append(SignatureEvidence(
                    revocation, EvidenceState.unverifiable,
                    'the subkey revocation could not be verified'))
            elif not crypto:
                evidence.append(SignatureEvidence(
                    revocation, EvidenceState.bad_signature,
                    'forged subkey revocation; cryptographic verification '
                    'failed, so the subkey remains bound'))
            elif revocation.created <= self._at and effective_revocation is None:
                effective_revocation = revocation
                evidence.insert(0, SignatureEvidence(
                    revocation, EvidenceState.valid,
                    'cryptographically valid holder subkey revocation in '
                    'effect at the evaluation time'))
            else:
                evidence.append(SignatureEvidence(
                    revocation, EvidenceState.future,
                    'the holder subkey revocation was created after the '
                    'evaluation time'))

        if effective_revocation is not None:
            return AuthorizationDecision(
                subkey, None, self._at, AuthorizationState.not_authorized,
                'the subkey was revoked by the primary key holder', evidence)

        # subkey validity period comes from the effective binding
        key_expiration = effective.key_expiration
        expires_at = None
        if key_expiration is not None and key_expiration.total_seconds() != 0:
            expires_at = subkey.created + key_expiration

        if expires_at is not None and self._at >= expires_at:
            evidence.append(SignatureEvidence(
                effective, EvidenceState.valid,
                'the effective binding set a subkey expiration of '
                '{}'.format(expires_at.isoformat())))
            return AuthorizationDecision(
                subkey, None, self._at, AuthorizationState.not_authorized,
                'the subkey had expired at the evaluation time', evidence)

        return AuthorizationDecision(
            subkey, None, self._at, AuthorizationState.authorized,
            'the subkey was validly bound and not revoked by its holder',
            evidence)

    def subkey_can_sign(self, subkey):
        """Whether a signing subkey was authorized to sign at the
        evaluation time.

        Beyond a valid, unexpired and unrevoked binding, a signing
        subkey must carry the Sign usage flag and, per RFC 4880, a valid
        embedded primary key binding signature (0x19) back-signed by the
        subkey.

        :rtype: :py:class:`AuthorizationDecision`
        """
        decision = self.subkey_decision(subkey)
        if decision.state is not AuthorizationState.authorized:
            return decision

        binding = decision.effective_signature
        flags = binding.key_flags
        if not flags:
            return AuthorizationDecision(
                subkey, KeyFlags.Sign, self._at, AuthorizationState.unknown,
                'the effective binding specifies no Key Flags, so the Sign '
                'capability cannot be established', decision.evidence)

        if KeyFlags.Sign not in flags:
            return AuthorizationDecision(
                subkey, KeyFlags.Sign, self._at,
                AuthorizationState.not_authorized,
                'the effective binding does not grant the subkey the Sign '
                'flag', decision.evidence)

        embedded = self._embedded_primary_binding(binding)
        if embedded is None:
            return AuthorizationDecision(
                subkey, KeyFlags.Sign, self._at,
                AuthorizationState.not_authorized,
                'a signing subkey requires an embedded primary key binding '
                'signature, which is absent', decision.evidence)

        back_sig = self._crypto_check(subkey, embedded, self._key)
        if back_sig is None:
            return AuthorizationDecision(
                subkey, KeyFlags.Sign, self._at, AuthorizationState.unknown,
                'the embedded primary key binding signature could not be '
                'verified', decision.evidence)
        if not back_sig:
            evidence = decision.evidence + [SignatureEvidence(
                embedded, EvidenceState.bad_signature,
                'the embedded primary key binding signature failed '
                'verification')]
            return AuthorizationDecision(
                subkey, KeyFlags.Sign, self._at,
                AuthorizationState.not_authorized,
                'the embedded primary key binding signature is invalid',
                evidence)

        evidence = decision.evidence + [SignatureEvidence(
            embedded, EvidenceState.valid,
            'embedded primary key binding back-signature verified')]
        return AuthorizationDecision(
            subkey, KeyFlags.Sign, self._at, AuthorizationState.authorized,
            'the subkey held the Sign flag, was validly bound and carried a '
            'valid primary key binding back-signature', evidence)

    # ------------------------------------------------------------------
    # aggregate views
    # ------------------------------------------------------------------
    def can_sign(self, subkey=None):
        """Answer the archive question: could a signature be made at the
        evaluation time?

        With ``subkey=None`` the primary key's own Sign capability is
        evaluated.  Pass a subkey (or its key id) to evaluate that
        subkey instead.

        :rtype: :py:class:`AuthorizationDecision`
        """
        if subkey is None:
            return self.primary_can_sign()

        if isinstance(subkey, str):
            keyid = subkey
            if keyid not in self._key.subkeys:
                raise KeyError("no subkey with key id {:s}".format(keyid))
            subkey = self._key.subkeys[keyid]

        return self.subkey_can_sign(subkey)

    def signing_capabilities(self):
        """Return every component that could sign at the evaluation time.

        :returns: a list of ``(component, decision)`` pairs whose state is
                  :py:attr:`AuthorizationState.authorized`
        """
        capabilities = []

        primary = self.primary_can_sign()
        if primary.state is AuthorizationState.authorized:
            capabilities.append((self._key, primary))

        for subkey in self._key.subkeys.values():
            decision = self.subkey_can_sign(subkey)
            if decision.state is AuthorizationState.authorized:
                capabilities.append((subkey, decision))

        return capabilities
