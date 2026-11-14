""" revocation.py

Offline verification of OpenPGP key-revocation signatures.

This module implements the verification path for a revocation that may have
been produced either by the key itself or by a *designated revoker*.  The
caller supplies every candidate revoker public key explicitly; nothing is
fetched online, so the result is fully determined by the local material.

The order of checks matters and follows RFC 4880/4880bis:

1. A revocation is only meaningful when its signature type matches the target
   scope (primary key vs. subkey).
2. A self-revocation must be signed by the target's own primary key.
3. A third-party revocation needs a Revocation Key subpacket that
     - lives in the **hashed** area of a self-signature made by the *target*
       primary key (an unhashed claim, or one made by another key, is not an
       authorization),
     - matches the signing key on both fingerprint and public-key algorithm,
     - carries the required class bit (0x80).
4. Only after the authorization is established is the cryptographic signature
   checked, and it must verify against the target key.  A signature that is
   valid for some other key is :py:attr:`RevocationStatus.WrongTarget`, not a
   revocation of this target.

A plain successful signature verification never implies "revoked"; that
conclusion is only drawn here, once the authorization chain is complete.
"""
from datetime import datetime
from datetime import timezone

from cryptography.hazmat.primitives import hashes

from .constants import RevocationKeyClass
from .constants import RevocationStatus
from .constants import SignatureType
from .errors import PGPError

__all__ = ['RevocationVerification', 'verify_revocation']


class RevocationVerification(object):
    """The result of evaluating one revocation signature against one target.

    Attributes:
        status: A :py:obj:`~pgpy.constants.RevocationStatus` describing the
            outcome.
        target: The :py:obj:`~pgpy.PGPKey` that was being evaluated.
        signature: The revocation :py:obj:`~pgpy.PGPSignature`.
        revoker: The candidate :py:obj:`~pgpy.PGPKey` that produced the
            signature, when it could be identified among the supplied keys.
        authorization: The Revocation Key subpacket that authorized the
            revoker (only set for an authorized third-party revocation).
        at: The fixed verification moment used for time checks.
    """

    __slots__ = ('status', 'target', 'signature', 'revoker', 'authorization', 'at')

    def __init__(self, status, target, signature, revoker=None, authorization=None, at=None):
        self.status = status
        self.target = target
        self.signature = signature
        self.revoker = revoker
        self.authorization = authorization
        self.at = at

    def __bool__(self):
        return self.status.is_revoked

    __nonzero__ = __bool__

    def __repr__(self):
        return '<RevocationVerification({:s})>'.format(self.status.name)

    @property
    def is_revoked(self):
        """``True`` only if the target key is actually revoked."""
        return self.status.is_revoked

    @property
    def missing_authorization(self):
        """``True`` when authorization material is absent or structurally invalid.

        Distinct from a cryptographically bad revocation signature.
        """
        return self.status.missing_authorization


def _candidate_index(candidate_keys):
    """Map full fingerprint and key id to candidate primary keys."""
    by_fpr = {}
    by_keyid = {}
    for key in candidate_keys:
        if key is None:
            continue
        fpr = str(key.fingerprint)
        by_fpr[fpr] = key
        by_keyid.setdefault(key.fingerprint.keyid, key)
    return by_fpr, by_keyid


def _class_authorizes(rk_subpacket):
    """The class octet must have the 0x80 authorization bit set."""
    return bool(sum(rk_subpacket.keyclass) & int(RevocationKeyClass.Normal))


def _valid_at(signature, at):
    """True if ``signature`` is within its own validity window at moment ``at``.

    A signature with no expiration is always valid in time. The check uses the
    fixed verification moment rather than the wall clock so results are
    deterministic.
    """
    expires_at = signature.expires_at
    if expires_at is None or expires_at == signature.created:
        return True
    return expires_at > at


def _matches(rk_subpacket, revoker):
    """Fingerprint and public-key algorithm must both correspond to the revoker."""
    return (
        rk_subpacket.algorithm == revoker.key_algorithm
        and str(rk_subpacket.fingerprint) == str(revoker.fingerprint)
    )


def _cryptographically_verifies(key, target, signature):
    """Verify ``signature`` over ``target`` using ``key``.

    Returns ``True``/``False``. Any primitive that PGPy cannot evaluate raises
    the underlying :py:exc:`NotImplementedError` rather than being swallowed.
    """
    result = key.verify(target, signature)
    return bool(result)


def _raw_verifies_over(revoker, subject, signature):
    """Low-level check of ``signature`` against ``subject`` key material.

    Unlike :py:meth:`PGPKey.verify`, this does not require the verifying key
    to be the signature's issuer; it recomputes the hash over ``subject`` and
    checks it with ``revoker``'s public material. This is used to decide
    whether a signature is merely *about a different key*.
    """
    try:
        digest = signature.hashdata(subject)
        verified = revoker._key.verify(
            digest,
            signature.__sig__,
            getattr(hashes, signature.hash_algorithm.name)(),
        )
    except Exception:
        return False
    if verified is NotImplemented:
        return False
    return bool(verified)


def _select_authorization(target, revoker, authority_keys, at):
    """Find the strongest structural status for ``revoker`` on ``target``.

    ``authority_keys`` is the set of primary keys whose self-signatures are
    allowed to grant revocation authority over ``target``: the target itself
    for a primary key, or the target's parent primary for a subkey.

    Returns a ``(status, subpacket)`` tuple where ``subpacket`` is the
    authorizing Revocation Key subpacket when one fully matches.
    """
    authority_keyids = {k.fingerprint.keyid for k in authority_keys}
    saw_any_rk = False
    saw_unhashed = False
    saw_foreign = False
    saw_mismatch = False
    saw_expired_match = False
    matching = None

    for owner in authority_keys:
        for sig in owner._signatures:
            subpackets = sig._signature.subpackets
            hashed_rks = subpackets.hashed('RevocationKey')
            unhashed_rks = subpackets.unhashed('RevocationKey')

            if unhashed_rks:
                saw_any_rk = True
                saw_unhashed = True

            if not hashed_rks:
                continue

            saw_any_rk = True
            if sig.signer not in authority_keyids:
                # A Revocation Key on another key's self-signature cannot
                # authorize the revocation of this target.
                saw_foreign = True
                continue

            for rk in hashed_rks:
                if not _class_authorizes(rk):
                    saw_mismatch = True
                    continue
                if not _matches(rk, revoker):
                    saw_mismatch = True
                    continue
                # the subpacket matches; it only counts if still valid at `at`
                if _valid_at(sig, at):
                    matching = rk
                else:
                    saw_expired_match = True

    if matching is not None:
        return RevocationStatus.AuthorizedRevoked, matching
    if saw_expired_match and not saw_mismatch and not saw_foreign:
        return RevocationStatus.AuthorizationExpired, None
    if not saw_any_rk:
        return RevocationStatus.NoAuthorization, None
    if saw_mismatch:
        return RevocationStatus.RevokerNotAuthorized, None
    if saw_foreign:
        return RevocationStatus.AuthorizationFromOtherKey, None
    if saw_unhashed:
        return RevocationStatus.AuthorizationNotHashed, None
    if saw_expired_match:
        return RevocationStatus.AuthorizationExpired, None
    # Defensive fall-through: material existed but none was usable.
    return RevocationStatus.RevokerNotAuthorized, None


def verify_revocation(target, signature, candidate_keys, at=None):
    """Verify a key-revocation signature against ``target``, fully offline.

    :param target: The primary key or subkey the revocation is claimed against.
    :type target: :py:obj:`~pgpy.PGPKey`
    :param signature: The candidate revocation signature.
    :type signature: :py:obj:`~pgpy.PGPSignature`
    :param candidate_keys: Revoker public keys supplied explicitly by the
        caller. The target's own public key is considered automatically.
    :type candidate_keys: iterable of :py:obj:`~pgpy.PGPKey`
    :param at: Fixed verification moment used for expiry/validity decisions.
        Defaults to the current UTC time.
    :type at: :py:obj:`~datetime.datetime`
    :returns: :py:obj:`RevocationVerification`
    :raises: :py:exc:`~pgpy.errors.PGPError` if the signature type does not
        match the target's scope. A signer absent from ``candidate_keys`` is
        not raised; it yields :py:attr:`RevocationStatus.UnknownSigner`.
    """
    if at is None:
        at = datetime.now(timezone.utc)

    expected_type = SignatureType.KeyRevocation if target.is_primary else SignatureType.SubkeyRevocation
    if signature.type != expected_type:
        raise PGPError(
            "Signature type {:s} cannot revoke a {:s}; expected {:s}".format(
                signature.type.name,
                'primary key' if target.is_primary else 'subkey',
                expected_type.name,
            )
        )

    candidates = list(candidate_keys)

    # The primary key that owns the target: the target itself for a primary
    # key, or its parent primary for a subkey. A detached subkey whose weak
    # parent link was not retained can be re-attached from the supplied keys.
    owning_primary = target if target.is_primary else target.parent
    if owning_primary is None and not target.is_primary:
        sub_keyid = target.fingerprint.keyid
        owning_primary = next(
            (cand for cand in candidates
             if cand.is_primary and sub_keyid in cand.subkeys),
            None,
        )
    if owning_primary is None:
        raise PGPError("A subkey revocation requires its bound parent primary key")
    # Only this primary's self-signatures can grant revocation authority.
    authority_keys = [owning_primary]

    # the target and its owning primary are always possible (self) revokers
    for implicit in (target, owning_primary):
        if implicit is not None and not any(cnd.fingerprint == implicit.fingerprint for cnd in candidates):
            candidates.append(implicit.pubkey)

    by_fpr, by_keyid = _candidate_index(candidates)

    # Prefer the full fingerprint (IssuerFingerprint); fall back to the Issuer key id.
    signer_fpr = signature.signer_fingerprint
    revoker = by_fpr.get(str(signer_fpr)) if signer_fpr else None
    if revoker is None:
        revoker = by_keyid.get(signature.signer)

    if revoker is None:
        # Nothing local corresponds to the signer: the path cannot be completed
        # offline and this is distinguishable from a bad signature.
        return RevocationVerification(RevocationStatus.UnknownSigner, target, signature, at=at)

    # A subkey's hash data is computed through its parent primary. If the
    # supplied subkey lost its parent link, temporarily bind the resolved
    # owning primary for the duration of the cryptographic checks.
    rebound_parent = (not target.is_primary and target.parent is None and owning_primary is not None)
    if rebound_parent:
        target._parent = owning_primary

    try:
        # ---- 1. self-revocation path ---------------------------------------
        # A primary key revokes itself; a subkey is revoked by its parent primary.
        self_revoking = (
            target.is_primary and revoker.fingerprint == target.fingerprint
        ) or (
            not target.is_primary and revoker.fingerprint == owning_primary.fingerprint
        )
        if self_revoking:
            if _cryptographically_verifies(revoker, target, signature):
                return RevocationVerification(RevocationStatus.SelfRevoked, target, signature,
                                              revoker=revoker, at=at)
            # A self-issued signature that does not verify is simply invalid.
            return RevocationVerification(RevocationStatus.BadSignature, target, signature,
                                          revoker=revoker, at=at)

        # ---- 2. designated-revoker path: authorization first ---------------
        status, authorization = _select_authorization(target, revoker, authority_keys, at)
        if status != RevocationStatus.AuthorizedRevoked:
            return RevocationVerification(status, target, signature, revoker=revoker, at=at)

        # A revocation signature that is itself outside its validity window at the
        # verification moment cannot be acted upon.
        if not _valid_at(signature, at):
            return RevocationVerification(RevocationStatus.BadSignature, target, signature,
                                          revoker=revoker, authorization=authorization, at=at)

        # ---- 3. then the cryptographic signature over this target ----------
        if _cryptographically_verifies(revoker, target, signature):
            return RevocationVerification(RevocationStatus.AuthorizedRevoked, target, signature,
                                          revoker=revoker, authorization=authorization, at=at)

        # The revoker is authorized, but the signature does not verify on target.
        # If it cryptographically verifies over some other supplied key, then the
        # signature is simply about a different key (WrongTarget); otherwise it is
        # an invalid signature.
        for other in candidates:
            if other.fingerprint == target.fingerprint:
                continue
            if _raw_verifies_over(revoker, other, signature):
                return RevocationVerification(RevocationStatus.WrongTarget, target, signature,
                                              revoker=revoker, authorization=authorization, at=at)
            for subkey in other.subkeys.values():
                if _raw_verifies_over(revoker, subkey, signature):
                    return RevocationVerification(RevocationStatus.WrongTarget, target, signature,
                                                  revoker=revoker, authorization=authorization, at=at)

        return RevocationVerification(RevocationStatus.BadSignature, target, signature,
                                      revoker=revoker, authorization=authorization, at=at)
    finally:
        if rebound_parent:
            target._parent = None

