"""batch.py

Multi-recipient OpenPGP encryption with capability negotiation performed
strictly before any ciphertext is produced.

The recipient set is resolved to one usable encryption key per distinct
primary key.  Each recipient's algorithm preferences are read only from
hashed, cryptographically verified self-signatures (and, when present,
verified subkey binding signatures), then intersected.  Only after every
recipient is known to accept the selected symmetric cipher and compression
algorithm is the content encrypted and wrapped for each recipient.
"""
import binascii
import copy
import dataclasses
import warnings

from datetime import datetime
from datetime import timezone

from .constants import CompressionAlgorithm
from .constants import KeyFlags
from .constants import PubKeyAlgorithm
from .constants import SignatureType
from .constants import SymmetricKeyAlgorithm
from .errors import BatchEncryptionError
from .errors import DuplicateRecipientError
from .errors import MessageAlreadyEncryptedError
from .errors import NoCommonAlgorithmError
from .errors import PGPEncryptionError
from .errors import RecipientUnavailableError
from .packet.packets import IntegrityProtectedSKEDataV1
from .packet.packets import PKESessionKeyV3

__all__ = ['BatchEncryptionError',
           'EncryptionPolicy',
           'Recipient',
           'RecipientPlan',
           'BatchEncryptionReport',
           'encrypt_message_to_recipients']


# Ciphers PGPy can actually encrypt with.  Twofish is unsupported by the
# cryptography backend and IDEA is rejected as insecure by pgpy.symenc.
_ENCRYPTION_CIPHERS = frozenset((
    SymmetricKeyAlgorithm.TripleDES,
    SymmetricKeyAlgorithm.CAST5,
    SymmetricKeyAlgorithm.Blowfish,
    SymmetricKeyAlgorithm.AES128,
    SymmetricKeyAlgorithm.AES192,
    SymmetricKeyAlgorithm.AES256,
    SymmetricKeyAlgorithm.Camellia128,
    SymmetricKeyAlgorithm.Camellia192,
    SymmetricKeyAlgorithm.Camellia256,
))

# Ordering used to pick the strongest common cipher and to enforce
# ``EncryptionPolicy.minimum_cipher``.  RFC 6637 recommends choosing the
# stronger algorithm out of an unordered intersection.  Effective security
# strength, not declared key size, keeps the ordering honest: TripleDES has a
# 192-bit key but only ~112 bits of security, so it must not pass an AES-192
# floor.  Ties prefer AES, then the lower algorithm id for determinism.
_AES_CIPHERS = frozenset((SymmetricKeyAlgorithm.AES128,
                          SymmetricKeyAlgorithm.AES192,
                          SymmetricKeyAlgorithm.AES256))

_EFFECTIVE_STRENGTH_BITS = {
    SymmetricKeyAlgorithm.TripleDES: 112,
    SymmetricKeyAlgorithm.CAST5: 128,
    SymmetricKeyAlgorithm.Blowfish: 128,
    SymmetricKeyAlgorithm.AES128: 128,
    SymmetricKeyAlgorithm.Camellia128: 128,
    SymmetricKeyAlgorithm.AES192: 192,
    SymmetricKeyAlgorithm.Camellia192: 192,
    SymmetricKeyAlgorithm.AES256: 256,
    SymmetricKeyAlgorithm.Camellia256: 256,
}


def _cipher_strength(algorithm):
    return (_EFFECTIVE_STRENGTH_BITS[algorithm], algorithm in _AES_CIPHERS, -algorithm.value)


# RFC 4880 13.3.1: without a preference list, assume ZIP and Uncompressed.
_DEFAULT_COMPRESSION = (CompressionAlgorithm.ZIP, CompressionAlgorithm.Uncompressed)

# There is no cryptographic strength ordering for compression.  This order
# keeps PGPy's historical ZIP default when every recipient accepts it, then
# prefers the other supported formats deterministically.
_COMPRESSION_ORDER = (CompressionAlgorithm.ZIP,
                      CompressionAlgorithm.ZLIB,
                      CompressionAlgorithm.BZ2,
                      CompressionAlgorithm.Uncompressed)

# No authenticated symmetric preference subpacket means no explicit
# restriction.  Use a conservative implementation profile rather than
# guessing at legacy algorithms; TripleDES is included because RFC 4880
# makes it the MUST-implement algorithm.
_DEFAULT_CIPHERS = (SymmetricKeyAlgorithm.AES256,
                    SymmetricKeyAlgorithm.AES192,
                    SymmetricKeyAlgorithm.AES128,
                    SymmetricKeyAlgorithm.TripleDES)

_ENCRYPTION_ALGORITHMS = frozenset((PubKeyAlgorithm.RSAEncryptOrSign,
                                    PubKeyAlgorithm.ECDH))

_ENCRYPTION_USAGE = frozenset((KeyFlags.EncryptCommunications,
                               KeyFlags.EncryptStorage))

_CERTIFICATION_TYPES = frozenset((SignatureType.Generic_Cert,
                                  SignatureType.Persona_Cert,
                                  SignatureType.Casual_Cert,
                                  SignatureType.Positive_Cert))


def _enum(value, enum_type):
    """Accept either an enum member/int value or its documented name."""
    if isinstance(value, str):
        try:
            return enum_type[value]
        except KeyError:
            raise ValueError("{!r} is not a valid {:s} name".format(value, enum_type.__name__))
    return enum_type(value)


def _pairs(values, enum_type):
    if values is None:
        return None

    if isinstance(values, (enum_type, int, str)):
        values = (values,)

    return frozenset(_enum(v, enum_type) for v in values)


@dataclasses.dataclass(frozen=True)
class EncryptionPolicy:
    """Explicit limits that recipient preferences are never allowed to lower.

    ``minimum_cipher`` is an effective-strength floor: only ciphers at least as
    strong as this algorithm remain eligible, so an old preference list cannot
    downgrade the batch below it.  ``allowed_ciphers`` and
    ``allowed_compression`` are hard allow-lists.  ``minimum_key_bits`` rejects
    weaker RSA encryption keys; it fails closed for elliptic-curve keys, whose
    bit size is not comparable.  All limits are applied *after* taking the
    recipients' authenticated preference intersection, so preferences can only
    narrow the result, never widen it.
    """

    minimum_cipher: SymmetricKeyAlgorithm = None
    allowed_ciphers: frozenset = None
    allowed_compression: frozenset = None
    minimum_key_bits: int = None

    def __post_init__(self):
        if self.minimum_cipher is not None:
            object.__setattr__(self, 'minimum_cipher', _enum(self.minimum_cipher, SymmetricKeyAlgorithm))

        object.__setattr__(self, 'allowed_ciphers', _pairs(self.allowed_ciphers, SymmetricKeyAlgorithm))
        object.__setattr__(self, 'allowed_compression', _pairs(self.allowed_compression, CompressionAlgorithm))

        unsupported = {c for c in (self.allowed_ciphers or ()) if c not in _ENCRYPTION_CIPHERS}
        if self.minimum_cipher is not None and self.minimum_cipher not in _ENCRYPTION_CIPHERS:
            unsupported.add(self.minimum_cipher)
        if unsupported:
            raise ValueError("Policy names ciphers PGPy cannot encrypt with: {}".format(_names(unsupported)))

        if self.minimum_key_bits is not None and self.minimum_key_bits < 0:
            raise ValueError("minimum_key_bits cannot be negative")

    def describe(self):
        """Return a human-readable description of all explicitly configured limits."""
        parts = []
        if self.minimum_cipher is not None:
            parts.append("minimum cipher floor {:s} (preferences cannot lower it)".format(self.minimum_cipher.name))
        if self.allowed_ciphers is not None:
            parts.append("allowed ciphers [{}]".format(_names(self.allowed_ciphers)))
        if self.allowed_compression is not None:
            parts.append("allowed compression [{}]".format(_names(self.allowed_compression)))
        if self.minimum_key_bits is not None:
            parts.append("minimum encryption key size {:d} bits".format(self.minimum_key_bits))
        return "; ".join(parts) if parts else "no explicit limits beyond supported, non-insecure algorithms"


@dataclasses.dataclass(frozen=True)
class Recipient:
    """A recipient and the User ID whose authenticated preferences should apply."""
    key: object
    user: str = None


@dataclasses.dataclass(frozen=True)
class RecipientPlan:
    """The validated, authenticated capability set for one recipient."""
    primary_fingerprint: str
    encryption_key_fingerprint: str
    encryption_key_id: str
    key_algorithm: str
    user: str
    cipher_preferences: tuple
    compression_preferences: tuple
    permitted_ciphers: frozenset
    permitted_compression: frozenset
    notes: tuple


@dataclasses.dataclass(frozen=True)
class BatchEncryptionReport:
    """Explain which algorithms were chosen and why every recipient accepts them."""
    cipher: SymmetricKeyAlgorithm
    compression: CompressionAlgorithm
    cipher_candidates: frozenset
    compression_candidates: frozenset
    recipients: tuple
    policy: EncryptionPolicy
    duplicates_removed: tuple
    cipher_explicit: bool = False
    compression_explicit: bool = False

    def explain(self):
        """Return a multi-line explanation suitable for logs or an operator."""
        lines = [
            "Batch OpenPGP encryption plan",
            "  selected symmetric cipher: {:s}".format(self.cipher.name),
            "  selected compression: {:s}".format(self.compression.name),
            "  policy: {:s}".format(self.policy.describe()),
            "  common cipher candidates after all recipient preferences and policy: [{}]".format(
                _names(self.cipher_candidates)),
            "  common compression candidates after all recipient preferences and policy: [{}]".format(
                _names(self.compression_candidates)),
            ("  cipher selection: explicitly requested {:s}, and every recipient accepts it".format(self.cipher.name)
             if self.cipher_explicit else
             "  cipher selection: {:s} is the strongest cipher in the common candidate set".format(self.cipher.name)),
            ("  compression selection: explicitly requested {:s}, and every recipient accepts it".format(
                self.compression.name)
             if self.compression_explicit else
             "  compression selection: {:s} is PGPy's deterministic first choice in the common candidate set".format(
                 self.compression.name)),
            "  recipients:",
        ]

        for plan in self.recipients:
            lines.extend([
                "  - primary 0x{:s}, encryption key 0x{:s} ({:s}), UID {!r}".format(
                    plan.primary_fingerprint[-16:], plan.encryption_key_id, plan.key_algorithm, plan.user),
                "      authenticated cipher preferences: [{}]".format(_names(plan.cipher_preferences)),
                "      permitted ciphers after support and policy: [{}]".format(_names(plan.permitted_ciphers)),
                "      authenticated compression preferences: [{}]".format(_names(plan.compression_preferences)),
                "      permitted compression after support and policy: [{}]".format(
                    _names(plan.permitted_compression)),
                "      accepts selected cipher {:s}: {:s}; accepts selected compression {:s}: {:s}".format(
                    self.cipher.name, _yes_no(self.cipher in plan.permitted_ciphers),
                    self.compression.name, _yes_no(self.compression in plan.permitted_compression)),
            ])
            for note in plan.notes:
                lines.append("      note: {:s}".format(note))

        if self.duplicates_removed:
            lines.append("  duplicate recipient requests collapsed without adding a second session key packet: [{}]".format(
                ", ".join(self.duplicates_removed)))

        lines.append("  conclusion: {:s} and {:s} are in every recipient's authenticated, policy-filtered "
                     "preference set, so the single content ciphertext (and therefore the same session key) "
                     "is decryptable by all {:d} recipients.".format(
                         self.cipher.name, self.compression.name, len(self.recipients)))
        return "\n".join(lines)

    def as_dict(self):
        """Return the same information in a machine-readable form."""
        return {
            'cipher': self.cipher.name,
            'compression': self.compression.name,
            'cipher_candidates': sorted(c.name for c in self.cipher_candidates),
            'compression_candidates': sorted(c.name for c in self.compression_candidates),
            'policy': {
                'minimum_cipher': (self.policy.minimum_cipher.name
                                   if self.policy.minimum_cipher is not None else None),
                'allowed_ciphers': (sorted(c.name for c in self.policy.allowed_ciphers)
                                    if self.policy.allowed_ciphers is not None else None),
                'allowed_compression': (sorted(c.name for c in self.policy.allowed_compression)
                                        if self.policy.allowed_compression is not None else None),
                'minimum_key_bits': self.policy.minimum_key_bits,
            },
            'duplicates_removed': list(self.duplicates_removed),
            'cipher_explicit': self.cipher_explicit,
            'compression_explicit': self.compression_explicit,
            'recipients': [
                {
                    'primary_fingerprint': p.primary_fingerprint,
                    'encryption_key_fingerprint': p.encryption_key_fingerprint,
                    'encryption_key_id': p.encryption_key_id,
                    'key_algorithm': p.key_algorithm,
                    'user': p.user,
                    'cipher_preferences': [c.name for c in p.cipher_preferences],
                    'compression_preferences': [c.name for c in p.compression_preferences],
                    'permitted_ciphers': sorted(c.name for c in p.permitted_ciphers),
                    'permitted_compression': sorted(c.name for c in p.permitted_compression),
                    'accepts_cipher': self.cipher.name in {c.name for c in p.permitted_ciphers},
                    'accepts_compression': self.compression.name in {c.name for c in p.permitted_compression},
                    'notes': list(p.notes),
                }
                for p in self.recipients
            ],
        }


@dataclasses.dataclass
class _ResolvedRecipient:
    plan: RecipientPlan
    key: object


def _names(algorithms):
    return ", ".join(a.name for a in sorted(algorithms, key=lambda a: a.value))


def _yes_no(value):
    return 'yes' if value else 'no'


def _now():
    return datetime.now(timezone.utc)


def _hashed_flags(signature, subpacket_name):
    """Read a preference list only if it was in the signed (hashed) area."""
    try:
        subpackets = signature._signature.subpackets['h_' + subpacket_name]
    except Exception:
        return None
    if not subpackets:
        return None
    return tuple(subpackets[0].flags)


def _cipher_preferences(signature):
    # An explicit authenticated list is treated as exhaustive: the keyholder
    # enumerated exactly what they accept.  Silently appending the RFC 4880
    # MUST-implement TripleDES would make a genuinely disjoint preference set
    # look like it had a common cipher, which is precisely what this entry
    # point must not do.  Only when no list exists do we fall back to defaults.
    return _hashed_flags(signature, 'PreferredSymmetricAlgorithms')


def _compression_preferences(signature):
    return _hashed_flags(signature, 'PreferredCompressionAlgorithms')


def _verify(verifier, subject, signature):
    with warnings.catch_warnings():
        warnings.simplefilter('ignore')
        try:
            return bool(verifier.verify(subject, signature))
        except Exception:
            return False


def _signatures_of(key):
    """Yield signatures defensively; malformed packet data must not crash a batch."""
    try:
        signatures = list(key._signatures)
    except Exception:
        return

    for signature in signatures:
        yield signature


def _signature_is_current(signature):
    return signature.created <= _now()


def _is_self_issued(primary, signature):
    return (signature.signer == primary.fingerprint.keyid
            or signature.signer_fingerprint == primary.fingerprint)


def _latest_uid_signature(primary, uid):
    candidates = []
    for signature in _signatures_of(uid):
        if signature.type not in _CERTIFICATION_TYPES:
            continue
        if not _is_self_issued(primary, signature):
            continue
        if signature.is_expired or not _signature_is_current(signature):
            continue
        if not _verify(primary, uid, signature):
            continue
        candidates.append(signature)

    if not candidates:
        return None
    return max(candidates, key=lambda s: (s.created, s.hash_algorithm.value))


def _uid_revoked(primary, uid):
    for signature in _signatures_of(uid):
        if signature.type != SignatureType.CertRevocation:
            continue
        if not _is_self_issued(primary, signature):
            continue
        if signature.is_expired or not _signature_is_current(signature):
            continue
        if _verify(primary, uid, signature):
            return True
    return False


def _key_revoked(primary):
    for signature in _signatures_of(primary):
        if signature.type != SignatureType.KeyRevocation:
            continue
        if not _is_self_issued(primary, signature):
            continue
        if signature.is_expired or not _signature_is_current(signature):
            continue
        if _verify(primary, primary, signature):
            return True
    return False


def _subkey_revoked(primary, subkey):
    for signature in _signatures_of(subkey):
        if signature.type != SignatureType.SubkeyRevocation:
            continue
        if not _is_self_issued(primary, signature):
            continue
        if signature.is_expired or not _signature_is_current(signature):
            continue
        if _verify(primary, subkey, signature):
            return True
    return False


def _latest_binding_signature(primary, subkey):
    candidates = []
    for signature in _signatures_of(subkey):
        if signature.type != SignatureType.Subkey_Binding:
            continue
        if not _is_self_issued(primary, signature):
            continue
        if signature.is_expired or not _signature_is_current(signature):
            continue
        if not _verify(primary, subkey, signature):
            continue
        candidates.append(signature)

    if not candidates:
        return None
    return max(candidates, key=lambda s: s.created)


def _expiry(created, signature):
    if signature is None:
        return None
    expires = signature.key_expiration
    if expires is None:
        return None
    return created + expires


def _key_bits(key):
    """Return the integer key size, or ``None`` for elliptic-curve keys."""
    size = key.key_size
    return size if isinstance(size, int) else None


def _unavailable(recipient, reason):
    keyid = 'unknown'
    try:
        keyid = recipient.key.fingerprint.keyid
    except Exception:
        pass
    return RecipientUnavailableError("Recipient 0x{:s} has no usable encryption key: {:s}".format(keyid, reason))


def _resolve_recipient(recipient, policy):
    if not hasattr(recipient.key, 'is_primary') or not hasattr(recipient.key, 'fingerprint'):
        raise TypeError("Recipient key must be a PGPKey")

    key = recipient.key
    primary = key if key.is_primary else key.parent
    if primary is None:
        raise _unavailable(recipient, "subkey is not bound to a primary key")

    if primary.is_expired:
        raise _unavailable(recipient, "primary key is expired")
    if _key_revoked(primary):
        raise _unavailable(recipient, "primary key is revoked")

    # Select an authenticated primary User ID.  Preferences from other UIDs are
    # deliberately not unioned in: accepting a cipher some selected identity
    # never advertised would be ambiguous.
    matching = []
    for uid in primary.userids:
        if recipient.user is not None:
            haystack = (uid.name, uid.email, uid.comment, uid.userid, format(uid))
            if recipient.user not in haystack:
                continue
        signature = _latest_uid_signature(primary, uid)
        if signature is None:
            continue
        if _uid_revoked(primary, uid):
            continue
        matching.append((uid, signature))

    if not matching:
        if recipient.user is not None:
            raise _unavailable(recipient, "no authenticated, unrevoked User ID matches {!r}".format(recipient.user))
        raise _unavailable(recipient, "no authenticated, unrevoked User ID with a valid self-signature")

    primary_uids = [pair for pair in matching if pair[0].is_primary]
    if len(primary_uids) == 1:
        uid, uid_signature = primary_uids[0]
    else:
        uid, uid_signature = max(matching, key=lambda pair: pair[1].created)

    primary_expiry = _expiry(primary.created, uid_signature)
    if primary_expiry is not None and primary_expiry <= _now():
        raise _unavailable(recipient, "selected User ID self-signature marks the primary key expired")

    if not primary.is_public:
        primary = primary.pubkey

    # If the caller explicitly named a subkey, use only that key.  Otherwise
    # choose the newest usable encryption subkey, falling back to a primary key
    # that itself carries encryption usage flags.
    if key.is_primary:
        uid_flags = set(uid_signature.key_flags) if uid_signature is not None else set()
        candidates = list(primary.subkeys.values())
        if uid_flags & _ENCRYPTION_USAGE:
            candidates.append(primary)
    else:
        candidates = [key]

    usable = []
    rejected = []
    for candidate in candidates:
        candidate = candidate.pubkey if not candidate.is_public else candidate
        label = "0x{:s}".format(candidate.fingerprint.keyid)

        if candidate.key_algorithm not in _ENCRYPTION_ALGORITHMS:
            rejected.append("{:s}: unsupported encryption algorithm {:s}".format(
                label, candidate.key_algorithm.name))
            continue

        binding = None
        if candidate.is_primary:
            flags = set(getattr(uid_signature, 'key_flags', ())) | {KeyFlags.Certify}
        else:
            binding = _latest_binding_signature(primary, candidate)
            if binding is None:
                rejected.append("{:s}: no valid subkey binding signature".format(label))
                continue
            flags = set(binding.key_flags)

        if not (flags & _ENCRYPTION_USAGE):
            rejected.append("{:s}: no encryption usage flag".format(label))
            continue

        if not candidate.is_primary and _subkey_revoked(primary, candidate):
            rejected.append("{:s}: revoked".format(label))
            continue

        expiry = primary_expiry
        candidate_expiry = _expiry(candidate.created, binding) if binding is not None else None
        if candidate_expiry is not None and (expiry is None or candidate_expiry < expiry):
            expiry = candidate_expiry
        if expiry is not None and expiry <= _now():
            rejected.append("{:s}: expired".format(label))
            continue

        if policy.minimum_key_bits is not None:
            bits = _key_bits(candidate)
            if bits is None:
                rejected.append("{:s}: elliptic-curve key; minimum_key_bits cannot be evaluated, so "
                                "the policy fails closed".format(label))
                continue
            if bits < policy.minimum_key_bits:
                rejected.append("{:s}: key is {:d} bits, below policy floor {:d}".format(
                    label, bits, policy.minimum_key_bits))
                continue

        usable.append((candidate, binding))

    if not usable:
        detail = "; ".join(rejected) if rejected else "no encryption-capable key"
        raise _unavailable(recipient, detail)

    # Subkeys before primary, newest first, then key id for determinism.
    usable.sort(key=lambda item: (item[0].is_primary, -item[0].created.timestamp(), item[0].fingerprint.keyid))
    encryption_key, binding = usable[0]

    notes = []
    notes.append("encryption key selected from {:d} usable candidate(s)".format(len(usable)))
    if len(primary_uids) > 1:
        notes.append("multiple primary User IDs; selected the newest authenticated self-signature")
    if encryption_key.is_primary:
        notes.append("primary key itself carries encryption usage")
    if rejected:
        notes.append("other candidate keys rejected: " + "; ".join(rejected))
    if recipient.user is not None:
        notes.append("User ID selected explicitly by caller")
    if binding is not None and (_cipher_preferences(binding) is not None
                                or _compression_preferences(binding) is not None):
        notes.append("subkey binding signature also narrowed the preference intersection")

    # Collect authenticated preference lists from the UID self-signature and,
    # when it carries any, the subkey binding signature.  Unhashed subpackets
    # are ignored entirely because they are not covered by the signature.
    cipher_sources = [s for s in (_cipher_preferences(uid_signature),
                                  _cipher_preferences(binding) if binding is not None else None)
                      if s is not None]
    compression_sources = [s for s in (_compression_preferences(uid_signature),
                                       _compression_preferences(binding) if binding is not None else None)
                           if s is not None]

    if cipher_sources:
        authenticated_ciphers = set.intersection(*[set(s) for s in cipher_sources])
    else:
        authenticated_ciphers = set(_DEFAULT_CIPHERS)
        notes.append("no authenticated symmetric preference list; default profile applied")

    if compression_sources:
        authenticated_compression = set.intersection(*[set(s) for s in compression_sources])
    else:
        authenticated_compression = set(_DEFAULT_COMPRESSION)
        notes.append("no authenticated compression preference list; RFC 4880 default [ZIP, Uncompressed] applied")

    permitted_ciphers = {c for c in authenticated_ciphers if c in _ENCRYPTION_CIPHERS}
    unsupported = authenticated_ciphers - permitted_ciphers
    if unsupported:
        notes.append("unsupported or insecure cipher preferences ignored: [{}]".format(_names(unsupported)))

    if policy.allowed_ciphers is not None:
        denied = permitted_ciphers - set(policy.allowed_ciphers)
        permitted_ciphers &= set(policy.allowed_ciphers)
        if denied:
            notes.append("policy allowed_ciphers removed: [{}]".format(_names(denied)))

    if policy.minimum_cipher is not None:
        floor = _EFFECTIVE_STRENGTH_BITS[policy.minimum_cipher]
        denied = {c for c in permitted_ciphers if _EFFECTIVE_STRENGTH_BITS[c] < floor}
        permitted_ciphers -= denied
        if denied:
            notes.append("policy minimum cipher {:s} removed: [{}]".format(
                policy.minimum_cipher.name, _names(denied)))

    permitted_compression = set(authenticated_compression)
    if policy.allowed_compression is not None:
        denied = permitted_compression - set(policy.allowed_compression)
        permitted_compression &= set(policy.allowed_compression)
        if denied:
            notes.append("policy allowed_compression removed: [{}]".format(_names(denied)))

    plan = RecipientPlan(
        primary_fingerprint=str(primary.fingerprint),
        encryption_key_fingerprint=str(encryption_key.fingerprint),
        encryption_key_id=encryption_key.fingerprint.keyid,
        key_algorithm=encryption_key.key_algorithm.name,
        user=uid.userid,
        cipher_preferences=tuple(sorted(authenticated_ciphers, key=lambda a: a.value)),
        compression_preferences=tuple(sorted(authenticated_compression, key=lambda a: a.value)),
        permitted_ciphers=frozenset(permitted_ciphers),
        permitted_compression=frozenset(permitted_compression),
        notes=tuple(notes),
    )
    return _ResolvedRecipient(plan=plan, key=encryption_key)


def _normalize_recipients(recipients, default_user):
    from .pgp import PGPKey

    # Strings, bytes, dicts, and other iterables are common mistakes here and
    # would otherwise be silently iterated as a set of bogus recipients.
    if isinstance(recipients, (str, bytes, bytearray)):
        raise TypeError("recipients must be a collection of PGPKey objects, not a string")

    if isinstance(recipients, (PGPKey, Recipient)):
        recipients = [recipients]

    normalized = []
    for item in recipients:
        if isinstance(item, Recipient):
            normalized.append(item if item.user is not None else Recipient(item.key, default_user))

        elif isinstance(item, PGPKey):
            normalized.append(Recipient(item, default_user))

        elif isinstance(item, (tuple, list)) and len(item) == 2 and isinstance(item[1], (str, type(None))):
            normalized.append(Recipient(item[0], item[1] if item[1] is not None else default_user))

        else:
            raise TypeError("Each recipient must be a PGPKey, a Recipient, or a (PGPKey, user) pair")

    if not normalized:
        raise ValueError("At least one recipient is required")

    return normalized


def _deduplicate(resolved):
    """Collapse repeated requests for the same recipient.

    Repeats are harmless only when they resolve to the exact same primary key,
    encryption subkey, and User ID.  Anything else (for example the same
    primary key with two different UIDs, or two different encryption subkeys)
    is genuinely ambiguous and is rejected rather than silently resolved.
    """
    unique = []
    duplicates = []
    seen = {}

    for item in resolved:
        plan = item.plan
        identity = (plan.encryption_key_fingerprint, plan.user)
        prior_identities = seen.setdefault(plan.primary_fingerprint, set())

        if identity not in prior_identities:
            prior_identities.add(identity)
            unique.append(item)
            continue

        duplicates.append("0x{:s}".format(plan.encryption_key_id))

    for primary_fingerprint, identities in seen.items():
        if len(identities) > 1:
            raise DuplicateRecipientError(
                "Recipient primary key 0x{:s} was supplied more than once with different User ID or "
                "encryption subkey selections; this is ambiguous".format(primary_fingerprint[-16:]))

    return unique, duplicates


def _coerce_policy(policy):
    if policy is None:
        return EncryptionPolicy()
    if isinstance(policy, EncryptionPolicy):
        return policy
    if isinstance(policy, dict):
        return EncryptionPolicy(**policy)
    raise TypeError("policy must be an EncryptionPolicy, a dict, or None")


def encrypt_message_to_recipients(message, recipients, policy=None, user=None,
                                  cipher=None, compression=None,
                                  minimum_cipher=None, allowed_ciphers=None,
                                  allowed_compression=None, minimum_key_bits=None):
    """Encrypt a plaintext message to every recipient with one negotiated algorithm.

    All recipient validation, key selection, preference authentication, and
    algorithm negotiation happen before the session key is generated.  Each
    recipient's session key packet is also built before the content is
    encrypted, and the input message is never modified.  Any failure therefore
    produces no new ciphertext at all rather than a message encrypted for only
    part of the recipient set.
    """
    from .pgp import PGPMessage

    policy = _coerce_policy(policy)
    overrides = {name: value for name, value in (
        ('minimum_cipher', minimum_cipher),
        ('allowed_ciphers', allowed_ciphers),
        ('allowed_compression', allowed_compression),
        ('minimum_key_bits', minimum_key_bits),
    ) if value is not None}
    if overrides:
        policy = dataclasses.replace(policy, **overrides)

    if not isinstance(message, PGPMessage):
        raise TypeError("message must be a PGPMessage")

    if message.is_encrypted:
        raise MessageAlreadyEncryptedError(
            "This message is already encrypted. Batch encryption will not assume it can change the content "
            "cipher of existing ciphertext; create a new plaintext message instead.")

    if message.type == 'cleartext':
        raise PGPEncryptionError(
            "Cleartext signed messages cannot be batch-encrypted; create a binary literal message "
            "(PGPMessage.new(..., cleartext=False)) instead")

    requested_cipher = _enum(cipher, SymmetricKeyAlgorithm) if cipher is not None else None
    requested_compression = _enum(compression, CompressionAlgorithm) if compression is not None else None

    if requested_cipher is not None and (requested_cipher not in _ENCRYPTION_CIPHERS):
        raise PGPEncryptionError("Cipher {:s} is not supported for encryption".format(requested_cipher.name))

    normalized = _normalize_recipients(recipients, user)

    # Phase 1: validate every recipient and authenticate every preference
    # list.  Nothing is encrypted in this phase.
    resolved = [_resolve_recipient(recipient, policy) for recipient in normalized]
    resolved, duplicates = _deduplicate(resolved)

    cipher_candidates = set.intersection(*[set(item.plan.permitted_ciphers) for item in resolved])
    compression_candidates = set.intersection(*[set(item.plan.permitted_compression) for item in resolved])

    if requested_cipher is not None:
        if requested_cipher not in cipher_candidates:
            raise NoCommonAlgorithmError(
                "Requested cipher {:s} is not permitted by every recipient".format(requested_cipher.name),
                details={'requested': requested_cipher, 'recipients': resolved})

    if not cipher_candidates:
        detail = "; ".join(
            "0x{:s} permits [{}]".format(item.plan.encryption_key_id, _names(item.plan.permitted_ciphers))
            for item in resolved)
        raise NoCommonAlgorithmError(
            "No symmetric cipher is permitted by every recipient; no ciphertext was produced. "
            "Policy applied: {:s}. ".format(policy.describe()) + detail,
            details={'recipients': resolved, 'policy': policy})

    selected_cipher = requested_cipher or max(cipher_candidates, key=_cipher_strength)

    if requested_compression is not None:
        if requested_compression not in compression_candidates:
            raise NoCommonAlgorithmError(
                "Requested compression {:s} is not permitted by every recipient".format(
                    requested_compression.name),
                details={'requested': requested_compression, 'recipients': resolved})

    if not compression_candidates:
        detail = "; ".join(
            "0x{:s} permits [{}]".format(item.plan.encryption_key_id, _names(item.plan.permitted_compression))
            for item in resolved)
        raise NoCommonAlgorithmError(
            "No compression algorithm is permitted by every recipient; no ciphertext was produced. "
            "Policy applied: {:s}. ".format(policy.describe()) + detail,
            details={'recipients': resolved, 'policy': policy})

    if requested_compression is not None:
        selected_compression = requested_compression
    else:
        # Keep the caller's own compression choice when it is acceptable to
        # everyone; otherwise fall back to PGPy's deterministic preference order.
        own = message._compression
        selected_compression = own if own in compression_candidates else next(
            c for c in _COMPRESSION_ORDER if c in compression_candidates)

    # Phase 2: all validation passed.  Build every recipient's session key
    # packet first; only then encrypt the content once.
    sessionkey = selected_cipher.gen_key()
    pkesks = []
    try:
        for item in resolved:
            public_key = item.key if item.key.is_public else item.key.pubkey
            pkesk = PKESessionKeyV3()
            pkesk.encrypter = bytearray(binascii.unhexlify(public_key.fingerprint.keyid.encode('latin-1')))
            pkesk.pkalg = public_key.key_algorithm
            pkesk.encrypt_sk(public_key._key, selected_cipher, sessionkey)
            pkesks.append(pkesk)

        payload = copy.copy(message)
        payload._compression = selected_compression

        skedata = IntegrityProtectedSKEDataV1()
        skedata.encrypt(sessionkey, selected_cipher, payload.__bytes__())

        encrypted = PGPMessage()
        encrypted |= skedata
        for pkesk in pkesks:
            encrypted |= pkesk

        encrypted._encryption_report = BatchEncryptionReport(
            cipher=selected_cipher,
            compression=selected_compression,
            cipher_candidates=frozenset(cipher_candidates),
            compression_candidates=frozenset(compression_candidates),
            recipients=tuple(item.plan for item in resolved),
            policy=policy,
            duplicates_removed=tuple(duplicates),
            cipher_explicit=requested_cipher is not None,
            compression_explicit=requested_compression is not None,
        )
        return encrypted

    finally:
        del sessionkey
