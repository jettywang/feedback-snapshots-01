"""Publisher constraints applied *after* a signature has been fully verified.

The update channel only accepts code from a set of explicitly trusted publishers.
Certificates are renewed over time, so matching on the certificate's subject display
name (e.g. ``CN=...``) is not sufficient: a different key can carry the same name, and
a renewal can carry a different name while keeping the same key. This module therefore
pins publishers on the SHA-256 fingerprint of the leaf certificate's
SubjectPublicKeyInfo (SPKI), combined with an explicit validity interval during which
that key is accepted as the publisher.

The constraint is deliberately evaluated only against the leaf certificate that
actually completed file-digest, code-signature and trust-chain verification. It can
therefore never be satisfied by:

* a CA or root that happens to share a name with a publisher, or by any other
  certificate in the chain (only ``chain[-1]``, the end-entity signer, is considered);
* a nested signature (each nested SignedData is verified and constrained on its own
  signer leaf);
* a signature that did not verify (failing signatures never reach this check).
"""

from __future__ import annotations

import dataclasses
import datetime
from collections.abc import Iterable, Iterator
from typing import TYPE_CHECKING

from signify.exceptions import AuthenticodePublisherVerificationError

if TYPE_CHECKING:
    from signify.authenticode.signed_data import AuthenticodeSignature
    from signify.authenticode.trust_list import CertificateTrustList
    from signify.x509.certificates import Certificate

_EPOCH = datetime.datetime.min.replace(tzinfo=datetime.timezone.utc)
# Far-future upper bound, used when a publisher entry has no explicit end date.
_APOCALYPSE = datetime.datetime.max.replace(tzinfo=datetime.timezone.utc)


def _as_aware(value: datetime.datetime | None, default: datetime.datetime) -> datetime:
    if value is None:
        return default
    if value.tzinfo is None:
        return value.replace(tzinfo=datetime.timezone.utc)
    return value


def _normalize_spki_sha256(value: str | bytes) -> str:
    """Accepts a lowercase/uppercase hex string (with or without spaces) or raw digest
    bytes, and returns the canonical lowercase hex representation."""
    if isinstance(value, bytes):
        if len(value) != 32:
            raise ValueError(
                "A raw SPKI SHA-256 digest must be exactly 32 bytes, got"
                f" {len(value)}."
            )
        return value.hex()
    normalized = value.replace(" ", "").replace(":", "").lower()
    if len(normalized) != 64:
        raise ValueError(
            "An SPKI SHA-256 fingerprint must be 64 hexadecimal characters, got"
            f" {len(normalized)}: {value!r}."
        )
    if any(char not in "0123456789abcdef" for char in normalized):
        raise ValueError(f"Invalid hexadecimal SPKI SHA-256 fingerprint: {value!r}.")
    return normalized


@dataclasses.dataclass(frozen=True)
class TrustedPublisher:
    """A single trusted publisher entry.

    A publisher is identified solely by the SHA-256 fingerprint of the leaf
    certificate's SubjectPublicKeyInfo (``spki_sha256``), together with the interval
    ``[valid_from, valid_to]`` during which that key is accepted. The subject display
    name of the certificate is intentionally not part of the identity.

    Multiple entries may share the same ``spki_sha256`` to model renewal windows, and
    different entries with different ``spki_sha256`` model a genuine key rotation.

    :param spki_sha256: The SHA-256 fingerprint of the trusted leaf certificate's
        SubjectPublicKeyInfo, as hex (with or without spaces/colons) or raw bytes.
    :param valid_from: Start of the acceptance interval (inclusive). :const:`None`
        means the beginning of time.
    :param valid_to: End of the acceptance interval (inclusive). :const:`None` means
        no upper bound.
    :param label: Optional human-readable label, used only for reporting. It does not
        participate in matching and must never be treated as a security identifier.
    """

    spki_sha256: str
    valid_from: datetime.datetime | None = None
    valid_to: datetime.datetime | None = None
    label: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "spki_sha256", _normalize_spki_sha256(self.spki_sha256)
        )
        start = _as_aware(self.valid_from, _EPOCH)
        end = _as_aware(self.valid_to, _APOCALYPSE)
        if start > end:
            raise ValueError(
                f"TrustedPublisher {self.spki_sha256!r} has a valid_from later than"
                " its valid_to."
            )
        object.__setattr__(self, "valid_from", start)
        object.__setattr__(self, "valid_to", end)

    def matches(
        self, certificate: Certificate, at: datetime.datetime
    ) -> bool:
        """Returns whether the provided (already verified) leaf certificate is this
        publisher at the given time. Matching is on the SPKI fingerprint only and the
        validity interval; the subject name is ignored."""
        if certificate.spki_sha256_fingerprint != self.spki_sha256:
            return False
        return self.valid_from <= at <= self.valid_to


class PublisherPolicy:
    """An ordered collection of :class:`TrustedPublisher` entries.

    The policy is the explicit set of leaf SPKIs that are allowed to enter the update
    channel, each constrained to a validity interval. It performs no name matching:
    a certificate whose subject display name equals that of a trusted publisher is not
    accepted unless its SPKI is pinned here.
    """

    def __init__(self, publishers: Iterable[TrustedPublisher] = ()) -> None:
        self.publishers: tuple[TrustedPublisher, ...] = tuple(publishers)

    def __iter__(self) -> Iterator[TrustedPublisher]:
        return iter(self.publishers)

    def __len__(self) -> int:
        return len(self.publishers)

    def matching_entries(
        self, certificate: Certificate, at: datetime.datetime
    ) -> tuple[TrustedPublisher, ...]:
        """Returns all policy entries that accept the provided leaf certificate at the
        given time. All matching entries are returned (rather than the last one) so the
        caller can report every applicable basis, including overlapping renewal and
        key-rotation windows."""
        return tuple(
            entry
            for entry in self.publishers
            if entry.matches(certificate, at)
        )

    def is_trusted_publisher(
        self, certificate: Certificate, at: datetime.datetime
    ) -> bool:
        return bool(self.matching_entries(certificate, at))


@dataclasses.dataclass(frozen=True)
class PublisherVerification:
    """The publisher decision for one fully verified signature.

    :param signature: The SignedData structure whose signer leaf was evaluated.
    :param leaf: The end-entity (signer) certificate that actually completed the
        digest, code-signature and trust-chain verification. Only this certificate was
        considered.
    :param at: The timestamp used for evaluating the publisher validity interval.
    :param matches: The policy entries on which the leaf is accepted. Empty means the
        signature verified cryptographically but its publisher is not allowed.
    """

    signature: AuthenticodeSignature | CertificateTrustList
    leaf: Certificate
    at: datetime.datetime
    matches: tuple[TrustedPublisher, ...]

    @property
    def allowed(self) -> bool:
        return bool(self.matches)

    def raise_if_rejected(self) -> None:
        if self.allowed:
            return
        raise AuthenticodePublisherVerificationError(
            "The signature's leaf certificate "
            f"{self.leaf.subject.dn} (SPKI SHA-256"
            f" {self.leaf.spki_sha256_fingerprint}) is not an allowed publisher at"
            f" {self.at.isoformat()}."
        )


def evaluate_publisher(
    signature: AuthenticodeSignature | CertificateTrustList,
    leaf: Certificate,
    policy: PublisherPolicy | None,
    at: datetime.datetime,
) -> PublisherVerification:
    """Builds a :class:`PublisherVerification` for one verified signature.

    A :const:`None` policy means no publisher constraint is configured; the decision is
    still returned (with no matching entries) but callers skip enforcement entirely, so
    ordinary verification is unchanged.
    """
    at = _as_aware(at, datetime.datetime.now(datetime.timezone.utc))
    if policy is None:
        return PublisherVerification(
            signature=signature, leaf=leaf, at=at, matches=()
        )
    return PublisherVerification(
        signature=signature,
        leaf=leaf,
        at=at,
        matches=policy.matching_entries(leaf, at),
    )
