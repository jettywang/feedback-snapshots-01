"""Forensic status model for BitLocker (BDE) volumes.

The single ``BDE.encrypted`` boolean is not enough to drive a forensic UI. Three very different
situations all collapse to "looks unprotected" if you only look at whether a passphrase was
supplied:

* a *suspended* volume still stores every sector as ciphertext but ships a clear-key protector, so
  it opens without any external secret;
* a *partially converted* (paused) volume is ciphertext in one region and plaintext in another;
* a fully *decrypted* volume holds plaintext on disk and no usable FVEK at all.

This module answers four independent questions instead of one ambiguous label:

1. Is ciphertext still present on disk, and where? (a fact about the bytes, not the metadata)
2. Can the volume be unlocked without an external credential? (a fact about the protectors)
3. Is a conversion running or paused? (a fact about ``CurrentState``/``NextState``)
4. Which parts of the sector map are actually confirmed, versus only claimed by metadata?

Metadata-reported state (:class:`MetadataStatus`) and state proven by reading sectors
(:class:`ObservedSectorEvidence`) are kept in separate objects and never mixed. Not being given a
user passphrase only means we did not perform a key-dependent read; it must never be reported as
"the volume is unreadable", because a clear-key protector or plaintext regions may still open it.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING

from dissect.fve.bde.bde import BitlockerStream
from dissect.fve.bde.c_bde import FVE_KEY_PROTECTOR, FVE_STATE

if TYPE_CHECKING:
    from collections.abc import Iterator, Sequence

    from dissect.fve.bde.bde import BDE


class SectorDisposition(str, Enum):
    """How a logical sector is stored on the underlying disk."""

    ENCRYPTED = "encrypted"
    """The on-disk bytes are ciphertext and require the FVEK to recover the plaintext."""

    PLAINTEXT = "plaintext"
    """The on-disk bytes are already plaintext and need no decryption."""

    SPARSE = "sparse"
    """A reserved/virtualized region that the driver presents as all-zero bytes."""

    UNKNOWN = "unknown"
    """No sector was read here, so the disposition is metadata-only and unconfirmed."""


class AccessLevel(str, Enum):
    """Whether and how the plaintext of a volume can be reached."""

    OPEN_WITHOUT_CREDENTIAL = "open_without_credential"
    """A clear-key protector is present, or the whole volume is plaintext."""

    REQUIRES_EXTERNAL_CREDENTIAL = "requires_external_credential"
    """Ciphertext exists and only secret protectors (passphrase, recovery, TPM, BEK) can release it."""

    NOT_ASSESSED = "not_assessed"
    """The volume is locked and no read was attempted; accessibility is not proven either way."""


class ConversionPhase(str, Enum):
    """Human-readable interpretation of the metadata ``CurrentState``/``NextState`` pair."""

    ENCRYPTED_STEADY = "encrypted_steady"
    DECRYPTED_STEADY = "decrypted_steady"
    ENCRYPTING = "encrypting"
    DECRYPTING = "decrypting"
    PAUSED = "paused"
    SWITCHING = "switching"
    SWITCHING_DIRTY = "switching_dirty"
    UNKNOWN = "unknown"


# Secret-bearing protectors: using one always requires material that is not stored on the volume.
_SECRET_PROTECTORS = (
    FVE_KEY_PROTECTOR.TPM,
    FVE_KEY_PROTECTOR.TPM_PIN,
    FVE_KEY_PROTECTOR.EXTERNAL,
    FVE_KEY_PROTECTOR.RECOVERY_PASSWORD,
    FVE_KEY_PROTECTOR.PASSPHRASE,
)

_DEFAULT_SAMPLE_COUNT = 8


@dataclass(frozen=True)
class SectorObservation:
    """The verified disposition of a single logical sector, backed by an actual disk read."""

    logical_sector: int
    disposition: SectorDisposition
    on_disk_sector: int
    """The physical sector that was actually read (virtualized sectors live elsewhere)."""
    on_disk_entropy: float
    plaintext_signature: str | None
    raw_equals_decrypted_view: bool | None
    """True when the raw bytes already equal the exposed plaintext; None when no key is available."""

    def to_dict(self) -> dict:
        return {
            "logical_sector": self.logical_sector,
            "disposition": self.disposition.value,
            "on_disk_sector": self.on_disk_sector,
            "on_disk_entropy": round(self.on_disk_entropy, 4),
            "plaintext_signature": self.plaintext_signature,
            "raw_equals_decrypted_view": self.raw_equals_decrypted_view,
        }


@dataclass(frozen=True)
class ObservedSectorEvidence:
    """Facts established by reading bytes from the underlying disk."""

    sector_size: int
    volume_sectors: int
    observations: tuple[SectorObservation, ...]
    encrypted_sectors_observed: int
    plaintext_sectors_observed: int
    sparse_sectors_observed: int
    unknown_sectors_observed: int
    decrypted_view_available: bool
    """Whether an FVEK was available, allowing a key-dependent comparison."""

    @property
    def ciphertext_confirmed(self) -> bool:
        """At least one sampled sector was read and proven to hold ciphertext."""
        return self.encrypted_sectors_observed > 0

    @property
    def plaintext_confirmed(self) -> bool:
        """At least one sampled sector was read and proven to hold plaintext."""
        return self.plaintext_sectors_observed > 0

    def to_dict(self) -> dict:
        return {
            "sector_size": self.sector_size,
            "volume_sectors": self.volume_sectors,
            "ciphertext_confirmed": self.ciphertext_confirmed,
            "plaintext_confirmed": self.plaintext_confirmed,
            "decrypted_view_available": self.decrypted_view_available,
            "counts": {
                "encrypted": self.encrypted_sectors_observed,
                "plaintext": self.plaintext_sectors_observed,
                "sparse": self.sparse_sectors_observed,
                "unknown": self.unknown_sectors_observed,
                "sampled": len(self.observations),
            },
            "observations": [obs.to_dict() for obs in self.observations],
        }


@dataclass(frozen=True)
class MetadataStatus:
    """Everything the BitLocker metadata claims, without any independent verification."""

    version: int
    current_state: str
    current_state_value: int
    next_state: str
    next_state_value: int
    conversion_phase: ConversionPhase
    state_offset: int
    state_offset_sector: int
    state_size: int
    uses_eow_bitmap: bool
    fvek_type: str
    protectors: tuple[str, ...]
    has_clear_key: bool
    has_secret_protector: bool

    def to_dict(self) -> dict:
        return {
            "version": self.version,
            "current_state": self.current_state,
            "current_state_value": self.current_state_value,
            "next_state": self.next_state,
            "next_state_value": self.next_state_value,
            "conversion_phase": self.conversion_phase.value,
            "state_offset": self.state_offset,
            "state_offset_sector": self.state_offset_sector,
            "state_size": self.state_size,
            "uses_eow_bitmap": self.uses_eow_bitmap,
            "fvek_type": self.fvek_type,
            "protectors": list(self.protectors),
            "has_clear_key": self.has_clear_key,
            "has_secret_protector": self.has_secret_protector,
        }


@dataclass(frozen=True)
class AccessAssessment:
    """Whether the plaintext can be reached, kept independent of where ciphertext sits."""

    level: AccessLevel
    openable_without_external_credential: bool
    unlock_path: str | None
    rationale: str

    def to_dict(self) -> dict:
        return {
            "level": self.level.value,
            "openable_without_external_credential": self.openable_without_external_credential,
            "unlock_path": self.unlock_path,
            "rationale": self.rationale,
        }


@dataclass(frozen=True)
class VolumeStatus:
    """The complete, backend-ready forensic status of a BitLocker volume."""

    metadata: MetadataStatus
    access: AccessAssessment
    evidence: ObservedSectorEvidence
    summary: str
    """A short sentence a UI can show directly; never reduces the volume to a single encrypted flag."""

    def to_dict(self) -> dict:
        return {
            "summary": self.summary,
            "metadata": self.metadata.to_dict(),
            "access": self.access.to_dict(),
            "observed_evidence": self.evidence.to_dict(),
        }


def _shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = {}
    for byte in data:
        counts[byte] = counts.get(byte, 0) + 1
    length = len(data)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def _detect_plaintext_signature(buf: bytes) -> str | None:
    if len(buf) >= 11 and buf[3:11] == b"NTFS    ":
        return "NTFS"
    if len(buf) >= 8 and buf[:8] == b"FILE0\x00\x03\x00":
        return "NTFS_MFT_RECORD"
    if len(buf) >= 5 and buf[:5] == b"EXFAT":
        return "EXFAT"
    if len(buf) >= 4 and buf[3:7] in (b"FAT32", b"FAT16", b"FAT  "):
        return "FAT"
    if len(buf) >= 4 and buf[:4] == b"ReFS":
        return "ReFS"
    return None


def _classify_conversion(current: FVE_STATE, next_state: FVE_STATE) -> ConversionPhase:
    if current == FVE_STATE.ENCRYPTED and next_state == FVE_STATE.ENCRYPTED:
        return ConversionPhase.ENCRYPTED_STEADY
    if current == FVE_STATE.DECRYPTED and next_state == FVE_STATE.DECRYPTED:
        return ConversionPhase.DECRYPTED_STEADY
    if current == FVE_STATE.PAUSED:
        return ConversionPhase.PAUSED
    if current == FVE_STATE.SWITCHING_DIRTY:
        return ConversionPhase.SWITCHING_DIRTY
    if current in (FVE_STATE.SWITCHING,):
        return ConversionPhase.SWITCHING

    # A steady current state paired with a different target state means a pending conversion.
    if current in (FVE_STATE.DECRYPTED, FVE_STATE.ENCRYPTED) and next_state != current:
        return ConversionPhase.ENCRYPTING if next_state == FVE_STATE.ENCRYPTED else ConversionPhase.DECRYPTING
    return ConversionPhase.UNKNOWN


def read_metadata_status(bde: BDE) -> MetadataStatus:
    """Parse the self-reported metadata status without reading user-data sectors."""
    info = bde.information
    current = info.current_state
    next_state = info.next_state

    protectors = tuple(protector.name for protector in bde.vmk_types)
    has_clear_key = bde.has_clear_key()
    has_secret = any(protector in _SECRET_PROTECTORS for protector in bde.vmk_types)

    return MetadataStatus(
        version=bde.version,
        current_state=current.name,
        current_state_value=current.value,
        next_state=next_state.name,
        next_state_value=next_state.value,
        conversion_phase=_classify_conversion(current, next_state),
        state_offset=info.state_offset,
        state_offset_sector=info.state_offset // bde.sector_size,
        state_size=info.state_size,
        uses_eow_bitmap=bde.eow_information is not None,
        fvek_type=info.dataset.fvek_type.name,
        protectors=protectors,
        has_clear_key=has_clear_key,
        has_secret_protector=has_secret,
    )


def assess_access(bde: BDE, metadata: MetadataStatus, decrypted_view_available: bool) -> AccessAssessment:
    """Decide how the plaintext can be reached, independent of the on-disk ciphertext layout.

    A missing user passphrase is deliberately *not* treated as "unreadable". When the metadata is
    fully decrypted, or a clear-key protector is present, no external secret is needed at all.
    """
    if metadata.current_state == FVE_STATE.DECRYPTED.name:
        return AccessAssessment(
            level=AccessLevel.OPEN_WITHOUT_CREDENTIAL,
            openable_without_external_credential=True,
            unlock_path="plaintext_volume",
            rationale="Metadata reports DECRYPTED and there is no wrapped FVEK; sectors are read directly.",
        )

    if metadata.has_clear_key:
        return AccessAssessment(
            level=AccessLevel.OPEN_WITHOUT_CREDENTIAL,
            openable_without_external_credential=True,
            unlock_path="clear_key",
            rationale=(
                "A clear-key (obfuscated) VMK protector is stored on the volume, so the FVEK can be "
                "recovered without any user passphrase, recovery password, TPM or BEK material."
            ),
        )

    if metadata.has_secret_protector:
        return AccessAssessment(
            level=AccessLevel.REQUIRES_EXTERNAL_CREDENTIAL,
            openable_without_external_credential=False,
            unlock_path="secret_protector",
            rationale=(
                "Ciphertext is protected only by secret-bearing protectors "
                f"({', '.join(metadata.protectors)}); external credential material is required."
            ),
        )

    if decrypted_view_available:
        return AccessAssessment(
            level=AccessLevel.OPEN_WITHOUT_CREDENTIAL,
            openable_without_external_credential=True,
            unlock_path="already_unlocked",
            rationale="No on-volume protector remains, but a decrypted view was already supplied in memory.",
        )

    return AccessAssessment(
        level=AccessLevel.NOT_ASSESSED,
        openable_without_external_credential=False,
        unlock_path=None,
        rationale=(
            "No clear key or secret protector is visible and no key was supplied; accessibility is "
            "unproven, not proven impossible."
        ),
    )


def _default_sample_sectors(volume_sectors: int, count: int) -> list[int]:
    if volume_sectors <= 0:
        return []
    if volume_sectors <= count:
        return list(range(volume_sectors))
    # Evenly spread samples, always including the first and last user sectors.
    step = volume_sectors / count
    sectors = sorted({min(volume_sectors - 1, int(i * step)) for i in range(count)})
    if sectors[0] != 0:
        sectors.insert(0, 0)
    if sectors[-1] != volume_sectors - 1:
        sectors.append(volume_sectors - 1)
    return sectors


def observe_sectors(
    bde: BDE,
    sectors: Sequence[int] | None = None,
    *,
    sample_count: int = _DEFAULT_SAMPLE_COUNT,
) -> ObservedSectorEvidence:
    """Read selected sectors from disk and verify how each one is actually stored.

    The Bitlocker stream's own run classifier is the source of truth for *which* physical sector
    backs a logical sector (this handles virtualized header blocks, reserved sparse regions, EOW
    bitmaps and pre-EOW ``StateOffset`` watermarks). We then read that physical sector directly and
    record whether the bytes are ciphertext, plaintext or a synthetic zero region.

    When the volume is unlocked, the raw on-disk bytes are additionally compared against the
    decrypted view so that ciphertext is demonstrated rather than inferred. When it is locked, the
    run classifier plus a plaintext-signature/entropy check still gives a best-effort disposition
    marked as key-independent.
    """
    sector_size = bde.sector_size
    bde.fh.seek(0, 2)
    volume_bytes = bde.fh.tell()
    volume_sectors = volume_bytes // sector_size

    if sectors is None:
        sectors = _default_sample_sectors(volume_sectors, sample_count)

    decrypted_view_available = bde.unlocked
    # A BitlockerStream only needs the FVEK to decrypt bytes; its run classifier (which physical
    # sector backs a logical sector, and whether it is plaintext/encrypted/sparse) works while
    # locked, so construct it directly instead of going through the unlocking ``BDE.open()`` guard.
    stream = BitlockerStream(bde)

    observations: list[SectorObservation] = []
    encrypted = plaintext = sparse = unknown = 0

    for logical_sector in sectors:
        if not 0 <= logical_sector < volume_sectors:
            continue

        runs = list(stream._iter_runs(logical_sector * sector_size, sector_size))
        run_type, on_disk_sector, _ = runs[0]

        bde.fh.seek(on_disk_sector * sector_size)
        raw = bde.fh.read(sector_size)
        entropy = _shannon_entropy(raw)
        signature = _detect_plaintext_signature(raw)
        is_zero_sector = raw == b"\x00" * sector_size

        if run_type == stream.RUN_SPARSE:
            disposition = SectorDisposition.SPARSE
            sparse += 1
            raw_equals_view: bool | None = True
        elif run_type == stream.RUN_PLAIN:
            disposition = SectorDisposition.PLAINTEXT
            plaintext += 1
            raw_equals_view = True
        elif run_type == stream.RUN_VISTA_HEADER:
            # The Vista header is stored plaintext and only patched in memory on read.
            disposition = SectorDisposition.PLAINTEXT
            plaintext += 1
            raw_equals_view = None
        elif is_zero_sector and not decrypted_view_available:
            # A never-written sector inside an encrypted run is stored as raw zeros; without a key we
            # cannot demonstrate that this spot would decrypt to ciphertext, so leave it unconfirmed
            # rather than overstate that ciphertext was observed.
            disposition = SectorDisposition.UNKNOWN
            unknown += 1
            raw_equals_view = None
        else:
            disposition = SectorDisposition.ENCRYPTED
            encrypted += 1
            raw_equals_view = None

        if decrypted_view_available and disposition != SectorDisposition.SPARSE:
            stream.seek(logical_sector * sector_size)
            decrypted_view = stream.read(sector_size)
            raw_equals_view = raw == decrypted_view
            # With the key in hand, a raw-zero sector in an encrypted run is proven ciphertext-backed
            # when the decrypted view is non-trivially different from the on-disk zeros.
            if disposition == SectorDisposition.UNKNOWN and raw != decrypted_view:
                disposition = SectorDisposition.ENCRYPTED
                unknown -= 1
                encrypted += 1
            if raw_equals_view and signature is None:
                signature = _detect_plaintext_signature(decrypted_view)

        observations.append(
            SectorObservation(
                logical_sector=logical_sector,
                disposition=disposition,
                on_disk_sector=on_disk_sector,
                on_disk_entropy=entropy,
                plaintext_signature=signature,
                raw_equals_decrypted_view=raw_equals_view,
            )
        )

    return ObservedSectorEvidence(
        sector_size=sector_size,
        volume_sectors=volume_sectors,
        observations=tuple(observations),
        encrypted_sectors_observed=encrypted,
        plaintext_sectors_observed=plaintext,
        sparse_sectors_observed=sparse,
        unknown_sectors_observed=unknown,
        decrypted_view_available=decrypted_view_available,
    )


def _build_summary(metadata: MetadataStatus, access: AccessAssessment, evidence: ObservedSectorEvidence) -> str:
    parts: list[str] = []

    if evidence.ciphertext_confirmed and evidence.plaintext_confirmed:
        parts.append("partially encrypted: sampled sectors contain both ciphertext and plaintext")
    elif evidence.ciphertext_confirmed:
        parts.append("ciphertext present on disk")
    elif evidence.plaintext_confirmed:
        parts.append("no ciphertext found in sampled sectors (plaintext on disk)")
    else:
        parts.append("sector disposition not yet confirmed by a read")

    if access.openable_without_external_credential:
        parts.append("opens without an external credential")
    elif access.level == AccessLevel.REQUIRES_EXTERNAL_CREDENTIAL:
        parts.append("requires an external credential to decrypt")

    if metadata.conversion_phase == ConversionPhase.PAUSED:
        parts.append("conversion is paused")
    elif metadata.conversion_phase in (
        ConversionPhase.SWITCHING,
        ConversionPhase.SWITCHING_DIRTY,
        ConversionPhase.ENCRYPTING,
        ConversionPhase.DECRYPTING,
    ):
        parts.append(f"conversion in progress ({metadata.conversion_phase.value})")

    return "; ".join(parts)


def assess_volume(bde: BDE, sectors: Sequence[int] | None = None) -> VolumeStatus:
    """Produce the full forensic status object suitable for direct backend serialization.

    This never raises on a missing passphrase. Callers that can supply credentials should unlock the
    :class:`BDE` object first (clear key, passphrase, recovery password or BEK); the evidence object
    will then include key-dependent raw-vs-decrypted comparisons. Without a key it still reports the
    metadata claims and key-independent sector dispositions.
    """
    metadata = read_metadata_status(bde)
    evidence = observe_sectors(bde, sectors)
    access = assess_access(bde, metadata, evidence.decrypted_view_available)
    summary = _build_summary(metadata, access, evidence)
    return VolumeStatus(metadata=metadata, access=access, evidence=evidence, summary=summary)


def iter_status_records(status: VolumeStatus) -> Iterator[dict]:
    """Yield one flat record per observed sector, handy for tabular/forensic exports."""
    for observation in status.evidence.observations:
        yield {
            "current_state": status.metadata.current_state,
            "conversion_phase": status.metadata.conversion_phase.value,
            "access_level": status.access.level.value,
            **observation.to_dict(),
        }
