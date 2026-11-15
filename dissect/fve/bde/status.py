# References:
# - https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/
# - fvevol.sys, fveapi.dll

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import TYPE_CHECKING

from dissect.fve.bde.bde import BitlockerStream
from dissect.fve.bde.c_bde import FVE_KEY_PROTECTOR, FVE_STATE

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.fve.bde.bde import BDE
    from dissect.fve.bde.information import VmkInfoDatum


#: Human readable labels for the states stored in ``FVE_INFORMATION.CurrentState`` / ``NextState``.
FVE_STATE_LABELS = {
    FVE_STATE.DECRYPTED: "decrypted",
    FVE_STATE.SWITCHING_DIRTY: "switching_dirty",
    FVE_STATE.PAUSED: "paused",
    FVE_STATE.ENCRYPTED: "encrypted",
    FVE_STATE.SWITCHING: "switching",
}

#: Protectors that live on the machine and may be released automatically by Windows.
MACHINE_BOUND_PROTECTORS = frozenset((FVE_KEY_PROTECTOR.TPM, FVE_KEY_PROTECTOR.TPM_PIN))

#: Protectors that require a user supplied secret or an external key file.
CREDENTIAL_PROTECTORS = frozenset(
    (
        FVE_KEY_PROTECTOR.EXTERNAL,
        FVE_KEY_PROTECTOR.RECOVERY_PASSWORD,
        FVE_KEY_PROTECTOR.PASSPHRASE,
        FVE_KEY_PROTECTOR.TPM_PIN,
    )
)

#: Maximum number of sectors to sample when verifying the layout.
MAX_SAMPLES = 64

#: Maximum number of individual sample records to keep in the report.
MAX_SAMPLE_RECORDS = 32


def _state_name(state: FVE_STATE) -> str:
    return FVE_STATE_LABELS.get(state, state.name.lower())


def _protector_kinds(priority: int) -> tuple[str, ...]:
    names = [flag.name for flag in FVE_KEY_PROTECTOR if flag.value and priority & flag.value]
    if not names and not priority:
        names.append(FVE_KEY_PROTECTOR.CLEAR.name)
    elif not names:
        names.append("unknown")
    return tuple(names)


def _protector_kind_set(priority: int) -> set[FVE_KEY_PROTECTOR]:
    kinds = {flag for flag in FVE_KEY_PROTECTOR if flag.value and priority & flag.value}
    if not kinds and not priority:
        kinds.add(FVE_KEY_PROTECTOR.CLEAR)
    return kinds


def _magic_name(buf: bytes) -> str:
    if not buf:
        return "unreadable"
    if buf[3:11] == b"NTFS    ":
        return "ntfs"
    if buf[:5] == b"FILE0":
        return "file0"
    if buf[:8] == b"-FVE-FS-":
        return "fve_boot"
    if not any(buf):
        return "zero"
    return "none"


def _is_zero(buf: bytes) -> bool:
    return not any(buf)


def _ciphertext_label(encrypted: int, plaintext: int) -> str:
    if encrypted and plaintext:
        return "partial"
    if encrypted:
        return "present"
    if plaintext:
        return "none"
    return "unknown"


@dataclass(frozen=True)
class Protector:
    """A key protector as declared by the volume metadata."""

    identifier: str
    priority: int
    kinds: tuple[str, ...]
    label: str | None = None
    needs_secret: bool = False
    machine_bound: bool = False

    def to_dict(self) -> dict:
        result = asdict(self)
        result["kinds"] = list(self.kinds)
        return result


@dataclass(frozen=True)
class MetadataState:
    """The BitLocker information header fields.

    This is what the volume says about itself. It is the authority on the intended
    configuration, but it is not evidence about the bytes stored in individual sectors.
    """

    current: str
    next: str
    current_value: int
    next_value: int
    state_offset: int
    state_size: int
    information_blocks: int
    valid_information_blocks: int

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True)
class ConversionState:
    """Whether a conversion is running, paused, or only declared by the sector layout.

    ``watermark_source`` explains how ``watermark_sector`` was obtained:

    * ``eow_bitmap``: the EOW bitmap carries the per-range state
    * ``state_offset``: pre-EOW ``StateOffset`` is the encrypted/plaintext watermark
    * ``none``: no usable watermark is present
    """

    active: bool
    paused: bool
    direction: str | None
    phase: str
    incomplete: bool
    resumable: bool
    watermark_sector: int
    watermark_source: str
    state_size_sectors: int

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True)
class AccessState:
    """Whether the volume can be opened, with and without external credentials.

    ``readable`` is deliberately tri-state. ``None`` means "not tested", not "unreadable".
    A volume with only a passphrase/recovery protector is not proven unreadable just because
    no credential was supplied to this process.
    """

    unlocked: bool
    method: str | None
    credential_supplied: bool
    openable: bool | None
    without_external_credentials: bool | None
    requires_credential: bool | None
    readable: bool | None
    reason: str

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True)
class CiphertextState:
    """Ciphertext presence split into declaration and observation.

    ``declared`` comes from the sector layout (EOW bitmap or ``StateOffset``).
    ``observed`` comes from comparing raw sector bytes with the decrypted view.
    ``confirmed`` means at least one sampled sector supports the conclusion; it does not
    mean every sector in the volume was verified.
    """

    declared: str
    observed: str | None
    conclusion: str
    confirmed: bool
    note: str

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True)
class SectorRange:
    """A contiguous range of logical sectors with a nominal layout state."""

    start_sector: int
    sector_count: int
    encrypted: bool
    kind: str
    observed: str | None = None
    sampled_sectors: int = 0
    start_byte: int = 0
    size: int = 0

    def to_dict(self) -> dict:
        result = asdict(self)
        result["end_sector"] = self.start_sector + self.sector_count
        result["end_byte"] = self.start_byte + self.size
        return result


@dataclass(frozen=True)
class SectorEvidence:
    """Direct-read evidence collected from sampled logical sectors."""

    total_sectors: int
    sampled_sectors: int
    encrypted_samples: int
    plaintext_samples: int
    inconclusive_samples: int
    unverified_samples: int
    verified_bytes: int
    samples: tuple[dict, ...] = ()
    note: str = ""

    @property
    def verified_samples(self) -> int:
        return self.sampled_sectors - self.unverified_samples

    @property
    def unverified_sectors(self) -> int:
        return max(0, self.total_sectors - self.verified_samples)

    @property
    def coverage(self) -> float:
        return 0.0 if not self.total_sectors else self.verified_samples / self.total_sectors

    def to_dict(self) -> dict:
        result = asdict(self)
        result["samples"] = list(self.samples)
        result["verified_samples"] = self.verified_samples
        result["unverified_sectors"] = self.unverified_sectors
        result["coverage"] = self.coverage
        return result


@dataclass(frozen=True)
class SectorMap:
    """Nominal sector ranges plus the sampled verification result."""

    sector_size: int
    total_sectors: int
    encrypted_sectors: int
    plaintext_sectors: int
    sparse_sectors: int
    ranges: tuple[SectorRange, ...] = ()
    evidence: SectorEvidence | None = None

    @property
    def partial(self) -> bool:
        return bool(self.encrypted_sectors and self.plaintext_sectors)

    @property
    def verified_encrypted_sectors(self) -> int | None:
        return None if self.evidence is None else self.evidence.encrypted_samples

    @property
    def verified_plaintext_sectors(self) -> int | None:
        return None if self.evidence is None else self.evidence.plaintext_samples

    @property
    def coverage(self) -> float | None:
        return None if self.evidence is None else self.evidence.coverage

    def to_dict(self) -> dict:
        return {
            "sector_size": self.sector_size,
            "total_sectors": self.total_sectors,
            "encrypted_sectors": self.encrypted_sectors,
            "plaintext_sectors": self.plaintext_sectors,
            "sparse_sectors": self.sparse_sectors,
            "partial": self.partial,
            "ranges": [r.to_dict() for r in self.ranges],
            "evidence": None if self.evidence is None else self.evidence.to_dict(),
            "verified_encrypted_sectors": self.verified_encrypted_sectors,
            "verified_plaintext_sectors": self.verified_plaintext_sectors,
            "coverage": self.coverage,
        }


@dataclass
class BDEStatus:
    """Display-oriented status model for a BitLocker volume.

    The model keeps four questions apart:

    * :attr:`ciphertext` - is the volume still storing ciphertext?
    * :attr:`access` - can it be opened, and does that need an external credential?
    * :attr:`conversion` - is a conversion running, paused, or only implied by the layout?
    * :attr:`sector_map` - which logical ranges are declared encrypted/plaintext, and
      which sampled sectors confirm that declaration?

    ``metadata`` is self-reported by the volume. ``sector_map.evidence`` is obtained by
    reading raw sectors and comparing them with the decrypted view. They are reported
    separately and may disagree.
    """

    state: str
    state_label: str
    ciphertext: CiphertextState
    conversion: ConversionState
    access: AccessState
    sector_map: SectorMap
    metadata: MetadataState
    protectors: tuple[Protector, ...] = ()
    summary: str = ""
    warnings: tuple[str, ...] = field(default_factory=tuple)
    display: dict = field(default_factory=dict)

    @classmethod
    def from_bde(cls, bde: BDE, verify: bool = True) -> BDEStatus:
        """Build a status report from a parsed BDE volume.

        Clear-key volumes are verified through a separate parsed instance so that building a
        report does not change ``bde.unlocked``. If a volume was already unlocked, that same
        instance is used for verification.
        """
        metadata = _metadata(bde)
        size = _volume_size(bde)
        verification, verification_error = _verification_source(bde)
        sector_map = _sector_map(bde, verification, verify, size)
        conversion = _conversion(bde, sector_map, size)
        protectors = tuple(_protectors(bde))
        access = _access(bde, protectors, verification, verification_error)
        ciphertext = _ciphertext(sector_map)

        status = cls(
            state="unknown",
            state_label="Unknown",
            ciphertext=ciphertext,
            conversion=conversion,
            access=access,
            sector_map=sector_map,
            metadata=metadata,
            protectors=protectors,
        )
        status.state = _status_key(status)
        status.state_label = _STATE_LABELS[status.state]
        status.warnings = tuple(_warnings(status))
        status.summary = _summary(status)
        status.display = _display(status)
        return status

    def explain(self) -> list[str]:
        """Return short factual statements suitable for a details pane."""
        lines = [
            f"Metadata reports {self.metadata.current} (next state: {self.metadata.next}).",
            f"Ciphertext declared by the sector layout: {self.ciphertext.declared}.",
        ]

        if self.ciphertext.observed is None:
            evidence = self.sector_map.evidence
            if evidence is not None and evidence.unverified_samples:
                lines.append(
                    f"Ciphertext observation: {evidence.unverified_samples} declared-encrypted "
                    f"samples had no decrypted view; {evidence.plaintext_samples} plaintext sample(s) "
                    "were verified independently. The absence of ciphertext is therefore not proven."
                )
            else:
                lines.append("Ciphertext observation: no usable sector samples were verified.")
        else:
            evidence = self.sector_map.evidence
            lines.append(
                f"Ciphertext observed in sampled sectors: {self.ciphertext.observed} "
                f"({0 if evidence is None else evidence.encrypted_samples} encrypted, "
                f"{0 if evidence is None else evidence.plaintext_samples} plaintext samples)."
            )

        lines.append(
            f"Access: openable={_tri(self.access.openable)}, "
            f"without external credentials={_tri(self.access.without_external_credentials)}, "
            f"requires credential={_tri(self.access.requires_credential)}, "
            f"readable={_tri(self.access.readable)}."
        )
        lines.append(self.access.reason)

        if self.conversion.active or self.conversion.paused:
            lines.append(
                f"Conversion: phase={self.conversion.phase}, direction={self.conversion.direction}, "
                f"watermark={self.conversion.watermark_sector} sectors from {self.conversion.watermark_source}."
            )
        else:
            lines.append(f"Conversion: {self.conversion.phase}.")

        if self.ciphertext.conclusion in ("present", "partial") and self.access.without_external_credentials:
            lines.append(
                "These facts are compatible: the volume still stores ciphertext, but a clear "
                "(obfuscated) key protector in the metadata opens it without a user secret."
            )

        return lines

    def to_dict(self) -> dict:
        """Return a JSON-serialisable representation."""
        return {
            "state": self.state,
            "state_label": self.state_label,
            "ciphertext": self.ciphertext.to_dict(),
            "conversion": self.conversion.to_dict(),
            "access": self.access.to_dict(),
            "sector_map": self.sector_map.to_dict(),
            "metadata": self.metadata.to_dict(),
            "protectors": [p.to_dict() for p in self.protectors],
            "summary": self.summary,
            "warnings": list(self.warnings),
            "display": self.display,
            "explanation": self.explain(),
        }


_STATE_LABELS = {
    "decrypted": "Decrypted",
    "paused": "Paused conversion",
    "suspended": "Suspended (clear key)",
    "partially_encrypted_openable": "Partially encrypted (openable)",
    "partially_encrypted_credential_required": "Partially encrypted (credential required)",
    "partially_encrypted_locked": "Partially encrypted (locked)",
    "partially_encrypted_unknown": "Partially encrypted (access unknown)",
    "encrypted_openable": "Encrypted (openable)",
    "encrypted_credential_required": "Encrypted (credential required)",
    "encrypted_locked": "Encrypted (locked)",
    "encrypted_unknown": "Encrypted (access unknown)",
    "unknown": "Unknown",
}


def _metadata(bde: BDE) -> MetadataState:
    info = bde.information
    return MetadataState(
        current=_state_name(info.current_state),
        next=_state_name(info.next_state),
        current_value=int(info.current_state.value),
        next_value=int(info.next_state.value),
        state_offset=info.state_offset,
        state_size=info.state_size,
        information_blocks=len(bde._available_information),
        valid_information_blocks=len(bde._valid_information),
    )


def _protectors(bde: BDE) -> Iterator[Protector]:
    for vmk in bde.information.dataset.find_vmk():
        yield _protector(vmk)


def _protector(vmk: VmkInfoDatum) -> Protector:
    priority = int(vmk.priority.value)
    kinds = _protector_kinds(priority)
    kind_set = _protector_kind_set(priority)
    return Protector(
        identifier=str(vmk.identifier),
        priority=priority,
        kinds=kinds,
        label=vmk.label(),
        needs_secret=bool(kind_set & CREDENTIAL_PROTECTORS),
        machine_bound=bool(kind_set & MACHINE_BOUND_PROTECTORS),
    )


def _verification_source(bde: BDE) -> tuple[BDE | None, str | None]:
    """Return a BDE instance that can be read for verification, without mutating ``bde``."""
    if bde.unlocked:
        return bde, None

    if bde.has_clear_key():
        try:
            from dissect.fve.bde.bde import BDE

            bde.fh.seek(0)
            clone = BDE(bde.fh)
            clone.unlock_with_clear_key()
            return clone, None
        except Exception as e:
            return None, f"Clear key present but could not be used: {e}"

    return None, None


def _access(
    bde: BDE,
    protectors: tuple[Protector, ...],
    verification: BDE | None,
    verification_error: str | None,
) -> AccessState:
    kinds = {kind for p in protectors for kind in p.kinds}
    has_clear = "CLEAR" in kinds
    has_secret = any(p.needs_secret for p in protectors)
    has_machine_bound = any(p.machine_bound and not p.needs_secret for p in protectors)
    has_any = bool(protectors)

    if bde.decrypted:
        return AccessState(
            unlocked=True,
            method="plaintext",
            credential_supplied=False,
            openable=True,
            without_external_credentials=True,
            requires_credential=False,
            readable=True,
            reason="Volume metadata reports DECRYPTED; sectors are read as plaintext",
        )

    if bde.unlocked:
        method = "clear_key" if has_clear else "credential"
        return AccessState(
            unlocked=True,
            method=method,
            credential_supplied=method == "credential",
            openable=True,
            without_external_credentials=method == "clear_key",
            requires_credential=method == "credential",
            readable=True,
            reason="Volume is already unlocked in this process"
            if method == "credential"
            else "Volume is already unlocked with the clear (obfuscated) key",
        )

    if has_clear:
        if verification is not None:
            return AccessState(
                unlocked=False,
                method="clear_key",
                credential_supplied=False,
                openable=True,
                without_external_credentials=True,
                requires_credential=False,
                readable=True,
                reason="Clear (obfuscated) key protector is present and was verified; "
                "no user secret is needed to open the volume",
            )
        return AccessState(
            unlocked=False,
            method=None,
            credential_supplied=False,
            openable=None,
            without_external_credentials=True,
            requires_credential=False,
            readable=None,
            reason=verification_error
            or "Clear key protector is present; opening without a user secret was not verified",
        )

    if has_machine_bound:
        return AccessState(
            unlocked=False,
            method=None,
            credential_supplied=False,
            openable=None,
            without_external_credentials=None,
            requires_credential=False if not has_secret else None,
            readable=None,
            reason="Volume is locked and a machine-bound (TPM) protector is present; it may "
            "open without a user secret on the original machine, so accessibility is unknown",
        )

    if has_secret:
        return AccessState(
            unlocked=False,
            method=None,
            credential_supplied=False,
            openable=None,
            without_external_credentials=False,
            requires_credential=True,
            readable=None,
            reason="Volume is locked and every available protector requires an external "
            "credential; no credential was supplied, so readability was not tested",
        )

    if has_any:
        return AccessState(
            unlocked=False,
            method=None,
            credential_supplied=False,
            openable=None,
            without_external_credentials=None,
            requires_credential=None,
            readable=None,
            reason="Volume is locked and the available protector is not sufficient to determine accessibility",
        )

    return AccessState(
        unlocked=False,
        method=None,
        credential_supplied=False,
        openable=None,
        without_external_credentials=None,
        requires_credential=None,
        readable=None,
        reason="No usable key protector information found; accessibility is unknown",
    )


def _sector_runs(bde: BDE, size: int) -> list[tuple[str, int, int, int]]:
    """Return ``(kind, logical_sector, physical_sector, count)`` for every data range.

    A single pass over the full volume is used so that EOW chunk boundaries are resolved
    consistently. The iterator only yields one run per state change, not per sector.
    """
    sector_size = bde.sector_size
    total = size // sector_size

    runs = []
    logical = 0
    stream = bde.open_layout(size=size)
    for run_type, physical, count in stream._iter_runs(0, total * sector_size):
        count = min(count, total - logical)
        if count <= 0:
            if physical == 0:
                break
            continue

        if run_type == BitlockerStream.RUN_ENCRYPTED:
            kind = "encrypted"
        elif run_type == BitlockerStream.RUN_SPARSE:
            kind = "sparse"
        elif run_type == BitlockerStream.RUN_VISTA_HEADER:
            kind = "boot"
        else:
            kind = "plaintext"

        if (
            runs
            and runs[-1][0] == kind
            and runs[-1][1] + runs[-1][3] == logical
            and runs[-1][2] + runs[-1][3] == physical
        ):
            previous = runs[-1]
            runs[-1] = (kind, previous[1], previous[2], previous[3] + count)
        else:
            runs.append((kind, logical, physical, count))
        logical += count

    return runs


def _sample_sectors(runs: list[tuple[str, int, int, int]]) -> list[tuple[str, int, int, int]]:
    """Choose deterministic sample positions from the data ranges.

    Data ranges of the same kind are coalesced across the small reserved/sparse gaps,
    yielding one contiguous group per logical state. Each group contributes its first and
    last sector. This keeps the sample count small while still covering conversion
    watermarks and range boundaries.
    """
    groups: list[list[int | str]] = []
    for kind, logical, _, count in runs:
        if kind not in ("encrypted", "plaintext"):
            continue

        if groups and groups[-1][0] == kind:
            groups[-1][2] = logical + count
        else:
            groups.append([kind, logical, logical + count])

    candidates: list[tuple[str, int, int, int]] = [
        (str(kind), int(position), int(position), 1)
        for kind, start, end in groups
        for position in sorted((start, end - 1))
    ]

    if len(candidates) > MAX_SAMPLES:
        step = max(1, len(candidates) // MAX_SAMPLES)
        candidates = candidates[::step][:MAX_SAMPLES]

    return candidates


def _physical_sector(runs: list[tuple[str, int, int, int]], logical: int) -> int:
    """Map a logical sector to the physical sector it is stored at, including virtualization."""
    for _, start, physical, count in runs:
        if start <= logical < start + count:
            return physical + (logical - start)
    return logical


def _sector_map(bde: BDE, verification: BDE | None, verify: bool, size: int) -> SectorMap:
    sector_size = bde.sector_size
    runs = _sector_runs(bde, size)

    encrypted = sum(count for kind, _, _, count in runs if kind == "encrypted")
    plaintext = sum(count for kind, _, _, count in runs if kind in ("plaintext", "boot"))
    sparse = sum(count for kind, _, _, count in runs if kind == "sparse")
    total = sum(count for _, _, _, count in runs)

    observed_by_range: dict[tuple[int, int], list[str]] = {}
    evidence = None

    if verify:
        samples = _sample_sectors(runs)
        evidence = _collect_evidence(bde, verification, samples, total, sector_size, size, runs)
        observed_by_range = _observed_by_range(runs, samples, evidence)

    ranges = tuple(
        SectorRange(
            start_sector=logical,
            sector_count=count,
            encrypted=kind == "encrypted",
            kind=kind,
            observed=observed_by_range.get((logical, count)),
            sampled_sectors=sum(
                1
                for sample in (evidence.samples if evidence else ())
                if logical <= sample["logical_sector"] < logical + count
            ),
            start_byte=logical * sector_size,
            size=count * sector_size,
        )
        for kind, logical, _, count in runs
    )

    return SectorMap(
        sector_size=sector_size,
        total_sectors=total,
        encrypted_sectors=encrypted,
        plaintext_sectors=plaintext,
        sparse_sectors=sparse,
        ranges=ranges,
        evidence=evidence,
    )


def _collect_evidence(
    bde: BDE,
    verification: BDE | None,
    samples: list[tuple[str, int, int, int]],
    total: int,
    sector_size: int,
    size: int,
    runs: list[tuple[str, int, int, int]],
) -> SectorEvidence:
    stream = None
    if verification is not None:
        try:
            stream = verification.open(size=size)
        except Exception:
            stream = None

    records = []
    encrypted_samples = 0
    plaintext_samples = 0
    inconclusive_samples = 0
    unverified_samples = 0

    for nominal, logical, _, _ in samples:
        physical = _physical_sector(runs, logical)
        raw = _read_raw(bde, physical, sector_size)
        decrypted = _read_decrypted(stream, logical, sector_size) if nominal == "encrypted" else None

        if nominal == "plaintext":
            # Plaintext ranges need no decrypted view: a non-zero mismatch with the layout
            # cannot occur, and zero sectors are ambiguous by nature.
            observed = "inconclusive" if _is_zero(raw) else "plaintext"
        elif decrypted is None:
            observed = "unverified"
        elif raw == decrypted:
            observed = "inconclusive" if _is_zero(raw) else "plaintext"
        else:
            observed = "encrypted"

        if observed == "encrypted":
            encrypted_samples += 1
        elif observed == "plaintext":
            plaintext_samples += 1
        elif observed == "inconclusive":
            inconclusive_samples += 1
        elif observed == "unverified":
            unverified_samples += 1

        records.append(
            {
                "logical_sector": logical,
                "physical_sector": physical,
                "nominal": nominal,
                "observed": observed,
                "raw_magic": _magic_name(raw),
                "decrypted_magic": None if decrypted is None else _magic_name(decrypted),
                "raw_is_zero": _is_zero(raw),
            }
        )

    return SectorEvidence(
        total_sectors=total,
        sampled_sectors=len(samples),
        encrypted_samples=encrypted_samples,
        plaintext_samples=plaintext_samples,
        inconclusive_samples=inconclusive_samples,
        unverified_samples=unverified_samples,
        verified_bytes=(len(samples) - unverified_samples) * sector_size,
        samples=tuple(records[:MAX_SAMPLE_RECORDS]),
        note="A sample confirms that sector only. Ranges are nominal layout, not proof for "
        "every sector in the range. All-zero sectors are reported as inconclusive because "
        "plaintext zeros and ciphertext zeros cannot be distinguished without known plaintext. "
        "Encrypted-declared sectors that could not be compared with a decrypted view are "
        "reported as unverified.",
    )


def _read_raw(bde: BDE, sector: int, sector_size: int) -> bytes:
    bde.fh.seek(sector * sector_size)
    return bde.fh.read(sector_size)


def _read_decrypted(stream: BitlockerStream | None, sector: int, sector_size: int) -> bytes | None:
    if stream is None:
        return None
    stream.seek(sector * sector_size)
    return stream.read(sector_size)


def _observed_by_range(
    runs: list[tuple[str, int, int, int]],
    samples: list[tuple[str, int, int, int]],
    evidence: SectorEvidence,
) -> dict[tuple[int, int], str]:
    by_range: dict[tuple[int, int], list[str]] = {}
    sample_records = {record["logical_sector"]: record for record in evidence.samples}
    for _, logical, _, _ in samples:
        record = sample_records.get(logical)
        if record is None:
            continue

        for _, start, _, count in runs:
            if start <= logical < start + count:
                by_range.setdefault((start, count), []).append(record["observed"])
                break

    result = {}
    for key, values in by_range.items():
        observed = set(values)
        if "encrypted" in observed and "plaintext" in observed:
            result[key] = "mixed"
        elif "unverified" in observed:
            result[key] = "unverified"
        elif "encrypted" in observed:
            result[key] = "encrypted"
        elif "plaintext" in observed:
            result[key] = "plaintext"
        elif "inconclusive" in observed:
            result[key] = "inconclusive"
        else:
            result[key] = "unverified"
    return result


def _conversion(bde: BDE, sector_map: SectorMap, size: int) -> ConversionState:
    info = bde.information
    current = _state_name(info.current_state)
    target = _state_name(info.next_state)
    active = current in ("switching", "switching_dirty")
    paused = current == "paused"
    converting = active or paused

    direction = None
    if converting:
        if target == "decrypted":
            direction = "decrypting"
        elif target == "encrypted":
            direction = "encrypting"
        else:
            direction = "unknown"

    if active:
        phase = "active"
    elif paused:
        phase = "paused"
    elif sector_map.partial:
        phase = "layout_partial"
    else:
        phase = "none"

    if not sector_map.partial:
        watermark_source = "none"
        watermark = 0
    elif bde.eow_information is not None:
        watermark_source = "eow_bitmap"
        watermark = _eow_boundary_sector(bde, sector_map)
    elif info.state_offset and info.state_offset < size:
        watermark_source = "state_offset"
        watermark = info.state_offset // bde.sector_size
    else:
        watermark_source = "none"
        watermark = 0

    return ConversionState(
        active=active,
        paused=paused,
        direction=direction,
        phase=phase,
        incomplete=phase in ("layout_partial", "active"),
        resumable=converting,
        watermark_sector=watermark,
        watermark_source=watermark_source,
        state_size_sectors=info.state_size // bde.sector_size,
    )


def _eow_boundary_sector(bde: BDE, sector_map: SectorMap) -> int:
    """Return the first sector whose nominal state differs from the volume-wide majority."""
    ranges = [r for r in sector_map.ranges if r.kind in ("encrypted", "plaintext")]
    if not ranges:
        return 0

    encrypted = sum(r.sector_count for r in ranges if r.encrypted)
    plaintext = sum(r.sector_count for r in ranges if not r.encrypted)
    majority_encrypted = encrypted >= plaintext

    for sector_range in ranges:
        if sector_range.encrypted != majority_encrypted:
            return sector_range.start_sector
    return 0


def _volume_size(bde: BDE) -> int:
    size = getattr(bde.fh, "size", None)
    if size is not None:
        return size
    position = bde.fh.tell()
    try:
        bde.fh.seek(0, 2)
        return bde.fh.tell()
    finally:
        bde.fh.seek(position)


def _ciphertext(sector_map: SectorMap) -> CiphertextState:
    declared = _ciphertext_label(sector_map.encrypted_sectors, sector_map.plaintext_sectors)

    evidence = sector_map.evidence
    observed = None
    confirmed = False

    if evidence is not None and evidence.unverified_samples:
        # Some declared-encrypted samples could not be compared with a decrypted view.
        # Plaintext samples alone cannot rule out ciphertext elsewhere.
        note = (
            "Sampled sectors were only partially verifiable; at least one declared-encrypted "
            "sample had no decrypted view to compare against."
        )
        if evidence.encrypted_samples:
            observed = "present"
            confirmed = True
        return CiphertextState(
            declared=declared,
            observed=observed,
            conclusion=declared,
            confirmed=confirmed,
            note=note,
        )

    if evidence is not None:
        if evidence.encrypted_samples and evidence.plaintext_samples:
            observed = "partial"
            confirmed = True
        elif evidence.encrypted_samples:
            observed = "present"
            confirmed = True
        elif evidence.plaintext_samples:
            observed = "none"
            confirmed = True

    if observed is not None:
        conclusion = observed if declared != "partial" else "partial"
        note = "Observed from sampled sectors; this is sample-level confirmation, not a full-volume scan."
        if declared == "partial" and observed in ("present", "none"):
            note += f" The sampled sectors only observed {observed}, but the layout declares partial."
    else:
        conclusion = declared
        note = "Declared by the sector layout; no usable sector observation was available."

    if declared != "unknown" and observed is not None and declared != observed:
        note += f" Layout declares {declared}, but sampled reads observed {observed}."

    return CiphertextState(
        declared=declared,
        observed=observed,
        conclusion=conclusion,
        confirmed=confirmed,
        note=note,
    )


def _status_key(status: BDEStatus) -> str:
    conclusion = status.ciphertext.conclusion
    if status.metadata.current == "decrypted" and conclusion == "none":
        return "decrypted"
    if status.conversion.paused:
        return "paused"
    if status.access.without_external_credentials and conclusion in ("present", "partial") and status.access.openable:
        return "suspended"
    if conclusion == "partial":
        return f"partially_encrypted_{_access_key(status)}"
    if conclusion == "present":
        return f"encrypted_{_access_key(status)}"
    return "unknown"


def _access_key(status: BDEStatus) -> str:
    if status.access.openable is True:
        return "openable"
    if status.access.openable is False:
        return "locked"
    if status.access.requires_credential is True:
        return "credential_required"
    return "unknown"


def _warnings(status: BDEStatus) -> list[str]:
    warnings = []
    if (
        status.ciphertext.declared != "unknown"
        and status.ciphertext.observed is not None
        and status.ciphertext.declared != status.ciphertext.observed
    ):
        warnings.append(
            f"Metadata/layout declares ciphertext as {status.ciphertext.declared}, "
            f"but sampled reads observed {status.ciphertext.observed}."
        )
    if status.metadata.current == "encrypted" and status.sector_map.partial:
        warnings.append(
            "Metadata reports ENCRYPTED, but the sector layout is mixed; the reported state "
            "is the conversion target, not the state of every sector."
        )
    if status.metadata.current == "paused":
        warnings.append(
            "Metadata reports PAUSED; ciphertext may remain in some ranges even though a "
            "clear protector allows the volume to be opened."
        )
    if status.sector_map.partial and status.metadata.current not in ("paused", "switching", "switching_dirty"):
        warnings.append(
            "Volume is only partially converted. Use sector_map.ranges and evidence rather "
            "than the single metadata state for per-range display."
        )
    if status.access.readable is None:
        warnings.append(
            "Readability was not tested. A missing credential does not prove that the volume "
            "is unreadable; it only means this process could not open it without one."
        )
    if status.access.method == "clear_key" and not status.access.unlocked:
        warnings.append(
            "The clear key was verified through a separate parser instance; the original " "BDE object was not mutated."
        )
    return warnings


def _summary(status: BDEStatus) -> str:
    parts = [f"metadata={status.metadata.current}->{status.metadata.next}"]
    parts.append(f"ciphertext={status.ciphertext.conclusion} (declared={status.ciphertext.declared})")
    parts.append(f"phase={status.conversion.phase}")

    if status.access.without_external_credentials is True:
        parts.append("access=openable without external credentials")
    elif status.access.requires_credential is True:
        parts.append(
            "access=credential required; readability not tested"
            if status.access.readable is None
            else "access=credential supplied"
        )
    elif status.access.without_external_credentials is None:
        parts.append("access=machine-bound/unknown")

    if status.sector_map.evidence is not None:
        evidence = status.sector_map.evidence
        parts.append(
            f"samples={evidence.encrypted_samples} encrypted/{evidence.plaintext_samples} plaintext/"
            f"{evidence.inconclusive_samples} inconclusive/{evidence.unverified_samples} unverified"
        )
    return "; ".join(parts)


def _display(status: BDEStatus) -> dict:
    openable = status.access.openable
    still_ciphertext = status.ciphertext.conclusion in ("present", "partial")
    badges = []
    if still_ciphertext:
        badges.append("ciphertext")
    if status.sector_map.partial:
        badges.append("partial")
    if status.conversion.paused:
        badges.append("paused")
    elif status.conversion.active:
        badges.append("converting")
    if status.access.without_external_credentials:
        badges.append("no-secret")
    if status.access.requires_credential:
        badges.append("credential-required")
    if status.ciphertext.confirmed:
        badges.append("verified")

    return {
        "state": status.state,
        "label": status.state_label,
        "headline": _headline(status),
        "badges": badges,
        "metadata_state": status.metadata.current,
        "metadata_next_state": status.metadata.next,
        "ciphertext": status.ciphertext.conclusion,
        "still_ciphertext": still_ciphertext,
        "ciphertext_confirmed": status.ciphertext.confirmed,
        "openable_now": openable,
        "openable_without_credentials": status.access.without_external_credentials,
        "requires_credential": status.access.requires_credential,
        "readable": status.access.readable,
        "unlocked": status.access.unlocked,
        "conversion": {
            "active": status.conversion.active,
            "paused": status.conversion.paused,
            "phase": status.conversion.phase,
            "direction": status.conversion.direction,
        },
        "sectors": {
            "total": status.sector_map.total_sectors,
            "encrypted": status.sector_map.encrypted_sectors,
            "plaintext": status.sector_map.plaintext_sectors,
            "sparse": status.sector_map.sparse_sectors,
            "partial": status.sector_map.partial,
            "sampled": None if status.sector_map.evidence is None else status.sector_map.evidence.sampled_sectors,
            "verified_samples": None
            if status.sector_map.evidence is None
            else status.sector_map.evidence.verified_samples,
            "encrypted_samples": status.sector_map.verified_encrypted_sectors,
            "plaintext_samples": status.sector_map.verified_plaintext_sectors,
            "coverage": status.sector_map.coverage,
        },
        "warnings": list(status.warnings),
        "summary": status.summary,
        "explanation": status.explain(),
    }


def _headline(status: BDEStatus) -> str:
    if status.state == "decrypted":
        return "Decrypted; no ciphertext remains"
    if status.state == "suspended":
        return "Suspended: ciphertext remains, but the clear key opens it without a secret"
    if status.state == "paused":
        if status.ciphertext.conclusion == "none":
            return "Conversion paused; no ciphertext remains"
        return "Conversion paused; ciphertext remains in some ranges"
    if status.state == "partially_encrypted_openable":
        return "Partially encrypted; openable with the available key material"
    if status.state == "partially_encrypted_credential_required":
        return "Partially encrypted; an external credential is required"
    if status.state == "partially_encrypted_locked":
        return "Partially encrypted; locked"
    if status.state == "partially_encrypted_unknown":
        return "Partially encrypted; access could not be determined"
    if status.state == "encrypted_openable":
        return "Encrypted; openable with the available key material"
    if status.state == "encrypted_credential_required":
        return "Encrypted; an external credential is required"
    if status.state == "encrypted_locked":
        return "Encrypted; locked"
    if status.state == "encrypted_unknown":
        return "Encrypted; access could not be determined"
    return "Unknown state"


def _tri(value: bool | None) -> str:
    if value is None:
        return "unknown"
    return "yes" if value else "no"
