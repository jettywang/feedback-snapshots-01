from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from dissect.evidence.ewf.ewf import Segment

EVF_SIGNATURES = (b"EVF\x09\x0d\x0a\xff\x00", b"LVF\x09\x0d\x0a\xff\x00")

# A set identifier consisting entirely of NUL bytes means the producer did not record one.
UNSET_SET_IDENTIFIER = b"\x00" * 16


class CheckStatus(str, Enum):
    """The outcome of a single set-integrity check."""

    CONFIRMED = "confirmed"
    CONTRADICTED = "contradicted"
    UNCONFIRMABLE = "unconfirmable"


class CheckStage(str, Enum):
    """When a contradiction can be observed.

    ``OPEN`` checks only read segment headers and sections and can run while the container is
    opened. ``READ`` checks require accessing chunk data through the tables.
    """

    OPEN = "open"
    READ = "read"


@dataclass(frozen=True)
class IntegrityCheck:
    """A single collection-integrity observation.

    Args:
        name: Stable identifier of the check.
        status: Whether the expectation was confirmed, contradicted, or cannot be confirmed.
        detail: Human readable explanation of the observation.
    """

    name: str
    status: CheckStatus
    detail: str


@dataclass(frozen=True)
class VolumeParameters:
    """The volume parameters that must describe the same logical disk across every segment.

    Args:
        number_of_chunks: Number of chunks declared for the whole image.
        sectors_per_chunk: Number of sectors per chunk.
        sector_size: Number of bytes per sector.
        number_of_sectors: Total number of sectors, when provided by the section variant.
    """

    number_of_chunks: int
    sectors_per_chunk: int
    sector_size: int
    number_of_sectors: int | None


@dataclass
class SetIntegrity:
    """The result of validating that a collection of segments belongs to one coherent EWF image.

    Only information the EWF format actually records is treated as evidence. When the format does
    not provide enough information to confirm an expectation, the corresponding check is reported
    as :attr:`CheckStatus.UNCONFIRMABLE` instead of being guessed from file names.
    """

    checks: list[IntegrityCheck] = field(default_factory=list)

    def add(self, name: str, status: CheckStatus, detail: str) -> None:
        self.checks.append(IntegrityCheck(name, status, detail))

    @property
    def contradictions(self) -> list[IntegrityCheck]:
        """All checks that found a hard contradiction."""
        return [check for check in self.checks if check.status is CheckStatus.CONTRADICTED]

    @property
    def unconfirmable(self) -> list[IntegrityCheck]:
        """All expectations that could not be confirmed from the recorded metadata."""
        return [check for check in self.checks if check.status is CheckStatus.UNCONFIRMABLE]

    @property
    def is_coherent(self) -> bool:
        """Whether any hard (open- or read-time) contradiction was found."""
        return not self.contradictions

    def by_name(self, name: str) -> IntegrityCheck:
        for check in self.checks:
            if check.name == name:
                return check
        raise KeyError(name)


def _set_identifier(segment: Segment) -> bytes | None:
    """Return the recorded acquisition set identifier, or ``None`` when the segment records none.

    The Smart volume variant does not carry a set identifier, in which case the format simply does
    not provide the information and ``None`` is returned.
    """
    section = segment.identity_section
    if section is None or not hasattr(section.data, "set_identifier"):
        return None

    identifier = bytes(section.data.set_identifier)
    return None if identifier == UNSET_SET_IDENTIFIER else identifier


def _volume_parameters(segment: Segment) -> VolumeParameters | None:
    """Return the common volume parameters recorded by a segment, if present."""
    section = segment.identity_section
    if section is None:
        return None

    data = section.data
    number_of_sectors = getattr(data, "number_of_sectors", None)
    return VolumeParameters(
        number_of_chunks=data.number_of_chunks,
        sectors_per_chunk=data.sectors_per_chunk,
        sector_size=data.bytes_per_sector,
        number_of_sectors=number_of_sectors,
    )


def analyze_segments(segments: list[Segment], *, input_order: list[int] | None = None) -> SetIntegrity:
    """Validate the open-time coherence of an ordered collection of EWF segments.

    The segments must be ordered by their embedded segment number (1-based and contiguous). The
    optional ``input_order`` records the positions in which the segments were originally supplied,
    which allows reporting whether the caller provided them in canonical order.

    Only metadata stored inside the segments is inspected here; file names are never consulted.
    Contradictions that require dereferencing chunk offsets are not part of this analysis and are
    detected while reading.
    """
    report = SetIntegrity()
    total = len(segments)

    if input_order is not None and input_order != list(range(total)):
        report.add(
            "input_order",
            CheckStatus.CONFIRMED,
            "Segments were supplied out of order and will be ordered by their embedded segment numbers",
        )
    else:
        report.add(
            "input_order",
            CheckStatus.CONFIRMED,
            "Segments were supplied in canonical segment-number order",
        )

    # Signatures and the embedded, contiguous segment numbering.
    numbering_ok = True
    for position, segment in enumerate(segments):
        expected = position + 1
        if segment.header.signature not in EVF_SIGNATURES:
            numbering_ok = False
            report.add(
                "signature",
                CheckStatus.CONTRADICTED,
                (
                    f"Segment at position {position} has signature {segment.header.signature!r}, "
                    "expected an EVF/LVF signature"
                ),
            )
        if segment.number != expected:
            numbering_ok = False
            report.add(
                "segment_number",
                CheckStatus.CONTRADICTED,
                f"Segment at position {position} declares number {segment.number}, expected {expected}",
            )
    if numbering_ok:
        report.add(
            "segment_number",
            CheckStatus.CONFIRMED,
            f"All {total} segments declare contiguous numbers 1..{total}",
        )

    # Common acquisition identity. The set identifier is the strongest common identity the format
    # exposes, but a Smart volume variant or an unset identifier can leave it unavailable.
    reference_identifier: bytes | None = None
    identifier_contradiction = False
    missing_identifier = False
    for segment in segments:
        identifier = _set_identifier(segment)
        if identifier is None:
            missing_identifier = True
            continue
        if reference_identifier is None:
            reference_identifier = identifier
        elif identifier != reference_identifier:
            identifier_contradiction = True
            report.add(
                "set_identifier",
                CheckStatus.CONTRADICTED,
                (
                    f"Segment {segment.number} set identifier {identifier.hex()} does not match the reference "
                    f"{reference_identifier.hex()}"
                ),
            )

    if not identifier_contradiction:
        if reference_identifier is None:
            report.add(
                "set_identifier",
                CheckStatus.UNCONFIRMABLE,
                "No segment records an acquisition set identifier, so a common identity cannot be confirmed",
            )
        elif missing_identifier:
            report.add(
                "set_identifier",
                CheckStatus.UNCONFIRMABLE,
                f"Some segments record no set identifier; the others share {reference_identifier.hex()}",
            )
        else:
            report.add(
                "set_identifier",
                CheckStatus.CONFIRMED,
                f"All segments share acquisition set identifier {reference_identifier.hex()}",
            )

    # Common volume parameters.
    reference_params: VolumeParameters | None = None
    params_contradiction = False
    params_missing = False
    for segment in segments:
        params = _volume_parameters(segment)
        if params is None:
            params_missing = True
            continue
        if reference_params is None:
            reference_params = params
        elif params != reference_params:
            params_contradiction = True
            report.add(
                "volume_parameters",
                CheckStatus.CONTRADICTED,
                f"Segment {segment.number} volume parameters {params} do not match the reference {reference_params}",
            )

    if not params_contradiction:
        if reference_params is None:
            report.add(
                "volume_parameters",
                CheckStatus.UNCONFIRMABLE,
                "No segment records volume parameters, so a common volume geometry cannot be confirmed",
            )
        elif params_missing:
            report.add(
                "volume_parameters",
                CheckStatus.UNCONFIRMABLE,
                "Some segments record no volume parameters; the recorded parameters otherwise agree",
            )
        else:
            report.add(
                "volume_parameters",
                CheckStatus.CONFIRMED,
                f"All segments record identical volume parameters: {reference_params}",
            )

    # Termination relationship: only the final segment is terminated with a "done" section.
    for position, segment in enumerate(segments):
        is_last = position == total - 1
        if segment.is_terminal:
            if not is_last:
                report.add(
                    "termination",
                    CheckStatus.CONTRADICTED,
                    f"Segment {segment.number} is terminated with a done section but is not the final segment",
                )
        elif is_last:
            report.add(
                "termination",
                CheckStatus.CONTRADICTED,
                f"Final segment {segment.number} is not terminated with a done section",
            )
    if all(seg.is_terminal == (position == total - 1) for position, seg in enumerate(segments)):
        report.add(
            "termination",
            CheckStatus.CONFIRMED,
            "Only the final segment is terminated with a done section",
        )

    # Confirmable block count: table entries must add up to the number of chunks the volume declares.
    if reference_params is not None:
        table_chunks = sum(sum(table.number_of_entries for table in segment.tables) for segment in segments)
        declared_chunks = reference_params.number_of_chunks
        if table_chunks != declared_chunks:
            report.add(
                "block_count",
                CheckStatus.CONTRADICTED,
                (
                    f"Tables describe {table_chunks} chunks but the volume section declares {declared_chunks}; "
                    "the segment collection cannot represent the declared disk"
                ),
            )
        else:
            report.add(
                "block_count",
                CheckStatus.CONFIRMED,
                f"Table entries account for all {declared_chunks} chunks declared by the volume section",
            )
    else:
        report.add(
            "block_count",
            CheckStatus.UNCONFIRMABLE,
            "No volume section declares a chunk count, so the number of blocks cannot be confirmed",
        )

    return report
