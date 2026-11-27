# SPDX-FileCopyrightText: 2026 spdx contributors
#
# SPDX-License-Identifier: Apache-2.0
"""Offline verification of SPDX snippet ranges against the files they were taken from.

SPDX snippet ranges are 1-based and inclusive on both ends. Byte ranges count raw
octets (which matters for multi-byte encodings), while line ranges count logical
lines (``\\r\\n`` and ``\\n`` both terminate a single line). The two ranges are
therefore sliced independently, each in its own unit, and never converted into
each other.
"""
import hashlib
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from beartype.typing import Union

from spdx_tools.spdx.model import ChecksumAlgorithm, Document, File, Snippet

SUPPORTED_CHECKSUMS = {
    ChecksumAlgorithm.SHA1,
    ChecksumAlgorithm.SHA224,
    ChecksumAlgorithm.SHA256,
    ChecksumAlgorithm.SHA384,
    ChecksumAlgorithm.SHA512,
    ChecksumAlgorithm.MD5,
}


class RangeStatus(Enum):
    """Outcome of extracting one declared range from a source file."""

    MATCH = "match"
    """The range is in bounds and its extracted content is identical to the byte slice."""
    CONTENT_MISMATCH = "content_mismatch"
    """The range is in bounds and well-formed, but the independently extracted slices differ."""
    OUT_OF_BOUNDS = "out_of_bounds"
    """The declared range points past the end of the actual file."""
    NOT_PRESENT = "not_present"
    """The document does not declare a range of this unit."""


class SnippetStatus(Enum):
    VERIFIED = "verified"
    """Every declared range was extracted and all extracted slices agree."""
    MISMATCH = "mismatch"
    """At least one range is well-formed, but the extracted content does not agree."""
    OUT_OF_BOUNDS = "out_of_bounds"
    """At least one declared range points past the end of the actual file."""
    SOURCE_MISSING = "source_missing"
    """The file referenced by the snippet cannot be opened."""
    UNRESOLVED = "unresolved"
    """The snippet references an SPDX id that is not defined by the document."""


@dataclass(frozen=True)
class RangeVerification:
    """Result of checking a single 1-based inclusive range in its own unit."""

    unit: str
    declared_range: Optional[Tuple[int, int]]
    status: RangeStatus
    extracted_length: Optional[int] = None
    detail: Optional[str] = None


@dataclass(frozen=True)
class ChecksumVerification:
    algorithm: str
    declared: str
    actual: str
    matches: bool


@dataclass
class SnippetVerification:
    snippet_spdx_id: str
    file_spdx_id: str
    source_path: Optional[str]
    status: SnippetStatus
    byte_range: RangeVerification
    line_range: RangeVerification
    extracted_sha256: Optional[str] = None
    detail: Optional[str] = None

    @property
    def holds(self) -> bool:
        """True only when every declared range still resolves to identical content."""
        return self.status == SnippetStatus.VERIFIED


@dataclass
class SourceFileReport:
    """Reviewable summary of one source file on disk."""

    spdx_id: str
    declared_name: str
    resolved_path: Optional[str]
    file_size_bytes: Optional[int]
    line_count: Optional[int]
    newline_style: Optional[str]
    sha256: Optional[str]
    checksum_results: List[ChecksumVerification] = field(default_factory=list)
    exists: bool = True
    detail: Optional[str] = None


@dataclass
class VerificationReport:
    source_files: List[SourceFileReport] = field(default_factory=list)
    snippets: List[SnippetVerification] = field(default_factory=list)

    @property
    def verified_snippet_ids(self) -> List[str]:
        return [entry.snippet_spdx_id for entry in self.snippets if entry.holds]

    @property
    def failed_snippet_ids(self) -> List[str]:
        return [entry.snippet_spdx_id for entry in self.snippets if not entry.holds]


def _split_inclusive(raw: bytes, begin: int, end: int, unit: str) -> bytes:
    """Slice a 1-based inclusive range, converting units without mixing them."""
    if unit == "byte":
        return raw[begin - 1 : end]
    return b"".join(_split_lines(raw)[begin - 1 : end])


def _split_lines(raw: bytes) -> List[bytes]:
    """Split into logical lines, keeping every line terminator.

    ``\\r\\n`` is treated as one terminator and a lone ``\\r`` as another, so
    CRLF, CR and LF files with identical visible text produce the same number
    of logical lines.
    """
    lines: List[bytes] = []
    start = 0
    index = 0
    while index < len(raw):
        if raw[index] == 0x0A:  # \n
            lines.append(raw[start : index + 1])
            start = index + 1
        elif raw[index] == 0x0D:  # \r
            if index + 1 < len(raw) and raw[index + 1] == 0x0A:
                lines.append(raw[start : index + 2])
                index += 2
                start = index
                continue
            lines.append(raw[start : index + 1])
            start = index + 1
        index += 1
    if start < len(raw):
        lines.append(raw[start:])
    return lines


def _detect_newline_style(raw: bytes) -> str:
    has_crlf = b"\r\n" in raw
    stripped = raw.replace(b"\r\n", b"")
    has_lf = b"\n" in stripped
    has_cr = b"\r" in stripped
    styles = []
    if has_crlf:
        styles.append("CRLF")
    if has_cr:
        styles.append("CR")
    if has_lf:
        styles.append("LF")
    if not styles:
        return "none"
    if len(styles) == 1:
        return styles[0]
    return "mixed (" + " and ".join(styles) + ")"


def _verify_range(
    raw: bytes, declared_range: Optional[Tuple[int, int]], unit: str, total_units: int
) -> Tuple[RangeVerification, Optional[bytes]]:
    if declared_range is None:
        return RangeVerification(unit, None, RangeStatus.NOT_PRESENT), None

    begin, end = declared_range
    if begin < 1 or end < begin or end > total_units:
        return (
            RangeVerification(
                unit,
                declared_range,
                RangeStatus.OUT_OF_BOUNDS,
                detail=f"declared {unit} range {begin}:{end} does not fit into {total_units} {unit}(s)",
            ),
            None,
        )

    extracted = _split_inclusive(raw, begin, end, unit)
    return (
        RangeVerification(
            unit,
            declared_range,
            RangeStatus.MATCH,
            extracted_length=len(extracted),
        ),
        extracted,
    )


def _verify_checksums(raw: bytes, spdx_file: File) -> List[ChecksumVerification]:
    results: List[ChecksumVerification] = []
    for checksum in spdx_file.checksums:
        if checksum.algorithm not in SUPPORTED_CHECKSUMS:
            continue
        hasher = hashlib.new(checksum.algorithm.name.lower())
        hasher.update(raw)
        actual = hasher.hexdigest()
        results.append(
            ChecksumVerification(
                algorithm=checksum.algorithm.name,
                declared=checksum.value,
                actual=actual,
                matches=checksum.value.lower() == actual.lower(),
            )
        )
    return results


def _index_files(document: Document) -> Dict[str, File]:
    return {spdx_file.spdx_id: spdx_file for spdx_file in document.files}


def _resolve_source_path(
    spdx_file: File, base_dir: Path, path_overrides: Dict[str, Path]
) -> Optional[Path]:
    if spdx_file.spdx_id in path_overrides:
        return path_overrides[spdx_file.spdx_id]
    candidate = Path(spdx_file.name)
    if not candidate.is_absolute():
        candidate = base_dir / candidate
    return candidate


def _build_source_file_report(
    spdx_file: File, resolved_path: Path, path_overrides: Dict[str, Path]
) -> Tuple[SourceFileReport, Optional[bytes]]:
    try:
        raw = resolved_path.read_bytes()
    except OSError as error:
        report = SourceFileReport(
            spdx_id=spdx_file.spdx_id,
            declared_name=spdx_file.name,
            resolved_path=str(resolved_path),
            file_size_bytes=None,
            line_count=None,
            newline_style=None,
            sha256=None,
            exists=False,
            detail=f"could not read file: {error}",
        )
        return report, None

    sha256 = hashlib.sha256(raw).hexdigest()
    line_count = len(_split_lines(raw))
    report = SourceFileReport(
        spdx_id=spdx_file.spdx_id,
        declared_name=spdx_file.name,
        resolved_path=str(resolved_path),
        file_size_bytes=len(raw),
        line_count=line_count,
        newline_style=_detect_newline_style(raw),
        sha256=sha256,
        checksum_results=_verify_checksums(raw, spdx_file),
        exists=True,
    )
    return report, raw


def verify_snippet(
    snippet: Snippet,
    raw: Optional[bytes],
    source_path: Optional[Path],
) -> SnippetVerification:
    """Verify one snippet against the already-loaded bytes of its source file."""
    if raw is None:
        line_status = RangeStatus.NOT_PRESENT if snippet.line_range is None else RangeStatus.OUT_OF_BOUNDS
        return SnippetVerification(
            snippet_spdx_id=snippet.spdx_id,
            file_spdx_id=snippet.file_spdx_id,
            source_path=str(source_path) if source_path else None,
            status=SnippetStatus.SOURCE_MISSING,
            byte_range=RangeVerification("byte", snippet.byte_range, RangeStatus.OUT_OF_BOUNDS),
            line_range=RangeVerification("line", snippet.line_range, line_status),
            detail="source file could not be read",
        )

    byte_total = len(raw)
    line_total = len(_split_lines(raw))

    byte_result, byte_slice = _verify_range(raw, snippet.byte_range, "byte", byte_total)
    line_result, line_slice = _verify_range(raw, snippet.line_range, "line", line_total)

    statuses = {byte_result.status}
    if snippet.line_range is not None:
        statuses.add(line_result.status)

    if RangeStatus.OUT_OF_BOUNDS in statuses:
        status = SnippetStatus.OUT_OF_BOUNDS
    else:
        slices = [candidate for candidate in (byte_slice, line_slice) if candidate is not None]
        if all(candidate == slices[0] for candidate in slices[1:]):
            status = SnippetStatus.VERIFIED
        else:
            status = SnippetStatus.MISMATCH

    extracted_sha256 = hashlib.sha256(byte_slice).hexdigest() if byte_slice is not None else None

    detail = None
    if status == SnippetStatus.MISMATCH:
        detail = (
            f"byte range {snippet.byte_range} and line range {snippet.line_range} are both in bounds, "
            f"but extract different content ({len(byte_slice)} vs {len(line_slice)} bytes)"
        )

    return SnippetVerification(
        snippet_spdx_id=snippet.spdx_id,
        file_spdx_id=snippet.file_spdx_id,
        source_path=str(source_path) if source_path else None,
        status=status,
        byte_range=byte_result,
        line_range=line_result,
        extracted_sha256=extracted_sha256,
        detail=detail,
    )


def verify_document_snippets(
    document: Document,
    base_dir: Union[str, Path] = ".",
    path_overrides: Optional[Dict[str, Union[str, Path]]] = None,
) -> VerificationReport:
    """Verify every snippet in a parsed SPDX 2.x document against local source files.

    ``base_dir`` resolves relative file names; ``path_overrides`` maps an SPDX file id
    to an explicit replacement path (e.g. the "control" copy used in a re-check).
    No network access is performed.
    """
    base_path = Path(base_dir)
    overrides = {key: Path(value) for key, value in (path_overrides or {}).items()}
    files_by_id = _index_files(document)
    report = VerificationReport()
    loaded: Dict[str, Optional[bytes]] = {}
    paths: Dict[str, Optional[Path]] = {}

    referenced_file_ids = {snippet.file_spdx_id for snippet in document.snippets}
    for file_id in sorted(referenced_file_ids):
        spdx_file = files_by_id.get(file_id)
        if spdx_file is None:
            report.source_files.append(
                SourceFileReport(
                    spdx_id=file_id,
                    declared_name="<undefined>",
                    resolved_path=None,
                    file_size_bytes=None,
                    line_count=None,
                    newline_style=None,
                    sha256=None,
                    exists=False,
                    detail="no File element with this SPDX id exists in the document",
                )
            )
            loaded[file_id] = None
            paths[file_id] = None
            continue

        resolved_path = _resolve_source_path(spdx_file, base_path, overrides)
        file_report, raw = _build_source_file_report(spdx_file, resolved_path, overrides)
        report.source_files.append(file_report)
        loaded[file_id] = raw
        paths[file_id] = resolved_path

    for snippet in document.snippets:
        if snippet.file_spdx_id not in files_by_id:
            report.snippets.append(
                SnippetVerification(
                    snippet_spdx_id=snippet.spdx_id,
                    file_spdx_id=snippet.file_spdx_id,
                    source_path=None,
                    status=SnippetStatus.UNRESOLVED,
                    byte_range=RangeVerification("byte", snippet.byte_range, RangeStatus.OUT_OF_BOUNDS),
                    line_range=RangeVerification(
                        "line",
                        snippet.line_range,
                        RangeStatus.NOT_PRESENT if snippet.line_range is None else RangeStatus.OUT_OF_BOUNDS,
                    ),
                    detail="snippet references an SPDX file id that is not defined in the document",
                )
            )
            continue

        report.snippets.append(
            verify_snippet(snippet, loaded[snippet.file_spdx_id], paths[snippet.file_spdx_id])
        )

    return report
