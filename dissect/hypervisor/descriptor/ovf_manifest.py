from __future__ import annotations

import hashlib
import hmac
import re
from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING, BinaryIO
from urllib.parse import unquote

from dissect.hypervisor.descriptor.ovf import OVF
from dissect.hypervisor.exceptions import ManifestError

if TYPE_CHECKING:
    from collections.abc import Iterator, Mapping

# A manifest line is "<algorithm> (<name>) = <digest>", where the digest is
# hexadecimal. Names may contain spaces, parentheses or non-ASCII characters
# that the exporter percent-encoded.
_MANIFEST_LINE_RE = re.compile(
    r"^(?P<algorithm>[A-Za-z0-9_-]+)\s*\((?P<name>.*)\)\s*=\s*(?P<digest>[0-9A-Fa-f]+)\s*$"
)
_HASH_CHUNK_SIZE = 1024 * 1024


class ManifestStatus(Enum):
    """Outcome of checking a single file against the manifest."""

    VERIFIED = "verified"
    DIGEST_MISMATCH = "digest_mismatch"
    UNSUPPORTED_ALGORITHM = "unsupported_algorithm"
    MISSING_CANDIDATE = "missing_candidate"
    MISSING_FROM_MANIFEST = "missing_from_manifest"
    CONFLICTING_ENTRIES = "conflicting_entries"


@dataclass(frozen=True)
class ManifestDigest:
    """A single ``<algorithm> (<name>) = <digest>`` manifest entry."""

    algorithm: str
    digest: bytes


@dataclass(frozen=True)
class ManifestFileResult:
    """Verification details for one name referenced by the OVF."""

    name: str
    status: ManifestStatus
    expected: tuple[ManifestDigest, ...] = ()
    actual: tuple[ManifestDigest, ...] = ()
    detail: str | None = None


@dataclass(frozen=True)
class ManifestVerificationResult:
    """Result of verifying the complete set of files referenced by an OVF.

    A passing check only states that the supplied candidate files match the
    digests in the supplied manifest for the names referenced by the supplied
    OVF. It neither authenticates the manifest or OVF nor makes the export
    source itself trusted.
    """

    files: tuple[ManifestFileResult, ...] = ()
    unreferenced_manifest_entries: tuple[str, ...] = ()
    unreferenced_candidates: tuple[str, ...] = ()

    @property
    def verified(self) -> bool:
        return bool(self.files) and all(result.status is ManifestStatus.VERIFIED for result in self.files)

    def __bool__(self) -> bool:
        return self.verified


class OVFManifest:
    """Parser for an OVF manifest (``.mf``) file.

    Manifest names are connected to OVF ``ovf:href`` values exactly: OVF
    hrefs are percent-decoded and compared verbatim to manifest entry names.
    No directory lookups are performed.
    """

    def __init__(self, fh: BinaryIO | str):
        self.entries: dict[str, list[ManifestDigest]] = {}
        for line_number, line in enumerate(self._read_lines(fh), start=1):
            if not line:
                continue
            match = _MANIFEST_LINE_RE.match(line)
            if match is None:
                raise ManifestError(f"Malformed manifest entry on line {line_number}: {line!r}")
            # Manifest names are stored verbatim; only OVF hrefs are
            # percent-decoded when the two are connected in ``verify``.
            name = match.group("name")
            entry = ManifestDigest(
                algorithm=match.group("algorithm").lower(),
                digest=bytes.fromhex(match.group("digest")),
            )
            self.entries.setdefault(name, []).append(entry)

    @staticmethod
    def _read_lines(fh: BinaryIO | str) -> Iterator[str]:
        raw = fh.read() if not isinstance(fh, str) else fh.encode()
        for line in raw.decode("utf-8").splitlines():
            yield line.strip()

    def digests(self, name: str) -> tuple[ManifestDigest, ...]:
        return tuple(self.entries.get(name, ()))

    def verify(self, ovf: OVF, candidates: Mapping[str, BinaryIO]) -> ManifestVerificationResult:
        """Verify every file referenced by the OVF against the manifest.

        Args:
            ovf: Parsed OVF descriptor whose ``ovf:File`` references name the
                files that must be verified.
            candidates: Explicitly supplied candidate file streams keyed by
                decoded file name; nothing is looked up from a directory.

        Returns:
            A :class:`ManifestVerificationResult` describing each referenced
            file. It only evaluates to ``True`` when every referenced file
            verifies against every manifest digest.
        """
        referenced = {unquote(href) for href in ovf.references.values()}

        results = [self._verify_file(name, candidates) for name in referenced]
        unreferenced_manifest = tuple(sorted(set(self.entries) - referenced))
        unreferenced_candidates = tuple(sorted(set(candidates) - referenced))
        return ManifestVerificationResult(
            files=tuple(results),
            unreferenced_manifest_entries=unreferenced_manifest,
            unreferenced_candidates=unreferenced_candidates,
        )

    def _verify_file(self, name: str, candidates: Mapping[str, BinaryIO]) -> ManifestFileResult:
        digests = self.digests(name)
        if not digests:
            return ManifestFileResult(name, ManifestStatus.MISSING_FROM_MANIFEST)

        candidate = candidates.get(name)
        if candidate is None:
            return ManifestFileResult(
                name,
                ManifestStatus.MISSING_CANDIDATE,
                expected=digests,
                detail="No candidate file was supplied for this manifest entry",
            )

        conflict = self._conflicting_digests(digests)
        if conflict is not None:
            algorithm, digest_values = conflict
            return ManifestFileResult(
                name,
                ManifestStatus.CONFLICTING_ENTRIES,
                expected=digests,
                detail=(
                    f"Manifest contains multiple {algorithm} digests for {name!r}: "
                    f"{', '.join(value.hex() for value in digest_values)}"
                ),
            )

        algorithms = {entry.algorithm for entry in digests}
        actual = self._compute_digests(candidate, algorithms)

        mismatched = [
            entry
            for entry in digests
            if entry.algorithm in hashlib.algorithms_guaranteed
            and not hmac.compare_digest(actual[entry.algorithm], entry.digest)
        ]
        if mismatched:
            return ManifestFileResult(
                name,
                ManifestStatus.DIGEST_MISMATCH,
                expected=digests,
                actual=self._as_digests(actual),
                detail="Candidate file content does not match the manifest digest",
            )

        unsupported = sorted(alg for alg in algorithms if alg not in hashlib.algorithms_guaranteed)
        if unsupported:
            return ManifestFileResult(
                name,
                ManifestStatus.UNSUPPORTED_ALGORITHM,
                expected=digests,
                actual=self._as_digests(actual),
                detail=f"Unsupported digest algorithm(s): {', '.join(unsupported)}",
            )

        return ManifestFileResult(
            name,
            ManifestStatus.VERIFIED,
            expected=digests,
            actual=self._as_digests(actual),
        )

    @staticmethod
    def _conflicting_digests(
        digests: tuple[ManifestDigest, ...],
    ) -> tuple[str, list[bytes]] | None:
        seen: dict[str, bytes] = {}
        for entry in digests:
            previous = seen.get(entry.algorithm)
            if previous is not None and previous != entry.digest:
                return entry.algorithm, [previous, entry.digest]
            seen.setdefault(entry.algorithm, entry.digest)
        return None

    @staticmethod
    def _compute_digests(candidate: BinaryIO, algorithms: set[str]) -> dict[str, bytes]:
        hashers = {
            algorithm: hashlib.new(algorithm)
            for algorithm in algorithms
            if algorithm in hashlib.algorithms_guaranteed
        }
        while True:
            chunk = candidate.read(_HASH_CHUNK_SIZE)
            if not chunk:
                break
            for hasher in hashers.values():
                hasher.update(chunk)
        return {algorithm: hasher.digest() for algorithm, hasher in hashers.items()}

    @staticmethod
    def _as_digests(actual: Mapping[str, bytes]) -> tuple[ManifestDigest, ...]:
        return tuple(ManifestDigest(algorithm, digest) for algorithm, digest in sorted(actual.items()))


def verify_ovf_manifest(
    ovf: OVF,
    manifest: OVFManifest | BinaryIO | str,
    candidates: Mapping[str, BinaryIO],
) -> ManifestVerificationResult:
    """Verify an OVF export against an explicitly supplied manifest.

    The caller must supply the OVF, the manifest and every candidate file
    explicitly. Files are connected by name only; this function never searches
    a host directory for same-named files. A passing result merely proves that
    the contents of the supplied materials match; it does not establish that
    the export source itself is trusted.

    Args:
        ovf: Parsed OVF descriptor.
        manifest: Parsed manifest, or a manifest stream/text.
        candidates: Candidate file streams keyed by decoded file name.

    Returns:
        A :class:`ManifestVerificationResult`; ``result.verified`` (or
        ``bool(result)``) is only ``True`` when the whole referenced set
        verifies.
    """
    parsed_manifest = manifest if isinstance(manifest, OVFManifest) else OVFManifest(manifest)
    return parsed_manifest.verify(ovf, candidates)


__all__ = [
    "ManifestDigest",
    "ManifestError",
    "ManifestFileResult",
    "ManifestStatus",
    "ManifestVerificationResult",
    "OVFManifest",
    "verify_ovf_manifest",
]
