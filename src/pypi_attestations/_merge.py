"""Offline merging of attestation evidence collected from several backups.

This module is NOT a public API, and is not considered stable.

The merger is fully offline: it never performs network access and never
verifies signatures against a transparency log. Its job is to consolidate
attestation evidence that has already been collected (from one or more
backup copies) into a single, indexed :class:`MergeReceipt`.

Each piece of evidence is indexed by:

* the artifact digest (and name) it attests to;
* the publisher associated with the evidence (if any);
* the signature on the attestation statement; and
* the source record the evidence was loaded from.

The same attestation collected more than once is recognized as a duplicate
and merged into a single record, while attestations from different
publishers for the same package are kept as separate records. Any data that
cannot be carried through a format conversion, and any unknown fields
encountered while parsing, are reported explicitly on the affected records.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable
from enum import StrEnum
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field, TypeAdapter
from pydantic_core import ValidationError
from rfc8785 import dumps as canonicalize
from sigstore.models import Bundle, InvalidBundle
from sigstore_models.rekor.v1 import TransparencyLogEntry as _InnerTlogEntry

from pypi_attestations._impl import (
    Attestation,
    ConversionError,
    Envelope,
    Publisher,
    VerificationMaterial,
)

#: The wire key under which a PEP 740 attestation carries its envelope.
_ENVELOPE_KEY = "envelope"
#: The wire key under which a PEP 740 attestation carries its verification material.
_VM_KEY = "verification_material"
#: The wire key under which verification material carries its transparency entries.
_TLOG_KEY = "transparency_entries"
#: The wire key under which a Sigstore bundle carries its transparency entries.
_BUNDLE_TLOG_KEY = "tlogEntries"
#: The wire key under which a Sigstore bundle carries its verification material.
_BUNDLE_VM_KEY = "verificationMaterial"


class SourceKind(StrEnum):
    """The kind of source document an attestation was collected from."""

    PEP740_ATTESTATION = "pep740-attestation"
    """A standalone PEP 740 attestation object (``*.attestation``)."""

    PEP740_PROVENANCE = "pep740-provenance"
    """A PEP 740 provenance object (``*.provenance``)."""

    SIGSTORE_BUNDLE = "sigstore-bundle"
    """A Sigstore bundle (``*.sigstore``)."""


class WarningCode(StrEnum):
    """Stable codes for warnings attached to merged evidence records."""

    UNKNOWN_FIELDS = "unknown-fields"
    """The source document contained fields the merger does not model."""

    DROPPED_TRANSPARENCY_ENTRIES = "dropped-transparency-entries"
    """A Sigstore bundle carried multiple transparency entries; only the first survives."""

    UNKNOWN_PUBLISHER = "unknown-publisher"
    """The publisher could not be modeled, so only its raw form is retained."""


class EvidenceSource(BaseModel):
    """Provenance for a single observation of an attestation."""

    kind: SourceKind
    """The kind of document the attestation was collected from."""

    path: str
    """The path of the source document, as provided to the merger."""

    sha256: str
    """The SHA-256 digest of the raw bytes of the source document."""

    bundle_index: int | None = None
    """The index of the attestation within its source bundle, if applicable."""

    duplicate: bool = False
    """Whether this observation duplicated an already-collected attestation."""

    @classmethod
    def from_bytes(
        cls,
        kind: SourceKind,
        path: str,
        data: bytes,
        *,
        bundle_index: int | None = None,
        duplicate: bool = False,
    ) -> EvidenceSource:
        """Construct an :class:`EvidenceSource` from raw document bytes."""
        return cls(
            kind=kind,
            path=path,
            sha256=hashlib.sha256(data).hexdigest(),
            bundle_index=bundle_index,
            duplicate=duplicate,
        )


class OmittedData(BaseModel):
    """A piece of source data that could not be carried into the output."""

    location: str
    """A dotted path identifying where the data was found in the source document."""

    reason: str
    """Why the data was omitted during conversion."""

    data: Any = None
    """The omitted data itself, retained so the loss is fully visible."""


class EvidenceRecord(BaseModel):
    """A single indexed attestation within a :class:`MergeReceipt`."""

    evidence_id: str
    """A stable identifier for this (artifact, publisher, signature) evidence."""

    artifact_name: str
    """The distribution filename attested to by this evidence."""

    artifact_digest: str
    """The SHA-256 digest of the attested distribution."""

    publisher: Publisher | None = None
    """The modeled publisher, or `None` when the source carried no publisher."""

    publisher_raw: dict[str, Any] | None = None
    """The raw publisher mapping, retained when the publisher could not be modeled."""

    signature_sha256: str
    """The SHA-256 digest of the attestation signature bytes."""

    attestation: Attestation
    """The full PEP 740 attestation object."""

    sources: list[EvidenceSource]
    """Every observation of this attestation across the loaded backups."""

    unknown_fields: dict[str, Any] = Field(default_factory=dict)
    """Unknown fields encountered while parsing, keyed by dotted source path."""

    omitted: list[OmittedData] = Field(default_factory=list)
    """Data present in the source but not carried into the attestation object."""

    warnings: list[WarningCode] = Field(default_factory=list)
    """Stable warning codes describing problems with this record."""

    duplicate_of: str | None = None
    """The canonical `evidence_id` when this record was observed more than once."""

    def add_warning(self, code: WarningCode) -> None:
        """Attach a warning code, without producing duplicates."""
        if code not in self.warnings:
            self.warnings.append(code)

    def has_unknown_fields(self) -> bool:
        """Return whether this record independently reports unknown fields."""
        return bool(self.unknown_fields)


class MergeStats(BaseModel):
    """Summary counters for a merge run."""

    sources_seen: int = 0
    """The number of source documents read."""

    attestations_seen: int = 0
    """The number of attestation observations extracted from the sources."""

    records: int = 0
    """The number of distinct evidence records in the receipt."""

    duplicates: int = 0
    """The number of attestation observations recognized as duplicates."""

    records_with_warnings: int = 0
    """The number of records carrying at least one warning."""

    records_with_unknown_fields: int = 0
    """The number of records independently reporting unknown fields."""


class MergeError(ValueError):
    """An error occurred while loading or merging an evidence source."""


class MergeReceipt(BaseModel):
    """The result of merging one or more offline evidence sources."""

    records: list[EvidenceRecord]
    """The merged evidence records, sorted by artifact, publisher and signature."""

    stats: MergeStats
    """Summary counters for the merge run."""

    def get_record(self, evidence_id: str) -> EvidenceRecord:
        """Return the record with the given `evidence_id`.

        Raises `KeyError` if no record matches.
        """
        for record in self.records:
            if record.evidence_id == evidence_id:
                return record
        raise KeyError(evidence_id)

    def by_artifact(self, digest: str) -> list[EvidenceRecord]:
        """Return every record for the given artifact digest."""
        return [record for record in self.records if record.artifact_digest == digest]


# Fields modeled on each layer of a PEP 740 attestation document. Unknown
# keys found outside these sets are reported verbatim instead of being
# silently dropped by pydantic's default `extra="ignore"` behavior.
_ATTESTATION_FIELDS = {"version", "verification_material", "envelope"}
_VERIFICATION_MATERIAL_FIELDS = {"certificate", "transparency_entries"}
_ENVELOPE_FIELDS = {"statement", "signature"}
_TLOG_ENTRY_FIELDS = {
    "logIndex",
    "logId",
    "kindVersion",
    "integratedTime",
    "inclusionPromise",
    "inclusionProof",
    "canonicalizedBody",
}
_PROVENANCE_FIELDS = {"version", "attestation_bundles"}
_BUNDLE_FIELDS = {"mediaType", "verificationMaterial", "dsseEnvelope"}
_BUNDLE_VM_FIELDS = {
    "certificate",
    "tlogEntries",
    "timestampVerificationData",
    "tsa_certificate_chain",
}
_BUNDLE_CERT_FIELDS = {"rawBytes"}
_BUNDLE_DSSE_FIELDS = {"payload", "payloadType", "signatures"}

_PUBLISHER_ADAPTER = TypeAdapter(Publisher)


def _sha256_hex(data: bytes) -> str:
    """Return the hex-encoded SHA-256 digest of `data`."""
    return hashlib.sha256(data).hexdigest()


def _canonical_json(data: Any) -> bytes:
    """Return the JCS canonical JSON encoding of `data`."""
    return canonicalize(data)


def _fingerprint(data: Any) -> str:
    """Return a stable SHA-256 fingerprint for a JSON-compatible value."""
    return _sha256_hex(_canonical_json(data))


def _collect_extra_fields(
    raw: dict[str, Any], known: set[str], prefix: str
) -> dict[str, Any]:
    """Return the unknown keys of `raw`, keyed by dotted source path."""
    return {
        f"{prefix}.{key}" if prefix else key: value
        for key, value in raw.items()
        if key not in known
    }


def _collect_tlog_unknown_fields(
    raw_entries: Any, location: str, unknown: dict[str, Any]
) -> None:
    """Record unknown keys carried by each raw transparency log entry.

    Non-object entries are not inspected here: the PEP 740 model rejects them
    during validation, which surfaces as a :class:`MergeError`.
    """
    if not isinstance(raw_entries, list):
        return
    for index, entry in enumerate(raw_entries):
        if isinstance(entry, dict):
            entry_location = f"{location}[{index}]"
            unknown.update(_collect_extra_fields(entry, _TLOG_ENTRY_FIELDS, entry_location))


def _evidence_id(
    artifact_digest: str, publisher_fingerprint: str, signature_fingerprint: str
) -> str:
    """Build the stable identity of an evidence record."""
    material = f"{artifact_digest}:{publisher_fingerprint}:{signature_fingerprint}"
    return "evd-" + _sha256_hex(material.encode())[:16]


def _publisher_fingerprint(publisher: Publisher | None, raw: dict[str, Any] | None) -> str:
    """Return a stable fingerprint for a publisher identity.

    A missing publisher and an unmodeled publisher each get a distinct
    fingerprint so they never collapse onto one another.
    """
    if publisher is not None:
        return _fingerprint(publisher.model_dump(by_alias=True))
    if raw is not None:
        return "raw-" + _fingerprint(raw)
    return "no-publisher"


def _model_publisher(
    raw_publisher: Any, unknown: dict[str, Any], location: str
) -> tuple[Publisher | None, dict[str, Any] | None, list[WarningCode]]:
    """Model a publisher, retaining its raw form when it cannot be modeled."""
    if raw_publisher is None:
        return None, None, []
    if not isinstance(raw_publisher, dict):
        unknown[f"{location}.publisher"] = raw_publisher
        return None, None, [WarningCode.UNKNOWN_PUBLISHER]
    try:
        publisher = _PUBLISHER_ADAPTER.validate_python(raw_publisher)
    except ValidationError:
        unknown[f"{location}.publisher"] = raw_publisher
        return None, raw_publisher, [WarningCode.UNKNOWN_PUBLISHER]
    return publisher, None, []


class OfflineEvidenceMerger:
    """Merge attestation evidence collected from several offline backups.

    The merger accumulates attestation observations and deduplicates them by
    the tuple (artifact digest, publisher identity, signature). Observations
    of the same attestation from different backup files share one record and
    each keep their own :class:`EvidenceSource`, while different publishers
    for the same artifact produce separate records.
    """

    def __init__(self) -> None:
        """Initialize an empty merger."""
        self._records: dict[str, EvidenceRecord] = {}
        self._sources_seen = 0

    def merge_path(self, path: Path | str) -> None:
        """Load and merge every attestation contained in a document.

        Supported documents are standalone PEP 740 attestations, PEP 740
        provenance objects and Sigstore bundles. Raises :class:`MergeError`
        if the document cannot be read or parsed.
        """
        source_path = Path(path)
        try:
            data = source_path.read_bytes()
        except OSError as err:
            raise MergeError(f"could not read source {source_path}: {err}") from err
        self.merge_bytes(data, path=str(source_path))

    def merge_bytes(self, data: bytes, *, path: str) -> None:
        """Merge every attestation contained in raw document bytes."""
        try:
            raw = json.loads(data)
        except json.JSONDecodeError as err:
            raise MergeError(f"{path}: invalid JSON document: {err}") from err
        if not isinstance(raw, dict):
            raise MergeError(f"{path}: expected a JSON object at the document root")

        self._sources_seen += 1
        if _BUNDLE_VM_KEY in raw:
            self._merge_bundle(raw, data, path)
        elif "attestation_bundles" in raw:
            self._merge_provenance(raw, data, path)
        else:
            self._merge_attestation(raw, data, path, SourceKind.PEP740_ATTESTATION, None)

    def merge_paths(self, paths: Iterable[Path | str]) -> None:
        """Merge every document returned by `paths` in order."""
        for path in paths:
            self.merge_path(path)

    def _merge_bundle(self, raw: dict[str, Any], data: bytes, path: str) -> None:
        """Extract and index the single attestation carried by a bundle."""
        unknown = _collect_extra_fields(raw, _BUNDLE_FIELDS, "")
        vm = raw.get(_BUNDLE_VM_KEY)
        omitted: list[OmittedData] = []
        raw_entries: list[Any] = []
        if isinstance(vm, dict):
            unknown.update(_collect_extra_fields(vm, _BUNDLE_VM_FIELDS, _BUNDLE_VM_KEY))
            cert = vm.get("certificate")
            if isinstance(cert, dict):
                unknown.update(
                    _collect_extra_fields(
                        cert, _BUNDLE_CERT_FIELDS, f"{_BUNDLE_VM_KEY}.certificate"
                    )
                )
            maybe_entries = vm.get(_BUNDLE_TLOG_KEY)
            if isinstance(maybe_entries, list):
                raw_entries = maybe_entries
                if len(raw_entries) > 1:
                    omitted.append(
                        OmittedData(
                            location=f"{_BUNDLE_VM_KEY}.{_BUNDLE_TLOG_KEY}[1:]",
                            reason=(
                                "Sigstore bundles can carry multiple transparency entries, but a "
                                "PEP 740 attestation retains only the first"
                            ),
                            data=raw_entries[1:],
                        )
                    )
        dsse = raw.get("dsseEnvelope")
        if isinstance(dsse, dict):
            unknown.update(_collect_extra_fields(dsse, _BUNDLE_DSSE_FIELDS, "dsseEnvelope"))

        warnings: list[WarningCode] = []
        if len(raw_entries) > 1:
            warnings.append(WarningCode.DROPPED_TRANSPARENCY_ENTRIES)
            attestation = self._attestation_manually(raw, path)
        else:
            try:
                bundle = Bundle.from_json(data)
                attestation = Attestation.from_bundle(bundle)
            except (InvalidBundle, ConversionError, ValidationError, ValueError) as err:
                raise MergeError(f"{path}: invalid Sigstore bundle: {err}") from err

        source = EvidenceSource.from_bytes(SourceKind.SIGSTORE_BUNDLE, path, data)
        self._index(
            attestation=attestation,
            publisher=None,
            publisher_raw=None,
            source=source,
            unknown=unknown,
            omitted=omitted,
            extra_warnings=warnings,
        )

    @staticmethod
    def _attestation_manually(raw: dict[str, Any], path: str) -> Attestation:
        """Build a PEP 740 attestation without going through `sigstore.Bundle`.

        `sigstore` rejects bundles carrying more than one transparency entry
        on load. This mirrors `Attestation.from_bundle` while deliberately
        retaining only the first entry; the remainder are reported as omitted
        data by the caller.
        """
        try:
            vm = raw[_BUNDLE_VM_KEY]
            certificate = vm["certificate"]["rawBytes"].encode()
            envelope_raw = raw["dsseEnvelope"]
            statement = envelope_raw["payload"].encode()
            signature = envelope_raw["signatures"][0]["sig"].encode()
            first_entry = _InnerTlogEntry.from_dict(vm[_BUNDLE_TLOG_KEY][0]).to_dict()
        except (KeyError, IndexError, TypeError, ValueError, ValidationError) as err:
            raise MergeError(f"{path}: invalid Sigstore bundle: {err}") from err

        return Attestation(
            version=1,
            verification_material=VerificationMaterial(
                certificate=certificate,
                transparency_entries=[first_entry],
            ),
            envelope=Envelope(statement=statement, signature=signature),
        )

    def _merge_provenance(self, raw: dict[str, Any], data: bytes, path: str) -> None:
        """Extract and index every attestation within a provenance document."""
        unknown = _collect_extra_fields(raw, _PROVENANCE_FIELDS, "")
        bundles = raw.get("attestation_bundles")
        if not isinstance(bundles, list):
            raise MergeError(f"{path}: provenance 'attestation_bundles' must be a list")

        for bundle_index, bundle in enumerate(bundles):
            location = f"attestation_bundles[{bundle_index}]"
            if not isinstance(bundle, dict):
                unknown[location] = bundle
                continue
            bundle_unknown = dict(unknown)
            publisher, publisher_raw, publisher_warnings = _model_publisher(
                bundle.get("publisher"), bundle_unknown, location
            )
            attestations = bundle.get("attestations")
            if not isinstance(attestations, list):
                raise MergeError(f"{path}: {location}.attestations must be a list")
            for attestation_index, attestation_raw in enumerate(attestations):
                attestation_location = f"{location}.attestations[{attestation_index}]"
                if not isinstance(attestation_raw, dict):
                    bundle_unknown[attestation_location] = attestation_raw
                    continue
                source = EvidenceSource.from_bytes(
                    SourceKind.PEP740_PROVENANCE,
                    path,
                    data,
                    bundle_index=bundle_index,
                )
                self._index_raw_attestation(
                    attestation_raw,
                    source,
                    attestation_location,
                    bundle_unknown,
                    publisher=publisher,
                    publisher_raw=publisher_raw,
                    publisher_warnings=publisher_warnings,
                    path=path,
                )

    def _merge_attestation(
        self,
        raw: dict[str, Any],
        data: bytes,
        path: str,
        kind: SourceKind,
        bundle_index: int | None,
    ) -> None:
        """Index a standalone PEP 740 attestation document."""
        source = EvidenceSource.from_bytes(kind, path, data, bundle_index=bundle_index)
        self._index_raw_attestation(
            raw,
            source,
            "",
            {},
            publisher=None,
            publisher_raw=None,
            publisher_warnings=[],
            path=path,
        )

    def _index_raw_attestation(
        self,
        raw: dict[str, Any],
        source: EvidenceSource,
        location: str,
        inherited_unknown: dict[str, Any],
        *,
        publisher: Publisher | None,
        publisher_raw: dict[str, Any] | None,
        publisher_warnings: list[WarningCode],
        path: str,
    ) -> None:
        """Validate and index one raw PEP 740 attestation mapping."""
        unknown = dict(inherited_unknown)
        prefix = f"{location}." if location else ""
        unknown.update(_collect_extra_fields(raw, _ATTESTATION_FIELDS, location))

        vm = raw.get(_VM_KEY)
        if isinstance(vm, dict):
            unknown.update(
                _collect_extra_fields(vm, _VERIFICATION_MATERIAL_FIELDS, f"{prefix}{_VM_KEY}")
            )
            _collect_tlog_unknown_fields(
                vm.get(_TLOG_KEY), f"{prefix}{_VM_KEY}.{_TLOG_KEY}", unknown
            )

        envelope = raw.get(_ENVELOPE_KEY)
        if isinstance(envelope, dict):
            unknown.update(
                _collect_extra_fields(envelope, _ENVELOPE_FIELDS, f"{prefix}{_ENVELOPE_KEY}")
            )

        try:
            attestation = Attestation.model_validate(raw)
        except ValidationError as err:
            raise MergeError(f"{path}: invalid attestation: {err}") from err

        warnings = list(publisher_warnings)
        if unknown:
            warnings.append(WarningCode.UNKNOWN_FIELDS)

        self._index(
            attestation=attestation,
            publisher=publisher,
            publisher_raw=publisher_raw,
            source=source,
            unknown=unknown,
            omitted=[],
            extra_warnings=warnings,
        )

    def _index(
        self,
        *,
        attestation: Attestation,
        publisher: Publisher | None,
        publisher_raw: dict[str, Any] | None,
        source: EvidenceSource,
        unknown: dict[str, Any],
        omitted: list[OmittedData],
        extra_warnings: list[WarningCode],
    ) -> None:
        """Insert one attestation observation, deduplicating against existing records."""
        statement = attestation.statement
        subject = statement["subject"][0]
        artifact_name = subject["name"]
        artifact_digest = subject["digest"]["sha256"]
        signature_fingerprint = _sha256_hex(attestation.envelope.signature)
        publisher_fingerprint = _publisher_fingerprint(publisher, publisher_raw)
        identity = _evidence_id(artifact_digest, publisher_fingerprint, signature_fingerprint)

        existing = self._records.get(identity)
        if existing is not None:
            # Every re-observation of an already indexed attestation is a
            # duplicate, even when the backup bytes are identical; the
            # per-source path keeps the individual observations traceable.
            already_indexed = any(
                item.path == source.path and item.bundle_index == source.bundle_index
                for item in existing.sources
            )
            if not already_indexed:
                source.duplicate = True
                existing.sources.append(source)
            if unknown:
                existing.unknown_fields.update(unknown)
                existing.add_warning(WarningCode.UNKNOWN_FIELDS)
            for item in omitted:
                if item not in existing.omitted:
                    existing.omitted.append(item)
            for code in extra_warnings:
                existing.add_warning(code)
            return

        record = EvidenceRecord(
            evidence_id=identity,
            artifact_name=artifact_name,
            artifact_digest=artifact_digest,
            publisher=publisher,
            publisher_raw=publisher_raw,
            signature_sha256=signature_fingerprint,
            attestation=attestation,
            sources=[source],
            unknown_fields=unknown,
            omitted=omitted,
            warnings=list(extra_warnings),
        )
        self._records[identity] = record

    def build(self) -> MergeReceipt:
        """Finalize and return the sorted merge receipt."""
        records = sorted(
            self._records.values(),
            key=lambda record: (
                record.artifact_digest,
                _publisher_fingerprint(record.publisher, record.publisher_raw),
                record.signature_sha256,
            ),
        )
        duplicates = sum(1 for record in records for source in record.sources if source.duplicate)
        for record in records:
            if any(source.duplicate for source in record.sources):
                record.duplicate_of = record.evidence_id
        stats = MergeStats(
            sources_seen=self._sources_seen,
            attestations_seen=sum(len(record.sources) for record in records),
            records=len(records),
            duplicates=duplicates,
            records_with_warnings=sum(1 for record in records if record.warnings),
            records_with_unknown_fields=sum(1 for record in records if record.has_unknown_fields()),
        )
        return MergeReceipt(records=records, stats=stats)


def merge_evidence(paths: Iterable[Path | str]) -> MergeReceipt:
    """Merge the attestation evidence contained in the given source paths."""
    merger = OfflineEvidenceMerger()
    merger.merge_paths(paths)
    return merger.build()
