"""Shareable receipts describing the evidence read during verification.

A receipt records the source, time and digest of each piece of evidence that
was actually read.  It deliberately contains no credentials: URLs are
sanitised before they are written, so the resulting document can be shared
with others when investigating a verification failure.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import sys
import tempfile
from contextvars import ContextVar, Token
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal
from urllib.parse import urlsplit, urlunsplit

from pydantic import BaseModel, Field

if TYPE_CHECKING:  # pragma: no cover
    from collections.abc import Callable
    from types import TracebackType

_logger = logging.getLogger(__name__)

Segment = Literal["artifact", "provenance", "attestation"]
SourceKind = Literal["file", "url"]
Status = Literal["passed", "failed", "incomplete"]

# Keys whose values are redacted when they appear inside free-form text.
_SECRET_KEY_PATTERN = (
    "auth|authorization|credential|credentials|key|pass|passwd|password|secret"
    "|session|sig|signature|token"
)
_URL_USERINFO_RE = re.compile(r"(?i)(https?://)[^/\s@]+@")
_URL_QUERY_RE = re.compile(r"(?i)(https?://[^\s?#]+)\?[^\s#]*")
_URL_FRAGMENT_RE = re.compile(r"(?i)(https?://[^\s#]+)#\S*")
_SECRET_KV_RE = re.compile(
    rf"(?i)\b({_SECRET_KEY_PATTERN}|access_token|api_key|apikey|client_secret"
    rf"|x-amz-signature|x-goog-signature)\s*=\s*[^\s&;,\"']+"
)
_AUTH_HEADER_RE = re.compile(
    r"(?i)\b(authorization\s*[:=]\s*)(?:bearer\s+|basic\s+)?[^\s,;\"']+"
)


def now() -> str:
    """Return the current time as an RFC 3339 UTC timestamp."""
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def redact_text(value: str) -> str:
    """Remove credentials that may be embedded in free-form text."""
    value = _URL_USERINFO_RE.sub(r"\1", value)
    value = _URL_QUERY_RE.sub(r"\1?[REDACTED]", value)
    value = _URL_FRAGMENT_RE.sub(r"\1#[REDACTED]", value)
    value = _SECRET_KV_RE.sub(lambda match: f"{match.group(1)}=[REDACTED]", value)
    return _AUTH_HEADER_RE.sub(r"\1[REDACTED]", value)


class Digest(BaseModel):
    """A digest of the exact bytes that were read."""

    algorithm: Literal["sha256"] = "sha256"
    value: str


class Source(BaseModel):
    """The location a piece of evidence was read from."""

    kind: SourceKind
    location: str
    redacted: bool = False


class ReadRecord(BaseModel):
    """One piece of evidence that was actually read."""

    segment: Segment
    name: str
    source: Source
    time: str
    digest: Digest
    size: int


class EvidenceGap(BaseModel):
    """A piece of evidence that could not be read or used."""

    segment: Segment
    reason: str
    detail: str
    time: str
    source: Source | None = None


class Conclusion(BaseModel):
    """The verification conclusion, reconstructed from the recorded evidence."""

    status: Status
    verified: bool
    message: str | None = None


class ReplayedRead(BaseModel):
    """A recorded read reconstructed from its source."""

    segment: Segment
    name: str
    location: str
    recorded_time: str
    present: bool
    digest_matches: bool | None
    digest: Digest | None = None
    size: int | None = None


class ReplayResult(BaseModel):
    """The evidence and conclusion reconstructed from a receipt."""

    reads: list[ReplayedRead]
    evidence_gaps: list[EvidenceGap]
    conclusion: Conclusion


class Tool(BaseModel):
    """The tool that produced the receipt."""

    name: str = "pypi-attestations"
    version: str


class Receipt(BaseModel):
    """A shareable record of the evidence read during one verification."""

    receipt_version: Literal[1] = 1
    tool: Tool
    command: str
    environment: dict[str, Any] = Field(default_factory=dict)
    started_at: str
    finished_at: str | None = None
    reads: list[ReadRecord] = Field(default_factory=list)
    evidence_gaps: list[EvidenceGap] = Field(default_factory=list)
    redactions: list[str] = Field(default_factory=list)
    conclusion: Conclusion

    def reads_for(self, segment: Segment) -> list[ReadRecord]:
        """Return the reads recorded for the given segment."""
        return [record for record in self.reads if record.segment == segment]

    def gaps_for(self, segment: Segment) -> list[EvidenceGap]:
        """Return the evidence gaps recorded for the given segment."""
        return [gap for gap in self.evidence_gaps if gap.segment == segment]

    def complete(self) -> bool:
        """Return whether both artifact and attestation evidence were read."""
        segments = {record.segment for record in self.reads}
        return "artifact" in segments and bool(segments & {"provenance", "attestation"})


def _default_reader(source: Source) -> bytes | None:
    """Read a source from the local filesystem, when possible."""
    if source.kind != "file":
        return None
    try:
        return Path(source.location).read_bytes()
    except OSError:
        return None


def replay_receipt(
    receipt: Receipt,
    reader: Callable[[Source], bytes | None] | None = None,
) -> ReplayResult:
    """Reconstruct the evidence reads and conclusion recorded in a receipt.

    `reader` supplies the bytes for a recorded source; it defaults to reading
    local files and returning `None` for URLs.  This makes it possible to
    replay a receipt offline (with local copies or stubs) and determine
    whether the original reads can still be reproduced.
    """
    read_source = reader or _default_reader
    replayed: list[ReplayedRead] = []
    evidence_gaps = list(receipt.evidence_gaps)
    mismatched = False

    for record in receipt.reads:
        try:
            data = read_source(record.source)
        except OSError:
            data = None

        present = data is not None
        digest_matches: bool | None = None
        if present:
            digest_matches = hashlib.sha256(data).hexdigest() == record.digest.value
            if not digest_matches:
                mismatched = True
        else:
            evidence_gaps.append(
                EvidenceGap(
                    segment=record.segment,
                    reason="unavailable",
                    detail=f"Recorded evidence could not be read: {record.name}",
                    time=record.time,
                    source=record.source,
                )
            )

        replayed.append(
            ReplayedRead(
                segment=record.segment,
                name=record.name,
                location=record.source.location,
                recorded_time=record.time,
                present=present,
                digest_matches=digest_matches,
                digest=digest_of(data) if data is not None else record.digest,
                size=len(data) if data is not None else record.size,
            )
        )

    has_artifact = any(record.segment == "artifact" for record in receipt.reads)
    has_attestation = any(
        record.segment in ("provenance", "attestation") for record in receipt.reads
    )

    if mismatched:
        conclusion = Conclusion(
            status="failed",
            verified=False,
            message="recorded evidence no longer matches its digest",
        )
    elif receipt.conclusion.status == "failed":
        # The receipt records a definitive verification failure (no missing
        # evidence); replaying the same reads cannot turn it into a pass.
        conclusion = receipt.conclusion
    elif evidence_gaps:
        conclusion = Conclusion(
            status="incomplete",
            verified=False,
            message="evidence is incomplete: " + "; ".join(
                f"{gap.segment}: {gap.reason}" for gap in evidence_gaps
            ),
        )
    elif not has_artifact or not has_attestation:
        conclusion = Conclusion(
            status="incomplete",
            verified=False,
            message="receipt does not contain both artifact and attestation evidence",
        )
    else:
        conclusion = receipt.conclusion

    return ReplayResult(
        reads=replayed,
        evidence_gaps=evidence_gaps,
        conclusion=conclusion,
    )


def _sanitise_source(kind: SourceKind, location: str) -> tuple[Source, list[str]]:
    """Return a shareable source and the redactions that were applied."""
    redactions: list[str] = []
    if kind == "file":
        return Source(kind=kind, location=str(Path(location).expanduser().resolve())), redactions

    parts = urlsplit(location)
    netloc = parts.netloc
    if "@" in netloc:
        # Never retain index/user credentials embedded in the authority.
        netloc = netloc.rsplit("@", 1)[-1]
        redactions.append("url_userinfo")

    if parts.query:
        # Artifact URLs from an index are often pre-signed; keep none of the
        # query string so unknown credential parameter names cannot leak.
        redactions.append("url_query")

    if parts.fragment:
        redactions.append("url_fragment")

    location = urlunsplit((parts.scheme, netloc, parts.path, "", ""))
    return Source(kind=kind, location=location, redacted=bool(redactions)), redactions


def digest_of(data: bytes) -> Digest:
    """Return the SHA-256 digest of the given bytes."""
    return Digest(value=hashlib.sha256(data).hexdigest())


_ACTIVE_RECEIPT: ContextVar[ReceiptRecorder | None] = ContextVar(
    "pypi_attestations_active_receipt", default=None
)


def active_receipt() -> ReceiptRecorder | None:
    """Return the receipt recorder active for the current verification, if any."""
    return _ACTIVE_RECEIPT.get()


class ReceiptRecorder:
    """Collect evidence reads and write them to a shareable JSON receipt."""

    def __init__(
        self,
        path: Path,
        *,
        command: str,
        environment: dict[str, Any],
        tool_version: str,
    ) -> None:
        """Create a recorder that will write its receipt to `path`."""
        self._path = path
        self._redactions: set[str] = set()
        self._failure_message: str | None = None
        self._success_message: str | None = None
        self._token: Token[ReceiptRecorder | None] | None = None
        self._receipt = Receipt(
            tool=Tool(version=tool_version),
            command=command,
            environment=environment,
            started_at=now(),
            conclusion=Conclusion(status="failed", verified=False),
        )

    def __enter__(self) -> ReceiptRecorder:
        """Install this recorder as the active one."""
        self._token = _ACTIVE_RECEIPT.set(self)
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> Literal[False]:
        """Finalise and write the receipt, then propagate any exception."""
        if exc_type is None:
            status: Status = "passed"
            verified = True
            message = self._success_message
        elif exc_type is SystemExit:
            if self._success_message is not None:
                status = "passed"
                verified = True
                message = self._success_message
            elif self._receipt.evidence_gaps and not self._receipt.complete():
                # A missing piece of required evidence makes the result
                # inconclusive rather than a definitive verification failure.
                status = "incomplete"
                verified = False
                message = self._failure_message
            else:
                status = "failed"
                verified = False
                message = self._failure_message
        else:
            status = "failed"
            verified = False
            message = redact_text(str(exc)) if exc is not None else "verification failed"

        self._receipt.conclusion = Conclusion(status=status, verified=verified, message=message)
        self._receipt.finished_at = now()
        self._receipt.redactions = sorted(self._redactions)

        if self._token is not None:
            _ACTIVE_RECEIPT.reset(self._token)

        try:
            self._write()
        except OSError as write_error:
            _logger.error("Failed to write receipt %s: %s", self._path, write_error)
            if exc_type is None:
                raise SystemExit(1) from write_error

        return False

    def record_read(
        self,
        segment: Segment,
        *,
        kind: SourceKind,
        location: str,
        name: str,
        data: bytes | None = None,
        sha256: str | None = None,
        size: int | None = None,
        time: str | None = None,
    ) -> None:
        """Record evidence that was actually read."""
        if data is not None:
            digest = digest_of(data)
            size = len(data)
        else:
            if sha256 is None or size is None:
                raise ValueError("either data or both sha256 and size must be provided")
            digest = Digest(value=sha256)

        source, redactions = _sanitise_source(kind, location)
        for redaction in redactions:
            self._redactions.add(f"{segment}.source:{redaction}")
        self._receipt.reads.append(
            ReadRecord(
                segment=segment,
                name=name,
                source=source,
                time=time or now(),
                digest=digest,
                size=size,
            )
        )

    def record_gap(
        self,
        segment: Segment,
        reason: str,
        detail: str,
        *,
        kind: SourceKind | None = None,
        location: str | None = None,
        time: str | None = None,
    ) -> None:
        """Record evidence that was missing or unusable."""
        source = None
        if kind is not None and location is not None:
            source, redactions = _sanitise_source(kind, location)
            for redaction in redactions:
                self._redactions.add(f"{segment}.source:{redaction}")
        self._receipt.evidence_gaps.append(
            EvidenceGap(
                segment=segment,
                reason=reason,
                detail=redact_text(detail),
                time=time or now(),
                source=source,
            )
        )

    def record_failure(self, message: str) -> None:
        """Remember the error that stopped verification."""
        self._failure_message = redact_text(message)

    def record_success(self, message: str) -> None:
        """Remember the conclusion of a successful verification."""
        self._success_message = redact_text(message)

    @property
    def receipt(self) -> Receipt:
        """Return the receipt accumulated so far (primarily for tests)."""
        return self._receipt

    def _write(self) -> None:
        """Write the receipt as JSON, atomically when writing to a file."""
        payload = json.dumps(self._receipt.model_dump(mode="json"), indent=2, sort_keys=True)
        payload += "\n"
        if str(self._path) == "-":
            sys.stdout.write(payload)
            sys.stdout.flush()
            return

        parent = self._path.parent
        if str(parent) == "":
            parent = Path(".")
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{self._path.name}.", dir=parent, text=True
        )
        temporary_path = Path(temporary_name)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary_path, self._path)
        finally:
            temporary_path.unlink(missing_ok=True)


def record_read(
    segment: Segment,
    *,
    kind: SourceKind,
    location: str,
    name: str,
    data: bytes | None = None,
    sha256: str | None = None,
    size: int | None = None,
    time: str | None = None,
) -> None:
    """Record an evidence read with the active receipt, if there is one."""
    recorder = active_receipt()
    if recorder is not None:
        recorder.record_read(
            segment,
            kind=kind,
            location=location,
            name=name,
            data=data,
            sha256=sha256,
            size=size,
            time=time,
        )


def record_gap(
    segment: Segment,
    reason: str,
    detail: str,
    *,
    kind: SourceKind | None = None,
    location: str | None = None,
    time: str | None = None,
) -> None:
    """Record an evidence gap with the active receipt, if there is one."""
    recorder = active_receipt()
    if recorder is not None:
        recorder.record_gap(
            segment, reason, detail, kind=kind, location=location, time=time
        )


def record_failure(message: str) -> None:
    """Record a failure with the active receipt, if there is one."""
    recorder = active_receipt()
    if recorder is not None:
        recorder.record_failure(message)


def record_success(message: str) -> None:
    """Record a success with the active receipt, if there is one."""
    recorder = active_receipt()
    if recorder is not None:
        recorder.record_success(message)
