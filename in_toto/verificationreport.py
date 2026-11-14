# Copyright New York University and the in-toto contributors
# SPDX-License-Identifier: Apache-2.0

"""Auditable phase records for an in-toto verification run.

The verification workflow in :mod:`in_toto.verifylib` is split into distinct
attestation phases. This module provides a small structured report that records
the outcome of each phase for every layout level, including sublayouts.

The report is intentionally limited to phase names, statuses, evidence *paths*
and exception type/message strings. It never stores link or layout payload
contents, so it can be handed to operators without leaking the evidence itself.

It is particularly useful to tell apart two situations that both look like a
"missing link" in operational dashboards:

- a functionary did not (yet) submit an optional candidate, which may be
  skipped as long as the threshold can still be met, and
- evidence that exists on disk but cannot be read or parsed reliably, which
  always has to fail verification explicitly.
"""

import contextlib
from enum import Enum

import attr


class PhaseStatus(str, Enum):
    """Outcome of a single verification phase."""

    PASSED = "passed"
    FAILED = "failed"
    SKIPPED = "skipped"


class Phase(str, Enum):
    """Verification phases, in the order in which they are performed."""

    LAYOUT_SIGNATURES = "layout-signatures"
    LAYOUT_EXPIRATION = "layout-expiration"
    PARAMETER_SUBSTITUTION = "parameter-substitution"
    CANDIDATE_DISCOVERY = "candidate-discovery"
    SIGNER_THRESHOLDS = "signer-thresholds"
    SUBLAYOUT_VERIFICATION = "sublayout-verification"
    COMMAND_ALIGNMENT = "command-alignment"
    THRESHOLD_CONSTRAINTS = "threshold-constraints"
    STEP_RULES = "step-rules"
    INSPECTION_EXECUTION = "inspection-execution"
    INSPECTION_RULES = "inspection-rules"


@attr.s
class PhaseRecord:
    """Outcome of one phase on one layout level.

    Attributes:
      name: A :class:`Phase` value.
      status: A :class:`PhaseStatus` value.
      detail: Structured, payload-free context (e.g. per-candidate outcomes).
      evidence_paths: Paths of the evidence involved in this phase.
      error: ``"<ExceptionType>: <exception>"`` of the failure, if any.
      subreports: Child reports of recursively verified sublayouts.
    """

    name = attr.ib()
    status = attr.ib()
    detail = attr.ib(factory=dict)
    evidence_paths = attr.ib(factory=list)
    error = attr.ib(default=None)
    subreports = attr.ib(factory=list)


class VerificationReport:
    """Collects :class:`PhaseRecord` objects for one layout level."""

    def __init__(self, layout_name):
        self.layout_name = layout_name
        self.records = []

    def child(self, layout_name):
        """Create an empty report for a nested (sub)layout."""
        return VerificationReport(layout_name)

    def record(
        self,
        phase,
        status,
        detail=None,
        evidence_paths=None,
        error=None,
        subreports=None,
    ):
        """Append a phase record."""
        self.records.append(
            PhaseRecord(
                name=phase,
                status=status,
                detail=detail or {},
                evidence_paths=evidence_paths or [],
                error=(
                    f"{type(error).__name__}: {error}"
                    if error is not None
                    else None
                ),
                subreports=subreports or [],
            )
        )

    def has_phase(self, phase):
        """Return whether a record for ``phase`` already exists."""
        return any(record.name == phase for record in self.records)

    def skip_remaining(self, failed_phase):
        """Mark every phase after ``failed_phase`` as skipped.

        Phases that already have a record are left untouched. This makes it
        explicit that, e.g., inspections were never started once an earlier
        phase failed.
        """
        phases = list(Phase)
        start = phases.index(failed_phase) + 1
        for phase in phases[start:]:
            if not self.has_phase(phase):
                self.record(phase, PhaseStatus.SKIPPED)

    @contextlib.contextmanager
    def phase(self, phase, evidence_paths=None, detail=None):
        """Context manager recording a linear pipeline phase.

        Records ``PASSED`` on clean exit and ``FAILED`` (plus the remaining
        phases as ``SKIPPED``) on exception, then re-raises the exception.
        """
        try:
            yield
        except Exception as error:
            self.record(
                phase,
                PhaseStatus.FAILED,
                detail=detail,
                evidence_paths=evidence_paths,
                error=error,
            )
            self.skip_remaining(phase)
            raise
        self.record(
            phase,
            PhaseStatus.PASSED,
            detail=detail,
            evidence_paths=evidence_paths,
        )

    def render(self, indent=0):
        """Return a human readable, indented text representation."""
        pad = "  " * indent
        lines = [f"{pad}layout: {self.layout_name}"]
        for record in self.records:
            line = f"{pad}  [{record.status.value}] {record.name.value}"
            if record.evidence_paths:
                line += f" evidence={record.evidence_paths}"
            if record.detail:
                line += f" detail={record.detail}"
            lines.append(line)
            if record.error:
                lines.append(f"{pad}    error: {record.error}")
            for subreport in record.subreports:
                lines.append(subreport.render(indent + 2))
        return "\n".join(lines)


class NullVerificationReport(VerificationReport):
    """No-op report used when callers do not request phase tracking."""

    def __init__(self):
        super().__init__("")

    def child(self, layout_name):
        return self

    def record(self, *args, **kwargs):
        pass

    def has_phase(self, phase):
        return False

    def skip_remaining(self, failed_phase):
        pass

    @contextlib.contextmanager
    def phase(self, phase, evidence_paths=None, detail=None):
        yield

    def render(self, indent=0):
        return ""
