"""Snake-case compatibility spelling of :mod:`hatch.project.frontend.report`."""

from __future__ import annotations

from hatch.project.frontend.report import *  # noqa: F403
from hatch.project.frontend.report import FailureReport as ShareableFailureReport  # noqa: F401
from hatch.project.frontend.report import (
    BuildDiagnostic,
    FailureReport,
    RedactionPolicy,
    build_failure_bundle,
    call_identifiers_match,
    load_diagnostic,
    load_report,
    write_failure_bundle,
)

__all__ = [
    "FailureReport",
    "ShareableFailureReport",
    "BuildDiagnostic",
    "RedactionPolicy",
    "build_failure_bundle",
    "call_identifiers_match",
    "load_diagnostic",
    "load_report",
    "write_failure_bundle",
]
