"""Compatibility import path for build failure diagnostics/reports.

The canonical implementation lives in :mod:`hatch.project.frontend.report`.
"""

from __future__ import annotations

from hatch.project.frontend.report import (
    DIAGNOSTIC_FILENAMES,
    INTERNAL_DIAGNOSTIC_FILENAME,
    SHAREABLE_REPORT_FILENAME,
    SHAREABLE_REPORT_FILENAMES,
    BuildDiagnostic,
    BuildFailureReport,
    FailureReport,
    InternalDiagnostic,
    RedactionPolicy,
    ReportPolicy,
    ShareableFailureReport,
    ShareableReport,
    SanitizationPolicy,
    build_failure_bundle,
    call_identifiers_match,
    load_diagnostic,
    load_report,
    new_call_id,
    redact_for_sharing,
    resolve_call_id,
    sanitize,
    stage_for_hook,
    write_failure_bundle,
)

__all__ = [
    "DIAGNOSTIC_FILENAMES",
    "INTERNAL_DIAGNOSTIC_FILENAME",
    "SHAREABLE_REPORT_FILENAME",
    "SHAREABLE_REPORT_FILENAMES",
    "BuildDiagnostic",
    "BuildFailureReport",
    "FailureReport",
    "InternalDiagnostic",
    "RedactionPolicy",
    "ReportPolicy",
    "ShareableFailureReport",
    "ShareableReport",
    "SanitizationPolicy",
    "build_failure_bundle",
    "call_identifiers_match",
    "load_diagnostic",
    "load_report",
    "new_call_id",
    "redact_for_sharing",
    "resolve_call_id",
    "sanitize",
    "stage_for_hook",
    "write_failure_bundle",
]
