"""Singular compatibility spelling of :mod:`hatch.project.frontend.diagnostics`."""

from __future__ import annotations

from hatch.project.frontend.report import *  # noqa: F403
from hatch.project.frontend.report import BuildDiagnostic as Diagnostic  # noqa: F401
from hatch.project.frontend.report import BuildDiagnostic, RedactionPolicy

__all__ = ["Diagnostic", "BuildDiagnostic", "RedactionPolicy"]
