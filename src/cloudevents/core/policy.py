"""Convenience imports for source admission policies."""

from cloudevents.core.admission import (
    AdmissionDecision,
    AdmissionPolicy,
    BoundaryPolicy,
    ConnectionSourcePolicy,
    SourceAdmission,
    SourceAdmissionPolicy,
    SourceBoundaryPolicy,
    evaluate_admission,
)

__all__ = [
    "AdmissionDecision",
    "AdmissionPolicy",
    "BoundaryPolicy",
    "ConnectionSourcePolicy",
    "SourceAdmission",
    "SourceAdmissionPolicy",
    "SourceBoundaryPolicy",
    "evaluate_admission",
]
