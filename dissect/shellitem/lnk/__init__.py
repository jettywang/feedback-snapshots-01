from __future__ import annotations

from dissect.shellitem.lnk.lnk import Lnk, c_lnk
from dissect.shellitem.lnk.targets import (
    CandidateStatus,
    Relation,
    TargetCandidate,
    TargetReport,
    collect_targets,
)

__all__ = [
    "CandidateStatus",
    "Lnk",
    "Relation",
    "TargetCandidate",
    "TargetReport",
    "c_lnk",
    "collect_targets",
]
