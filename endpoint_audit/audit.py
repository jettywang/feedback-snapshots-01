"""High level orchestration: manifest -> parsed entries -> pair verdicts."""

from __future__ import annotations

from dataclasses import dataclass, field

from .extensions import DiscloserRegistry
from .manifest import Declaration
from .model import ParsedEntry, Verdict
from .overlap import PairVerdict, audit_pairs, group_pairs
from .parser import parse_endpoint


@dataclass
class AuditResult:
    entries: list[ParsedEntry] = field(default_factory=list)
    pairs: list[PairVerdict] = field(default_factory=list)

    @property
    def grouped(self) -> dict[Verdict, list[PairVerdict]]:
        return group_pairs(self.pairs)

    @property
    def parse_issues(self) -> list:
        return [issue for entry in self.entries for issue in entry.issues]

    @property
    def has_confirmed_overlap(self) -> bool:
        return any(pair.verdict is Verdict.OVERLAP for pair in self.pairs)

    @property
    def has_pending(self) -> bool:
        return any(pair.verdict is Verdict.UNKNOWN for pair in self.pairs)

    def to_dict(self) -> dict:
        return {
            "entries": [entry.to_dict() for entry in self.entries],
            "pairs": [pair.to_dict() for pair in self.pairs],
            "summary": {
                "overlap": len(self.grouped[Verdict.OVERLAP]),
                "separate": len(self.grouped[Verdict.SEPARATE]),
                "unknown": len(self.grouped[Verdict.UNKNOWN]),
                "parse_issues": len(self.parse_issues),
            },
        }


def audit_declarations(
    declarations: list[Declaration],
    registry: DiscloserRegistry | None = None,
) -> AuditResult:
    registry = registry if registry is not None else DiscloserRegistry()
    entries = [
        parse_endpoint(decl.endpoint, decl.coordinate, registry)
        for decl in declarations
    ]
    return AuditResult(entries=entries, pairs=audit_pairs(entries))
