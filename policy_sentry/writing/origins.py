"""Per-statement origin tracking used while a template is rendered."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable

ACCESS_LEVEL_SECTIONS = {
    "Read": "read",
    "Write": "write",
    "List": "list",
    "Tagging": "tagging",
    "Permissions management": "permissions-management",
}


@dataclass
class Origin:
    """Why one action ended up in one SID group."""

    kind: str
    template_section: str
    requested_arns: list[str] = field(default_factory=list)
    requested_access_level: str | None = None
    resource_type: str | None = None
    dependent_of: list[str] = field(default_factory=list)
    detail: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "template_section": self.template_section,
            "requested_arns": self.requested_arns,
            "requested_access_level": self.requested_access_level,
            "resource_type": self.resource_type,
            "dependent_of": self.dependent_of,
            "detail": self.detail,
        }


class OriginTracker:
    """Records per-(SID, action) origins while ``SidGroup`` builds a policy."""

    def __init__(self) -> None:
        self._records: dict[tuple[str, str], Origin] = {}

    def record(self, sid: str, action: str, origin: Origin, *, overwrite: bool = False) -> None:
        key = (sid, action.lower())
        if overwrite or key not in self._records:
            self._records[key] = origin

    def get(self, sid: str, action: str) -> Origin | None:
        return self._records.get((sid, action.lower()))

    def origins_for_action(self, action: str) -> list[tuple[str, Origin]]:
        wanted = action.lower()
        return [(sid, origin) for (sid, name), origin in self._records.items() if name == wanted]

    def items(self) -> Iterable[tuple[tuple[str, str], Origin]]:
        return self._records.items()

    def actions(self) -> set[str]:
        """Every action name that has at least one origin record."""
        return {action for (_sid, action) in self._records}

    def retain_existing(self, actions_by_sid: dict[str, list[str]]) -> None:
        """Drop records for actions/sids that no longer exist after filtering."""
        allowed = {(sid, action.lower()) for sid, actions in actions_by_sid.items() for action in actions}
        self._records = {key: origin for key, origin in self._records.items() if key in allowed}

    def merge_sids(self, mapping: dict[str, str]) -> None:
        """Move records from SIDs that minimization folded into another statement."""
        if not mapping:
            return
        merged: dict[tuple[str, str], Origin] = {}
        for (sid, action), origin in self._records.items():
            merged[(resolve_sid(sid, mapping), action)] = origin
        self._records = merged


def resolve_sid(sid: str, mapping: dict[str, str]) -> str:
    """Follow a SID rename chain (a merge can itself be renamed by minimization)."""
    seen = set()
    while sid in mapping and sid not in seen:
        seen.add(sid)
        sid = mapping[sid]
    return sid
