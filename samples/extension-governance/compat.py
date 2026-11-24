"""
Ingest adapters for historical CloudEvents.

Producers that already emitted legacy envelopes must keep working after the
catalogue is enforced.  The rule is: *ingest* is permissive and records what it
had to adapt; *produce* is strict.  That keeps a replay of an old topic readable
without making the same legacy shape legal for new events.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping

from policy import (
    SPEC_ATTRIBUTES,
    VERSION_ATTRIBUTE_ALIASES,
    Catalogue,
    Decision,
    ExtensionStatus,
    Mode,
)


@dataclass
class IngestResult:
    attributes: dict[str, Any]
    sidecar: dict[str, Any] = field(default_factory=dict)
    decisions: list[Decision] = field(default_factory=list)

    def records_by_kind(self) -> dict[str, list[Decision]]:
        grouped: dict[str, list[Decision]] = {}
        for decision in self.decisions:
            grouped.setdefault(decision.record_kind, []).append(decision)
        return grouped


def ingest_attributes(
    attributes: Mapping[str, Any],
    specversion: str,
    *,
    binding: str,
    catalogue: Catalogue,
) -> IngestResult:
    """Normalise one historical event for a read-only/consumer path.

    - spec attributes pass through unchanged
    - a wrong-version spec attribute is rewritten to the local version's name
      when a successor exists, otherwise dropped into the sidecar
    - catalogue aliases are rewritten to the canonical extension name
    - unknown but syntactically valid extensions are preserved on the event
    - syntactically invalid names are preserved in a sidecar so no data is lost,
      but they are not placed on the core event
    """

    result = IngestResult(attributes={})
    for name, value in attributes.items():
        if name in SPEC_ATTRIBUTES.get(specversion, frozenset()):
            result.attributes[name] = value
            continue

        decision = catalogue.evaluate(
            name,
            value,
            specversion,
            binding=binding,
            stage="ingest",
            mode=Mode.OBSERVE,
        )
        result.decisions.append(decision)

        if decision.status is ExtensionStatus.VERSION_MISMATCH:
            owner, successor = VERSION_ATTRIBUTE_ALIASES.get(name, (None, None))
            if successor:
                result.attributes[successor] = value
            else:
                result.sidecar[name] = value
            continue

        if decision.status is ExtensionStatus.INVALID_SYNTAX:
            result.sidecar[name] = value
            continue

        if decision.status is ExtensionStatus.RESERVED:
            result.sidecar[name] = value
            continue

        target = decision.canonical_name or name
        result.attributes[target] = value

    return result


def admit_new(
    attributes: Mapping[str, Any],
    specversion: str,
    *,
    binding: str,
    catalogue: Catalogue,
    mode: Mode,
) -> tuple[dict[str, Any], list[Decision]]:
    """Gate a newly produced event.  Returns only the accepted attributes."""

    accepted: dict[str, Any] = {}
    decisions: list[Decision] = []
    for name, value in attributes.items():
        if name in SPEC_ATTRIBUTES.get(specversion, frozenset()):
            accepted[name] = value
            continue
        decision = catalogue.evaluate(
            name,
            value,
            specversion,
            binding=binding,
            stage="produce",
            mode=mode,
        )
        decisions.append(decision)
        if decision.accepted:
            accepted[decision.canonical_name or name] = value
    return accepted, decisions
