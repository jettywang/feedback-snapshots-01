from __future__ import annotations

from dataclasses import dataclass, field

from django.conf import settings

from csp.constants import NONE

# Where the value of a delivered CSP header came from.
SOURCE_EXISTING_HEADER = "existing_header"
SOURCE_VIEW = "view"
SOURCE_SETTINGS = "settings"
SOURCE_ABSENT = "absent"

# Fetch directives that fall back to ``default-src`` when they are not part of
# the delivered policy. Order matches the CSP specification.
_FETCH_DIRECTIVES = (
    "child-src",
    "connect-src",
    "font-src",
    "frame-src",
    "img-src",
    "manifest-src",
    "media-src",
    "object-src",
    "script-src",
    "script-src-attr",
    "script-src-elem",
    "style-src",
    "style-src-attr",
    "style-src-elem",
    "worker-src",
)

# Directives whose presence is a bare token rather than a list of sources.
_BOOLEAN_DIRECTIVES = (
    "upgrade-insecure-requests",
    "block-all-mixed-content",
)


@dataclass
class DirectiveConflict:
    """A single directive that violates the application policy floor."""

    directive: str
    reason: str
    floor_sources: tuple[str, ...]
    delivered_sources: tuple[str, ...]
    source: str


@dataclass
class PolicyFloorReport:
    """Outcome of checking one delivered CSP header against the floor."""

    header: str
    enforced: bool
    compliant: bool
    floor: dict[str, tuple[str, ...]]
    effective_policy: dict[str, tuple[str, ...]]
    header_source: str
    conflicts: list[DirectiveConflict] = field(default_factory=list)

    @property
    def reasons(self) -> list[str]:
        return [conflict.reason for conflict in self.conflicts]


def parse_policy(policy: str) -> dict[str, tuple[str, ...]]:
    """Parse a serialized CSP header into a mapping of directives to sources.

    Boolean directives map to an empty tuple, matching how the rest of
    django-csp represents a bare directive token.
    """
    directives: dict[str, tuple[str, ...]] = {}
    for part in policy.split(";"):
        tokens = part.split()
        if not tokens:
            continue
        name = tokens[0]
        directives[name] = tuple(tokens[1:])
    return directives


def get_floor_directives(report_only: bool) -> dict[str, tuple[str, ...]]:
    setting_name = (
        "CONTENT_SECURITY_POLICY_REPORT_ONLY_FLOOR"
        if report_only
        else "CONTENT_SECURITY_POLICY_FLOOR"
    )
    config = getattr(settings, setting_name, None) or {}
    directives = config.get("DIRECTIVES", {}) if isinstance(config, dict) else {}
    parsed: dict[str, tuple[str, ...]] = {}
    for name, value in directives.items():
        if value is None:
            continue
        if isinstance(value, bool):
            if value:
                parsed[name] = ()
            continue
        if isinstance(value, (list, tuple, set)):
            parsed[name] = tuple(sorted(value))
        else:
            parsed[name] = (value,)
    return parsed


def _effective_sources(
    directive: str,
    delivered: dict[str, tuple[str, ...]],
) -> tuple[str, ...] | None:
    """Return the sources governing ``directive`` in the delivered policy.

    Fetch directives fall back to ``default-src``. A value of ``None`` means
    the delivered policy does not govern the directive at all.
    """
    if directive in delivered:
        return delivered[directive]
    if directive in _FETCH_DIRECTIVES and "default-src" in delivered:
        return delivered["default-src"]
    return None


def evaluate_policy_floor(
    header: str,
    delivered_policy: str,
    header_source: str,
    report_only: bool = False,
) -> PolicyFloorReport:
    """Check a delivered CSP header against the configured policy floor."""
    floor = get_floor_directives(report_only)
    effective = parse_policy(delivered_policy) if delivered_policy else {}

    conflicts: list[DirectiveConflict] = []
    for directive, floor_sources in floor.items():
        delivered_sources = _effective_sources(directive, effective)

        if delivered_sources is None:
            reason = f"missing required directive '{directive}'"
            conflicts.append(
                DirectiveConflict(
                    directive=directive,
                    reason=reason,
                    floor_sources=floor_sources,
                    delivered_sources=(),
                    source=header_source,
                )
            )
            continue

        if directive in _BOOLEAN_DIRECTIVES:
            # The floor only asks for the bare token; being present is enough.
            continue

        if NONE in delivered_sources:
            # "'none'" denies every source and therefore satisfies any floor.
            continue

        extra = sorted(set(delivered_sources) - set(floor_sources))
        if extra:
            reason = (
                f"directive '{directive}' allows sources not permitted by the "
                f"policy floor: {', '.join(extra)}"
            )
            conflicts.append(
                DirectiveConflict(
                    directive=directive,
                    reason=reason,
                    floor_sources=floor_sources,
                    delivered_sources=delivered_sources,
                    source=header_source,
                )
            )

    return PolicyFloorReport(
        header=header,
        enforced=not report_only,
        compliant=not conflicts,
        floor=floor,
        effective_policy=effective,
        header_source=header_source,
        conflicts=conflicts,
    )
