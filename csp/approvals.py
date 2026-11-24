"""Policy approval review for django-csp.

This module is intentionally additive: it does not change how CSP headers are
built.  It provides a small, deterministic model that lets an application bind
an approval to a *site*, a *directive*, a *mode* (enforced or report-only) and
the *actual source tokens* that were approved.  Policy evidence can be captured
from the middleware for individual pages, including pages whose policy is
locally overridden by a view decorator.

The review report answers two questions that are otherwise easy to conflate:

* Which approvals are still backed by a policy that is actually delivered?
* Where does a controlled source appear on a page without an approval that
  applies to that page?

The second check is deliberately scope-aware.  An approval for
``shop.example/checkout/`` never widens to another page, another site, or the
other policy mode.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from django.conf import settings

from csp.utils import build_directives

ENFORCE = "enforce"
REPORT_ONLY = "report-only"

VALID = "valid"
NEEDS_REVIEW = "needs_review"
PENDING = "pending"
NOT_DELIVERED = "not_delivered"

_MODE_ALIASES = {
    "enforce": ENFORCE,
    "enforced": ENFORCE,
    "enforcing": ENFORCE,
    "report-only": REPORT_ONLY,
    "report_only": REPORT_ONLY,
    "reportonly": REPORT_ONLY,
    "report": REPORT_ONLY,
    "reporting": REPORT_ONLY,
}


def normalize_mode(mode: str | None) -> str:
    """Return the canonical mode name for *mode*.

    Enforced and report-only approvals are never interchangeable.  Only the
    spelling of the mode is normalized; the distinction is preserved.
    """

    key = str(mode or ENFORCE).strip().lower().replace(" ", "-")
    try:
        return _MODE_ALIASES[key]
    except KeyError:
        raise ValueError(f"Unknown CSP approval mode: {mode!r}") from None


def _as_sources(value: Any) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        values: Iterable[Any] = (value,)
    elif isinstance(value, (set, frozenset)):
        values = sorted(value, key=str)
    elif isinstance(value, (list, tuple)):
        values = value
    else:
        try:
            values = tuple(value)
        except TypeError:
            values = (value,)

    sources = []
    for item in values:
        if item is None:
            continue
        source = str(item).strip()
        if source and source not in sources:
            sources.append(source)
    return tuple(sources)


def _as_pages(value: Any) -> tuple[str, ...] | None:
    if value is None:
        return None
    if isinstance(value, str):
        pages = (value,)
    else:
        try:
            pages = tuple(str(page).strip() for page in value if str(page).strip())
        except TypeError:
            pages = (str(value).strip(),)
    if not pages:
        return None
    return tuple(dict.fromkeys(pages))


def _page_matches(page: str, prefixes: Sequence[str] | None) -> bool:
    if not prefixes:
        return True
    for prefix in prefixes:
        normalized = prefix.rstrip("/")
        if not normalized:
            # "/" (or a bare trailing slash) means the whole site.
            return True
        if page == normalized or page == f"{normalized}/" or page.startswith(f"{normalized}/"):
            return True
    return False


@dataclass(frozen=True, init=False)
class Approval:
    """A recorded approval for one controlled source set.

    ``pages`` is a tuple of URL prefixes.  ``None`` means the whole site.  An
    approval is bound to exactly one site, directive and mode; sharing an
    approval across any of those boundaries is not inferred.

    The constructor accepts the aliases ``id``, ``source`` and ``scope`` so a
    review table can be bound directly from rows.
    """

    approval_id: str
    site: str
    directive: str
    sources: tuple[str, ...]
    mode: str
    pages: tuple[str, ...] | None
    note: str

    def __init__(
        self,
        approval_id: str | None = None,
        site: str = "",
        directive: str = "",
        sources: Any = (),
        mode: str = ENFORCE,
        pages: Any = None,
        note: str = "",
        **aliases: Any,
    ) -> None:
        if approval_id is None:
            approval_id = aliases.pop("id", None)
        if not sources and "source" in aliases:
            sources = aliases.pop("source")
        if pages is None and "scope" in aliases:
            pages = aliases.pop("scope")
        if aliases:
            unknown = ", ".join(sorted(aliases))
            raise TypeError(f"Unexpected approval field(s): {unknown}")

        approval_id = str(approval_id or "").strip()
        site = str(site).strip()
        directive = str(directive).strip()
        normalized_sources = _as_sources(sources)
        if not approval_id:
            raise ValueError("Approval requires a non-empty approval_id")
        if not site:
            raise ValueError("Approval requires a non-empty site")
        if not directive:
            raise ValueError("Approval requires a non-empty directive")
        if not normalized_sources:
            raise ValueError("Approval requires at least one source")

        object.__setattr__(self, "approval_id", approval_id)
        object.__setattr__(self, "site", site)
        object.__setattr__(self, "directive", directive)
        object.__setattr__(self, "sources", normalized_sources)
        object.__setattr__(self, "mode", normalize_mode(mode))
        object.__setattr__(self, "pages", _as_pages(pages))
        object.__setattr__(self, "note", str(note))

    @property
    def id(self) -> str:
        """Alias used by report consumers that expect a plain ``id``."""

        return self.approval_id

    def covers_page(self, page: str) -> bool:
        return _page_matches(page, self.pages)

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "approval_id": self.approval_id,
            "site": self.site,
            "directive": self.directive,
            "sources": list(self.sources),
            "mode": self.mode,
        }
        if self.pages:
            data["pages"] = list(self.pages)
        if self.note:
            data["note"] = self.note
        return data

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> Approval:
        approval_id = data.get("approval_id", data.get("id"))
        if approval_id is None:
            raise ValueError("Approval data requires 'approval_id' or 'id'")
        return cls(
            approval_id=str(approval_id),
            site=str(data["site"]),
            directive=str(data["directive"]),
            sources=data.get("sources", data.get("source", ())),
            mode=normalize_mode(data.get("mode", ENFORCE)),
            pages=data.get("pages", data.get("scope")),
            note=str(data.get("note", "")),
        )


@dataclass(frozen=True)
class PolicySnapshot:
    """The effective directives captured for one site/page/mode.

    ``directives`` maps a directive name to the source tokens that would be
    written to the header.  ``source_origins`` records, per directive and
    source, whether the token came from the site settings or a view-local
    declaration.  The nonce sentinel is not part of a snapshot because it is
    per-request material, not an approval target.
    """

    site: str
    page: str
    mode: str = ENFORCE
    directives: Mapping[str, tuple[str, ...]] = field(default_factory=dict)
    origins: Mapping[str, str] = field(default_factory=dict)
    source_origins: Mapping[str, Mapping[str, str]] = field(default_factory=dict)
    delivered: bool = True

    def __post_init__(self) -> None:
        if not str(self.site).strip():
            raise ValueError("PolicySnapshot requires a non-empty site")
        page = str(self.page or "/")
        object.__setattr__(self, "site", str(self.site).strip())
        object.__setattr__(self, "page", page)
        object.__setattr__(self, "mode", normalize_mode(self.mode))
        object.__setattr__(
            self,
            "directives",
            {str(name): _as_sources(values) for name, values in dict(self.directives).items()},
        )
        object.__setattr__(self, "origins", {str(k): str(v) for k, v in dict(self.origins).items()})
        object.__setattr__(
            self,
            "source_origins",
            {
                str(directive): {str(source): str(origin) for source, origin in dict(entries).items()}
                for directive, entries in dict(self.source_origins).items()
            },
        )

    def sources_for(self, directive: str) -> tuple[str, ...]:
        return tuple(self.directives.get(directive, ()))

    def origin_for(self, directive: str, source: str) -> str:
        return self.source_origins.get(directive, {}).get(source, self.origins.get(directive, "settings"))

    @property
    def evidence(self) -> str:
        """A stable, human-readable policy value for review material."""

        return "; ".join(f"{name} {' '.join(values)}".strip() for name, values in self.directives.items())

    def to_dict(self) -> dict[str, Any]:
        return {
            "site": self.site,
            "page": self.page,
            "mode": self.mode,
            "delivered": self.delivered,
            "directives": {name: list(values) for name, values in self.directives.items()},
            "origins": dict(self.origins),
            "source_origins": {name: dict(values) for name, values in self.source_origins.items()},
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> PolicySnapshot:
        return cls(
            site=str(data["site"]),
            page=str(data.get("page", "/")),
            mode=normalize_mode(data.get("mode", ENFORCE)),
            directives={str(name): _as_sources(values) for name, values in dict(data.get("directives", {})).items()},
            origins=dict(data.get("origins", {})),
            source_origins={str(name): dict(values) for name, values in dict(data.get("source_origins", {})).items()},
            delivered=bool(data.get("delivered", True)),
        )


def _render_sources(
    *,
    mode: str,
    config: Mapping[str, Any] | None,
    update: Mapping[str, Any] | None,
    replace: Mapping[str, Any] | None,
) -> dict[str, tuple[str, ...]]:
    rendered = build_directives(
        config=dict(config) if config is not None else None,
        update=dict(update) if update is not None else None,
        replace=dict(replace) if replace is not None else None,
        nonce=None,
        report_only=normalize_mode(mode) == REPORT_ONLY,
    )
    return {str(name): tuple(str(value).split()) for name, value in rendered.items()}


def capture_snapshot(
    *,
    site: str,
    page: str = "/",
    mode: str = ENFORCE,
    config: Mapping[str, Any] | None = None,
    update: Mapping[str, Any] | None = None,
    replace: Mapping[str, Any] | None = None,
    delivered: bool = True,
) -> PolicySnapshot:
    """Capture the effective policy for one page.

    Pass ``config``/``update``/``replace`` exactly as the middleware receives
    them (``None`` means the site settings).  The origin of each approved
    source is derived from those inputs so a view-local declaration is visible
    as its own review basis.
    """

    mode = normalize_mode(mode)
    directives = _render_sources(mode=mode, config=config, update=update, replace=replace)
    origins: dict[str, str] = {}
    source_origins: dict[str, dict[str, str]] = {}

    if config is not None:
        # A view config replaces the site configuration wholesale.
        base: dict[str, tuple[str, ...]] = {}
        view_directives = {str(name) for name in config}
    else:
        base = _render_sources(mode=mode, config=None, update=None, replace=None)
        view_directives = {str(name) for name in (update or {})} | {str(name) for name in (replace or {})}

    for name, values in directives.items():
        entries: dict[str, str] = {}
        if name in view_directives:
            if config is not None:
                for source in values:
                    entries[source] = "view"
            elif name in set(replace or {}):
                for source in values:
                    entries[source] = "view"
            else:
                base_sources = set(base.get(name, ()))
                for source in values:
                    entries[source] = "settings" if source in base_sources else "view"
        else:
            for source in values:
                entries[source] = "settings"

        source_origins[name] = entries
        if not entries:
            # Boolean directives have no source tokens; retain a directive-level
            # origin so the report can still say where the declaration came from.
            origins[name] = "view" if name in view_directives else "settings"
        elif all(origin == "view" for origin in entries.values()):
            origins[name] = "view"
        elif all(origin == "settings" for origin in entries.values()):
            origins[name] = "settings"
        else:
            origins[name] = "settings+view"

    return PolicySnapshot(
        site=site,
        page=page,
        mode=mode,
        directives=directives,
        origins=origins,
        source_origins=source_origins,
        delivered=delivered,
    )


@dataclass(frozen=True)
class PageDecision:
    page: str
    mode: str
    status: str
    directive: str
    expected_sources: tuple[str, ...]
    actual_sources: tuple[str, ...]
    missing_sources: tuple[str, ...] = ()
    source_origins: Mapping[str, str] = field(default_factory=dict)
    reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "page": self.page,
            "mode": self.mode,
            "status": self.status,
            "directive": self.directive,
            "expected_sources": list(self.expected_sources),
            "actual_sources": list(self.actual_sources),
            "missing_sources": list(self.missing_sources),
            "source_origins": dict(self.source_origins),
            "reason": self.reason,
        }


@dataclass(frozen=True)
class ApprovalResult:
    approval: Approval
    status: str
    pages: tuple[PageDecision, ...] = ()
    reasons: tuple[str, ...] = ()

    @property
    def approval_id(self) -> str:
        return self.approval.approval_id

    @property
    def page_decisions(self) -> tuple[PageDecision, ...]:
        return self.pages

    def to_dict(self) -> dict[str, Any]:
        return {
            "approval": self.approval.to_dict(),
            "status": self.status,
            "pages": [decision.to_dict() for decision in self.pages],
            "reasons": list(self.reasons),
        }


@dataclass(frozen=True)
class UnapprovedUse:
    site: str
    page: str
    mode: str
    directive: str
    source: str
    policy_source: str = "settings"

    def to_dict(self) -> dict[str, Any]:
        return {
            "site": self.site,
            "page": self.page,
            "mode": self.mode,
            "directive": self.directive,
            "source": self.source,
            "policy_source": self.policy_source,
        }


@dataclass(frozen=True)
class ReviewReport:
    results: tuple[ApprovalResult, ...] = ()
    unapproved_uses: tuple[UnapprovedUse, ...] = ()
    snapshots: tuple[PolicySnapshot, ...] = ()

    @property
    def valid(self) -> tuple[ApprovalResult, ...]:
        return tuple(result for result in self.results if result.status == VALID)

    @property
    def needs_review(self) -> tuple[ApprovalResult, ...]:
        return tuple(result for result in self.results if result.status == NEEDS_REVIEW)

    @property
    def pending(self) -> tuple[ApprovalResult, ...]:
        return tuple(result for result in self.results if result.status == PENDING)

    @property
    def valid_approvals(self) -> tuple[Approval, ...]:
        return tuple(result.approval for result in self.valid)

    @property
    def stale_approvals(self) -> tuple[Approval, ...]:
        return tuple(result.approval for result in self.needs_review)

    def to_dict(self) -> dict[str, Any]:
        return {
            "approvals": [result.to_dict() for result in self.results],
            "valid": [result.approval_id for result in self.valid],
            "needs_review": [result.approval_id for result in self.needs_review],
            "pending": [result.approval_id for result in self.pending],
            "unapproved_uses": [use.to_dict() for use in self.unapproved_uses],
            "snapshots": [snapshot.to_dict() for snapshot in self.snapshots],
        }

    def to_json(self, *, indent: int | None = 2) -> str:
        import json

        return json.dumps(self.to_dict(), ensure_ascii=False, indent=indent, sort_keys=True)

    def summary(self) -> str:
        lines = [f"{len(self.valid)} approval(s) valid, " f"{len(self.needs_review)} need review, " f"{len(self.pending)} pending evidence."]
        for result in self.needs_review:
            details = "; ".join(result.reasons) or "policy no longer supports the approval"
            lines.append(f"- {result.approval_id}: {details}")
        for use in self.unapproved_uses:
            lines.append(f"- unapproved: {use.source} in {use.directive} on " f"{use.site}{use.page} ({use.mode})")
        return "\n".join(lines)


class ApprovalRegistry:
    """Collect approvals and policy snapshots, then produce a review report."""

    def __init__(
        self,
        approvals: Iterable[Approval] = (),
        snapshots: Iterable[PolicySnapshot] = (),
        managed_sources: Iterable[str] | None = None,
    ) -> None:
        self._approvals: list[Approval] = []
        self._snapshots: dict[tuple[str, str, str], PolicySnapshot] = {}
        self._managed_sources = _as_sources(managed_sources) if managed_sources is not None else None
        for approval in approvals:
            self.add_approval(approval)
        for snapshot in snapshots:
            self.record_snapshot(snapshot)

    @property
    def approvals(self) -> tuple[Approval, ...]:
        return tuple(self._approvals)

    @property
    def snapshots(self) -> tuple[PolicySnapshot, ...]:
        return tuple(self._snapshots.values())

    @property
    def managed_sources(self) -> tuple[str, ...]:
        if self._managed_sources is not None:
            return self._managed_sources
        return _as_sources(source for approval in self._approvals for source in approval.sources)

    def add_approval(self, approval: Approval | Mapping[str, Any], **kwargs: Any) -> Approval:
        if isinstance(approval, Approval):
            if not kwargs:
                result = approval
            else:
                data = approval.to_dict()
                data.update(kwargs)
                result = Approval.from_dict(data)
        elif isinstance(approval, Mapping):
            data = dict(approval)
            data.update(kwargs)
            result = Approval.from_dict(data)
        else:
            result = Approval(approval, **kwargs)
        for existing in self._approvals:
            if existing.approval_id == result.approval_id:
                raise ValueError(f"Duplicate approval_id: {result.approval_id!r}")
        self._approvals.append(result)
        return result

    def record_snapshot(self, snapshot: PolicySnapshot | Mapping[str, Any], **kwargs: Any) -> PolicySnapshot:
        if isinstance(snapshot, PolicySnapshot):
            if kwargs:
                data = snapshot.to_dict()
                data.update(kwargs)
                result = PolicySnapshot.from_dict(data)
            else:
                result = snapshot
        elif isinstance(snapshot, Mapping):
            data = dict(snapshot)
            data.update(kwargs)
            result = PolicySnapshot.from_dict(data)
        else:
            raise TypeError("record_snapshot expects a PolicySnapshot or mapping")
        self._snapshots[(result.site, result.page, result.mode)] = result
        return result

    def capture(self, **kwargs: Any) -> PolicySnapshot:
        snapshot = capture_snapshot(**kwargs)
        return self.record_snapshot(snapshot)

    def clear_snapshots(self) -> None:
        self._snapshots.clear()

    def to_dict(self) -> dict[str, Any]:
        return {
            "approvals": [approval.to_dict() for approval in self._approvals],
            "snapshots": [snapshot.to_dict() for snapshot in self._snapshots.values()],
            "managed_sources": list(self._managed_sources) if self._managed_sources is not None else None,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> ApprovalRegistry:
        return cls(
            approvals=[Approval.from_dict(item) for item in data.get("approvals", ())],
            snapshots=[PolicySnapshot.from_dict(item) for item in data.get("snapshots", ())],
            managed_sources=data.get("managed_sources"),
        )

    @classmethod
    def from_settings(cls, settings_obj: Any = None) -> ApprovalRegistry:
        settings_obj = settings_obj or settings
        raw_approvals = getattr(settings_obj, "CSP_POLICY_APPROVALS", ()) or ()
        managed = getattr(settings_obj, "CSP_POLICY_MANAGED_SOURCES", None)
        return cls(
            approvals=[item if isinstance(item, Approval) else Approval.from_dict(item) for item in raw_approvals],
            managed_sources=managed,
        )

    def _applicable(self, approval: Approval, snapshot: PolicySnapshot) -> bool:
        return approval.site == snapshot.site and approval.mode == snapshot.mode and approval.covers_page(snapshot.page)

    def _evaluate_approval(self, approval: Approval) -> ApprovalResult:
        decisions: list[PageDecision] = []
        applicable = [snapshot for snapshot in self._snapshots.values() if self._applicable(approval, snapshot)]

        if not applicable:
            return ApprovalResult(
                approval=approval,
                status=PENDING,
                reasons=(
                    f"no policy evidence captured for site={approval.site!r}, " f"mode={approval.mode!r}, pages={approval.pages or 'site-wide'}",
                ),
            )

        for snapshot in applicable:
            if not snapshot.delivered:
                decisions.append(
                    PageDecision(
                        page=snapshot.page,
                        mode=snapshot.mode,
                        status=NOT_DELIVERED,
                        directive=approval.directive,
                        expected_sources=approval.sources,
                        actual_sources=snapshot.sources_for(approval.directive),
                        missing_sources=approval.sources,
                        reason="policy is not delivered on this page",
                    )
                )
                continue

            actual = snapshot.sources_for(approval.directive)
            missing = tuple(source for source in approval.sources if source not in actual)
            origins = {source: snapshot.origin_for(approval.directive, source) for source in approval.sources if source in actual}
            if missing:
                decision = PageDecision(
                    page=snapshot.page,
                    mode=snapshot.mode,
                    status=NEEDS_REVIEW,
                    directive=approval.directive,
                    expected_sources=approval.sources,
                    actual_sources=actual,
                    missing_sources=missing,
                    source_origins=origins,
                    reason=(f"directive {approval.directive!r} no longer contains " f"{', '.join(missing)}"),
                )
            else:
                decision = PageDecision(
                    page=snapshot.page,
                    mode=snapshot.mode,
                    status=VALID,
                    directive=approval.directive,
                    expected_sources=approval.sources,
                    actual_sources=actual,
                    source_origins=origins,
                    reason="approved source still present",
                )
            decisions.append(decision)

        delivered_decisions = [decision for decision in decisions if decision.status != NOT_DELIVERED]
        if not delivered_decisions:
            status = PENDING
            reasons = (f"policy is not delivered on any captured page for site={approval.site!r}",)
        elif any(decision.status == NEEDS_REVIEW for decision in decisions):
            status = NEEDS_REVIEW
            reasons = tuple(f"{decision.page}: {decision.reason}" for decision in decisions if decision.status == NEEDS_REVIEW)
        elif all(decision.status == VALID for decision in decisions):
            status = VALID
            reasons = ()
        else:
            status = PENDING
            reasons = ("policy evidence is incomplete",)

        return ApprovalResult(approval=approval, status=status, pages=tuple(decisions), reasons=reasons)

    def _unapproved_uses(self) -> tuple[UnapprovedUse, ...]:
        controlled = set(self.managed_sources)
        if not controlled:
            return ()

        uses: list[UnapprovedUse] = []
        seen: set[tuple[str, str, str, str, str]] = set()
        for snapshot in self._snapshots.values():
            if not snapshot.delivered:
                continue
            for directive, actual in snapshot.directives.items():
                for source in actual:
                    if source not in controlled:
                        continue
                    covering = [
                        approval
                        for approval in self._approvals
                        if approval.site == snapshot.site
                        and approval.mode == snapshot.mode
                        and approval.directive == directive
                        and source in approval.sources
                        and approval.covers_page(snapshot.page)
                    ]
                    if covering:
                        continue
                    key = (snapshot.site, snapshot.page, snapshot.mode, directive, source)
                    if key in seen:
                        continue
                    seen.add(key)
                    uses.append(
                        UnapprovedUse(
                            site=snapshot.site,
                            page=snapshot.page,
                            mode=snapshot.mode,
                            directive=directive,
                            source=source,
                            policy_source=snapshot.origin_for(directive, source),
                        )
                    )
        return tuple(uses)

    def review(self) -> ReviewReport:
        results = tuple(self._evaluate_approval(approval) for approval in self._approvals)
        return ReviewReport(
            results=results,
            unapproved_uses=self._unapproved_uses(),
            snapshots=self.snapshots,
        )


def review_approvals(
    approvals: Iterable[Approval | Mapping[str, Any]] = (),
    snapshots: Iterable[PolicySnapshot | Mapping[str, Any]] = (),
    managed_sources: Iterable[str] | None = None,
) -> ReviewReport:
    """Build a review report from approval rows and captured policy snapshots."""

    registry = ApprovalRegistry(approvals=approvals, snapshots=snapshots, managed_sources=managed_sources)
    return registry.review()


def review_from_settings(settings_obj: Any = None) -> ReviewReport:
    """Review approvals declared in ``CSP_POLICY_APPROVALS``.

    This is the deploy-time/check-command friendly entry point.  It reads the
    registered approvals but has no per-page policy evidence, so approvals come
    back as ``pending`` until snapshots are supplied with
    :class:`ApprovalRegistry.capture` or ``CSP_POLICY_SNAPSHOTS``.
    """

    settings_obj = settings_obj or settings
    registry = ApprovalRegistry.from_settings(settings_obj)
    for snapshot in getattr(settings_obj, "CSP_POLICY_SNAPSHOTS", ()) or ():
        registry.record_snapshot(snapshot if isinstance(snapshot, PolicySnapshot) else PolicySnapshot.from_dict(snapshot))
    return registry.review()
