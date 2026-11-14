#
# This file is part of pysnmp software.
#
# Copyright (c) 2005-2020, Ilya Etingof <etingof@gmail.com>
# License: https://www.pysnmp.com/pysnmp/license.html
#
"""RFC 3415 vacmAccessTable row selection.

This module models the access row selection procedure from RFC 3415,
section 3.2 and the DESCRIPTION clause of ``vacmAccessTable``.  It is
deliberately independent of the MIB instrumentation and of the caches
used by :class:`pysnmp.proto.acmod.rfc3415.Vacm`: callers supply the
active table rows and the request parameters.

Candidate eligibility and preference are kept separate:

* Eligibility (RFC 3415, ``vacmAccessTable`` step 1) requires the
  requested group, a context match, an exact or ``any`` security model
  and a security level no greater than the requested one.
* Preference (RFC 3415, ``vacmAccessTable`` step 2) then applies, in
  order, exact security model over ``any``, exact context prefix over a
  prefix match, longest matching prefix, and finally highest security
  level.

A row that fails an eligibility test can therefore never win merely
because it has a longer context prefix or a higher security level.
"""

from dataclasses import dataclass

EXACT_CONTEXT_MATCH = 1
PREFIX_CONTEXT_MATCH = 2
ANY_SECURITY_MODEL = 0


@dataclass(frozen=True)
class AccessRow:
    """One active row of ``vacmAccessTable``.

    All context and view names are represented as bytes so that the
    selection model does not depend on any particular ASN.1 value class.
    """

    group_name: bytes
    context_prefix: bytes
    security_model: int
    security_level: int
    context_match: int
    read_view: bytes
    write_view: bytes
    notify_view: bytes

    def view_name(self, view_type: str) -> bytes:
        """Return the view name column belonging to ``view_type``.

        Each view type must use its own column; no view type falls back
        to another one when its own view name is empty.
        """
        if view_type == "read":
            return self.read_view
        if view_type == "write":
            return self.write_view
        if view_type == "notify":
            return self.notify_view
        raise ValueError(f"Unsupported view type {view_type!r}")

    def context_matches(self, context_name: bytes) -> bool:
        """Return whether this row's context prefix matches the request."""
        if self.context_match == EXACT_CONTEXT_MATCH:
            return self.context_prefix == context_name
        if self.context_match == PREFIX_CONTEXT_MATCH:
            return context_name.startswith(self.context_prefix)
        return False

    def is_eligible(
        self,
        group_name: bytes,
        context_name: bytes,
        security_model: int,
        security_level: int,
    ) -> bool:
        """Return whether this row is a candidate for the request."""
        return (
            self.group_name == group_name
            and self.context_matches(context_name)
            and self.security_model in (security_model, ANY_SECURITY_MODEL)
            and self.security_level <= security_level
        )


@dataclass(frozen=True)
class SelectionBasis:
    """The RFC 3415 step 2 criteria that selected the winning row."""

    security_model: str
    context_match: str
    context_prefix_length: int
    security_level: int

    def summary(self) -> str:
        """Return a compact human readable explanation."""
        return (
            f"securityModel={self.security_model}, "
            f"contextPrefix={self.context_match}"
            f"({self.context_prefix_length}), "
            f"securityLevel={self.security_level}"
        )


@dataclass(frozen=True)
class RowSelection:
    """Result of selecting one ``vacmAccessTable`` row."""

    eligible: tuple[AccessRow, ...]
    selected: "AccessRow | None"
    view_name: "bytes | None"
    basis: "SelectionBasis | None"
    reason: str


PRIORITY_STAGES = (
    "security_model",
    "exact_context",
    "prefix_length",
    "security_level",
)
"""The RFC 3415 step 2 preference ladder.

The tuple is module level so that tests can temporarily reorder one
stage and verify that the fixture detects the resulting wrong allow.
Production code always uses the order above.
"""


def _row_sort_key(row: AccessRow) -> tuple:
    """Build a deterministic ordering for reporting and tie-breaking."""
    return (
        row.context_prefix,
        row.security_model,
        row.security_level,
        row.context_match,
        row.read_view,
        row.write_view,
        row.notify_view,
    )


def _apply_stage(candidates, stage, context_name, security_model):
    """Narrow candidates by one RFC 3415 step 2 preference stage."""
    if stage == "security_model":
        preferred = tuple(
            row for row in candidates if row.security_model == security_model
        )
        return preferred or candidates

    if stage == "exact_context":
        preferred = tuple(
            row for row in candidates if row.context_prefix == context_name
        )
        return preferred or candidates

    if stage == "prefix_length":
        longest = max(len(row.context_prefix) for row in candidates)
        return tuple(row for row in candidates if len(row.context_prefix) == longest)

    if stage == "security_level":
        highest = max(row.security_level for row in candidates)
        return tuple(row for row in candidates if row.security_level == highest)

    raise ValueError(f"Unsupported priority stage {stage!r}")


def select_access_row(
    rows,
    group_name: bytes,
    context_name: bytes,
    security_model: int,
    security_level: int,
    view_type: str,
) -> RowSelection:
    """Select the ``vacmAccessTable`` row for a request.

    Args:
        rows: Iterable of :class:`AccessRow` objects to consider.
        group_name: Group name resolved from ``vacmSecurityToGroupTable``.
        context_name: Context name from the request.
        security_model: Security model from the request.
        security_level: Security level from the request.
        view_type: One of ``"read"``, ``"write"`` or ``"notify"``.

    Returns:
        RowSelection: The eligible candidates, the winning row, the view
        name from that row, and the priority basis that selected it.  If
        no row is eligible, ``selected`` and ``basis`` are ``None`` and
        ``reason`` is ``"no-eligible-row"``.

    Eligibility is computed first and independently of preference, so a
    row rejected by step 1 never becomes a candidate.  Preference then
    follows :data:`PRIORITY_STAGES`.
    """
    if view_type not in ("read", "write", "notify"):
        raise ValueError(f"Unsupported view type {view_type!r}")

    # RFC 3415, vacmAccessTable step 1: candidate eligibility.
    eligible = tuple(
        sorted(
            (
                row
                for row in rows
                if row.is_eligible(
                    group_name, context_name, security_model, security_level
                )
            ),
            key=_row_sort_key,
        )
    )

    if not eligible:
        return RowSelection(
            eligible=eligible,
            selected=None,
            view_name=None,
            basis=None,
            reason="no-eligible-row",
        )

    candidates = eligible

    # RFC 3415, vacmAccessTable step 2.
    for stage in PRIORITY_STAGES:
        candidates = _apply_stage(candidates, stage, context_name, security_model)

    # The indexed table normally leaves a single row here.  Keep the
    # result deterministic even if a caller supplies duplicate rows.
    selected = min(candidates, key=_row_sort_key)

    return RowSelection(
        eligible=eligible,
        selected=selected,
        view_name=selected.view_name(view_type),
        basis=SelectionBasis(
            security_model=(
                "specific" if selected.security_model == security_model else "any"
            ),
            context_match=(
                "exact" if selected.context_prefix == context_name else "prefix"
            ),
            context_prefix_length=len(selected.context_prefix),
            security_level=selected.security_level,
        ),
        reason="selected",
    )


@dataclass(frozen=True)
class AccessDecision:
    """Complete outcome of one ``isAccessAllowed`` evaluation.

    ``eligible`` lists every candidate row that passed the step 1 tests,
    ``selected`` is the row chosen by step 2, ``basis`` records which
    preference selected it, ``view_name`` is the view taken from the
    selected row's column for ``view_type``, and ``allowed`` is the final
    result of matching ``variable_name`` against that view.
    """

    security_model: int
    security_name: bytes
    security_level: int
    view_type: str
    context_name: bytes
    variable_name: tuple
    eligible: tuple[AccessRow, ...]
    selected: "AccessRow | None"
    basis: "SelectionBasis | None"
    view_name: "bytes | None"
    allowed: bool
    error_indication: object
    reason: str
