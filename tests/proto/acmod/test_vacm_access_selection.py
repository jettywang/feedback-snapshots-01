"""RFC 3415 vacmAccessTable row-selection tests.

Every configuration in this module is built by writing the real
SNMP-VIEW-BASED-ACM-MIB rows through ``pysnmp.entity.config`` helpers and
then exercising either ``Vacm.evaluate_access`` or ``is_access_allowed``.
No private ranking function is called directly.

The tests assert three things for each request: the eligible candidate
set, the priority that selected the winner, and the final OID decision.
"""

import pytest

from pysnmp.entity import config, engine
from pysnmp.proto import errind, error, rfc1902
from pysnmp.proto.acmod import vacm_access

PUBLIC = rfc1902.OctetString(b"public")

INCLUDED_TREE = (1, 3, 6, 1, 2, 1)
EXCLUDED_LEAF = (1, 3, 6, 1, 2, 1, 1, 1)

READ_OID = (1, 3, 6, 1, 2, 1, 2, 1, 0)
DECOY_ONLY_OID = (1, 3, 6, 1, 2, 2, 1, 0)


def _new_engine(*contexts):
    """Create an engine with the given vacmContextTable rows."""
    snmpEngine = engine.SnmpEngine()

    for contextName in contexts:
        config.add_context(snmpEngine, contextName)

    return snmpEngine


def _add_access(
    snmpEngine,
    group_name,
    context_prefix,
    security_model,
    security_level,
    context_match,
    read_view=b"",
    write_view=b"",
    notify_view=b"",
):
    """Write one active vacmAccessTable row."""
    config.add_vacm_access(
        snmpEngine,
        group_name,
        context_prefix,
        security_model,
        security_level,
        context_match,
        read_view,
        write_view,
        notify_view,
    )


def _add_views(snmpEngine, *view_names):
    """Give each named view a covering included subtree."""
    for view_name in view_names:
        config.add_vacm_view(snmpEngine, view_name, "included", INCLUDED_TREE, b"")


def _evaluate(
    snmpEngine,
    context_name,
    security_model=2,
    security_level=1,
    security_name=PUBLIC,
    view_type="read",
    variable_name=READ_OID,
):
    """Evaluate access through the ACM registered on the engine."""
    return snmpEngine.access_control_model[3].evaluate_access(
        snmpEngine,
        security_model,
        security_name,
        security_level,
        view_type,
        rfc1902.OctetString(context_name),
        variable_name,
    )


def _describe(decision):
    """Compact assertion message carrying the full decision evidence."""
    return (
        f"reason={decision.reason} "
        f"eligible={[(row.context_prefix, row.security_model, row.security_level) for row in decision.eligible]} "
        f"selected={decision.selected.context_prefix if decision.selected else None!r} "
        f"basis={decision.basis.summary() if decision.basis else None} "
        f"view={decision.view_name!r} allowed={decision.allowed}"
    )


# ---------------------------------------------------------------------------
# Eligibility is independent of preference
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "hard_to_satisfy",
    [
        # Security model index 3 does not match the requested model 2
        # and is not 'any'.
        dict(asset=b"ctx", security_model=3, security_level=1, match=2),
        # authPriv exceeds the requested authNoPriv.
        dict(asset=b"ctx", security_model=2, security_level=3, match=2),
        # An exact match against another context name.
        dict(asset=b"ctx-other", security_model=2, security_level=1, match=1),
        # A prefix the requested context name does not start with.
        dict(asset=b"zzz", security_model=2, security_level=1, match=2),
    ],
    ids=["security-model", "security-level", "exact-context", "prefix-context"],
)
def test_ineligible_row_cannot_win_with_longer_prefix_or_higher_level(hard_to_satisfy):
    """A row failing step 1 must not outrank an eligible, shorter row."""
    snmpEngine = _new_engine(b"", b"ctx", b"ctx-other")
    config.add_vacm_group(snmpEngine, "group", 2, PUBLIC)

    # The eligible row has the shortest possible context prefix.  The
    # decoy is longer, or higher-level, or higher-model.
    _add_access(snmpEngine, "group", b"", 2, 1, 2, read_view=b"view-base")
    _add_access(
        snmpEngine,
        "group",
        hard_to_satisfy["asset"],
        hard_to_satisfy["security_model"],
        hard_to_satisfy["security_level"],
        hard_to_satisfy["match"],
        read_view=b"view-decoy",
    )
    _add_views(snmpEngine, "view-base", "view-decoy")

    decision = _evaluate(snmpEngine, b"ctx", security_level=2)

    assert decision.allowed is True, _describe(decision)
    assert decision.view_name == b"view-base", _describe(decision)
    assert decision.basis.security_model == "specific", _describe(decision)
    assert decision.basis.context_prefix_length == 0, _describe(decision)
    assert decision.basis.security_level == 1, _describe(decision)
    assert decision.selected.context_prefix == b"", _describe(decision)
    # The decoy never entered the candidate set.
    assert decision.eligible == (decision.selected,), _describe(decision)
    # The decision record carries the winning evidence for auditing.
    assert decision.view_name == b"view-base"
    assert decision.reason == "allowed"
    assert decision.error_indication == errind.accessAllowed
    assert decision.variable_name == READ_OID
    assert decision.view_type == "read"


def test_candidate_set_lists_every_eligible_row():
    """Eligible rows are reported even when they lose the preference race."""
    snmpEngine = _new_engine(b"", b"ctx-public-sub")
    config.add_vacm_group(snmpEngine, "group", 2, PUBLIC)

    _add_access(snmpEngine, "group", b"", 2, 1, 2, read_view=b"view-base")
    _add_access(snmpEngine, "group", b"ctx", 0, 1, 2, read_view=b"view-any")
    _add_access(snmpEngine, "group", b"ctx-public", 2, 1, 2, read_view=b"view-long")
    _add_access(
        snmpEngine, "group", b"ctx-public-sub", 2, 3, 1, read_view=b"view-denied"
    )
    _add_views(snmpEngine, "view-base", "view-any", "view-long", "view-denied")

    decision = _evaluate(snmpEngine, b"ctx-public-sub", security_level=2)

    # The authPriv-only row is not eligible at authNoPriv; the 'any'
    # row is eligible but loses on security model.
    eligible = {
        (row.context_prefix, row.security_model, row.security_level)
        for row in decision.eligible
    }
    assert eligible == {
        (b"", 2, 1),
        (b"ctx", 0, 1),
        (b"ctx-public", 2, 1),
    }
    assert decision.allowed is True, _describe(decision)
    assert decision.view_name == b"view-long", _describe(decision)
    assert decision.basis.security_model == "specific", _describe(decision)
    assert decision.basis.context_prefix_length == len(b"ctx-public"), _describe(
        decision
    )


# ---------------------------------------------------------------------------
# The four RFC 3415 step 2 preferences
# ---------------------------------------------------------------------------


def test_security_model_precedes_context_prefix_length():
    """Exact security model beats an 'any' row with a longer prefix."""
    snmpEngine = _new_engine(b"", b"ctx-public")
    config.add_vacm_group(snmpEngine, "group", 2, PUBLIC)

    _add_access(snmpEngine, "group", b"ctx", 2, 1, 2, read_view=b"view-specific")
    _add_access(snmpEngine, "group", b"ctx-public", 0, 1, 2, read_view=b"view-any")
    _add_views(snmpEngine, "view-specific", "view-any")

    decision = _evaluate(snmpEngine, b"ctx-public")

    assert decision.allowed is True, _describe(decision)
    assert decision.view_name == b"view-specific", _describe(decision)
    assert decision.basis.security_model == "specific", _describe(decision)
    assert decision.basis.context_prefix_length == len(b"ctx"), _describe(decision)


def test_exact_context_precedes_longer_prefix():
    """An exact context match beats a longer prefix match."""
    snmpEngine = _new_engine(b"", b"ctx-public")
    config.add_vacm_group(snmpEngine, "group", 2, PUBLIC)

    _add_access(snmpEngine, "group", b"ctx-public", 2, 1, 1, read_view=b"view-exact")
    _add_access(snmpEngine, "group", b"ctx-", 2, 1, 2, read_view=b"view-prefix")
    _add_views(snmpEngine, "view-exact", "view-prefix")

    decision = _evaluate(snmpEngine, b"ctx-public")

    assert decision.allowed is True, _describe(decision)
    assert decision.view_name == b"view-exact", _describe(decision)
    assert decision.basis.context_match == "exact", _describe(decision)


def test_longest_prefix_precedes_security_level():
    """Among prefix matches, the longest prefix beats a higher level."""
    snmpEngine = _new_engine(b"", b"ctx-public")
    config.add_vacm_group(snmpEngine, "group", 2, PUBLIC)

    _add_access(snmpEngine, "group", b"ctx", 2, 3, 2, read_view=b"view-short-high")
    _add_access(snmpEngine, "group", b"ctx-public", 2, 1, 2, read_view=b"view-long")
    _add_views(snmpEngine, "view-short-high", "view-long")

    decision = _evaluate(snmpEngine, b"ctx-public", security_level=3)

    assert decision.allowed is True, _describe(decision)
    assert decision.view_name == b"view-long", _describe(decision)
    assert decision.basis.context_prefix_length == len(b"ctx-public"), _describe(
        decision
    )
    assert decision.basis.security_level == 1, _describe(decision)


def test_highest_security_level_breaks_final_tie():
    """Equally indexed rows differing only in level select the highest."""
    snmpEngine = _new_engine(b"", b"ctx")
    config.add_vacm_group(snmpEngine, "group", 2, PUBLIC)

    _add_access(snmpEngine, "group", b"ctx", 2, 1, 1, read_view=b"view-low")
    _add_access(snmpEngine, "group", b"ctx", 2, 2, 1, read_view=b"view-mid")
    _add_access(snmpEngine, "group", b"ctx", 2, 3, 1, read_view=b"view-high")
    _add_views(snmpEngine, "view-low", "view-mid", "view-high")

    decision = _evaluate(snmpEngine, b"ctx", security_level=3)

    assert decision.allowed is True, _describe(decision)
    assert decision.view_name == b"view-high", _describe(decision)
    assert decision.basis.security_level == 3, _describe(decision)
    assert {row.security_level for row in decision.eligible} == {1, 2, 3}


# ---------------------------------------------------------------------------
# No candidate, and view isolation per type
# ---------------------------------------------------------------------------


def test_no_eligible_candidate_is_an_access_entry_error():
    """A context-matching row whose level is too high yields noAccessEntry."""
    snmpEngine = _new_engine(b"", b"ctx")
    config.add_vacm_group(snmpEngine, "group", 2, PUBLIC)

    _add_access(snmpEngine, "group", b"ctx", 2, 3, 1, read_view=b"view-high")
    _add_views(snmpEngine, "view-high")

    decision = _evaluate(snmpEngine, b"ctx", security_level=2)

    assert decision.allowed is False, _describe(decision)
    assert decision.eligible == ()
    assert decision.selected is None
    assert decision.basis is None
    assert decision.reason == "no-eligible-row"
    assert decision.error_indication == errind.noAccessEntry

    with pytest.raises(error.StatusInformation) as errorInfo:
        snmpEngine.access_control_model[3].is_access_allowed(
            snmpEngine, 2, PUBLIC, 2, "read", rfc1902.OctetString(b"ctx"), READ_OID
        )

    assert errorInfo.value["errorIndication"] == errind.noAccessEntry


def test_view_types_do_not_borrow_each_other():
    """read, write and notify resolve only their own view column."""
    snmpEngine = _new_engine(b"", b"ctx")
    config.add_vacm_group(snmpEngine, "group", 2, PUBLIC)

    _add_access(
        snmpEngine,
        "group",
        b"ctx",
        2,
        1,
        1,
        read_view=b"view-read",
        write_view=b"",
        notify_view=b"view-notify",
    )
    _add_views(snmpEngine, "view-read", "view-notify")

    read_decision = _evaluate(snmpEngine, b"ctx", view_type="read")
    write_decision = _evaluate(snmpEngine, b"ctx", view_type="write")
    notify_decision = _evaluate(snmpEngine, b"ctx", view_type="notify")

    assert read_decision.allowed is True, _describe(read_decision)
    assert read_decision.view_name == b"view-read"

    # The empty write view must not fall back to the read or notify view.
    assert write_decision.allowed is False, _describe(write_decision)
    assert write_decision.view_name == b""
    assert write_decision.reason == "empty-view"
    assert write_decision.error_indication == errind.noSuchView

    assert notify_decision.allowed is True, _describe(notify_decision)
    assert notify_decision.view_name == b"view-notify"


def test_unknown_view_name_yields_no_such_view():
    """A selected row naming a missing view must not reuse another view."""
    snmpEngine = _new_engine(b"", b"ctx")
    config.add_vacm_group(snmpEngine, "group", 2, PUBLIC)

    _add_access(snmpEngine, "group", b"ctx", 2, 1, 1, read_view=b"view-missing")
    _add_views(snmpEngine, "view-other")

    decision = _evaluate(snmpEngine, b"ctx")

    assert decision.allowed is False, _describe(decision)
    assert decision.selected.context_prefix == b"ctx"
    assert decision.reason == "unknown-view"
    assert decision.error_indication == errind.noSuchView

    # The legacy entry point must raise rather than return a status object,
    # otherwise a missing view would silently read as "allowed".
    with pytest.raises(error.StatusInformation) as errorInfo:
        snmpEngine.access_control_model[3].is_access_allowed(
            snmpEngine, 2, PUBLIC, 1, "read", rfc1902.OctetString(b"ctx"), READ_OID
        )

    assert errorInfo.value["errorIndication"] == errind.noSuchView


def test_excluded_subtree_inside_included_view():
    """Final OID decision honours the view's excluded subtree."""
    snmpEngine = _new_engine(b"", b"ctx")
    config.add_vacm_group(snmpEngine, "group", 2, PUBLIC)

    _add_access(snmpEngine, "group", b"ctx", 2, 1, 1, read_view=b"view")
    config.add_vacm_view(snmpEngine, "view", "included", INCLUDED_TREE, b"")
    config.add_vacm_view(snmpEngine, "view", "excluded", EXCLUDED_LEAF, b"")

    allowed = _evaluate(snmpEngine, b"ctx", variable_name=READ_OID)
    denied = _evaluate(snmpEngine, b"ctx", variable_name=EXCLUDED_LEAF + (0,))

    assert allowed.allowed is True, _describe(allowed)
    assert allowed.view_name == b"view"
    assert denied.allowed is False, _describe(denied)
    assert denied.reason == "not-in-view"
    assert denied.error_indication == errind.notInView


# ---------------------------------------------------------------------------
# Cache rebuilds from the live MIB, independent of insertion order
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "rows",
    [
        (
            (b"", 2, 1, 2, b"view-base"),
            (b"ctx-public", 0, 1, 2, b"view-any"),
            (b"ctx", 2, 2, 2, b"view-high"),
        ),
        (
            (b"ctx", 2, 2, 2, b"view-high"),
            (b"ctx-public", 0, 1, 2, b"view-any"),
            (b"", 2, 1, 2, b"view-base"),
        ),
        (
            (b"ctx-public", 0, 1, 2, b"view-any"),
            (b"", 2, 1, 2, b"view-base"),
            (b"ctx", 2, 2, 2, b"view-high"),
        ),
    ],
    ids=["ascending", "descending", "mixed"],
)
def test_selection_is_independent_of_row_insertion_order(rows):
    """The same logical table selects the same row in any insertion order."""
    snmpEngine = _new_engine(b"", b"ctx", b"ctx-public")
    config.add_vacm_group(snmpEngine, "group", 2, PUBLIC)

    for prefix, security_model, security_level, context_match, view in rows:
        _add_access(
            snmpEngine,
            "group",
            prefix,
            security_model,
            security_level,
            context_match,
            read_view=view,
        )
        _add_views(snmpEngine, view)

    decision = _evaluate(snmpEngine, b"ctx-public", security_level=2)

    # RFC 3415: the exact context beats the 'any' row; security level
    # then chooses the higher of the two remaining levels.
    assert decision.allowed is True, _describe(decision)
    assert decision.view_name == b"view-high", _describe(decision)
    assert decision.selected.context_prefix == b"ctx"
    assert decision.basis.security_model == "specific"
    assert decision.basis.security_level == 2


def test_cache_rebuilds_after_rows_are_added_and_removed():
    """Hot caches must track real row creation, replacement and deletion."""
    snmpEngine = _new_engine(b"", b"ctx")
    config.add_vacm_group(snmpEngine, "group", 2, PUBLIC)

    _add_access(snmpEngine, "group", b"ctx", 2, 1, 1, read_view=b"view-low")
    _add_views(snmpEngine, "view-low", "view-high")

    first = _evaluate(snmpEngine, b"ctx")
    assert first.view_name == b"view-low", _describe(first)

    # Add a higher-level row with the same indices except for level.
    _add_access(snmpEngine, "group", b"ctx", 2, 2, 1, read_view=b"view-high")

    second = _evaluate(snmpEngine, b"ctx", security_level=2)
    assert second.view_name == b"view-high", _describe(second)
    assert second.basis.security_level == 2

    # Delete the winning row; the older row must become selected again.
    config.delete_vacm_access(snmpEngine, "group", b"ctx", 2, 2)

    third = _evaluate(snmpEngine, b"ctx", security_level=2)
    assert third.view_name == b"view-low", _describe(third)
    assert third.basis.security_level == 1

    # Delete every access row; the decision becomes noAccessEntry.
    config.delete_vacm_access(snmpEngine, "group", b"ctx", 2, 1)

    fourth = _evaluate(snmpEngine, b"ctx", security_level=2)
    assert fourth.allowed is False, _describe(fourth)
    assert fourth.reason == "no-eligible-row"
    assert fourth.eligible == ()
    assert fourth.error_indication == errind.noAccessEntry


def test_cache_rebuild_after_view_tree_changes():
    """Deleting a view row must invalidate the cached view tree."""
    snmpEngine = _new_engine(b"", b"ctx")
    config.add_vacm_group(snmpEngine, "group", 2, PUBLIC)

    _add_access(snmpEngine, "group", b"ctx", 2, 1, 1, read_view=b"view")
    config.add_vacm_view(snmpEngine, "view", "included", INCLUDED_TREE, b"")

    before = _evaluate(snmpEngine, b"ctx")
    assert before.allowed is True, _describe(before)

    config.delete_vacm_view(snmpEngine, "view", INCLUDED_TREE)

    after = _evaluate(snmpEngine, b"ctx")
    assert after.allowed is False, _describe(after)
    assert after.view_name == b"view"
    assert after.basis is not None
    assert after.reason == "unknown-view"
    assert after.error_indication == errind.noSuchView


def test_cache_rebuild_after_row_replacement_with_new_view_name():
    """Replacing a row's read view must be observed by the next request."""
    snmpEngine = _new_engine(b"", b"ctx", b"ctx-sub")
    config.add_vacm_group(snmpEngine, "group", 2, PUBLIC)

    _add_access(snmpEngine, "group", b"ctx", 2, 1, 2, read_view=b"view-old")
    _add_views(snmpEngine, "view-old", "view-new")

    first = _evaluate(snmpEngine, b"ctx-sub")
    assert first.view_name == b"view-old", _describe(first)

    # Same indices, different view column content.
    config.add_vacm_access(
        snmpEngine,
        "group",
        b"ctx",
        2,
        1,
        "prefix",
        b"view-new",
        b"",
        b"",
    )

    second = _evaluate(snmpEngine, b"ctx-sub")
    assert second.view_name == b"view-new", _describe(second)


def test_cache_rebuild_after_in_place_column_write():
    """A SET of a non-index column must invalidate the row cache.

    ``config.add_vacm_access`` rewrites the whole row, but instrumentation
    may also SET just one column.  Only that column's branch version is
    bumped then, so the cache key must cover the row's columns.
    """
    snmpEngine = _new_engine(b"", b"ctx")
    config.add_vacm_group(snmpEngine, "group", 2, PUBLIC)

    _add_access(snmpEngine, "group", b"ctx", 2, 1, 1, read_view=b"view-old")
    _add_views(snmpEngine, "view-old", "view-new")

    first = _evaluate(snmpEngine, b"ctx")
    assert first.view_name == b"view-old", _describe(first)

    (vacmAccessReadViewName,) = snmpEngine.get_mib_builder().import_symbols(
        "SNMP-VIEW-BASED-ACM-MIB", "vacmAccessReadViewName"
    )
    instance = vacmAccessReadViewName.getNextNode(vacmAccessReadViewName.name)
    snmpEngine.message_dispatcher.mib_instrum_controller.write_variables((
        instance.name,
        b"view-new",
    ))

    second = _evaluate(snmpEngine, b"ctx")
    assert second.view_name == b"view-new", _describe(second)


def test_cache_rebuild_after_in_place_view_column_write():
    """A SET of vacmViewTreeFamilyType must change the OID decision."""
    snmpEngine = _new_engine(b"", b"ctx")
    config.add_vacm_group(snmpEngine, "group", 2, PUBLIC)

    _add_access(snmpEngine, "group", b"ctx", 2, 1, 1, read_view=b"view")
    config.add_vacm_view(snmpEngine, "view", "included", INCLUDED_TREE, b"")

    before = _evaluate(snmpEngine, b"ctx")
    assert before.allowed is True, _describe(before)

    (vacmViewTreeFamilyType,) = snmpEngine.get_mib_builder().import_symbols(
        "SNMP-VIEW-BASED-ACM-MIB", "vacmViewTreeFamilyType"
    )
    instance = vacmViewTreeFamilyType.getNextNode(vacmViewTreeFamilyType.name)
    snmpEngine.message_dispatcher.mib_instrum_controller.write_variables((
        instance.name,
        2,
    ))

    after = _evaluate(snmpEngine, b"ctx")
    assert after.allowed is False, _describe(after)
    assert after.reason == "not-in-view"


def test_cache_rebuild_after_group_mapping_changes():
    """Changing vacmSecurityToGroupTable must invalidate the group cache."""
    snmpEngine = _new_engine(b"", b"ctx")
    config.add_vacm_group(snmpEngine, "group-a", 2, PUBLIC)
    config.add_vacm_group(snmpEngine, "group-b", 2, PUBLIC)

    _add_access(snmpEngine, "group-a", b"ctx", 2, 1, 1, read_view=b"view-a")
    _add_access(snmpEngine, "group-b", b"ctx", 2, 1, 1, read_view=b"view-b")
    _add_views(snmpEngine, "view-a", "view-b")

    # The later write wins the (securityModel, securityName) index.
    first = _evaluate(snmpEngine, b"ctx")
    assert first.view_name in (b"view-a", b"view-b"), _describe(first)

    config.add_vacm_group(snmpEngine, "group-a", 2, PUBLIC)

    second = _evaluate(snmpEngine, b"ctx")
    assert second.view_name == b"view-a", _describe(second)
    assert second.selected.group_name == b"group-a"


def test_denied_request_does_not_leak_allowed_result():
    """A denied OID must raise notInView and never report success."""
    snmpEngine = _new_engine(b"", b"ctx")
    config.add_vacm_group(snmpEngine, "group", 2, PUBLIC)

    _add_access(snmpEngine, "group", b"ctx", 2, 1, 1, read_view=b"view")
    config.add_vacm_view(snmpEngine, "view", "included", INCLUDED_TREE, b"")

    with pytest.raises(error.StatusInformation) as errorInfo:
        snmpEngine.access_control_model[3].is_access_allowed(
            snmpEngine,
            2,
            PUBLIC,
            1,
            "read",
            rfc1902.OctetString(b"ctx"),
            DECOY_ONLY_OID,
        )

    assert errorInfo.value["errorIndication"] == errind.notInView


# ---------------------------------------------------------------------------
# The fixture must notice a reversed priority stage
# ---------------------------------------------------------------------------

_INVERSION_CASES = [
    (
        "exact_context_before_security_model",
        [
            # (prefix, model, level, match, view)
            (b"ctx-public", 0, 1, 1, b"view-any-exact"),
            (b"ctx", 2, 1, 2, b"view-specific"),
        ],
        dict(context_name=b"ctx-public", security_level=2),
        b"view-specific",
        b"view-any-exact",
        (
            "exact_context",
            "security_model",
            "prefix_length",
            "security_level",
        ),
    ),
    (
        "security_level_before_prefix_length",
        [
            (b"ctx", 2, 3, 2, b"view-short-high"),
            (b"ctx-publ", 2, 1, 2, b"view-long-low"),
        ],
        dict(context_name=b"ctx-public", security_level=3),
        b"view-long-low",
        b"view-short-high",
        (
            "security_model",
            "exact_context",
            "security_level",
            "prefix_length",
        ),
    ),
    (
        "prefix_length_before_security_model",
        [
            (b"ctx", 2, 1, 2, b"view-specific"),
            (b"ctx-public", 0, 1, 2, b"view-any-long"),
        ],
        dict(context_name=b"ctx-public", security_level=2),
        b"view-specific",
        b"view-any-long",
        (
            "exact_context",
            "prefix_length",
            "security_model",
            "security_level",
        ),
    ),
]


@pytest.mark.parametrize(
    "case_name,rows,request_kwargs,expected_view,decoy_view,inverted_order",
    _INVERSION_CASES,
    ids=[case[0] for case in _INVERSION_CASES],
)
def test_fixture_detects_reversed_priority(
    monkeypatch,
    case_name,
    rows,
    request_kwargs,
    expected_view,
    decoy_view,
    inverted_order,
):
    """Temporarily reversing a stage must surface the wrongly allowed row.

    The least-privilege configuration selects a row whose view covers a
    narrower OID set.  After swapping one RFC 3415 preference with its
    neighbour, the fixture asserts the winner changed and that the
    wrongly selected view is reported.
    """
    snmpEngine = _new_engine(b"", b"ctx", b"ctx-public")
    config.add_vacm_group(snmpEngine, "group", 2, PUBLIC)

    for prefix, security_model, security_level, context_match, view in rows:
        _add_access(
            snmpEngine,
            "group",
            prefix,
            security_model,
            security_level,
            context_match,
            read_view=view,
        )
        # The correct winner only sees READ_OID; the decoy sees both.
        config.add_vacm_view(
            snmpEngine,
            view,
            "included",
            DECOY_ONLY_OID,
            b"",
        )

    config.delete_vacm_view(snmpEngine, expected_view, DECOY_ONLY_OID)
    config.add_vacm_view(snmpEngine, expected_view, "included", READ_OID[:-1], b"")

    baseline = _evaluate(snmpEngine, **request_kwargs)
    assert baseline.allowed is True, _describe(baseline)
    assert baseline.view_name == expected_view, _describe(baseline)

    monkeypatch.setattr(vacm_access, "PRIORITY_STAGES", inverted_order)

    inverted = _evaluate(snmpEngine, **request_kwargs)
    assert inverted.view_name == decoy_view, _describe(inverted)
    assert inverted.view_name != expected_view, _describe(inverted)

    # The wrong winner must actually change the OID decision for an OID
    # that only the decoy view covers.
    inverted_oid = _evaluate(
        snmpEngine, **{**request_kwargs, "variable_name": DECOY_ONLY_OID}
    )
    assert inverted_oid.view_name == decoy_view, _describe(inverted_oid)
    assert inverted_oid.allowed is True, _describe(inverted_oid)

    # Restoring the RFC order restores the least-privilege decision.
    monkeypatch.setattr(
        vacm_access,
        "PRIORITY_STAGES",
        (
            "security_model",
            "exact_context",
            "prefix_length",
            "security_level",
        ),
    )
    restored = _evaluate(
        snmpEngine, **{**request_kwargs, "variable_name": DECOY_ONLY_OID}
    )
    assert restored.view_name == expected_view, _describe(restored)
    assert restored.allowed is False, _describe(restored)
