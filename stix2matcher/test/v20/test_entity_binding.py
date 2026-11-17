"""
Entity-binding regression tests for STIX 2.0.

A comparison expression's AND must be satisfied by one root SCO: two files in
one observed-data must not have their properties stitched together into a
single hit.  An AND between two observation expressions is different: it
requires two distinct observations, and each side may use its own observed-data.

See ``stix2matcher.test.entity_binding_model`` for the finite model and the
explicit table of legal/illegal bindings.
"""
import pytest

from stix2matcher.test.entity_binding_model import (
    ALLOWED_BINDINGS,
    REJECTED_BINDINGS,
    STIX_20,
    binding_provenance,
    public_hit_observed_data,
)

_stix_version = STIX_20


def _legal_observed_data(case):
    return {value for binding in case.bindings for value in binding if value is not None}


@pytest.mark.parametrize("case", ALLOWED_BINDINGS, ids=lambda case: case.id)
def test_allowed_bindings_match_the_whole_entity(case):
    actual = binding_provenance(_stix_version, case.pattern, case.scenarios)
    assert actual == case.bindings, case.why


@pytest.mark.parametrize("case", ALLOWED_BINDINGS, ids=lambda case: case.id)
def test_allowed_bindings_report_a_legal_hit_source(case):
    # match() exposes only the first binding, so check that its hit source is
    # one of the legal observations, never an unrelated one.
    actual = public_hit_observed_data(_stix_version, case.pattern, case.scenarios)
    assert actual
    assert actual <= _legal_observed_data(case), case.why


@pytest.mark.parametrize("case", REJECTED_BINDINGS, ids=lambda case: case.id)
def test_rejected_bindings_do_not_stitch_two_entities(case):
    actual = binding_provenance(_stix_version, case.pattern, case.scenarios)
    assert actual == frozenset(), case.why


@pytest.mark.parametrize("case", REJECTED_BINDINGS, ids=lambda case: case.id)
def test_rejected_bindings_report_no_hit_source(case):
    actual = public_hit_observed_data(_stix_version, case.pattern, case.scenarios)
    assert actual == frozenset(), case.why


def test_model_halves_are_genuinely_half_matches():
    # Guard the model itself: each half must match on its own, but their
    # conjunction must not.  If the model drifted, the rejection tests above
    # could pass for the wrong reason.
    name_only = ("[file:name = 'malware.exe']", "two-files-one-observation")
    size_only = ("[file:size > 1000]", "two-files-one-observation")

    for pattern, scenario in (name_only, size_only):
        assert binding_provenance(_stix_version, pattern, (scenario,))

    assert not binding_provenance(
        _stix_version,
        "[file:name = 'malware.exe' AND file:size > 1000]",
        ("two-files-one-observation",),
    )

    # The whole object satisfies all three.
    whole = "one-file-both-properties"
    for pattern in (
        "[file:name = 'malware.exe']",
        "[file:size > 1000]",
        "[file:name = 'malware.exe' AND file:size > 1000]",
    ):
        assert binding_provenance(_stix_version, pattern, (whole,))


def test_model_reference_halves_are_genuinely_half_matches():
    # Same guard for references: each half matches via a different root, so
    # only the conjunction is rejected.
    for pattern in (
        "[file:name = 'dropper']",
        "[file:parent_ref.size > 1000]",
    ):
        assert binding_provenance(_stix_version, pattern, ("ref-two-roots",))

    assert not binding_provenance(
        _stix_version,
        "[file:name = 'dropper' AND file:parent_ref.size > 1000]",
        ("ref-two-roots",),
    )


def test_model_cross_referents_are_a_legal_complex_path():
    # Both referents belong to one root; the complex path is legitimate and
    # must keep working.  This guards against "fixing" binding by forbidding
    # every multi-referent path.
    for pattern in (
        "[file:parent_refs[*].name = 'alpha']",
        "[file:parent_refs[*].size > 1000]",
        "[file:parent_refs[*].name = 'alpha' AND file:parent_refs[*].size > 1000]",
    ):
        assert binding_provenance(_stix_version, pattern, ("ref-cross-branches",))


def test_comparison_and_versus_observation_and_are_distinct():
    # The same two observed-data SDOs: the comparison-level AND cannot span
    # them, but the observation-level AND must.  This is the sharpest
    # contrast between the two operators.
    comparison_level = binding_provenance(
        _stix_version,
        "[file:name = 'malware.exe' AND file:size > 1000]",
        ("name-file", "size-file"),
    )
    observation_level = binding_provenance(
        _stix_version,
        "[file:name = 'malware.exe'] AND [file:size > 1000]",
        ("name-file", "size-file"),
    )

    assert comparison_level == frozenset()
    assert observation_level == frozenset({
        (
            "observed-data--name-file",
            "observed-data--size-file",
        ),
    })


def test_comparison_and_versus_observation_and_same_observation():
    # Two half-files inside one observed-data: neither operator may stitch
    # them, because the comparison needs one root and the observation-level
    # AND needs two distinct observations (number_observed is 1).
    scenarios = ("two-files-one-observation",)

    assert not binding_provenance(
        _stix_version,
        "[file:name = 'malware.exe' AND file:size > 1000]",
        scenarios,
    )
    assert not binding_provenance(
        _stix_version,
        "[file:name = 'malware.exe'] AND [file:size > 1000]",
        scenarios,
    )
