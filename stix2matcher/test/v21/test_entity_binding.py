"""
Entity-binding regression tests for STIX 2.1.

The STIX 2.1 model in ``stix2matcher.test.entity_binding_model`` wraps one
observed-data and its SCOs in a bundle, so the hit source has two layers: the
bundle returned by match() and the observed-data inside it.  These tests assert
the observed-data provenance, which is the part that identifies the entity.
"""
import pytest

from stix2matcher.test.entity_binding_model import (
    ALLOWED_BINDINGS,
    REJECTED_BINDINGS,
    STIX_21,
    binding_provenance,
    public_hit_observed_data,
)

_stix_version = STIX_21


def _legal_observed_data(case):
    return {value for binding in case.bindings for value in binding if value is not None}


@pytest.mark.parametrize("case", ALLOWED_BINDINGS, ids=lambda case: case.id)
def test_allowed_bindings_match_the_whole_entity(case):
    actual = binding_provenance(_stix_version, case.pattern, case.scenarios)
    assert actual == case.bindings, case.why


@pytest.mark.parametrize("case", ALLOWED_BINDINGS, ids=lambda case: case.id)
def test_allowed_bindings_report_a_legal_hit_source(case):
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
    for pattern in ("[file:name = 'malware.exe']", "[file:size > 1000]"):
        assert binding_provenance(_stix_version, pattern, ("two-files-one-observation",))

    assert not binding_provenance(
        _stix_version,
        "[file:name = 'malware.exe' AND file:size > 1000]",
        ("two-files-one-observation",),
    )

    whole = "one-file-both-properties"
    for pattern in (
        "[file:name = 'malware.exe']",
        "[file:size > 1000]",
        "[file:name = 'malware.exe' AND file:size > 1000]",
    ):
        assert binding_provenance(_stix_version, pattern, (whole,))


def test_model_reference_halves_are_genuinely_half_matches():
    for pattern in ("[file:name = 'dropper']", "[file:parent_ref.size > 1000]"):
        assert binding_provenance(_stix_version, pattern, ("ref-two-roots",))

    assert not binding_provenance(
        _stix_version,
        "[file:name = 'dropper' AND file:parent_ref.size > 1000]",
        ("ref-two-roots",),
    )


def test_model_cross_referents_are_a_legal_complex_path():
    for pattern in (
        "[file:parent_refs[*].name = 'alpha']",
        "[file:parent_refs[*].size > 1000]",
        "[file:parent_refs[*].name = 'alpha' AND file:parent_refs[*].size > 1000]",
    ):
        assert binding_provenance(_stix_version, pattern, ("ref-cross-branches",))


def test_comparison_and_versus_observation_and_are_distinct():
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
