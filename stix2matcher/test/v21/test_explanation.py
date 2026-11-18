import copy
import json

import pytest

from stix2matcher.matcher import (
    MatchExplanation,
    explain_match,
    match,
    verify_explanation,
)

_stix_version = '2.1'
_observations = [
    {
        "type": "bundle",
        "id": "bundle--explanation-a",
        "objects": [
            {
                "type": "observed-data",
                "id": "observed-data--explanation-a",
                "spec_version": "2.1",
                "number_observed": 1,
                "first_observed": "2020-01-01T00:00:00Z",
                "last_observed": "2020-01-01T00:00:00Z",
                "object_refs": [
                    "person--alice",
                    "person--bob",
                    "person--dave",
                ],
            },
            {
                "type": "person",
                "id": "person--alice",
                "name": "alice",
                "knows_ref": "person--bob",
            },
            {"type": "person", "id": "person--bob", "name": "bob"},
            {"type": "person", "id": "person--dave", "name": "dave"},
        ],
    },
    {
        "type": "bundle",
        "id": "bundle--explanation-b",
        "objects": [
            {
                "type": "observed-data",
                "id": "observed-data--explanation-b",
                "spec_version": "2.1",
                "number_observed": 1,
                "first_observed": "2020-01-01T00:00:05Z",
                "last_observed": "2020-01-01T00:00:05Z",
                "object_refs": ["person--carol"],
            },
            {"type": "person", "id": "person--carol", "name": "carol"},
        ],
    },
]

# A rule with a reference, an OR, an unselected branch, and a temporal
# qualifier.
_pattern = (
    "(([person:knows_ref.name = 'bob'] OR [person:name = 'zelda']) "
    "AND [person:name = 'carol']) WITHIN 10 SECONDS"
)


def test_default_match_contract_is_unchanged():
    result = match(
        "[person:knows_ref.name = 'bob']", _observations,
        stix_version=_stix_version,
    )
    assert type(result) is list
    assert result == match(
        "[person:knows_ref.name = 'bob']", _observations,
        stix_version=_stix_version, explain=False,
    )


def test_explanation_is_also_the_matching_sdos():
    result = match(_pattern, _observations, stix_version=_stix_version,
                   explain=True)
    assert isinstance(result, MatchExplanation)
    assert isinstance(result, list)
    assert result == match(_pattern, _observations,
                           stix_version=_stix_version)
    assert result.matched is True
    assert result["witnesses"] == list(result.witnesses)
    assert explain_match(_pattern, _observations,
                         stix_version=_stix_version).to_dict() == \
        result.to_dict()


def test_witness_links_expression_root_path_instance_and_time():
    result = match(_pattern, _observations, stix_version=_stix_version,
                   explain=True)
    by_expression = dict(
        (witness.expression, witness) for witness in result.witnesses
    )

    ref = by_expression["[person:knows_ref.name = 'bob']"]
    assert ref.root_sco["id"] == "person--alice"
    assert ref.root_sco["type"] == "person"
    assert ref.path == "knows_ref.name"
    assert ref.property == "knows_ref.name"
    assert ref.operator == "="
    assert ref.literal == "bob"
    assert ref.value == "bob"
    # The reference path records the actual referent that was selected.
    tokens = ref.comparisons[0].tokens
    assert {"kind": "root", "sco_id": "person--alice",
            "type": "person"} in tokens
    assert {"kind": "reference", "property": "knows_ref",
            "target_sco_id": "person--bob"} in tokens
    assert ref.comparisons[0].reference_chain == [
        "person--alice", "person--bob",
    ]

    assert ref.observation.id == "observed-data--explanation-a"
    assert ref.observation.instance == 0
    assert ref.time.first_observed == "2020-01-01T00:00:00Z"
    assert ref.time.last_observed == "2020-01-01T00:00:00Z"

    carol = by_expression["[person:name = 'carol']"]
    assert carol.root_sco["id"] == "person--carol"
    assert carol.observation.id == "observed-data--explanation-b"
    assert carol.path == "name"

    # The WITHIN scope is recorded as an explicit temporal constraint.
    assert any(
        constraint["kind"] == "within" and
        constraint["seconds"] == 10 and
        set(constraint["slots"]) == {0, 2}
        for constraint in result.time_constraints
    )


def test_or_explains_only_the_selected_branch():
    result = match(_pattern, _observations, stix_version=_stix_version,
                   explain=True)
    ref = result.witnesses[0]
    witnesses = json.dumps(result.to_dict()["witnesses"])

    # 'zelda' was never satisfied, so it is not part of the reason.
    assert "zelda" not in witnesses
    assert all("zelda" not in witness.expression
               for witness in result.witnesses)
    assert ref.evaluation.kind == "test"


def test_explanation_does_not_dump_unrelated_objects_or_bundles():
    result = match(_pattern, _observations, stix_version=_stix_version,
                   explain=True)
    serialized = json.dumps(result.to_dict())

    # dave is in the bundle but plays no role in this match; the bundle
    # wrapper itself is not copied into the explanation either.
    assert "dave" not in serialized
    assert "bundle--explanation-a" not in serialized
    assert "bundle--explanation-b" not in serialized
    for witness in result.witnesses:
        assert witness.root_sco["id"] in serialized


def test_explanation_can_be_replayed_independently():
    result = match(_pattern, _observations, stix_version=_stix_version,
                   explain=True)
    assert result.verify(_observations) is True
    assert verify_explanation(result.to_dict(), _observations) is True
    assert verify_explanation(result, _observations) is True

    # Round-tripping through JSON loses no replayable evidence.
    restored = json.loads(json.dumps(result.to_dict()))
    assert verify_explanation(restored, _observations) is True

    # A witness that no longer carries its comparison tokens is rejected.
    broken = copy.deepcopy(result.to_dict())
    broken["witnesses"][0]["comparisons"][0]["tokens"] = []
    assert verify_explanation(broken, _observations) is False


def test_replacing_the_reason_object_invalidates_the_reason():
    result = match(_pattern, _observations, stix_version=_stix_version,
                   explain=True)
    assert result.verify(_observations) is True

    changed = copy.deepcopy(_observations)
    for bundle in changed:
        for obj in bundle["objects"]:
            if obj.get("name") == "bob":
                obj["name"] = "robert"

    # The explanation no longer recomputes, and a fresh match agrees.
    assert result.verify(changed) is False
    assert not match(_pattern, changed, stix_version=_stix_version)


def test_unrelated_object_does_not_become_part_of_the_reason():
    result = match(_pattern, _observations, stix_version=_stix_version,
                   explain=True)

    changed = copy.deepcopy(_observations)
    for bundle in changed:
        for obj in bundle["objects"]:
            if obj.get("name") == "dave":
                obj["name"] = "eve"

    assert result.verify(changed) is True


def test_explanation_order_is_repeatable():
    first = match(_pattern, _observations, stix_version=_stix_version,
                  explain=True).to_dict()
    second = match(_pattern, _observations, stix_version=_stix_version,
                   explain=True).to_dict()

    assert first == second
    assert [witness["slot"] for witness in first["witnesses"]] == \
        sorted(witness["slot"] for witness in first["witnesses"])


def test_no_match_has_no_fabricated_witness():
    result = match(
        "([person:name = 'nobody'] OR [person:name = 'zelda'])",
        _observations, stix_version=_stix_version, explain=True,
    )
    assert result.matched is False
    assert result.witnesses == ()
    assert result == []
    assert result.to_dict()["witnesses"] == []
    assert result.verify(_observations) is True


@pytest.mark.parametrize("pattern", [
    "[person:knows_refs[*].name = 'carol']",
    "[person:knows_refs[*].name = 'alice' OR person:knows_ref.name = 'bob']",
    "[person:knows_refs[*].name = 'carol' AND person:knows_refs[*].name = 'bob']",
    "[person:knows_refs[*].knows_refs[*].name = 'alice']",
])
def test_reference_witnesses(patch_observations, pattern):
    result = match(pattern, patch_observations, stix_version=_stix_version,
                   explain=True)
    assert result.matched
    assert result.verify(patch_observations)
    assert all(witness.comparisons for witness in result.witnesses)


@pytest.fixture
def patch_observations():
    return [
        {
            "type": "bundle",
            "id": "bundle--reference-explanation",
            "objects": [
                {
                    "type": "observed-data",
                    "id": "observed-data--reference-explanation",
                    "spec_version": "2.1",
                    "number_observed": 1,
                    "first_observed": "1984-06-26T13:53:04Z",
                    "last_observed": "1984-06-26T13:53:04Z",
                    "object_refs": [
                        "person--e34",
                        "person--e3f",
                        "person--e91",
                    ],
                },
                {
                    "type": "person",
                    "id": "person--e34",
                    "name": "alice",
                    "knows_ref": "person--e3f",
                },
                {
                    "type": "person",
                    "id": "person--e3f",
                    "name": "bob",
                    "knows_refs": ["person--e34", "person--e91"],
                },
                {
                    "type": "person",
                    "id": "person--e91",
                    "name": "carol",
                    "knows_refs": ["person--e34", "person--e3f", "person--e91"],
                },
            ],
        },
    ]
