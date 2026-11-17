import pytest

from stix2matcher.matcher import MatcherException, match

_stix_version = '2.1'


def _observed_data(sdo_id, object_refs):
    return {
        "type": "observed-data",
        "spec_version": "2.1",
        "id": sdo_id,
        "number_observed": 1,
        "first_observed": "2021-01-01T00:00:00Z",
        "last_observed": "2021-01-01T00:00:00Z",
        "object_refs": object_refs
    }


def _file(sco_id, name):
    return {
        "type": "file",
        "spec_version": "2.1",
        "id": sco_id,
        "name": name
    }


def _bundle(bundle_id, objects):
    return {
        "type": "bundle",
        "id": bundle_id,
        "objects": objects
    }


def _result_sdo_ids(sdos):
    return [sdo["objects"][0]["id"] for sdo in sdos]


def _result_object_ids(sdo):
    return [obj.get("id") for obj in sdo["objects"]]


# Two observations have their conditions deliberately split apart.  Each has
# one file which only its own observation references, and they legally share
# a third, identical SCO.  Observation 3 references a file which is only
# present in observation 1's bundle.
def _observations():
    return [
        _bundle("bundle--1", [
            _observed_data("observed-data--1", ["file--one", "file--shared"]),
            _file("file--one", "one.bin"),
            _file("file--shared", "shared.bin"),
            _file("file--decoy", "decoy.bin")
        ]),
        _bundle("bundle--2", [
            _observed_data("observed-data--2", ["file--two", "file--shared"]),
            _file("file--two", "two.bin"),
            _file("file--shared", "shared.bin")
        ]),
        _bundle("bundle--3", [
            _observed_data("observed-data--3", ["file--one", "file--three"]),
            _file("file--three", "three.bin")
        ])
    ]


def test_conditions_from_two_observations_do_not_combine():
    # "one.bin" belongs to observation 1, "two.bin" to observation 2.  They
    # must never be joined into a single-observation match.
    assert not match("[file:name='one.bin' AND file:name='two.bin']",
                     _observations(), stix_version=_stix_version)


def test_unreferenced_sco_in_own_bundle_is_not_usable():
    # "decoy.bin" is physically in bundle 1 but absent from observation 1's
    # object_refs, so it is not part of the observation.
    assert not match("[file:name='decoy.bin']", _observations(),
                     stix_version=_stix_version)


def test_unresolved_reference_is_not_borrowed_from_another_bundle():
    # Observation 3 references file--one, which only exists in bundle 1.
    # file--three proves observation 3 itself is usable, but file--one must
    # remain unresolved rather than being borrowed from bundle 1.
    assert not match("[file:name='one.bin' AND file:name='three.bin']",
                     _observations(), stix_version=_stix_version)

    result = match("[file:name='one.bin']", _observations(),
                   stix_version=_stix_version)
    assert _result_sdo_ids(result) == ["observed-data--1"]

    # A dedicated observation whose only reference does not resolve must not
    # match anything, even though another bundle happens to define that SCO.
    observations = _observations()
    observations.append(_bundle("bundle--4", [
        _observed_data("observed-data--4", ["file--one"])
    ]))
    assert not match("[file:name='one.bin']", [
        observations[-1]
    ], stix_version=_stix_version)
    result = match("[file:name='one.bin']", observations,
                   stix_version=_stix_version)
    assert "observed-data--4" not in _result_sdo_ids(result)


def test_unresolved_reference_does_not_drop_legal_observation_material():
    result = match("[file:name='three.bin']", _observations(),
                   stix_version=_stix_version)
    assert _result_sdo_ids(result) == ["observed-data--3"]
    assert _result_object_ids(result[0]) == [
        "observed-data--3", "file--three"
    ]


def test_result_only_carries_participating_observation_materials():
    result = match("[file:name='one.bin']", _observations(),
                   stix_version=_stix_version)
    assert len(result) == 1
    assert set(_result_object_ids(result[0])) == {
        "observed-data--1", "file--one", "file--shared"
    }


def test_shared_sco_remains_matchable_for_each_observation():
    result = match("[file:name='shared.bin']", _observations(),
                   stix_version=_stix_version)
    # match() returns only the first binding's observation; whichever one it
    # is, it must be self-contained, not a union of observation materials.
    assert len(result) == 1
    assert set(_result_object_ids(result[0])) in (
        {"observed-data--1", "file--one", "file--shared"},
        {"observed-data--2", "file--two", "file--shared"}
    )


def test_observation_level_and_keeps_legal_two_observation_result():
    result = match("[file:name='one.bin'] AND [file:name='two.bin']",
                   _observations(), stix_version=_stix_version)
    assert sorted(_result_sdo_ids(result)) == [
        "observed-data--1", "observed-data--2"
    ]
    expected = {
        "observed-data--1": {
            "observed-data--1", "file--one", "file--shared"
        },
        "observed-data--2": {
            "observed-data--2", "file--two", "file--shared"
        }
    }
    for sdo in result:
        sdo_id = sdo["objects"][0]["id"]
        assert set(_result_object_ids(sdo)) == expected[sdo_id]


def test_sco_shared_by_two_observations_in_one_bundle():
    # A single bundle where both observations reference the same SCO.  Use
    # observation-level AND because comparison-expression AND intersects the
    # root SCO sets within a single observation.
    bundle = _bundle("bundle--in-bundle-share", [
        _observed_data("observed-data--left", ["file--one", "file--shared"]),
        _observed_data("observed-data--right", ["file--two", "file--shared"]),
        _file("file--one", "one.bin"),
        _file("file--two", "two.bin"),
        _file("file--shared", "shared.bin")
    ])
    left = match("[file:name='one.bin'] AND [file:name='shared.bin']",
                 [bundle], stix_version=_stix_version)
    assert sorted(_result_sdo_ids(left)) == [
        "observed-data--left", "observed-data--right"
    ]

    right = match("[file:name='two.bin'] AND [file:name='shared.bin']",
                  [bundle], stix_version=_stix_version)
    assert sorted(_result_sdo_ids(right)) == [
        "observed-data--left", "observed-data--right"
    ]

    # Both conditions split across the two observations still must not join
    # into a single-observation match.
    assert not match("[file:name='one.bin' AND file:name='two.bin']",
                     [bundle], stix_version=_stix_version)


def test_reference_chain_stays_within_object_refs():
    # A chain target is only reachable if it is itself part of the
    # observation's object_refs; a chain must not escape to another bundle.
    observations = [
        _bundle("bundle--chain", [
            _observed_data("observed-data--chain", ["file--child"]),
            {
                "type": "file",
                "spec_version": "2.1",
                "id": "file--child",
                "name": "child.bin",
                "parent_ref": "file--parent"
            }
        ]),
        _bundle("bundle--chain-parent", [
            _observed_data("observed-data--parent", ["file--parent"]),
            _file("file--parent", "parent.bin")
        ])
    ]
    assert not match("[file:parent_ref.name='parent.bin']", observations,
                     stix_version=_stix_version)

    # When the target is in the same object_refs list the chain is legal.
    same_bundle = _bundle("bundle--chain-ok", [
        _observed_data("observed-data--chain-ok",
                       ["file--child", "file--parent"]),
        {
            "type": "file",
            "spec_version": "2.1",
            "id": "file--child",
            "name": "child.bin",
            "parent_ref": "file--parent"
        },
        _file("file--parent", "parent.bin")
    ])
    result = match("[file:parent_ref.name='parent.bin']", [same_bundle],
                   stix_version=_stix_version)
    assert _result_sdo_ids(result) == ["observed-data--chain-ok"]


def test_returned_result_preserves_observed_data_identity():
    result = match("[file:name='two.bin']", _observations(),
                   stix_version=_stix_version)
    assert len(result) == 1
    observed_data = result[0]["objects"][0]
    assert observed_data["type"] == "observed-data"
    assert observed_data["id"] == "observed-data--2"
    assert set(observed_data["object_refs"]) == {"file--two", "file--shared"}


def test_repeated_reference_in_object_refs_is_deduplicated():
    bundle = _bundle("bundle--repeat-ref", [
        _observed_data("observed-data--repeat-ref",
                       ["file--shared", "file--shared"]),
        _file("file--shared", "shared.bin")
    ])
    result = match("[file:name='shared.bin']", [bundle],
                   stix_version=_stix_version)
    assert _result_sdo_ids(result) == ["observed-data--repeat-ref"]
    assert _result_object_ids(result[0]) == [
        "observed-data--repeat-ref", "file--shared"
    ]


def test_identical_duplicate_objects_in_one_bundle_are_harmless():
    bundle = _bundle("bundle--dup-identical", [
        _observed_data("observed-data--dup-identical", ["file--shared"]),
        _file("file--shared", "shared.bin"),
        _file("file--shared", "shared.bin")
    ])
    result = match("[file:name='shared.bin']", [bundle],
                   stix_version=_stix_version)
    assert _result_sdo_ids(result) == ["observed-data--dup-identical"]


def test_conflicting_duplicate_sco_ids_in_one_bundle_are_rejected():
    bundle = _bundle("bundle--dup-conflict", [
        _observed_data("observed-data--dup-conflict", ["file--shared"]),
        _file("file--shared", "shared.bin"),
        _file("file--shared", "other.bin")
    ])
    with pytest.raises(MatcherException):
        match("[file:name='shared.bin']", [bundle], stix_version=_stix_version)


def test_conflicting_duplicate_observed_data_ids_in_one_bundle_are_rejected():
    bundle = _bundle("bundle--dup-od-conflict", [
        _observed_data("observed-data--dup", ["file--shared"]),
        _observed_data("observed-data--dup", ["file--one"]),
        _file("file--shared", "shared.bin"),
        _file("file--one", "one.bin")
    ])
    with pytest.raises(MatcherException):
        match("[file:name='shared.bin']", [bundle], stix_version=_stix_version)


def test_same_sco_id_in_different_bundles_resolves_locally():
    # Bundles are independent reference scopes; the same SCO id may appear in
    # both, and each observation resolves to its own bundle's copy.
    observations = [
        _bundle("bundle--left", [
            _observed_data("observed-data--left", ["file--shared"]),
            _file("file--shared", "left.bin")
        ]),
        _bundle("bundle--right", [
            _observed_data("observed-data--right", ["file--shared"]),
            _file("file--shared", "right.bin")
        ])
    ]
    left = match("[file:name='left.bin']", observations,
                 stix_version=_stix_version)
    assert _result_sdo_ids(left) == ["observed-data--left"]

    right = match("[file:name='right.bin']", observations,
                  stix_version=_stix_version)
    assert _result_sdo_ids(right) == ["observed-data--right"]


def test_numeric_local_ids_are_not_resolved_in_2_1():
    # 2.0 resolves local numeric ids inside one observation; 2.1 object_refs
    # are full STIX ids and must not adopt that namespace.
    bundle = _bundle("bundle--numeric", [
        _observed_data("observed-data--numeric", ["0"]),
        _file("file--shared", "shared.bin")
    ])
    assert not match("[file:name='shared.bin']", [bundle],
                     stix_version=_stix_version)
