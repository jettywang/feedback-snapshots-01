"""
STIX 2.1 end-to-end regression for ISSUBSET / ISSUPERSET.

The 2.0 companion file covers the comparison semantics and illegal-input
handling in depth; this file focuses on the 2.1 packaging differences that can
break root-object/observation binding: observed-data SDOs reference SCOs by id
through object_refs, and multiple observed-data SDOs are split out of a single
bundle before matching.

Expected truth values come from the same independent ipaddress-based oracle.
"""

import pytest

from stix2matcher.matcher import MatcherException, match
from stix2matcher.test._ip_subset_oracle import (
    OracleError,
    expected_is_subset,
)

_stix_version = "2.1"

_HOST = "host--00000000-0000-4000-8000-000000000001"
_TRAFFIC = "network-traffic--00000000-0000-4000-8000-000000000002"
_DST_INSIDE = "ipv4-addr--00000000-0000-4000-8000-000000000003"
_DST_OUTSIDE = "ipv4-addr--00000000-0000-4000-8000-000000000004"
_OTHER_HOST = "host--00000000-0000-4000-8000-000000000005"
_V6 = "ipv6-addr--00000000-0000-4000-8000-000000000006"

_bundle = {
    "type": "bundle",
    "id": "bundle--00000000-0000-4000-8000-0000000000aa",
    "objects": [
        {
            "id": "observed-data--00000000-0000-4000-8000-000000000010",
            "type": "observed-data",
            "number_observed": 1,
            "first_observed": "2020-01-01T00:00:00Z",
            "last_observed": "2020-01-01T00:00:00Z",
            "object_refs": [_HOST, _TRAFFIC, _DST_INSIDE, _DST_OUTSIDE,
                            _OTHER_HOST, _V6],
            "spec_version": "2.1",
        },
        {
            "id": _HOST,
            "type": "host",
            "addresses": [
                "10.0.0.5",
                "10.0.0.99",
                "192.168.1.10",
                "2001:db8::5",
            ],
        },
        {
            "id": _TRAFFIC,
            "type": "network-traffic",
            "dst_ref": _DST_INSIDE,
        },
        {"id": _DST_INSIDE, "type": "ipv4-addr", "value": "10.1.2.3"},
        {"id": _DST_OUTSIDE, "type": "ipv4-addr", "value": "203.0.113.7"},
        {
            "id": _OTHER_HOST,
            "type": "host",
            "addresses": ["198.51.100.4", "198.51.100.8"],
        },
        {"id": _V6, "type": "ipv6-addr", "value": "2001:db8:1::42"},
        {
            "id": "observed-data--00000000-0000-4000-8000-000000000020",
            "type": "observed-data",
            "number_observed": 1,
            "first_observed": "2020-02-02T00:00:00Z",
            "last_observed": "2020-02-02T00:00:00Z",
            "object_refs": ["ipv4-addr--00000000-0000-4000-8000-000000000007"],
            "spec_version": "2.1",
        },
        {
            "id": "ipv4-addr--00000000-0000-4000-8000-000000000007",
            "type": "ipv4-addr",
            "value": "172.16.4.4",
        },
    ],
}


def _matches(pattern):
    return bool(match(pattern, [_bundle], stix_version=_stix_version))


def _single_sdo_observation(value, first_observed="2020-01-01T00:00:00Z"):
    addr_id = "ipv4-addr--00000000-0000-4000-8000-0000000000b1"
    return [{
        "type": "bundle",
        "id": "bundle--00000000-0000-4000-8000-0000000000bb",
        "objects": [
            {
                "id": "observed-data--00000000-0000-4000-8000-0000000000b2",
                "type": "observed-data",
                "number_observed": 1,
                "first_observed": first_observed,
                "last_observed": first_observed,
                "object_refs": [addr_id],
                "spec_version": "2.1",
            },
            {"id": addr_id, "type": "ipv4-addr", "value": value},
        ],
    }]


@pytest.mark.parametrize("value, cidr", [
    ("10.1.2.3", "10.0.0.0/8"),
    ("11.1.2.3", "10.0.0.0/8"),
    ("10.0.0.5", "0.0.0.0/0"),
    ("2001:db8::1", "2001:db8::/32"),
    ("2001:db9::1", "2001:db8::/32"),
    ("2001:db8::1", "::/0"),
])
def test_v21_subset_matches_oracle(value, cidr):
    expected = expected_is_subset(value, cidr)
    result = bool(match(
        "[ipv4-addr:value ISSUBSET '{}']".format(cidr),
        _single_sdo_observation(value),
        stix_version=_stix_version,
    ))
    assert result is expected


@pytest.mark.parametrize("pattern, expected", [
    ("[host:addresses[*] ISSUBSET '10.0.0.0/8']", True),
    ("[host:addresses[*] NOT ISSUBSET '10.0.0.0/8']", True),
    ("[host:addresses[*] ISSUBSET '172.16.0.0/12']", False),
    ("[host:addresses[*] NOT ISSUBSET '172.16.0.0/12']", True),
    ("[host:addresses[*] ISSUBSET '2001:db8::/32']", True),
])
def test_v21_multiple_addresses_per_root(pattern, expected):
    assert _matches(pattern) is expected


def test_v21_dereferenced_object_ref_path():
    # dst_ref resolves to the inside address; the sibling outside SCO must not
    # be used as evidence.
    assert _matches(
        "[network-traffic:dst_ref.value ISSUBSET '10.0.0.0/8']") is True
    assert _matches(
        "[network-traffic:dst_ref.value NOT ISSUBSET '10.0.0.0/8']") is False
    assert _matches(
        "[network-traffic:dst_ref.value ISSUBSET '203.0.113.0/24']") is False


def test_v21_root_binding_not_leaked_between_scos():
    pattern = (
        "[host:addresses[*] ISSUBSET '198.51.100.0/24' "
        "AND host:addresses[*] ISSUBSET '10.0.0.0/8']"
    )
    assert _matches(pattern) is False
    assert _matches(
        "[host:addresses[*] ISSUBSET '198.51.100.0/24']") is True
    assert _matches("[host:addresses[*] ISSUBSET '10.0.0.0/8']") is True


def test_v21_observation_join_binds_distinct_sdos():
    # The two observed-data SDOs split from the bundle must be bound
    # distinctly; the returned bundles identify which observations were used.
    pattern = (
        "[ipv4-addr:value ISSUBSET '10.0.0.0/8'] "
        "AND [ipv4-addr:value ISSUBSET '172.16.0.0/12']"
    )
    binding = match(pattern, [_bundle], stix_version=_stix_version)
    assert binding
    timestamps = sorted(
        obj["first_observed"]
        for bundle in binding
        for obj in bundle["objects"]
        if obj["type"] == "observed-data"
    )
    assert timestamps == [
        "2020-01-01T00:00:00Z",
        "2020-02-02T00:00:00Z",
    ]


def test_v21_family_mismatch_is_defined_false():
    assert _matches("[ipv6-addr:value ISSUBSET '10.0.0.0/8']") is False
    assert _matches("[ipv6-addr:value NOT ISSUBSET '10.0.0.0/8']") is True
    assert expected_is_subset("2001:db8:1::42", "10.0.0.0/8") is False


@pytest.mark.parametrize("bad_cidr", [
    "10.0.0.0/33",
    "10.0.0.0/abc",
    "2001:db8::/129",
    "10.0.0.0",
])
def test_v21_illegal_cidr_raises(bad_cidr):
    with pytest.raises(OracleError):
        expected_is_subset("10.0.0.1", bad_cidr)
    with pytest.raises(MatcherException):
        match(
            "[ipv4-addr:value ISSUBSET '{}']".format(bad_cidr),
            [_bundle],
            stix_version=_stix_version,
        )


@pytest.mark.parametrize("bad_value", [
    "010.0.0.1",
    "10.0.0",
    "999.0.0.1",
    "not-an-ip",
])
def test_v21_illegal_observed_value_raises(bad_value):
    with pytest.raises(OracleError):
        expected_is_subset(bad_value, "10.0.0.0/8")
    with pytest.raises(MatcherException):
        match(
            "[ipv4-addr:value ISSUBSET '10.0.0.0/8']",
            _single_sdo_observation(bad_value),
            stix_version=_stix_version,
        )


def test_v21_wildcard_prefixes():
    assert _matches(
        "[host:addresses[*] ISSUBSET '0.0.0.0/0']") is True
    assert _matches("[host:addresses[*] ISSUBSET '::/0']") is True
    assert _matches(
        "[host:addresses[*] ISSUBSET '255.255.255.255/32']") is False
