"""
End-to-end regression for the STIX ISSUBSET / ISSUPERSET comparison operators.

These tests drive the public ``match()`` entry point with full observed-data
SDOs (never the internal helpers directly), so every expectation exercises the
whole pipeline: object-path selection, dereferencing, the root Cyber Observable
object binding logic, the NOT complement, and observation-level joins.

Expected truth values are computed independently from the matcher via
stix2matcher.test._ip_subset_oracle, which is built on the standard library's
ipaddress module.  A test therefore fails with a concrete reason if the matcher
relies on a host implicit conversion, silently accepts an illegal CIDR as an
ordinary inequality, reverses the subset direction, or binds an observation to
the wrong root object.
"""

import pytest

from stix2matcher.matcher import MatcherException, match
from stix2matcher.test._ip_subset_oracle import (
    OracleError,
    expected_is_subset,
    expected_is_superset,
)

_stix_version = "2.0"

# Three distinct observations so that observation-level bindings can be told
# apart through first_observed in the assertions below.
_observations = [
    {
        "type": "observed-data",
        "number_observed": 1,
        "first_observed": "2020-01-01T00:00:00Z",
        "last_observed": "2020-01-01T00:00:00Z",
        "objects": {
            # Root object holding several addresses at once, including an
            # address outside the tested prefix and an IPv6 address.
            "0": {
                "type": "host",
                "addresses": [
                    "10.0.0.5",
                    "10.0.0.99",
                    "192.168.1.10",
                    "2001:db8::5",
                ],
            },
            # A network connection whose dereferenced destination is inside
            # 10.0.0.0/8, while a sibling address object is outside it.
            "1": {
                "type": "network-traffic",
                "dst_ref": "2",
            },
            "2": {
                "type": "ipv4-addr",
                "value": "10.1.2.3",
            },
            "3": {
                "type": "ipv4-addr",
                "value": "203.0.113.7",
            },
            # A second, independent root object whose own addresses must not
            # leak into bindings rooted at object "0".
            "4": {
                "type": "host",
                "addresses": [
                    "198.51.100.4",
                    "198.51.100.8",
                ],
            },
        },
    },
    {
        "type": "observed-data",
        "number_observed": 1,
        "first_observed": "2020-02-02T00:00:00Z",
        "last_observed": "2020-02-02T00:00:00Z",
        "objects": {
            "0": {
                "type": "ipv4-addr",
                # Non-canonical host bits: the value is 10.0.0.0/8 with host
                # bits set; the canonical prefix is obtained by masking.
                "value": "10.255.255.255/8",
            },
            "1": {
                "type": "ipv6-addr",
                "value": "2001:db8:1::42",
            },
        },
    },
    {
        "type": "observed-data",
        "number_observed": 1,
        "first_observed": "2020-03-03T00:00:00Z",
        "last_observed": "2020-03-03T00:00:00Z",
        "objects": {
            "0": {
                "type": "ipv4-addr",
                "value": "172.16.4.4",
            },
        },
    },
]


def _matches(pattern):
    return bool(match(pattern, _observations, stix_version=_stix_version))


def _match_on(observation, operator, literal):
    pattern = "[ipv4-addr:value {} '{}']".format(operator, literal)
    return bool(match(pattern, observation, stix_version=_stix_version))


# ---------------------------------------------------------------------------
# 1. Prefix-set truth table, independently computed with ipaddress
# ---------------------------------------------------------------------------

# (observation value, pattern CIDR literal): ISSUBSET value-in-CIDR
_subset_cases = [
    # IPv4 containment, including boundary addresses of the prefix.
    ("10.0.0.5", "10.0.0.0/8"),
    ("10.255.255.255", "10.0.0.0/8"),
    ("11.0.0.1", "10.0.0.0/8"),
    ("10.0.0.5", "10.0.0.0/32"),
    ("10.0.0.5", "10.0.0.5/32"),
    # Extreme and wildcard prefixes.
    ("10.0.0.5", "0.0.0.0/0"),
    ("0.0.0.0", "0.0.0.0/0"),
    # Prefix-to-prefix containment in both directions.
    ("10.0.0.0/16", "10.0.0.0/8"),
    ("10.0.0.0/8", "10.0.0.0/16"),
    ("10.0.0.0/8", "10.0.0.0/8"),
    # Non-canonical host bits in the observed CIDR: masking, not literal
    # integer comparison, decides the result.
    ("10.255.255.255/8", "10.0.0.0/8"),
    ("10.255.255.255/8", "10.0.0.0/16"),
    # IPv6 containment and extreme prefixes.
    ("2001:db8::1", "2001:db8::/32"),
    ("2001:db9::1", "2001:db8::/32"),
    ("2001:db8:1::42", "2001:db8::/32"),
    ("2001:db8:1::42", "::/0"),
    ("::1", "::/0"),
    ("2001:db8::/48", "2001:db8::/32"),
    ("2001:db8::/32", "2001:db8::/48"),
    ("2001:db8::1/128", "2001:db8::1/128"),
]


@pytest.mark.parametrize("value, cidr", _subset_cases)
def test_issubset_truth_table(value, cidr):
    pattern = "[ipv4-addr:value ISSUBSET '{}']".format(cidr)
    expected = expected_is_subset(value, cidr)
    observation = [
        {
            "type": "observed-data",
            "number_observed": 1,
            "first_observed": "2020-01-01T00:00:00Z",
            "last_observed": "2020-01-01T00:00:00Z",
            "objects": {
                "0": {"type": "ipv4-addr", "value": value},
            },
        }
    ]
    assert bool(match(pattern, observation, stix_version=_stix_version)) == expected


# (observed CIDR value, pattern IP/CIDR literal): ISSUPERSET
# value-must-contain-literal.  The first element is always valid CIDR because
# the observation side of ISSUPERSET is the container.
_superset_cases = [
    ("10.0.0.0/8", "10.1.2.3"),
    ("10.0.0.0/8", "10.0.0.0/16"),
    ("10.0.0.0/16", "10.0.0.0/8"),
    ("10.0.0.0/8", "11.1.2.3"),
    ("0.0.0.0/0", "10.1.2.3"),
    ("10.0.0.5/32", "10.0.0.5"),
    ("10.0.0.5/32", "10.0.0.6"),
    ("2001:db8::/32", "2001:db8:1::1"),
    ("2001:db8::/32", "2001:db9::1"),
    ("::/0", "2001:db8::1"),
    ("2001:db8::1/128", "2001:db8::1"),
    ("2001:db8::/48", "2001:db8::/32"),
]


@pytest.mark.parametrize("value, literal", _superset_cases)
def test_issuperset_truth_table(value, literal):
    pattern = "[ipv4-addr:value ISSUPERSET '{}']".format(literal)
    expected = expected_is_superset(value, literal)
    observation = [
        {
            "type": "observed-data",
            "number_observed": 1,
            "first_observed": "2020-01-01T00:00:00Z",
            "last_observed": "2020-01-01T00:00:00Z",
            "objects": {
                "0": {"type": "ipv4-addr", "value": value},
            },
        }
    ]
    assert bool(match(pattern, observation, stix_version=_stix_version)) == expected


def test_subset_direction_is_not_reversed():
    # /16 is a strict subset of /8: subset must be true one way and false the
    # other.  A direction-reversed implementation gets this pair wrong.
    inner = "10.0.0.0/16"
    outer = "10.0.0.0/8"
    inner_obs = [
        {
            "type": "observed-data",
            "number_observed": 1,
            "first_observed": "2020-01-01T00:00:00Z",
            "last_observed": "2020-01-01T00:00:00Z",
            "objects": {"0": {"type": "ipv4-addr", "value": inner}},
        }
    ]
    assert expected_is_subset(inner, outer) is True
    assert _match_on(inner_obs, "ISSUBSET", outer) is True

    assert expected_is_subset(outer, inner) is False
    outer_obs = [
        {
            "type": "observed-data",
            "number_observed": 1,
            "first_observed": "2020-01-01T00:00:00Z",
            "last_observed": "2020-01-01T00:00:00Z",
            "objects": {"0": {"type": "ipv4-addr", "value": outer}},
        }
    ]
    assert _match_on(outer_obs, "ISSUBSET", inner) is False


# ---------------------------------------------------------------------------
# 2. Multiple addresses in one observation and the NOT complement
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("pattern, expected", [
    # At least one address of root "0" is inside the prefix -> hit.
    ("[host:addresses[*] ISSUBSET '10.0.0.0/8']", True),
    # Complement: at least one address lies outside -> NOT also has a witness.
    ("[host:addresses[*] NOT ISSUBSET '10.0.0.0/8']", True),
    # No address of this host is inside 172.16.0.0/12.
    ("[host:addresses[*] ISSUBSET '172.16.0.0/12']", False),
    # Therefore every address satisfies the complement.
    ("[host:addresses[*] NOT ISSUBSET '172.16.0.0/12']", True),
    # IPv6 address in the same list is independently selectable.
    ("[host:addresses[*] ISSUBSET '2001:db8::/32']", True),
    ("[host:addresses[*] NOT ISSUBSET '2001:db8::/32']", True),
])
def test_multiple_addresses_per_root(pattern, expected):
    assert _matches(pattern) is expected


def test_not_complement_matches_oracle_for_each_value():
    # The NOT operator must be the logical complement of the positive test for
    # every individually selected address, not an any/all mix-up.
    for value in ("10.0.0.5", "192.168.1.10", "2001:db8::5"):
        cidr = "10.0.0.0/8" if ":" not in value else "2001:db8::/32"
        positive = expected_is_subset(value, cidr)
        observation = [
            {
                "type": "observed-data",
                "number_observed": 1,
                "first_observed": "2020-01-01T00:00:00Z",
                "last_observed": "2020-01-01T00:00:00Z",
                "objects": {"0": {"type": "ipv4-addr", "value": value}},
            }
        ]
        assert _match_on(observation, "ISSUBSET", cidr) is positive
        assert _match_on(observation, "NOT ISSUBSET", cidr) is not positive


# ---------------------------------------------------------------------------
# 3. Reference paths: dereferenced values and root-object binding
# ---------------------------------------------------------------------------

def test_dereferenced_reference_path_hits():
    # network-traffic "1" -> ipv4-addr "2" (10.1.2.3).  The hit must be
    # justified by the dereferenced object, not the sibling object "3".
    assert _matches(
        "[network-traffic:dst_ref.value ISSUBSET '10.0.0.0/8']") is True
    assert _matches(
        "[network-traffic:dst_ref.value NOT ISSUBSET '10.0.0.0/8']") is False


def test_reference_path_miss_is_not_rescued_by_sibling_address():
    # Object "3" (203.0.113.7) is outside the prefix; object "2" is inside.
    # A matcher that ignores reference scoping would wrongly match.
    assert _matches(
        "[network-traffic:dst_ref.value ISSUBSET '203.0.113.0/24']") is False
    assert _matches(
        "[network-traffic:dst_ref.value NOT ISSUBSET '203.0.113.0/24']") \
        is True


def test_root_binding_not_leaked_between_objects():
    # Root "4" only holds 198.51.100.0/24 addresses.  Even though observation 0
    # also contains in-prefix addresses under other roots, this root-scoped
    # conjunction must fail because no single root satisfies both tests.
    pattern = (
        "[host:addresses[*] ISSUBSET '198.51.100.0/24' "
        "AND host:addresses[*] ISSUBSET '10.0.0.0/8']"
    )
    assert _matches(pattern) is False
    # Each conjunct individually has a witness in observation 0, proving the
    # failure is a root-binding intersection issue rather than missing data.
    assert _matches(
        "[host:addresses[*] ISSUBSET '198.51.100.0/24']") is True
    assert _matches("[host:addresses[*] ISSUBSET '10.0.0.0/8']") is True


def test_other_objects_address_does_not_cause_false_positive():
    # Observation 1's object "1" is IPv6 and object "0" is an IPv4 CIDR.
    # Selecting the IPv6 object against an IPv4 prefix is a family mismatch:
    # a defined non-match, never satisfied by the sibling IPv4 object.
    assert _matches(
        "[ipv6-addr:value ISSUBSET '10.0.0.0/8']") is False
    assert _matches(
        "[ipv6-addr:value NOT ISSUBSET '10.0.0.0/8']") is True


# ---------------------------------------------------------------------------
# 4. Observation-level bindings and wildcard candidates
# ---------------------------------------------------------------------------

def test_observation_join_requires_distinct_observations():
    # Within one observation the two ipv4-addr roots cannot both be bound to the
    # same observation for an observation-level AND; across the three
    # observations there are enough distinct witnesses to satisfy the join.
    pattern = (
        "[ipv4-addr:value ISSUBSET '10.0.0.0/8'] "
        "AND [ipv4-addr:value ISSUBSET '172.16.0.0/12']"
    )
    single = [_observations[0]]
    assert bool(match(pattern, single, stix_version=_stix_version)) is False
    assert _matches(pattern) is True
    binding = match(pattern, _observations, stix_version=_stix_version)
    timestamps = sorted(sdo["first_observed"] for sdo in binding)
    assert timestamps == [
        "2020-01-01T00:00:00Z",
        "2020-03-03T00:00:00Z",
    ]


@pytest.mark.parametrize("cidr, expected", [
    ("0.0.0.0/0", True),    # IPv4 wildcard matches every IPv4 observation
    ("::/0", True),         # IPv6 wildcard matches every IPv6 observation
    ("255.255.255.255/32", False),
    ("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128", False),
])
def test_wildcard_prefix_candidates(cidr, expected):
    assert _matches(
        "[host:addresses[*] ISSUBSET '{}']".format(cidr)) is expected


# ---------------------------------------------------------------------------
# 5. Address-family mismatch is a defined non-match, not an error or inequality
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("value, literal", [
    ("2001:db8::1", "10.0.0.0/8"),
    ("10.0.0.1", "2001:db8::/32"),
    ("2001:db8::/48", "10.0.0.0/8"),
    ("10.0.0.0/8", "2001:db8::/32"),
])
def test_family_mismatch_is_defined_false(value, literal):
    # The independently computed expectation agrees that the prefix sets are
    # merely disjoint; neither side is malformed.
    assert expected_is_subset(value, literal) is False
    observation = [
        {
            "type": "observed-data",
            "number_observed": 1,
            "first_observed": "2020-01-01T00:00:00Z",
            "last_observed": "2020-01-01T00:00:00Z",
            "objects": {"0": {"type": "ipv4-addr", "value": value}},
        }
    ]
    # The matcher must not raise and must not coerce one family into the other.
    assert bool(match(
        "[ipv4-addr:value ISSUBSET '{}']".format(literal),
        observation,
        stix_version=_stix_version,
    )) is False
    # The complement of a defined false result is true.
    assert bool(match(
        "[ipv4-addr:value NOT ISSUBSET '{}']".format(literal),
        observation,
        stix_version=_stix_version,
    )) is True


def test_mixed_family_observation_remains_queryable():
    # One root object carrying both IPv4 and IPv6 addresses must still match
    # family-specific prefixes without an exception or cross-family leakage.
    assert _matches(
        "[host:addresses[*] ISSUBSET '10.0.0.0/8']") is True
    assert _matches(
        "[host:addresses[*] ISSUBSET '2001:db8::/32']") is True
    assert _matches(
        "[host:addresses[*] ISSUBSET '172.16.0.0/12']") is False


# ---------------------------------------------------------------------------
# 6. Illegal input must raise, never be treated as ordinary inequality
# ---------------------------------------------------------------------------

_illegal_cidrs = [
    "10.0.0.0/33",       # prefix beyond IPv4 width
    "10.0.0.0/abc",      # non-numeric prefix
    "10.0.0.0/-1",       # negative prefix
    "10.0.0.0",          # missing prefix where CIDR is required
    "2001:db8::/129",    # prefix beyond IPv6 width
    "2001:db8::/xx",     # non-numeric IPv6 prefix
]
_illegal_values = [
    "010.0.0.1",         # leading-zero octal form: host implicit conversion
    "10.0.0",            # inet_aton shorthand form
    "999.0.0.1",         # octet out of range
    "2001:db8::/g",      # malformed prefix
    "not-an-ip",
]


@pytest.mark.parametrize("bad_cidr", _illegal_cidrs)
def test_illegal_cidr_literal_raises(bad_cidr):
    with pytest.raises(OracleError):
        expected_is_subset("10.0.0.1", bad_cidr)
    pattern = "[ipv4-addr:value ISSUBSET '{}']".format(bad_cidr)
    with pytest.raises(MatcherException):
        match(pattern, _observations, stix_version=_stix_version)


@pytest.mark.parametrize("bad_value", _illegal_values)
def test_illegal_observed_value_raises(bad_value):
    observation = [
        {
            "type": "observed-data",
            "number_observed": 1,
            "first_observed": "2020-01-01T00:00:00Z",
            "last_observed": "2020-01-01T00:00:00Z",
            "objects": {"0": {"type": "ipv4-addr", "value": bad_value}},
        }
    ]
    with pytest.raises(OracleError):
        expected_is_subset(bad_value, "10.0.0.0/8")
    with pytest.raises(MatcherException):
        match(
            "[ipv4-addr:value ISSUBSET '10.0.0.0/8']",
            observation,
            stix_version=_stix_version,
        )


def test_issuperset_requires_cidr_observation_value():
    # A plain IP on the container side is not a valid prefix set.
    observation = [
        {
            "type": "observed-data",
            "number_observed": 1,
            "first_observed": "2020-01-01T00:00:00Z",
            "last_observed": "2020-01-01T00:00:00Z",
            "objects": {"0": {"type": "ipv4-addr", "value": "10.0.0.5"}},
        }
    ]
    with pytest.raises(OracleError):
        expected_is_superset("10.0.0.5", "10.0.0.1")
    with pytest.raises(MatcherException):
        match(
            "[ipv4-addr:value ISSUPERSET '10.0.0.1']",
            observation,
            stix_version=_stix_version,
        )


def test_non_string_value_is_not_an_illegal_cidr():
    # Non-IP-typed JSON values are simply non-matching; they must not be
    # conflated with malformed CIDR strings and therefore must not raise.
    observation = [
        {
            "type": "observed-data",
            "number_observed": 1,
            "first_observed": "2020-01-01T00:00:00Z",
            "last_observed": "2020-01-01T00:00:00Z",
            "objects": {"0": {"type": "x", "count": 7}},
        }
    ]
    assert bool(match(
        "[x:count ISSUBSET '10.0.0.0/8']",
        observation,
        stix_version=_stix_version,
    )) is False
    assert bool(match(
        "[x:count NOT ISSUBSET '10.0.0.0/8']",
        observation,
        stix_version=_stix_version,
    )) is True
