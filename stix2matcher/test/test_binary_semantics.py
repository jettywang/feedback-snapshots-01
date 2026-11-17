"""
End-to-end comparison regressions for binary threat indicators.

The table below is deliberately independent from the matcher implementation:
each row pins one operator, one literal form (hex, base64, JSON string, LIKE,
MATCHES), one input value, and the exact set of observations that must be
bound.  The cases exercise zero bytes, bytes which are not valid UTF-8, and
characters which cannot be represented as a single byte, and they keep three
different notions apart:

* binary values are compared as byte sequences;
* text values are compared after Unicode NFC normalization;
* only the LIKE/MATCHES pattern is NFC-normalized for text operands, while its
  codepoints are used as raw byte values for binary operands.

STIX 2.0 and 2.1 encode observations differently, but the expected bindings
are the same, so every row is checked against both supported versions.
"""

import pytest
from stix2patterns.pattern import ParseException

from stix2matcher.matcher import MatchListener, MatcherException, Pattern, match

# Two distinct observations.  Property names use the _hex/_bin suffixes STIX
# assigns to binary values, so the matcher's own suffix handling is exercised
# instead of values prepared by the test.
_SCO_A = {
    "type": "binary_test",
    "name": u"alice",
    "nfc_text": u"\u00e9",
    "nfd_text": u"e\u0301",
    "hex_name_hex": u"616c696365",
    "hex_zero_hex": u"00",
    "hex_ff_hex": u"ff",
    "hex_newline_hex": u"0a",
    "hex_crlf_hex": u"0d0a",
    "hex_utf8_e_acute_hex": u"c3a9",
    "hex_latin1_e_acute_hex": u"e9",
    "hex_combining_e_acute_hex": u"65cc81",
    "b64_name_bin": u"YWxpY2U=",
    "b64_zero_bin": u"AA==",
    "b64_ff_bin": u"/w==",
    "text_zero": u"\x00",
    "crlf_text": u"\r\n",
    "count": 5,
}

_SCO_B = {
    "type": "binary_test",
    "name": u"bob",
    "nfc_text": u"\u00f6",
    "nfd_text": u"o\u0308",
    "hex_name_hex": u"626f62",
    "hex_zero_hex": u"01",
    "hex_ff_hex": u"fe",
    "hex_newline_hex": u"0b",
    "hex_crlf_hex": u"0d0b",
    "hex_utf8_e_acute_hex": u"c3b6",
    "hex_latin1_e_acute_hex": u"f6",
    "hex_combining_e_acute_hex": u"6fcc88",
    "b64_name_bin": u"Ym9i",
    "b64_zero_bin": u"AQ==",
    "b64_ff_bin": u"/g==",
    "text_zero": u"\x01",
    "crlf_text": u"\r\x0b",
    "count": 5,
}

_OD_A = "observed-data--00000000-0000-4000-8000-000000000001"
_OD_B = "observed-data--00000000-0000-4000-8000-000000000002"

_SCO_A_ID = "binary_test--00000000-0000-4000-8000-00000000000a"
_SCO_B_ID = "binary_test--00000000-0000-4000-8000-00000000000b"

_OBSERVATION_NAMES = {_OD_A: "A", _OD_B: "B"}


def _observed_data_20(observed_id, sco):
    return {
        "id": observed_id,
        "type": "observed-data",
        "number_observed": 1,
        "first_observed": "2011-12-03T21:34:41Z",
        "last_observed": "2011-12-03T21:34:41Z",
        "objects": {"0": sco},
    }


def _bundle(observed_id, sco):
    return {
        "type": "bundle",
        "id": "bundle--" + observed_id[len("observed-data--"):],
        "objects": [
            {
                "id": observed_id,
                "type": "observed-data",
                "number_observed": 1,
                "first_observed": "2011-12-03T21:34:41Z",
                "last_observed": "2011-12-03T21:34:41Z",
                "object_refs": [sco["id"]],
                "spec_version": "2.1",
            },
            sco,
        ],
    }


_OBSERVATIONS = {
    "2.0": [
        _observed_data_20(_OD_A, _SCO_A),
        _observed_data_20(_OD_B, _SCO_B),
    ],
    "2.1": [
        _bundle(_OD_A, dict(_SCO_A, id=_SCO_A_ID)),
        _bundle(_OD_B, dict(_SCO_B, id=_SCO_B_ID)),
    ],
}


def _observed_data_ids(sdo):
    """Extract observed-data ids from a matched SDO in either version's
    representation."""
    ids = set()
    if sdo.get("type") == "observed-data":
        ids.add(sdo["id"])
    objects = sdo.get("objects")
    if isinstance(objects, list):
        for obj in objects:
            if isinstance(obj, dict) and obj.get("type") == "observed-data":
                ids.add(obj["id"])
    return ids


def _all_binding_ids(pattern_str, stix_version):
    """
    Run the matcher and return the observed-data ids of *all* bindings (not
    just the first one), so the table verifies the final binding set.
    """
    compiled = Pattern(pattern_str, stix_version)
    listener = MatchListener(
        _OBSERVATIONS[stix_version], stix_version=stix_version
    )
    compiled.walk(listener)

    ids = set()
    for binding in listener.matched():
        for sdo in listener.get_sdos_from_binding(binding):
            ids |= _observed_data_ids(sdo)

    return {_OBSERVATION_NAMES[obs_id] for obs_id in ids}


def _focus_values(pattern_str):
    """The property values a pattern compares, for failure messages."""
    prop = pattern_str.split(":")[1]
    for separator in (" ", "]"):
        prop = prop.split(separator)[0]
    return {
        "property": prop,
        "A": _SCO_A.get(prop),
        "B": _SCO_B.get(prop),
    }


def _describe(pattern_str):
    """Describe the operator and inputs of a pattern, for failure messages."""
    prop = _focus_values(pattern_str)
    operator = pattern_str.split(prop["property"], 1)[1].rsplit("]", 1)[0]
    return (
        "operator {operator!r} on property {prop!r} "
        "(observation A value {a!r}, observation B value {b!r})".format(
            operator=operator.strip(),
            prop=prop["property"],
            a=prop["A"],
            b=prop["B"],
        )
    )


# (case id, pattern, expected observation names).  The expectation is derived
# from the STIX semantics above, not from the current implementation.
_CASES = [
    # Hex/base64/string literals against hex/base64 JSON properties.
    ("hex_eq_hex_property", "[binary_test:hex_name_hex = h'616c696365']", ("A",)),
    ("hex_eq_b64_property", "[binary_test:b64_name_bin = h'616c696365']", ("A",)),
    ("b64_eq_hex_property", "[binary_test:hex_name_hex = b'YWxpY2U=']", ("A",)),
    ("b64_eq_b64_property", "[binary_test:b64_name_bin = b'YWxpY2U=']", ("A",)),
    ("b64_eq_other_value", "[binary_test:b64_name_bin = b'Ym9i']", ("B",)),
    ("str_eq_binary_property", "[binary_test:hex_name_hex = 'alice']", ("A",)),
    ("hex_eq_other_value", "[binary_test:hex_name_hex = h'626f62']", ("B",)),
    ("str_ne_binary_property", "[binary_test:hex_name_hex != 'alice']", ("B",)),
    ("b64_ne_binary_property", "[binary_test:b64_name_bin != 'alice']", ("B",)),

    # A character below U+0100 denotes its own byte value, not its UTF-8
    # encoding.
    ("latin1_byte_eq_char", "[binary_test:hex_latin1_e_acute_hex = 'é']", ("A",)),
    ("latin1_byte_eq_hex", "[binary_test:hex_latin1_e_acute_hex = h'e9']", ("A",)),
    ("utf8_bytes_ne_char", "[binary_test:hex_utf8_e_acute_hex = 'é']", ()),
    ("utf8_bytes_ne_hex", "[binary_test:hex_utf8_e_acute_hex = h'c3a9']", ("A",)),
    ("utf8_bytes_ne_latin1_hex", "[binary_test:hex_utf8_e_acute_hex = h'e9']", ()),

    # Zero bytes.
    ("zero_hex_eq_hex", "[binary_test:hex_zero_hex = h'00']", ("A",)),
    ("zero_hex_eq_b64", "[binary_test:hex_zero_hex = b'AA==']", ("A",)),
    ("zero_hex_eq_char", "[binary_test:hex_zero_hex = '\x00']", ("A",)),
    ("zero_b64_eq_char", "[binary_test:b64_zero_bin = '\x00']", ("A",)),
    ("zero_hex_like", "[binary_test:hex_zero_hex LIKE '\x00']", ("A",)),
    ("zero_hex_matches", "[binary_test:hex_zero_hex MATCHES '^\x00$']", ("A",)),
    ("zero_text_like", "[binary_test:text_zero LIKE '\x00']", ("A",)),
    ("zero_text_matches", "[binary_test:text_zero MATCHES '^\x00$']", ("A",)),
    ("zero_hex_not_like", "[binary_test:hex_zero_hex NOT LIKE '\x00']", ("B",)),

    # Non-UTF-8 bytes (0xFF/0xFE) must be compared as bytes, never decoded.
    ("ff_hex_eq_hex", "[binary_test:hex_ff_hex = h'ff']", ("A",)),
    ("ff_hex_eq_b64", "[binary_test:hex_ff_hex = b'/w==']", ("A",)),
    ("ff_b64_eq_b64", "[binary_test:b64_ff_bin = b'/w==']", ("A",)),
    ("ff_b64_eq_hex", "[binary_test:b64_ff_bin = h'ff']", ("A",)),
    ("ff_b64_like_single_byte", "[binary_test:b64_ff_bin LIKE '_']", ("A", "B")),
    ("ff_b64_matches_single_byte", "[binary_test:b64_ff_bin MATCHES '^.$']", ("A", "B")),
    ("ff_hex_eq_char_255", "[binary_test:hex_ff_hex = 'ÿ']", ("A",)),
    ("ff_hex_like_single_byte", "[binary_test:hex_ff_hex LIKE '_']", ("A", "B")),
    ("ff_hex_like_any", "[binary_test:hex_ff_hex LIKE '%']", ("A", "B")),
    ("ff_hex_matches_single_byte", "[binary_test:hex_ff_hex MATCHES '^.$']", ("A", "B")),
    ("ff_hex_matches_two_bytes", "[binary_test:hex_ff_hex MATCHES '^..$']", ()),
    ("ff_hex_matches_char_255", "[binary_test:hex_ff_hex MATCHES '^ÿ$']", ("A",)),
    ("ff_hex_not_like_char_255", "[binary_test:hex_ff_hex NOT LIKE 'ÿ']", ("B",)),
    ("ff_hex_not_matches_char_255", "[binary_test:hex_ff_hex NOT MATCHES '^ÿ$']", ("B",)),

    # The LIKE wildcards match any value, including byte 0x0A (newline).
    ("newline_hex_like_underscore", "[binary_test:hex_newline_hex LIKE '_']", ("A", "B")),
    ("newline_hex_like_any", "[binary_test:hex_newline_hex LIKE '%']", ("A", "B")),
    ("newline_hex_like_char", "[binary_test:hex_newline_hex LIKE '\n']", ("A",)),
    ("crlf_hex_like_two", "[binary_test:hex_crlf_hex LIKE '__']", ("A", "B")),
    ("newline_text_like", "[binary_test:crlf_text LIKE '%']", ("A", "B")),

    # Characters which cannot map to a single byte make binary/string
    # comparisons false; NOT of equality is still true, but NOT of an
    # ordering comparison is not.
    ("high_char_eq_binary", "[binary_test:hex_name_hex = 'ălice']", ()),
    ("high_char_ne_binary", "[binary_test:hex_name_hex != 'ălice']", ("A", "B")),
    ("high_char_not_eq_binary", "[binary_test:hex_name_hex NOT = 'ălice']", ("A", "B")),
    ("high_char_not_ne_binary", "[binary_test:hex_name_hex NOT != 'ălice']", ()),
    ("high_char_like_binary", "[binary_test:hex_name_hex LIKE 'ă%']", ()),
    ("high_char_not_like_binary", "[binary_test:hex_name_hex NOT LIKE 'ă%']", ("A", "B")),
    ("high_char_matches_binary", "[binary_test:hex_name_hex MATCHES '^ălice$']", ()),
    ("high_char_not_matches_binary", "[binary_test:hex_name_hex NOT MATCHES '^ălice$']", ("A", "B")),
    ("high_char_not_gt_binary", "[binary_test:hex_name_hex NOT > 'ălice']", ()),
    ("high_char_not_lt_binary", "[binary_test:hex_name_hex NOT < 'ălice']", ()),
    ("high_char_not_ge_binary", "[binary_test:hex_name_hex NOT >= 'ălice']", ()),
    ("high_char_not_le_binary", "[binary_test:hex_name_hex NOT <= 'ălice']", ()),

    # Byte ordering compares byte values.
    ("byte_gt_hex", "[binary_test:hex_name_hex > h'616c696365']", ("B",)),
    ("byte_lt_hex", "[binary_test:hex_name_hex < h'616c696365']", ()),
    ("byte_gt_text", "[binary_test:hex_name_hex > 'alice']", ("B",)),
    ("byte_ge_text", "[binary_test:hex_name_hex >= 'alice']", ("A", "B")),

    # Mixed types: equality is simply unequal (NOT flips), but an ordering
    # comparison that cannot be performed must stay false even under NOT.
    ("mixed_eq_binary", "[binary_test:count = h'00']", ()),
    ("mixed_ne_binary", "[binary_test:count != h'00']", ("A", "B")),
    ("mixed_not_eq_binary", "[binary_test:count NOT = h'00']", ("A", "B")),
    ("mixed_not_ne_binary", "[binary_test:count NOT != h'00']", ()),
    ("mixed_gt_binary", "[binary_test:count > h'00']", ()),
    ("mixed_not_gt_binary", "[binary_test:count NOT > h'00']", ()),
    ("mixed_not_lt_binary", "[binary_test:count NOT < h'00']", ()),
    ("mixed_not_gt_b64", "[binary_test:count NOT > b'AA==']", ()),

    # Text LIKE/MATCHES use NFC, equality does not.
    ("text_nfd_like_nfc", "[binary_test:nfd_text LIKE 'é']", ("A",)),
    ("text_nfd_matches_nfc", "[binary_test:nfd_text MATCHES '^é$']", ("A",)),
    ("text_nfd_eq_nfc", "[binary_test:nfd_text = 'é']", ()),
    ("text_nfd_ne_nfc", "[binary_test:nfd_text != 'é']", ("A", "B")),
    ("text_nfc_eq_nfc", "[binary_test:nfc_text = 'é']", ("A",)),

    # Text LIKE/MATCHES normalize both sides to NFC, so a decomposed pattern
    # matches a decomposed value.
    ("text_nfd_like_decomposed", "[binary_test:nfd_text LIKE 'e\u0301']", ("A",)),

    # Binary LIKE/MATCHES must not NFC-normalize the pattern.  A pattern
    # containing a combining mark (U+0301 > U+00FF) cannot be represented as
    # single-byte values, so it must match no binary value even though NFC
    # would collapse it to the single character U+00E9.
    ("binary_like_decomposed_pattern", "[binary_test:hex_latin1_e_acute_hex LIKE 'e\u0301']", ()),
    ("binary_matches_decomposed_pattern", "[binary_test:hex_latin1_e_acute_hex MATCHES '^e\u0301$']", ()),
    ("binary_like_both_e_acute_forms", "[binary_test:hex_combining_e_acute_hex LIKE 'é']", ()),
    ("binary_latin1_like_composed", "[binary_test:hex_latin1_e_acute_hex LIKE 'é']", ("A",)),
    ("binary_latin1_matches_composed", "[binary_test:hex_latin1_e_acute_hex MATCHES '^é$']", ("A",)),
]


def _case_id(case):
    return case[0]


@pytest.mark.parametrize("stix_version", ["2.0", "2.1"])
@pytest.mark.parametrize("case", _CASES, ids=_case_id)
def test_binary_comparison_bindings(case, stix_version):
    _, pattern_str, expected = case
    expected = set(expected)

    try:
        actual = _all_binding_ids(pattern_str, stix_version)
    except Exception as e:
        pytest.fail(
            "matching raised {cls} for STIX {version} pattern {pattern!r}: "
            "{describe}; expected bindings {expected}".format(
                cls=type(e).__name__,
                version=stix_version,
                pattern=pattern_str,
                describe=_describe(pattern_str),
                expected=sorted(expected),
            )
        )

    assert actual == expected, (
        "wrong observation bindings for STIX {version} pattern {pattern!r}: "
        "{describe}; expected {expected}, got {actual}".format(
            version=stix_version,
            pattern=pattern_str,
            describe=_describe(pattern_str),
            expected=sorted(expected),
            actual=sorted(actual),
        )
    )


@pytest.mark.parametrize("pattern_str, expected", [
    ("[binary_test:hex_name_hex = h'616c696365']", ("A",)),
    ("[binary_test:hex_zero_hex = '\x00']", ("A",)),
    ("[binary_test:hex_ff_hex = 'ÿ']", ("A",)),
    ("[binary_test:nfd_text LIKE 'é']", ("A",)),
    ("[binary_test:nfd_text = 'é']", ()),
    ("[binary_test:count NOT > h'00']", ()),
], ids=[
    "hex-literal", "zero-byte", "byte-0xff", "text-nfc-like", "text-eq-exact",
    "not-incomparable-order",
])
@pytest.mark.parametrize("stix_version", ["2.0", "2.1"])
def test_public_match_api_bindings(pattern_str, expected, stix_version):
    """The public match() API must expose the same binding decisions."""
    try:
        sdos = match(
            pattern_str, _OBSERVATIONS[stix_version], stix_version=stix_version
        )
    except Exception as e:
        pytest.fail(
            "match() raised {cls} for STIX {version} pattern {pattern!r}: "
            "{describe}; expected bindings {expected}".format(
                cls=type(e).__name__,
                version=stix_version,
                pattern=pattern_str,
                describe=_describe(pattern_str),
                expected=sorted(expected),
            )
        )

    ids = set()
    for sdo in sdos:
        ids |= _observed_data_ids(sdo)
    actual = {_OBSERVATION_NAMES[obs_id] for obs_id in ids}

    assert actual == set(expected), (
        "match({!r}) bound {} but expected {} for {}".format(
            pattern_str, sorted(actual), sorted(expected),
            _describe(pattern_str),
        )
    )


@pytest.mark.parametrize("stix_version", ["2.0", "2.1"])
@pytest.mark.parametrize("pattern_str", [
    "[binary_test:hex_name_hex = h'6']",
    "[binary_test:hex_name_hex = h'zz']",
    "[binary_test:hex_name_hex = b'!!!!']",
    "[binary_test:hex_name_hex = b'AAAAA']",
], ids=["odd-hex-digits", "nonhex-digits", "invalid-base64", "bad-padding"])
def test_malformed_binary_literal_is_an_error(pattern_str, stix_version):
    """A malformed hex/base64 literal must be rejected at parse time, not
    treated as an empty/odd value which could satisfy a NOT comparison."""
    with pytest.raises(ParseException):
        match(pattern_str, _OBSERVATIONS[stix_version], stix_version=stix_version)


@pytest.mark.parametrize("stix_version", ["2.0", "2.1"])
@pytest.mark.parametrize("bad_value, prop", [
    ("zz", "bad_hex_hex"),
    ("0", "odd_hex_hex"),
    ("!!!", "bad_b64_bin"),
    ("YWxpY2U", "unpadded_b64_bin"),
], ids=["nonhex-json", "odd-hex-json", "invalid-base64-json", "unpadded-base64-json"])
def test_malformed_json_binary_value_is_an_error(bad_value, prop, stix_version):
    """A malformed JSON binary value must raise, not silently become empty
    bytes: with NOT, silent empty bytes would turn invalid input into a
    match."""
    if stix_version == "2.0":
        observations = [
            dict(
                _observed_data_20(observed_id, dict(sco)),
                objects={"0": dict(sco, **{prop: bad_value})},
            )
            for observed_id, sco in (
                (_OD_A, _SCO_A),
                (_OD_B, _SCO_B),
            )
        ]
    else:
        observations = [
            _bundle(
                observed_id,
                dict(dict(sco, id=sco_id), **{prop: bad_value}),
            )
            for observed_id, sco, sco_id in (
                (_OD_A, _SCO_A, _SCO_A_ID),
                (_OD_B, _SCO_B, _SCO_B_ID),
            )
        ]

    pattern_str = "[binary_test:{} NOT = 'alice']".format(prop)
    with pytest.raises(MatcherException):
        match(pattern_str, observations, stix_version=stix_version)
