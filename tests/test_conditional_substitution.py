"""
Forensic regression tests for ConditionalSubstitution (BXML token 0x0E).

The EVTX records here are synthesized in-memory by tests/evtx_binary.py from
the binary token specification; they are never captured from this renderer's
output. Every expected XML string below is derived by hand from the template's
declared semantics (which element/attribute owns which substitution), not from
renderer output.

The property under test: when a conditional substitution resolves to NULL,
only the single element or attribute that owns it is suppressed. Independent
siblings (including a normal substitution and nested elements) must survive,
and explicit empty strings / numeric zeros must remain distinguishable from a
missing (NULL) value.
"""
import os
import importlib.util

import pytest

import Evtx.Evtx as evtx
import Evtx.Nodes as e_nodes

from evtx_binary import EvtxBuilder, V_NULL, V_WSTRING, V_UBYTE, V_DWORD


NS = "http://example.com/forensic"

# Hand-derived templates for the rendered record. Newlines mirror the renderer's
# per-close-element newlines; these describe the intended template semantics
# rather than any captured output.
XML_ALL_NULL = (
    '<Event xmlns="' + NS + '"><Data>kept-normal</Data>\n'
    "<Group><OptAttr></OptAttr>\n"
    "</Group>\n"
    "</Event>\n"
)

XML_EMPTY_STRINGS = (
    '<Event xmlns="' + NS + '"><Data>kept-normal</Data>\n'
    "<Optional></Optional>\n"
    '<Group><OptAttr Attr=""></OptAttr>\n'
    "<Nested></Nested>\n"
    "</Group>\n"
    "</Event>\n"
)

XML_ZERO_VALUES = (
    '<Event xmlns="' + NS + '"><Data>kept-normal</Data>\n'
    "<Optional>0</Optional>\n"
    '<Group><OptAttr Attr="0"></OptAttr>\n'
    "<Nested>0</Nested>\n"
    "</Group>\n"
    "</Event>\n"
)

XML_TYPE_MISMATCH = (
    '<Event xmlns="' + NS + '"><Data>kept-normal</Data>\n'
    "<Optional>7</Optional>\n"
    "<Group><OptAttr></OptAttr>\n"
    "</Group>\n"
    "</Event>\n"
)


def build_log(tmp_path, records):
    """write a synthetic one-chunk EVTX file and return its path."""
    path = os.path.join(str(tmp_path), "conditional.evtx")
    with open(path, "wb") as f:
        f.write(EvtxBuilder().build_file(records))
    return path


def only(iterable):
    for item in iterable:
        return item
    raise RuntimeError("expected at least one item")


# Each record shares one template:
#   <Data>      normal substitution 0 (always rendered)
#   <Optional>  conditional substitution 1 (element-level)
#   <OptAttr Attr="..."> conditional substitution 2 (attribute-level)
#   <Nested>    conditional substitution 3 (nested inside <Group>)
@pytest.fixture
def conditional_path(tmp_path):
    records = [
        # 1. default / missing values: every conditional is NULL and must be
        #    suppressed, while the normal sibling stays.
        (
            1,
            130000000000000000,
            [
                (V_WSTRING, "kept-normal"),
                (V_NULL, None),
                (V_NULL, None),
                (V_NULL, None),
            ],
        ),
        # 2. explicit empty strings: present but empty, a distinct evidentiary
        #    state from NULL, so nothing is suppressed.
        (
            2,
            130000000100000000,
            [
                (V_WSTRING, "kept-normal"),
                (V_WSTRING, ""),
                (V_WSTRING, ""),
                (V_WSTRING, ""),
            ],
        ),
        # 3. legitimate zero values: zeros are real values and must render as
        #    "0", never collapse into a suppressed node.
        (
            3,
            130000000200000000,
            [
                (V_WSTRING, "kept-normal"),
                (V_DWORD, 0),
                (V_DWORD, 0),
                (V_UBYTE, 0),
            ],
        ),
        # 4. type mismatch: the template declares a WSTRING conditional but the
        #    record supplies a UBYTE 7. The value is still present (not NULL),
        #    so it renders; remaining NULL conditionals are still suppressed.
        (
            4,
            130000000300000000,
            [
                (V_WSTRING, "kept-normal"),
                (V_UBYTE, 7),
                (V_NULL, None),
                (V_NULL, None),
            ],
        ),
    ]
    return build_log(tmp_path, records)


def _rendered_xml(path):
    """render every record inside the open mmap and return plain strings."""
    with evtx.Evtx(path) as log:
        return [record.xml() for record in log.records()]


def _rendered_by_num(path):
    with evtx.Evtx(path) as log:
        return {record.record_num(): record.xml() for record in log.records()}


def test_file_and_chunk_checksums_valid(conditional_path):
    # the "negative" (suppression) records still live in a structurally legal
    # outer record and chunk with valid checksums.
    with evtx.Evtx(conditional_path) as log:
        assert log.get_file_header().verify()
        chunk = only(log.chunks())
        assert chunk.verify()
        assert len(list(chunk.records())) == 4


def test_each_record_self_consistent(conditional_path):
    with evtx.Evtx(conditional_path) as log:
        for record in log.records():
            assert record.magic() == 0x2A2A
            assert record.verify()
            # four substitutions parsed with the expected concrete variant types
            subs = record.root().substitutions()
            assert len(subs) == 4


def test_rendered_xml_matches_hand_derived_semantics(conditional_path):
    expected = {
        1: XML_ALL_NULL,
        2: XML_EMPTY_STRINGS,
        3: XML_ZERO_VALUES,
        4: XML_TYPE_MISMATCH,
    }
    with evtx.Evtx(conditional_path) as log:
        rendered = {record.record_num(): record.xml() for record in log.records()}

    assert rendered == expected


def test_null_suppresses_only_owning_nodes(conditional_path):
    xml = _rendered_xml(conditional_path)[0]

    # NULL conditionals remove their owning element/attribute.
    assert "<Optional>" not in xml
    assert "<Nested>" not in xml
    assert "Attr=" not in xml

    # independent siblings and the outer envelope survive.
    assert xml.startswith('<Event xmlns="' + NS + '">')
    assert "<Data>kept-normal</Data>" in xml
    assert "<Group>" in xml and "</Group>" in xml
    assert xml.rstrip().endswith("</Event>")


def test_empty_string_is_distinct_from_null(conditional_path):
    rendered = _rendered_xml(conditional_path)
    null_xml, empty_xml = rendered[0], rendered[1]

    # explicit empty string keeps the nodes but with empty content/attribute.
    assert "<Optional></Optional>" in empty_xml
    assert "<Nested></Nested>" in empty_xml
    assert 'Attr=""' in empty_xml

    # whereas NULL removed them altogether.
    assert "<Optional>" not in null_xml
    assert 'Attr=""' not in null_xml


def test_zero_is_distinct_from_null_and_empty(conditional_path):
    zero_xml = _rendered_xml(conditional_path)[2]

    assert "<Optional>0</Optional>" in zero_xml
    assert "<Nested>0</Nested>" in zero_xml
    assert 'Attr="0"' in zero_xml
    # a rendered zero must never look like an empty or suppressed value.
    assert "<Optional></Optional>" not in zero_xml
    assert 'Attr=""' not in zero_xml


def test_type_mismatch_value_is_not_suppressed(conditional_path):
    with evtx.Evtx(conditional_path) as log:
        mismatch = list(log.records())[3]
        sub = mismatch.root().substitutions()[1]

        # the stored variant disagrees with the template's WSTRING declaration...
        assert isinstance(sub, e_nodes.UnsignedByteTypeNode)
        # ...yet a present, non-NULL value renders instead of being suppressed.
        xml = mismatch.xml()

    assert "<Optional>7</Optional>" in xml
    # and NULL siblings in the same record are still suppressed.
    assert "<Nested>" not in xml
    assert "Attr=" not in xml


@pytest.mark.skipif(
    importlib.util.find_spec("lxml") is None, reason="lxml not installed"
)
def test_every_rendered_record_is_valid_xml(conditional_path):
    import lxml.etree

    with evtx.Evtx(conditional_path) as log:
        for record in log.records():
            doc = record.lxml()  # raises if the rendered XML is not well-formed
            ns = {"e": NS}
            # the independent normal sibling parses on every record, including
            # the fully-suppressed one.
            assert doc.find("e:Data", ns).text == "kept-normal"


def test_conditional_predicate_distinguishes_null_from_zero(conditional_path):
    # guard the suppression predicate directly: an exact NullTypeNode is the
    # only value that suppresses; a numeric zero (different type) does not.
    with evtx.Evtx(conditional_path) as log:
        records = list(log.records())
        all_null = records[0].root().substitutions()
        zero_values = records[2].root().substitutions()

    cond = e_nodes.ConditionalSubstitutionNode.__new__(e_nodes.ConditionalSubstitutionNode)
    cond.index = lambda: 1

    assert isinstance(all_null[1], e_nodes.NullTypeNode)
    assert cond.should_suppress(all_null) is True

    assert not isinstance(zero_values[1], e_nodes.NullTypeNode)
    assert cond.should_suppress(zero_values) is False
