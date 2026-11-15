"""
forensic output contract tests for the strict/display XML rendering.

these build complete, short EVTX records from hand crafted BinXML (see
mini_evtx.py) so the exact raw bytes of every problematic value are under
test control: C0 control characters, lone UTF-16 surrogates, attribute
vs. text positions, ordinary XML markup and non-BMP characters.
"""
import base64
import os

import pytest

import Evtx.Evtx as evtx
import Evtx.XmlEncoding as e_xml
from Evtx.XmlEncoding import InvalidXmlCharacterError

from mini_evtx import build_evtx


@pytest.fixture
def evtx_path(tmp_path):
    def _build(records):
        image = build_evtx(records)
        path = tmp_path / "contract.evtx"
        path.write_bytes(image)
        return str(path)

    return _build


class RenderedRecord(object):
    """
    a snapshot of a record that stays valid after the EVTX mmap closes.

    rendering and raw byte capture happen inside the open context, so
    tests can assert freely afterwards.
    """

    def __init__(self, record):
        self.record_num = record.record_num()
        self.raw = bytes(record.data())
        self.substitution_strings = [s.string() for s in record.root().substitutions()]
        self.strict_error = None
        self.strict_xml = None
        try:
            self.strict_xml = record.xml()
        except InvalidXmlCharacterError as error:
            self.strict_error = error
        self.display_xml = record.xml_display()

    def xml(self):
        if self.strict_error is not None:
            raise self.strict_error
        return self.strict_xml

    def xml_display(self):
        return self.display_xml

    def data(self):
        return self.raw


def _records(path):
    with evtx.Evtx(path) as log:
        return [RenderedRecord(record) for record in log.records()]


def test_strict_rejects_control_character_with_field_and_reason(evtx_path):
    path = evtx_path([(1, "ab\x03cd", "text\x07")])
    record = _records(path)[0]

    with pytest.raises(InvalidXmlCharacterError) as excinfo:
        record.xml()

    error = excinfo.value
    assert error.reason == e_xml.AnomalyReason.CONTROL_CHARACTER
    assert error.codepoint == 0x03
    assert error.field.startswith("root.@Attr")
    # the offending, unaltered value is retained on the error.
    assert error.original == "ab\x03cd"


def test_strict_rejects_lone_surrogate(evtx_path):
    path = evtx_path([(1, "sur\ud800ro", "x\udfff")])
    record = _records(path)[0]

    with pytest.raises(InvalidXmlCharacterError) as excinfo:
        record.xml()

    error = excinfo.value
    assert error.reason == e_xml.AnomalyReason.LONE_SURROGATE
    assert error.codepoint == 0xD800
    assert any(0xD800 <= ord(char) <= 0xDFFF for char in error.original)


def test_strict_preserves_xml_markup_and_non_bmp(evtx_path):
    # & and < keep their XML semantics (entities), the quote is escaped in
    # the attribute and the non-BMP emoji round trips as a numeric ref.
    path = evtx_path([(1, "emoji\U0001F600", "u&v<w")])
    record = _records(path)[0]

    rendered = record.xml()
    assert "&#128512;" in rendered
    assert "u&amp;v&lt;w" in rendered
    assert "&amp;" in rendered or "&lt;" in rendered

    # the parsed BinXML value still holds the original scalar.
    assert record.substitution_strings[0] == "emoji\U0001F600"


def test_attribute_and_text_use_different_escaping(evtx_path):
    path = evtx_path([(1, 'q"r', "a&b")])
    record = _records(path)[0]
    rendered = record.xml()

    # double quote is escaped only inside the attribute.
    assert 'Attr="q&quot;r"' in rendered
    assert "<Data>a&amp;b</Data>" in rendered


def test_display_mode_is_parser_readable_and_ledgered(evtx_path):
    import xml.etree.ElementTree as ET

    path = evtx_path([(1, "ab\x03cd", "sur\ud800ro")])
    record = _records(path)[0]

    display = record.xml_display()
    # a standard library parser must accept the document.
    doc = ET.fromstring(display)

    ns = {"evtx": e_xml.ANOMALIES_NAMESPACE}
    anomalies = doc.findall(".//evtx:Anomaly", ns)
    reasons = {a.get("Reason") for a in anomalies}
    assert e_xml.AnomalyReason.CONTROL_CHARACTER.value in reasons
    assert e_xml.AnomalyReason.LONE_SURROGATE.value in reasons

    for anomaly in anomalies:
        # every in-document marker has a matching ledger entry.
        assert anomaly.get("Marker") in display
        raw = base64.b64decode(anomaly.get("OriginalUTF16LEBase64"))
        decoded = raw.decode("utf-16-le", "surrogatepass")
        assert chr(int(anomaly.get("Codepoint")[2:], 16)) in decoded


def test_display_markers_keep_distinct_raw_values_distinguishable(evtx_path):
    # two different raw values that share an unrepresentable code point
    # must not collapse into an identical report.
    path = evtx_path([(1, "a\x03", "b\x03")])
    record = _records(path)[0]
    display = record.xml_display()

    ns = {"evtx": e_xml.ANOMALIES_NAMESPACE}
    doc = __import__("xml.etree.ElementTree", fromlist=["ElementTree"]).fromstring(display)
    anomalies = doc.findall(".//evtx:Anomaly", ns)
    assert len(anomalies) == 2
    markers = {a.get("Marker") for a in anomalies}
    assert len(markers) == 2  # unique per anomaly index
    raws = {a.get("OriginalUTF16LEBase64") for a in anomalies}
    assert len(raws) == 2  # and the originals stay distinct


def test_display_marker_literal_in_evidence_is_not_confused_with_a_marker(evtx_path):
    # an attacker controlled value that textually resembles a display
    # marker must remain ordinary text in strict mode and get its own,
    # ledger-backed marker only if it contains an illegal code point.
    literal = "EVTX-INVALID-CHAR-0000-U+0003"
    path = evtx_path([(1, literal, "plain")])
    record = _records(path)[0]

    rendered = record.xml()
    assert literal in rendered  # legal text flows through verbatim (escaped)

    display = record.xml_display()
    # no anomaly is recorded for a purely textual marker look-alike.
    assert "<evtx:Anomaly " not in display
    assert literal in display


def test_rendering_never_mutates_record_bytes(evtx_path):
    path = evtx_path([(1, "ab\x03cd\ud800", "x\x07")])
    record = _records(path)[0]

    # strict rendering rejected the record but kept the raw bytes.
    assert isinstance(record.strict_error, InvalidXmlCharacterError)
    assert record.data()[:4] == b"\x2a\x2a\x00\x00"

    # display rendering produced a document without touching those bytes.
    assert record.xml_display()
    assert record.data()[:4] == b"\x2a\x2a\x00\x00"

    # re-rendering inside a fresh open context gives the same raw bytes.
    with evtx.Evtx(path) as log:
        fresh = next(log.records())
        fresh_raw = bytes(fresh.data())
        with pytest.raises(InvalidXmlCharacterError):
            fresh.xml()
        assert bytes(fresh.data()) == fresh_raw
        fresh.xml_display()
        assert bytes(fresh.data()) == fresh_raw
    assert record.data() == fresh_raw


def test_legal_whitespace_control_chars_pass(evtx_path):
    # tab, LF and CR are legal XML characters and must not be replaced.
    path = evtx_path([(1, "a\tb", "x\ny\r")])
    record = _records(path)[0]
    rendered = record.xml()
    assert "a\tb" in rendered
    assert "x\ny\r" in rendered
    assert record.xml_display().count("<evtx:Anomaly ") == 0


def test_multiple_records_render_independently(evtx_path):
    path = evtx_path([(1, "ok", "fine"), (2, "bad\x01", "good"), (3, "also\x02", "fine")])
    records = _records(path)

    assert records[0].xml() is not None
    with pytest.raises(InvalidXmlCharacterError):
        records[1].xml()
    with pytest.raises(InvalidXmlCharacterError):
        records[2].xml()

    import xml.etree.ElementTree as ET

    for record in records:
        ET.fromstring(record.xml_display())
