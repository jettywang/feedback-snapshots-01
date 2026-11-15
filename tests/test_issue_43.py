import os
import base64

import pytest

import Evtx.Evtx as evtx
import Evtx.XmlEncoding as e_xml
from Evtx.XmlEncoding import InvalidXmlCharacterError


def get_record_by_num(log, record_num):
    for record in log.records():
        if record.record_num() == record_num:
            return record
    raise KeyError(record_num)


def test_issue_43(data_path):
    """
    regression test demonstrating issue 43.

    record 508 holds lone UTF-16 surrogate code units.  these are now
    preserved while parsing (surrogatepass) instead of crashing the
    decoder, and strict XML rendering rejects them with a diagnostic
    rather than silently dropping evidence.

    Args:
      data_path (str): the file system path of the test directory.
    """
    with evtx.Evtx(os.path.join(data_path, "issue_43.evtx")) as log:
        bad_rec = get_record_by_num(log, 508)
        with pytest.raises(InvalidXmlCharacterError) as excinfo:
            _ = bad_rec.xml()

        error = excinfo.value
        assert error.reason == e_xml.AnomalyReason.LONE_SURROGATE
        assert 0xD800 <= error.codepoint <= 0xDFFF
        # the unaltered original value is retained on the exception.
        assert any(0xD800 <= ord(c) <= 0xDFFF for c in error.original)
        assert error.field


def test_issue_43_display(data_path):
    """
    the display rendering of the surrogate record is parser readable and
    carries a reviewable anomaly record whose raw UTF-16LE bytes match
    the original evidence.

    Args:
      data_path (str): the file system path of the test directory.
    """
    import xml.etree.ElementTree as ET

    with evtx.Evtx(os.path.join(data_path, "issue_43.evtx")) as log:
        bad_rec = get_record_by_num(log, 508)
        raw_before = bytes(bad_rec.data())

        display = bad_rec.xml_display()
        ET.fromstring(display)

        ns = {"evtx": e_xml.ANOMALIES_NAMESPACE}
        doc = ET.fromstring(display)
        anomalies = doc.findall(".//evtx:Anomaly", ns)
        assert len(anomalies) >= 1
        assert all(a.get("Reason") == e_xml.AnomalyReason.LONE_SURROGATE.value for a in anomalies)

        # every marker referenced in the document has a ledger entry,
        # and the ledger's base64 raw bytes decode back to a value that
        # contains the exact surrogate code point reported.
        markers = {a.get("Marker") for a in anomalies}
        assert markers
        for anomaly in anomalies:
            assert anomaly.get("Marker") in display
            raw = base64.b64decode(anomaly.get("OriginalUTF16LEBase64"))
            decoded = raw.decode("utf-16-le", "surrogatepass")
            assert chr(int(anomaly.get("Codepoint")[2:], 16)) in decoded

        # rendering never mutates the underlying record bytes.
        assert bytes(bad_rec.data()) == raw_before

