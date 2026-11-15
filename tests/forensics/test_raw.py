#
# This file is part of pyasn1 software.
#
# Copyright (c) 2026, Simon Pichugin <simon.pichugin@gmail.com>
# License: https://pyasn1.readthedocs.io/en/latest/license.html
#
import sys
import unittest

from tests.base import BaseTestCase

from pyasn1.forensics.raw import ForensicError
from pyasn1.forensics.raw import walk_tlv


class RawWalkerTestCase(BaseTestCase):

    def test_context_tag_dissects_without_schema(self):
        # A bare context-specific tag that the DER decoder cannot interpret
        # schemalessly must still be dissected by the raw walker.
        root = walk_tlv(bytes.fromhex('3003810107'))
        assert root.tag_class_name == 'universal'
        assert root.tag_number == 16
        assert root.constructed is True
        child = root.children[0]
        assert child.path == '0'
        assert child.tag_class_name == 'context'
        assert child.tag_number == 1
        assert child.constructed is False
        assert child.content_octets == b'\x07'
        assert child.tlv_octets == bytes.fromhex('810107')

    def test_content_octets_are_never_interpreted(self):
        # OCTET STRING whose payload looks like an INTEGER TLV stays a leaf.
        node = walk_tlv(bytes.fromhex('0403020105'))
        assert node.constructed is False
        assert node.children == ()
        assert node.content_octets == bytes.fromhex('020105')

    def test_high_tag_number(self):
        # Base-128 high-tag-number form: 690 encodes as 0x85 0x32.
        node = walk_tlv(bytes([0x9F, 0x85, 0x32, 0x01, 0x07]))
        assert node.tag_number == 690
        assert node.tag_class_name == 'context'
        assert node.identifier_octets == bytes([0x9F, 0x85, 0x32])
        assert node.content_octets == b'\x07'

    def test_long_form_length_and_span(self):
        body = b'\x00' * 200
        node = walk_tlv(b'\x04\x81\xc8' + body)
        assert node.tag_number == 4
        assert node.length_octets == b'\x81\xc8'
        assert len(node.content_octets) == 200
        assert node.content_end == 3 + 200

    def test_indefinite_length_ber(self):
        node = walk_tlv(bytes.fromhex('30800201050000'))
        assert node.indefinite is True
        assert len(node.children) == 1
        assert node.children[0].content_octets == b'\x05'
        assert node.tlv_octets == bytes.fromhex('30800201050000')

    def test_nested_paths_and_round_trip(self):
        # SEQUENCE { SEQUENCE { INTEGER 1 }, INTEGER 2, BIT STRING '' }
        wire = bytes.fromhex('300a30030201010201020300')
        root = walk_tlv(wire)
        assert root.tlv_octets == wire
        assert root.children[0].path == '0'
        assert root.children[0].children[0].path == '0.0'
        assert root.children[1].path == '1'
        assert root.children[2].path == '2'

    def test_malformed_substrate_rejected(self):
        cases = (
            b'',
            b'\x30',
            b'\x30\x05\x02\x01',
            b'\x30\x03\x02\x01\x01\xff',
            b'\x30\xff',
            b'\x9f',
        )
        for wire in cases:
            try:
                walk_tlv(wire)
            except ForensicError:
                pass
            else:
                assert 0, 'malformed substrate tolerated: %r' % wire

    def test_nesting_depth_is_bounded(self):
        from pyasn1.forensics.raw import MAX_NESTING_DEPTH

        def wrap(body):
            length = len(body)
            if length < 128:
                return b'\x30' + bytes([length]) + body
            octets = length.to_bytes((length.bit_length() + 7) // 8, 'big')
            return b'\x30' + bytes([0x80 | len(octets)]) + octets + body

        wire = b'\x02\x01\x01'
        for _ in range(MAX_NESTING_DEPTH + 5):
            wire = wrap(wire)
        try:
            walk_tlv(wire)
        except ForensicError as exc:
            assert 'nesting depth' in str(exc)
        else:
            assert 0, 'nesting beyond limit tolerated'

    def test_to_dict_is_plain_data(self):
        root = walk_tlv(bytes.fromhex('3003810107'))
        data = root.to_dict()
        assert data['children'][0]['tagClass'] == 'context'
        assert data['children'][0]['contentOctets'] == '07'


suite = unittest.TestLoader().loadTestsFromModule(sys.modules[__name__])

if __name__ == '__main__':
    unittest.TextTestRunner(verbosity=2).run(suite)
