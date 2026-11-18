# -*- coding: utf-8 -*-
"""
Independent layout regression tests for oleform.

These tests do not rely on Office or any ActiveX control: the binary ``f`` and
``o`` streams described in [MS-OFORMS] are built in memory from explicit field
layouts. The goal is to prove that the controls *declared* in the ``f`` stream
stay correctly paired with the control *data* read sequentially from the
``o`` stream.

Coverage:
- several property masks (name/tag/id/tabindex/tip text present or absent),
- compressed (one byte per char) and Unicode text, including empty strings,
- 4-byte alignment padding inside data blocks and between site records,
- nested controls expressed through FormObjectDepthTypeCount depths,
- unknown control types and corrupt byte counts,
- per-control markers that expose the exact control where f/o desync starts.

The empty string (``b''``) and an absent property (``None``) are asserted
separately, because the parser used to collapse both into the same value.
"""

import io
import struct
import unittest

from oletools import oleform


# ---------------------------------------------------------------------------
# Tiny byte-buffer builder matching the [MS-OFORMS] on-disk alignment rules.
# ---------------------------------------------------------------------------

class BufferBuilder(object):
    def __init__(self):
        self.buf = bytearray()

    def u8(self, value):
        self.buf += struct.pack('<B', value)

    def u16(self, value):
        self.buf += struct.pack('<H', value)

    def u32(self, value):
        self.buf += struct.pack('<L', value)

    def raw(self, data):
        self.buf += data

    def align4(self, start):
        offset = (len(self.buf) - start) % 4
        if offset:
            self.buf += b'\x00' * (4 - offset)

    def __len__(self):
        return len(self.buf)


def encode_text(text, unicode):
    if unicode:
        return text.encode('utf-16-le')
    return text.encode('latin-1')


def count_with_flag(data, unicode):
    # CountOfBytesWithCompressionFlag / CountOfCharsWithCompressionFlag:
    # bit 31 clear = compressed text, bit 31 set = Unicode text.
    count = len(data)
    if unicode:
        count |= 0x80000000
    return count


def text_props_blob():
    # TextProps (versions 0,2) with cbTextProps == 0.
    return b'\x00\x02\x00\x00'


# ---------------------------------------------------------------------------
# f stream: FormControl + FormSiteData (OleSiteConcreteControl records).
# ---------------------------------------------------------------------------

def build_site(site):
    # fClsidCacheIndex, fBitFlags and fObjectStreamSize are written for every
    # site (matching real Office forms); name-like fields vary with the mask.
    mask = (1 << 4) | (1 << 5) | (1 << 7)
    if site.get('name') is not None:
        mask |= 1 << 0
    if site.get('tag') is not None:
        mask |= 1 << 1
    if site.get('id') is not None:
        mask |= 1 << 2
    if site.get('tabindex') is not None:
        mask |= 1 << 6
    if site.get('control_tip_text') is not None:
        mask |= 1 << 11

    inner = BufferBuilder()
    inner.u32(mask)
    data_block_start = len(inner)
    text_data = {}
    # fName and fTag counts (mask bits 0 and 1) lead the SiteDataBlock.
    for key, unicode_key in (('name', 'name_unicode'),
                             ('tag', 'tag_unicode')):
        value = site.get(key)
        if value is not None:
            is_unicode = site.get(unicode_key, False)
            blob = encode_text(value, is_unicode)
            inner.u32(count_with_flag(blob, is_unicode))
            text_data[key] = blob
    if site.get('control_tip_text') is not None:
        is_unicode = site.get('control_tip_text_unicode', False)
        text_data['control_tip_text'] = encode_text(
            site['control_tip_text'], is_unicode)
    if site.get('id') is not None:
        inner.u32(site['id'])
    inner.u32(site.get('bit_flags', 0))
    inner.u32(site.get('object_stream_size', 0))
    if site.get('tabindex') is not None:
        inner.u16(site['tabindex'])
    inner.u16(site['clsid'])
    # fControlTipText (mask bit 11) is ordered after fGroupID/fClsidCacheIndex
    # and before fRuntimeLicKey in the SiteDataBlock.
    if site.get('control_tip_text') is not None:
        inner.u32(count_with_flag(text_data['control_tip_text'], is_unicode))
    inner.align4(data_block_start)               # SiteDataBlock 4-byte padding

    for key in ('name', 'tag', 'control_tip_text'):
        if key in text_data:
            inner.raw(text_data[key])            # SiteExtraDataBlock strings

    outer = BufferBuilder()
    outer.u16(0)                                  # version
    outer.u16(len(inner))                         # cbSite
    outer.raw(inner.buf)
    return bytes(outer.buf)


def build_f_stream(nodes):
    """nodes: iterable of (depth, site-dict); depth 0 is a top-level control."""
    nodes = list(nodes)
    form_inner = BufferBuilder()
    form_inner.u32(0)                             # empty FormPropMask

    builder = BufferBuilder()
    builder.u8(0)
    builder.u8(4)                                 # FormControl versions
    builder.u16(len(form_inner))                  # cbform
    builder.raw(form_inner.buf)
    builder.u16(0)                                # CountOfSiteClassInfo

    site_blobs = [build_site(site) for _, site in nodes]
    builder.u32(len(nodes))                       # CountOfSites
    count_pos = len(builder)
    builder.u32(0)                                # CountOfBytes placeholder
    depth_start = len(builder)
    for _depth, _site in nodes:
        builder.u8(_depth)                        # FormObjectDepthTypeCount
        builder.u8(1)                            # SITE_TYPE
    builder.align4(depth_start)                  # will_pad alignment
    for blob in site_blobs:
        builder.raw(blob)
    # The parser jumps over the depth/type block plus every site record.
    struct.pack_into('<L', builder.buf, count_pos, len(builder) - depth_start)
    return bytes(builder.buf)


# ---------------------------------------------------------------------------
# o stream control data (only the controls the task needs to distinguish).
# ---------------------------------------------------------------------------

def build_label_blob(caption, unicode=False):
    mask = 0
    caption_blob = b''
    if caption is not None:
        mask |= 1 << 3                           # fCaption
        caption_blob = encode_text(caption, unicode)

    inner = BufferBuilder()
    inner.u32(mask)
    data_block_start = len(inner)
    if caption is not None:
        inner.u32(count_with_flag(caption_blob, unicode))
    inner.align4(data_block_start)
    inner.raw(caption_blob)                       # empty b'' kept when present
    inner.u32(0)
    inner.u32(0)                                  # Size (8 bytes)

    outer = BufferBuilder()
    outer.u8(0)
    outer.u8(2)
    outer.u16(len(inner))
    outer.raw(inner.buf)
    outer.raw(text_props_blob())
    return bytes(outer.buf)


def build_morph_blob(value=None, caption=None, group_name=None,
                     value_unicode=False, caption_unicode=False,
                     group_unicode=False):
    mask = 1 << 8                                 # fSize (Size always read)
    blobs = {}
    if value is not None:
        mask |= 1 << 22                          # fValue
        blobs['value'] = encode_text(value, value_unicode)
    if caption is not None:
        mask |= 1 << 23                          # fCaption
        blobs['caption'] = encode_text(caption, caption_unicode)
    if group_name is not None:
        mask |= 1 << 32                          # fGroupName
        blobs['group_name'] = encode_text(group_name, group_unicode)

    inner = BufferBuilder()
    inner.u32(mask & 0xFFFFFFFF)
    inner.u32(mask >> 32)
    data_block_start = len(inner)
    if value is not None:
        inner.u32(count_with_flag(blobs['value'], value_unicode))
    if caption is not None:
        inner.u32(count_with_flag(blobs['caption'], caption_unicode))
    if group_name is not None:
        inner.u32(count_with_flag(blobs['group_name'], group_unicode))
    inner.align4(data_block_start)
    inner.u32(0)
    inner.u32(0)                                  # Size
    inner.raw(blobs.get('value', b''))
    inner.raw(blobs.get('caption', b''))
    inner.raw(blobs.get('group_name', b''))

    outer = BufferBuilder()
    outer.u8(0)
    outer.u8(2)
    outer.u16(len(inner))
    outer.raw(inner.buf)
    outer.raw(text_props_blob())
    return bytes(outer.buf)


# ---------------------------------------------------------------------------
# Minimal stand-in for an OLE structured storage file: path -> bytes.
# ---------------------------------------------------------------------------

class FakeOleFile(object):
    def __init__(self, streams):
        self._streams = streams

    def openstream(self, path):
        if isinstance(path, (list, tuple)):
            path = '/'.join(path)
        return io.BytesIO(self._streams[path])


# Every control carries a unique marker name so failures name the control where
# f and o streams first disagree.
SITES = [
    dict(marker='LabelFull', clsid=21, name='LabelFull', id=1, tabindex=0,
         tag='tag-1', control_tip_text='tip-1', caption='Label caption'),
    dict(marker='LabelEmpty', clsid=21, name='LabelEmpty', id=2, tabindex=1,
         caption=''),
    dict(marker='LabelAbsent', clsid=21, name='LabelAbsent', id=3, tabindex=2),
    dict(marker='TextBoxUnicode', clsid=23, name='TextBoxUnicode', id=4,
         tabindex=3, value=u'café', value_unicode=True,
         caption=u'¥-yen', caption_unicode=False),
    dict(marker='TextBoxEmpty', clsid=23, name='TextBoxEmpty', id=5,
         tabindex=4, value='', caption=''),
    dict(marker='TextBoxAbsent', clsid=23, name='TextBoxAbsent', id=6,
         tabindex=5),
    dict(marker='ComboGroup', clsid=25, name='ComboGroup', id=7, tabindex=6,
         value='option-x', group_name='group-1'),
    dict(marker='OptionUnicode', clsid=27, name='OptionUnicode', id=8,
         tabindex=7, value='1', caption=u'Opt €', caption_unicode=True),
]


def site_o_blob(site):
    if site['clsid'] == 21:
        return build_label_blob(site.get('caption'),
                                site.get('caption_unicode', False))
    return build_morph_blob(site.get('value'), site.get('caption'),
                            site.get('group_name'),
                            site.get('value_unicode', False),
                            site.get('caption_unicode', False),
                            site.get('group_unicode', False))


def build_pair(sites=None):
    """Return (f-bytes, o-bytes, expected o-ranges keyed by marker)."""
    sites = SITES if sites is None else sites
    nodes = [(0, site) for site in sites]
    f_bytes = build_f_stream(nodes)
    ranges = {}
    pieces = []
    offset = 0
    for site in sites:
        blob = site_o_blob(site)
        ranges[site['marker']] = (offset, offset + len(blob))
        pieces.append(blob)
        offset += len(blob)
    return f_bytes, b''.join(pieces), ranges


def parse_with_ranges(f_bytes, o_bytes):
    """Drive the parser the same way extract_OleFormVariables does, recording
    the o-stream span consumed for each declared control."""
    ole = FakeOleFile({'f': f_bytes, 'o': o_bytes})
    f_stream = oleform.ExtendedStream.open(ole, 'f')
    variables = list(oleform.consume_FormControl(f_stream))

    o_stream = oleform.ExtendedStream.open(ole, 'o')
    observed = []
    for variable in variables:
        start = o_stream._pos
        clsid = variable['ClsidCacheIndex']
        if clsid == 21:
            oleform.consume_LabelControl(o_stream)
        elif clsid in (15, 23, 24, 25, 26, 27, 28):
            oleform.consume_MorphDataControl(o_stream)
        else:
            o_stream.raise_error(
                'Unsupported stored type in user form: {0}'.format(clsid))
        observed.append((variable, (start, o_stream._pos)))
    return f_stream, o_stream, observed


class TestOleFormLayoutRegression(unittest.TestCase):

    def test_controls_pair_with_o_stream_ranges(self):
        f_bytes, o_bytes, expected_ranges = build_pair()
        f_stream, o_stream, observed = parse_with_ranges(f_bytes, o_bytes)

        # The f stream is consumed up to its last byte.
        self.assertEqual(f_stream._pos, len(f_bytes))
        # One o-range per declared control, in declaration order.
        self.assertEqual([v['name'] for v, _ in observed],
                         [site['name'].encode('latin-1') for site in SITES])
        for variable, observed_range in observed:
            marker = variable['name'].decode('latin-1')
            self.assertEqual(observed_range, expected_ranges[marker],
                             'o-stream range mismatch for control ' + marker)
        # No bytes are left over, otherwise later data would be misattributed.
        self.assertEqual(o_stream._pos, len(o_bytes))

    def test_masks_names_values_and_text_encoding(self):
        f_bytes, o_bytes, _ = build_pair()
        ole = FakeOleFile({'f': f_bytes, 'o': o_bytes})
        variables = oleform.extract_OleFormVariables(ole, [])
        by_name = dict((v['name'].decode('latin-1'), v) for v in variables)

        full = by_name['LabelFull']
        self.assertEqual(full['tag'], b'tag-1')
        self.assertEqual(full['control_tip_text'], b'tip-1')
        self.assertEqual(full['caption'], b'Label caption')

        unicode_box = by_name['TextBoxUnicode']
        self.assertEqual(unicode_box['value'], u'café'.encode('utf-16-le'))
        self.assertEqual(unicode_box['caption'], b'\xa5-yen')

        option = by_name['OptionUnicode']
        self.assertEqual(option['value'], b'1')
        self.assertEqual(option['caption'], u'Opt €'.encode('utf-16-le'))

        combo = by_name['ComboGroup']
        self.assertEqual(combo['value'], b'option-x')
        self.assertEqual(combo['group_name'], b'group-1')

    def test_empty_string_is_distinct_from_absent_field(self):
        f_bytes, o_bytes, _ = build_pair()
        ole = FakeOleFile({'f': f_bytes, 'o': o_bytes})
        variables = oleform.extract_OleFormVariables(ole, [])
        by_name = dict((v['name'].decode('latin-1'), v) for v in variables)

        # Present but empty strings are preserved as b'' (label and morph).
        self.assertEqual(by_name['LabelEmpty']['caption'], b'')
        self.assertEqual(by_name['TextBoxEmpty']['value'], b'')
        self.assertEqual(by_name['TextBoxEmpty']['caption'], b'')
        # Absent properties stay None instead of being confused with ''.
        self.assertIsNone(by_name['LabelAbsent']['caption'])
        self.assertIsNone(by_name['TextBoxAbsent']['value'])
        self.assertIsNone(by_name['TextBoxAbsent']['caption'])
        self.assertIsNone(by_name['TextBoxAbsent']['group_name'])
        # Fields that the control type never exposes remain None as well.
        self.assertIsNone(by_name['LabelFull']['value'])

    def test_nested_controls_keep_declaration_order_and_ranges(self):
        nested = [
            (0, dict(marker='Root', clsid=21, name='Root', id=1,
                     tabindex=0, caption='root')),
            (1, dict(marker='Child', clsid=23, name='Child', id=2,
                     tabindex=0, value='child-value')),
            (2, dict(marker='GrandChild', clsid=21, name='GrandChild', id=3,
                     tabindex=0, caption='grand')),
            (0, dict(marker='Sibling', clsid=21, name='Sibling', id=4,
                     tabindex=1, caption='sibling')),
        ]
        f_bytes = build_f_stream(nested)
        o_pieces = []
        ranges = {}
        offset = 0
        for _depth, site in nested:
            blob = site_o_blob(site)
            ranges[site['marker']] = (offset, offset + len(blob))
            o_pieces.append(blob)
            offset += len(blob)
        o_bytes = b''.join(o_pieces)

        f_stream, o_stream, observed = parse_with_ranges(f_bytes, o_bytes)
        self.assertEqual(f_stream._pos, len(f_bytes))
        self.assertEqual([v['name'].decode('latin-1') for v, _ in observed],
                         ['Root', 'Child', 'GrandChild', 'Sibling'])
        for variable, observed_range in observed:
            marker = variable['name'].decode('latin-1')
            self.assertEqual(observed_range, ranges[marker])
        self.assertEqual(o_stream._pos, len(o_bytes))

    # -- mutations: each must raise and point at the offending control ------

    def test_unknown_control_type_does_not_shift_later_controls(self):
        sites = [dict(site) for site in SITES]
        sites[3] = dict(sites[3])
        sites[3]['clsid'] = 999                  # unknown ClsidCacheIndex
        f_bytes, o_bytes, ranges = build_pair(sites)
        with self.assertRaises(oleform.OleFormParsingError) as context:
            ole = FakeOleFile({'f': f_bytes, 'o': o_bytes})
            oleform.extract_OleFormVariables(ole, [])
        # The reported o-stream offset must fall inside the offending
        # control's expected span, naming where f and o first diverge.
        message = str(context.exception)
        self.assertIn('999', message)
        reported_offset = int(message.split(':', 2)[1].lstrip('/'))
        start, end = ranges['TextBoxUnicode']
        self.assertTrue(start <= reported_offset <= end,
                        'error offset {0} outside TextBoxUnicode span {1}'
                        .format(reported_offset, (start, end)))

    def test_corrupt_byte_count_desyncs_at_named_control(self):
        f_bytes, o_bytes, ranges = build_pair()
        marker = 'TextBoxUnicode'
        start, end = ranges[marker]
        corrupted = bytearray(o_bytes)
        # MorphData header: 2 version + 2 cb + 8 mask bytes, then fValue count.
        count_offset = start + 12
        original = struct.unpack('<L', corrupted[count_offset:count_offset + 4])[0]
        # Inflating the declared size makes this control read past its own
        # span, which must be caught instead of bleeding into the next one.
        struct.pack_into('<L', corrupted, count_offset, original + 4)
        with self.assertRaises(oleform.OleFormParsingError) as context:
            parse_with_ranges(f_bytes, bytes(corrupted))
        message = str(context.exception)
        self.assertIn('Bad jump', message)
        # The reported offset is the end of the corrupted control's span.
        reported_offset = int(message.split(':', 2)[1].lstrip('/'))
        self.assertTrue(start <= reported_offset <= end,
                        'error offset {0} outside {1} span {2}'
                        .format(reported_offset, marker, (start, end)))

    def test_removing_padding_is_flagged_at_first_affected_site(self):
        f_bytes, o_bytes, _ranges = build_pair()
        first_site = build_site(SITES[0])
        site_pos = f_bytes.find(first_site[:8])
        self.assertGreater(site_pos, 0)
        corrupted = bytearray(f_bytes)
        # Remove one alignment/padding byte immediately before the first site:
        # the depth/type block loses 4-byte alignment and the first site is
        # read from the wrong offset, so desync is reported at the first site.
        del corrupted[site_pos - 1]
        with self.assertRaises(oleform.OleFormParsingError) as context:
            parse_with_ranges(bytes(corrupted), o_bytes)
        message = str(context.exception)
        self.assertTrue(
            'OleSiteConcreteControl' in message
            or 'FormObjectDepthTypeCount' in message,
            'expected a first-site alignment error, got: ' + message)

    def test_swapping_control_declarations_is_detected(self):
        # Swap two f-stream site declarations but keep the o stream unchanged.
        # The o bytes still parse, yet the marker that owns each o-range is now
        # the wrong control, so name/value ownership must visibly disagree.
        swapped_sites = [dict(site) for site in SITES]
        swapped_sites[0], swapped_sites[1] = swapped_sites[1], swapped_sites[0]
        original_f, o_bytes, original_ranges = build_pair()
        swapped_f, _swapped_o, _swapped_ranges = build_pair(swapped_sites)

        def owner_by_range(f_bytes):
            _f, _o, observed = parse_with_ranges(f_bytes, o_bytes)
            return dict((rng, variable['name'].decode('latin-1'))
                        for variable, rng in observed)

        original_owners = owner_by_range(original_f)
        swapped_owners = owner_by_range(swapped_f)

        full_range = original_ranges['LabelFull']
        # Correct layout attributes the range to LabelFull; the swap moves it
        # to LabelEmpty, which is the exact control where desync is visible.
        self.assertEqual(original_owners[full_range], 'LabelFull')
        self.assertEqual(swapped_owners[full_range], 'LabelEmpty')
        self.assertNotEqual(original_owners, swapped_owners)


if __name__ == '__main__':
    unittest.main()
