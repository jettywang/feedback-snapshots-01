"""Read-only forensic parsing tests (RFC 4880 packet placement)."""
import os

import pytest

from pgpy import PGPMessage
from pgpy import ByteRange
from pgpy import forensic_scan
from pgpy import forensic_scan_file
from pgpy.constants import PacketTag
from pgpy.errors import PGPError

FORENSIC_DIR = os.path.join(os.path.dirname(__file__), 'testdata', 'forensics')
CLEAN_SAMPLE = os.path.join(
    FORENSIC_DIR, 'sample.marker-unknown-compressed-literals.pgp')
GARBAGE_SAMPLE = os.path.join(FORENSIC_DIR, 'sample.trailing-garbage.pgp')


def new_length(length):
    if length < 192:
        return bytes([length])
    if length < 8384:
        value = length - 192
        return bytes([(value >> 8) + 192, value & 0xFF])
    return b'\xff' + length.to_bytes(4, 'big')


def new_packet(tag, body):
    return bytes([0xC0 | tag]) + new_length(len(body)) + body


def literal_packet(filename, text):
    name = filename.encode('utf-8')
    body = (b'b' + bytes([len(name)]) + name
            + b'\x00\x00\x00\x00' + text.encode('utf-8'))
    return new_packet(11, body)


@pytest.fixture(scope='module')
def clean_blob():
    with open(CLEAN_SAMPLE, 'rb') as handle:
        return bytearray(handle.read())


@pytest.fixture(scope='module')
def report(clean_blob):
    return forensic_scan(clean_blob)


def test_sample_covers_required_packet_kinds(report):
    tags = [entry.tag for entry in report]
    assert PacketTag.Marker in tags
    assert PacketTag.CompressedData in tags
    assert PacketTag.LiteralData in tags
    # one unknown tag (16) plus three literals (two compressed, one outer,
    # one partial literal)
    assert report.unknown_packets[0].tag == 16
    assert sum(1 for t in tags if t == PacketTag.LiteralData) == 4


def test_packet_order_matches_input(report, clean_blob):
    # the outer packets appear in exactly the order they were written
    outer = [p for p in report if p.depth == 0]
    assert [p.tag for p in outer] == [
        PacketTag.Marker, 16, PacketTag.CompressedData,
        PacketTag.LiteralData, PacketTag.LiteralData]

    # walk order is depth-first and indexes are assigned monotonically
    assert [p.index for p in report] == list(range(len(report)))

    # every outer range slices the original bytes at that position
    cursor = 0
    for entry in outer:
        assert entry.range.start == cursor
        assert entry.container == 'outer'
        assert entry.offset_space == 'outer'
        cursor = entry.range.end
    assert cursor == len(clean_blob)


def test_ranges_slice_original_bytes(report, clean_blob):
    for entry in report:
        source = clean_blob if entry.container == 'outer' else entry.parent.nested_data
        chunk = source[entry.range.start:entry.range.end]
        assert chunk[0] & 0x80
        assert entry.header_range.start == entry.range.start
        assert entry.body_range.start >= entry.header_range.start
        assert entry.body_range.end == entry.range.end


def test_reassemble_reproduces_input(report, clean_blob):
    assert report.complete is True
    assert report.reassemble() == bytes(clean_blob)
    assert report.trailing == ByteRange(len(clean_blob), len(clean_blob))


def test_partial_length_segments_map_to_real_bytes(report, clean_blob):
    partial = [p for p in report if p.partial_length]
    assert len(partial) == 1
    entry = partial[0]

    # three segments: two 512-byte partial bodies plus a final body
    assert len(entry.segments) == 3
    assert [segment.partial for segment in entry.segments] == [True, True, False]

    # each segment body slices the original input, no recomputed length used
    recovered = bytearray()
    for segment in entry.segments:
        recovered += clean_blob[segment.body.start:segment.body.end]
        # the length header sits immediately before its segment body
        assert segment.header.end == segment.body.start
    # segment bodies concatenate to the full literal payload (format byte,
    # zero-length filename, 4 mtime octets, then the 1100 text octets),
    # recoverable directly from the original input bytes
    joined = bytes(recovered)
    assert joined == b'b' + b'\x00' + b'\x00\x00\x00\x00' + b'P' * 1100

    # the packet-level range starts at the tag byte and covers every segment
    # header and body through the end of the final segment
    assert entry.range.start == entry.header_range.start
    assert entry.range.end == entry.segments[-1].body.end
    assert entry.header_range.start == entry.segments[0].header.start - 1

    # the recorded partial length octets are the original on-wire bytes
    # (0xE9 means a 512-octet partial body), not a re-encoded length
    first_header = clean_blob[entry.segments[0].header.start:
                              entry.segments[0].header.end]
    second_header = clean_blob[entry.segments[1].header.start:
                               entry.segments[1].header.end]
    assert first_header == b'\xe9'
    assert second_header == b'\xe9'
    assert entry.segments[0].body.length == 512
    assert entry.segments[1].body.length == 512


def test_compressed_container_uses_separate_offset_space(report):
    container = next(p for p in report if p.tag == PacketTag.CompressedData)
    children = report.children(container)

    assert len(children) == 2
    for child in children:
        assert child.depth == container.depth + 1
        assert child.parent is container
        assert child.container == 'compressed'
        assert child.offset_space == 'compressed@{}'.format(container.index)
        # nested offsets restart at zero in their own coordinate system,
        # independent of where the container sits in the outer stream
        assert children[0].range.start == 0

    # the nested stream itself reassembles to the decompressed payload
    nested = container.nested_data
    assert nested[:1] == b'\xcb'
    rebuilt = b''.join(nested[c.range.start:c.range.end] for c in children)
    assert rebuilt == nested


def test_unknown_and_ignored_packets_stay_visible(report):
    unknown = report.unknown_packets
    assert len(unknown) == 1
    assert unknown[0].status == 'opaque'
    assert unknown[0].known is False
    assert unknown[0].tag_name == 'Unknown'

    ignored = report.ignored_packets
    ignored_tags = {p.tag for p in ignored}
    assert PacketTag.Marker in ignored_tags
    assert 16 in ignored_tags


def test_extra_literal_is_reported_not_swallowed(report):
    literals = [p for p in report if p.tag == PacketTag.LiteralData and p.depth == 0]
    # first outer literal is assembled into the high-level message...
    assert literals[0].disposition == 'assembled'
    # ...the later partial literal is rejected but still fully reported
    assert literals[1].disposition == 'rejected'
    assert literals[1].status == 'parsed'


def test_high_level_message_only_exposes_first_literal(report):
    message = report.high_level_message()
    assert message is not None
    # the compressed packet unwraps to the first literal the loader accepts
    assert message.type == 'literal'
    assert bytes(message.message) == b'first compressed literal'

    # the forensic tree still knows about every other literal packet
    all_literals = [p for p in report if p.tag == PacketTag.LiteralData]
    assert len(all_literals) == 4


def test_high_level_loader_demonstrates_lossiness(clean_blob):
    # PGPMessage cannot represent the unknown tag and raises; the forensic
    # entry point never loses that packet
    with pytest.raises(Exception):
        PGPMessage.from_blob(clean_blob)


def test_trailing_garbage_is_reported(clean_blob):
    blob = bytes(clean_blob) + b'\xde\xad\xbe\xef'
    result = forensic_scan(blob)

    assert result.complete is False
    assert result.trailing == ByteRange(len(clean_blob), len(blob))
    assert result.reassemble() == blob
    # confirmed packets are all retained
    assert len(result.packets) == len(forensic_scan(clean_blob).packets)


def test_parse_failure_keeps_confirmed_ranges():
    good = new_packet(PacketTag.Marker, b'PGP')
    # a packet that claims 50 body bytes but only provides 5
    broken = bytes([0xCB]) + b'\xff' + (50).to_bytes(4, 'big') + b'hello'
    result = forensic_scan(good + broken)

    assert result.complete is False
    assert result.fatal_error is not None
    # the valid leading packet is preserved with its confirmed range
    assert len(result.packets) == 1
    assert result.packets[0].tag == PacketTag.Marker
    assert result.packets[0].range == ByteRange(0, len(good))
    # the unparseable remainder stays visible
    assert result.trailing == ByteRange(len(good), len(good) + len(broken))
    assert result.reassemble() == good + broken
    # no fake-complete message is handed back
    assert result.high_level_message() is None


def test_encrypted_packets_are_not_decrypted():
    # tag 18 (SEIPD) ciphertext: the scanner records it opaquely
    payload = b'\x00' * 32
    encrypted = new_packet(PacketTag.SymmetricallyEncryptedIntegrityProtectedData,
                           payload)
    result = forensic_scan(encrypted)
    entry = result.packets[0]

    assert entry.is_encrypted is True
    assert entry.status == 'opaque'
    assert entry.packet is None
    # the original ciphertext bytes are still exactly in place
    assert result.reassemble() == encrypted


def test_forensic_scan_file_entrypoint(clean_blob):
    result = forensic_scan_file(CLEAN_SAMPLE)
    assert result.reassemble() == bytes(clean_blob)


def test_old_format_header_ranges():
    # old-style marker packet: tag 10, one-octet length, 3 body bytes
    old_packet = b'\xa8\x03PGP'
    result = forensic_scan(old_packet)
    entry = result.packets[0]

    assert entry.new_format is False
    assert entry.range == ByteRange(0, 5)
    assert entry.header_range == ByteRange(0, 2)
    assert entry.body_range == ByteRange(2, 5)
    assert result.reassemble() == old_packet


def test_indeterminate_length_runs_to_end():
    # old-style length type 3: no length field, body runs to end of stream
    packet = b'\xa3PGPdata'
    result = forensic_scan(packet)
    entry = result.packets[0]

    assert entry.new_format is False
    assert entry.header_range == ByteRange(0, 1)
    assert entry.body_range == ByteRange(1, len(packet))
    assert entry.range == ByteRange(0, len(packet))
    assert result.reassemble() == packet


def test_nested_truncation_marks_parent_and_keeps_outer_bytes():
    import zlib

    # a literal packet that claims 50 body bytes but only provides 5
    broken_inner = b'\xcb\xff' + (50).to_bytes(4, 'big') + b'short'
    compressed_block = zlib.compress(broken_inner)
    outer = (new_packet(PacketTag.CompressedData,
                        bytes([2]) + compressed_block))

    result = forensic_scan(outer)
    parent = result.packets[0]

    assert result.complete is False
    assert result.fatal_error is not None
    assert result.fatal_error.startswith('compressed@0:')
    # the parent container carries the nested failure instead of hiding it
    assert parent.status == 'error'
    assert 'nested stream truncated' in parent.error
    # outer confirmed bytes remain fully recoverable
    assert result.reassemble() == outer


def test_empty_input_yields_empty_complete_report():
    result = forensic_scan(b'')
    assert result.complete is True
    assert len(result.packets) == 0
    assert result.trailing == ByteRange(0, 0)
    assert result.reassemble() == b''


def test_armored_input_is_supported_and_reassembled():
    # a plain literal message round-trips through ASCII armor and is still
    # fully reconstructable by the read-only scanner
    message = PGPMessage.from_blob(literal_packet('a.txt', 'armored text'))
    armored = str(message)
    assert 'BEGIN PGP MESSAGE' in armored

    result = forensic_scan(armored)
    assert result.armor['magic'] == 'MESSAGE'
    assert result.complete is True
    # reassembly reproduces the de-armored binary body, not the armor text
    assert result.reassemble() == bytes(message)
