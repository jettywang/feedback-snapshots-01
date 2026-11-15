import binascii
import struct

import Evtx.Evtx as evtx

from Evtx.inventory import chunk_inventory


def make_variant(buf, chunk_count):
    """
    build a header-only variant of an EVTX image: patch chunk_count and
    repair the header CRC so the header stays self-consistent while its
    claims now contradict the physical file contents.
    """
    variant = bytearray(buf)
    struct.pack_into("<H", variant, 0x2A, chunk_count)
    struct.pack_into("<I", variant, 0x7C, binascii.crc32(bytes(variant[:0x78])) & 0xFFFFFFFF)
    return variant


def test_inventory_real_sample(system):
    """
    the real system.evtx sample: 9 declared chunks, 17 physical slots,
    slots 9-16 are zeroed. no residual chunks; the only contradiction is
    the dirty header's next_record_number lagging the chunk contents.
    """
    inv = chunk_inventory(system)

    assert inv["header"]["oldest_chunk"] == 0
    assert inv["header"]["current_chunk_number"] == 8
    assert inv["header"]["chunk_count"] == 9
    assert inv["file"]["physical_slot_count"] == 17

    by_class = {}
    for c in inv["chunks"]:
        by_class.setdefault(c["classification"], []).append(c["slot"])
    assert by_class["active"] == list(range(9))
    assert by_class["empty"] == list(range(9, 17))
    assert "residual" not in by_class

    # slot order, ring order, and record-number order all agree here
    assert inv["traversal"]["iterated_slots"] == list(range(9))
    assert inv["traversal"]["logical_order_from_header"] == list(range(9))
    assert inv["traversal"]["record_number_order_of_confirmed_active"] == list(range(9))
    assert inv["traversal"]["confirmed_record_total"] == 1601
    assert inv["traversal"]["residual_record_total_excluded"] == 0

    # the dirty header's next_record_number (13528) does not follow the
    # last confirmed record (13649); the contradiction must be preserved
    assert any("next_record_number" in c for c in inv["conflicts"])

    # the inventory's iterated slots match what the parser really walks
    fh = evtx.FileHeader(system, 0x0)
    walked = [(c._offset - fh.header_chunk_size()) // 0x10000 for c in fh.chunks()]
    assert walked == inv["traversal"]["iterated_slots"]


def test_inventory_header_only_variant(system):
    """
    header-only variant of system.evtx with chunk_count patched 9 -> 6.
    slots 6-8 still hold valid chunks (records 13108-13649) but fall
    outside the declared set: they must be reported as unconfirmed
    residual and excluded from the confirmed event count.
    """
    variant = make_variant(system, 6)
    inv = chunk_inventory(variant)

    # the header itself is still self-consistent
    assert inv["header"]["checksum_ok"] is True
    assert inv["header"]["chunk_count"] == 6

    by_class = {}
    for c in inv["chunks"]:
        by_class.setdefault(c["classification"], []).append(c["slot"])
    assert by_class["active"] == [0, 1, 2, 3, 4, 5]
    assert by_class["residual"] == [6, 7, 8]
    assert by_class["empty"] == list(range(9, 17))

    # residual chunks keep their confirmable record ranges visible...
    residual = {c["slot"]: c for c in inv["chunks"] if c["classification"] == "residual"}
    assert residual[6]["log_first_record_number"] == 13108
    assert residual[8]["log_last_record_number"] == 13649
    assert residual[8]["is_current"] is True

    # ...but are excluded from the confirmed count
    assert inv["traversal"]["iterated_slots"] == [0, 1, 2, 3, 4, 5]
    assert inv["traversal"]["confirmed_record_total"] == 1059
    assert inv["traversal"]["residual_record_total_excluded"] == 542

    # current_chunk_number (8) is outside the declared set, so the ring
    # order cannot be derived and must not be guessed
    assert inv["traversal"]["logical_order_from_header"] is None

    # all contradictions are preserved, not resolved
    assert any("residual" in c for c in inv["conflicts"])
    assert any("current_chunk_number" in c for c in inv["conflicts"])
    assert any("next_record_number" in c for c in inv["conflicts"])

    # the standard traversal agrees: it walks only the declared slots
    fh = evtx.FileHeader(variant, 0x0)
    walked = [(c._offset - fh.header_chunk_size()) // 0x10000 for c in fh.chunks()]
    assert walked == [0, 1, 2, 3, 4, 5]
    assert sum(1 for c in fh.chunks() for _ in c.records()) == 1059
