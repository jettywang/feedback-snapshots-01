from __future__ import annotations

import struct
from io import BytesIO

import pytest

from dissect.regf import regf
from dissect.regf.exceptions import RegistryKeyNotFoundError

# ---------------------------------------------------------------------------
# Explicitly computed collision inputs
# ---------------------------------------------------------------------------
#
# ``lh`` (HashLeaf) entries carry a 32-bit ``HashKey`` produced by
# ``regf.hashname``: h = (h * 37 + ord(ch)) & 0xffffffff over ``name.upper()``.
#
# A hash collision is therefore a pair of distinct names whose per-character
# ordinal deltas satisfy:
#
#     sum(delta_i * 37 ** (n - 1 - i)) == 0 (mod 2 ** 32)
#
# The balanced base-37 expansion of 2 ** 32 (digits kept in -18..18) is
#
#     2**32 = 2*37**6 - 12*37**5 - 2*37**4 - 12*37**3 - 1*37**2 - 14*37 + 7
#
# so a 7-character delta vector [2, -12, -2, -12, -1, -14, 7] applied to a
# base character whose shifted neighbours are all ordinary uppercase letters
# yields two *different* ASCII names with the *same* registry hash.
HASH_DELTA = (2, -12, -2, -12, -1, -14, 7)

# All uppercase: ``str.upper()`` is the identity, so both names really hash
# together with no case folding involved.
HASH_NAME_A = "O" * 7
HASH_NAME_B = "".join(chr(ord("O") + delta) for delta in HASH_DELTA)  # "QCMCNAV"

# A third, absent name on the same hash bucket (its delta vector sums to
# 2 * 2**32 == 0 mod 2**32). It must never resolve to either existing cell.
HASH_NAME_ABSENT = "R\\J\\LX]"

# Same construction shifted onto CJK unified ideographs (0x4fF2..0x5007),
# which have no Unicode case mapping: two distinct Unicode names, one bucket.
_UNICODE_BASE = 0x5000
UNICODE_HASH_NAME_A = chr(_UNICODE_BASE) * 7
UNICODE_HASH_NAME_B = "".join(chr(_UNICODE_BASE + delta) for delta in HASH_DELTA)

# ``lf`` (FastLeaf) entries only store a 4-character lowercase name hint.
# Two distinct ASCII names sharing the first four characters collide on the
# hint; a missing-key name with the same hint must still be rejected.
HINT_NAME_A = "Policies"
HINT_NAME_B = "Policy"
HINT_NAME_ABSENT = "Poli"

# Non-ASCII names get an all-zero hint, so every Unicode entry in an ``lf``
# index collides on the (empty) hint and relies entirely on the final name
# comparison.
UNICODE_HINT_NAME_A = "Администратор"
UNICODE_HINT_NAME_B = "Администраторы"

_KEY_NODE_SIZE = 0x4C
_HBASE_BLOCK_SIZE = 0x1000
_HBIN_HEADER_SIZE = 0x20
_NO_CELL = 0xFFFFFFFF


def _encode_key_name(name: str) -> tuple[bytes, int, int]:
    """Encode a key name exactly the way Windows stores it in an ``nk`` cell."""
    if name.isascii():
        # COMP_NAME: ASCII names are stored as raw bytes.
        return name.encode("ascii"), len(name), regf.KEY.COMP_NAME
    # Full UTF-16-LE name, NameLength is expressed in bytes.
    blob = name.encode("utf-16-le")
    return blob, len(blob), 0


def _key_node_cell(parent: int, name: str) -> bytes:
    name_blob, name_length, flags = _encode_key_name(name)
    node = struct.pack(
        "<2sHQIIIIIIIIIIIIIIIHH",
        b"nk",
        flags,
        0,  # LastWriteTime
        0,  # Spare (ULONG)
        parent,
        0,  # SubKeyCounts[STABLE]
        0,  # SubKeyCounts[VOLATILE]
        _NO_CELL,  # SubKeyLists[STABLE]
        _NO_CELL,  # SubKeyLists[VOLATILE]
        0,  # ValueList.Count
        _NO_CELL,  # ValueList.List
        _NO_CELL,  # Security
        _NO_CELL,  # Class
        0,  # MaxNameLen
        0,  # MaxClassLen
        0,  # MaxValueNameLen
        0,  # MaxValueDataLen
        0,  # WorkVar
        name_length,
        0,  # ClassLength
    )
    assert len(node) == _KEY_NODE_SIZE
    return _cell(node + name_blob)


def _cell(payload: bytes) -> bytes:
    # Cell size includes the 4-byte size field, is positive when free and
    # negative when allocated; cells are 4-byte aligned.
    size = -(4 + len(payload) + (-len(payload) % 4))
    padding = b"\x00" * (-len(payload) % 4)
    return struct.pack("<i", size) + payload + padding


def build_collision_hive(index_signature: str, names: tuple[str, str], reverse: bool) -> tuple[BytesIO, dict[str, int]]:
    """Build an in-memory hive whose root index contains a real on-disk collision.

    The hive uses genuine registry bytes (HBASE_BLOCK, HBIN, ``nk`` and
    ``lf``/``lh`` cells); only the container is in-memory. ``reverse`` swaps
    the order of the two colliding index entries without moving any cell, so
    lookup order can be proven irrelevant to the resolved identity.
    """
    ordered = list(reversed(names)) if reverse else list(names)

    # Cell offsets are relative to the start of the first hbin; the first cell
    # starts immediately after the 0x20-byte hbin header.
    root_offset = _HBIN_HEADER_SIZE

    # Build every child cell first; their offsets follow the root and index
    # cells, whose sizes are fixed for a two-entry index.
    child_cells = {name: _key_node_cell(root_offset, name) for name in ordered}
    root_placeholder = _cell(b"\x00" * (_KEY_NODE_SIZE + len(b"ROOT")))
    index_cell_size = 4 + 4 + 8 * len(ordered)

    offsets: dict[str, int] = {}
    cursor = root_offset + len(root_placeholder) + index_cell_size
    for name in ordered:
        offsets[name] = cursor
        cursor += len(child_cells[name])

    index_entries = bytearray()
    for name in ordered:
        cell_offset = offsets[name]
        if index_signature == "lf":
            name_blob, _, _ = _encode_key_name(name)
            # Windows leaves the hint zero for non-ASCII names; only the first
            # four ASCII characters are stored otherwise.
            hint = name_blob[:4].ljust(4, b"\x00") if name.isascii() else b"\x00\x00\x00\x00"
            index_entries += struct.pack("<I4s", cell_offset, hint)
        else:
            index_entries += struct.pack("<II", cell_offset, regf.hashname(name))

    index_offset = root_offset + len(root_placeholder)
    index_cell = _cell(
        struct.pack("<2sH", index_signature.encode("ascii"), len(ordered)) + bytes(index_entries)
    )
    assert len(index_cell) == index_cell_size

    root_name_blob, root_name_length, root_flags = _encode_key_name("ROOT")
    root_node = struct.pack(
        "<2sHQIIIIIIIIIIIIIIIHH",
        b"nk",
        root_flags,
        0,
        0,  # Spare (ULONG)
        _NO_CELL,  # Parent
        len(ordered),  # SubKeyCounts[STABLE]
        0,
        index_offset,  # SubKeyLists[STABLE]
        _NO_CELL,
        0,
        _NO_CELL,
        _NO_CELL,
        _NO_CELL,
        0,
        0,
        0,
        0,
        0,  # WorkVar
        root_name_length,
        0,
    ) + root_name_blob
    root_cell = _cell(root_node)
    assert len(root_cell) == len(root_placeholder)

    hbin_payload = root_cell + index_cell + b"".join(child_cells[name] for name in ordered)
    # The whole hive (4 KiB base block plus hbins) is block aligned.
    hive_size = _HBASE_BLOCK_SIZE + _HBIN_HEADER_SIZE + len(hbin_payload)
    hive_size += -hive_size % _HBASE_BLOCK_SIZE
    hbin_size = hive_size - _HBASE_BLOCK_SIZE
    hbin = bytearray(hbin_size)
    struct.pack_into("<4sIIQQQ", hbin, 0, b"hbin", 0, hbin_size, 0, 0, 0)
    hbin[_HBIN_HEADER_SIZE : _HBIN_HEADER_SIZE + len(hbin_payload)] = hbin_payload

    # HBASE_BLOCK: checksum is the XOR of the first 508 bytes as 32-bit words.
    # Fields are written at their explicit offsets (Signature 0x00, RootCell
    # 0x24, Length 0x28, FileName 0x30, CheckSum 0x1FC).
    header = bytearray(_HBASE_BLOCK_SIZE)
    struct.pack_into(
        "<4sIIQIIIIIII",
        header,
        0x00,
        b"regf",
        1,  # Sequence1
        1,  # Sequence2
        0,  # TimeStamp (LARGE_INTEGER)
        1,  # Major
        3,  # Minor
        0,  # Type
        0,  # Format
        root_offset,  # RootCell @ 0x24
        hbin_size,  # Length @ 0x28
        1,  # Cluster @ 0x2C
    )
    filename = "collision.regf".encode("latin1")
    header[0x30 : 0x30 + len(filename)] = filename
    checksum = regf.xor32_crc(bytes(header[:508]))
    struct.pack_into("<I", header, 508, checksum)

    return BytesIO(bytes(header) + hbin), offsets


@pytest.fixture
def lf_ascii_hives() -> tuple[regf.RegistryHive, regf.RegistryHive, dict[str, int]]:
    forward, offsets = build_collision_hive("lf", (HINT_NAME_A, HINT_NAME_B), reverse=False)
    reversed_order, _ = build_collision_hive("lf", (HINT_NAME_A, HINT_NAME_B), reverse=True)
    return regf.RegistryHive(forward), regf.RegistryHive(reversed_order), offsets


@pytest.fixture
def lf_unicode_hives() -> tuple[regf.RegistryHive, regf.RegistryHive, dict[str, int]]:
    forward, offsets = build_collision_hive("lf", (UNICODE_HINT_NAME_A, UNICODE_HINT_NAME_B), reverse=False)
    reversed_order, _ = build_collision_hive("lf", (UNICODE_HINT_NAME_A, UNICODE_HINT_NAME_B), reverse=True)
    return regf.RegistryHive(forward), regf.RegistryHive(reversed_order), offsets


@pytest.fixture
def lh_ascii_hives() -> tuple[regf.RegistryHive, regf.RegistryHive, dict[str, int]]:
    forward, offsets = build_collision_hive("lh", (HASH_NAME_A, HASH_NAME_B), reverse=False)
    reversed_order, _ = build_collision_hive("lh", (HASH_NAME_A, HASH_NAME_B), reverse=True)
    return regf.RegistryHive(forward), regf.RegistryHive(reversed_order), offsets


@pytest.fixture
def lh_unicode_hives() -> tuple[regf.RegistryHive, regf.RegistryHive, dict[str, int]]:
    forward, offsets = build_collision_hive("lh", (UNICODE_HASH_NAME_A, UNICODE_HASH_NAME_B), reverse=False)
    reversed_order, _ = build_collision_hive("lh", (UNICODE_HASH_NAME_A, UNICODE_HASH_NAME_B), reverse=True)
    return regf.RegistryHive(forward), regf.RegistryHive(reversed_order), offsets


def _raw_index_cells(hive: regf.RegistryHive) -> tuple[bytes, str]:
    root = hive.root()
    index = root._subkey_list
    assert isinstance(index, regf.FastLeaf | regf.HashLeaf)
    index_offset = root.cell.SubKeyLists[regf.STABLE]
    return hive.cell_data(index_offset), index.__class__.__name__


def test_collision_constants_actually_collide() -> None:
    # Guard the hand-computed inputs: the pairs must be distinct but share
    # their on-disk bucket key.
    assert HASH_NAME_A != HASH_NAME_B
    assert regf.hashname(HASH_NAME_A) == regf.hashname(HASH_NAME_B)
    assert regf.hashname(HASH_NAME_A) == regf.hashname(HASH_NAME_B.lower())
    assert regf.hashname(HASH_NAME_ABSENT) == regf.hashname(HASH_NAME_A)
    assert HASH_NAME_ABSENT not in (HASH_NAME_A, HASH_NAME_B)

    assert UNICODE_HASH_NAME_A != UNICODE_HASH_NAME_B
    assert regf.hashname(UNICODE_HASH_NAME_A) == regf.hashname(UNICODE_HASH_NAME_B)

    assert HINT_NAME_A[:4].lower() == HINT_NAME_B[:4].lower() == HINT_NAME_ABSENT.lower()
    assert UNICODE_HINT_NAME_A != UNICODE_HINT_NAME_B


def test_lf_ascii_hint_collision(lf_ascii_hives: tuple) -> None:
    forward, reversed_order, offsets = lf_ascii_hives

    raw, index_name = _raw_index_cells(forward)
    assert index_name == "FastLeaf"
    # Both entries genuinely carry the same on-disk hint (entry layout is
    # Cell(4) + NameHint(4), preceded by the 4-byte index header).
    assert raw[8:12] == raw[16:20] == HINT_NAME_A[:4].encode("ascii")

    for hive in (forward, reversed_order):
        root = hive.root()
        assert isinstance(root._subkey_list, regf.FastLeaf)

        enumerated = {key.name for key in root.subkeys()}
        assert enumerated == {HINT_NAME_A, HINT_NAME_B}

        # The colliding hint must never let one cell impersonate the other,
        # regardless of which entry is stored first.
        first = root.subkey(HINT_NAME_A)
        second = root.subkey(HINT_NAME_B)
        assert first.name == HINT_NAME_A
        assert second.name == HINT_NAME_B
        assert first is not second

        # Case-insensitive resolution still lands on the exact matching cell.
        assert root.subkey(HINT_NAME_A.lower()).name == HINT_NAME_A
        assert root.subkey(HINT_NAME_B.upper()).name == HINT_NAME_B

        # A name sharing the hint but absent from the cells is not accepted.
        with pytest.raises(RegistryKeyNotFoundError):
            root.subkey(HINT_NAME_ABSENT)

        # Repeated queries are served from the per-key cache and stay distinct.
        assert root.subkey(HINT_NAME_A) is first
        assert root.subkey(HINT_NAME_B) is second
        assert root._cache[HINT_NAME_A.lower()] is first
        assert root._cache[HINT_NAME_B.lower()] is second

    # Reversing the on-disk entry order must not swap the resolved identities.
    assert reversed_order.root().subkey(HINT_NAME_A).name == forward.root().subkey(HINT_NAME_A).name
    assert reversed_order.root().subkey(HINT_NAME_B).name == forward.root().subkey(HINT_NAME_B).name
    assert {key.name for key in reversed_order.root().subkeys()} == set(offsets)


def test_lf_unicode_zero_hint_collision(lf_unicode_hives: tuple) -> None:
    forward, reversed_order, _ = lf_unicode_hives

    raw, index_name = _raw_index_cells(forward)
    assert index_name == "FastLeaf"
    # Non-ASCII names are stored with all-zero name hints.
    assert raw[8:12] == raw[16:20] == b"\x00\x00\x00\x00"

    for hive in (forward, reversed_order):
        root = hive.root()
        enumerated = [key.name for key in root.subkeys()]
        assert sorted(enumerated) == sorted([UNICODE_HINT_NAME_A, UNICODE_HINT_NAME_B])

        first = root.subkey(UNICODE_HINT_NAME_A)
        second = root.subkey(UNICODE_HINT_NAME_B)
        assert first.name == UNICODE_HINT_NAME_A
        assert second.name == UNICODE_HINT_NAME_B
        assert first is not second
        assert root.subkey(UNICODE_HINT_NAME_A) is first
        assert root.subkey(UNICODE_HINT_NAME_B) is second

        with pytest.raises(RegistryKeyNotFoundError):
            root.subkey("倀倀")

    assert reversed_order.root().subkey(UNICODE_HINT_NAME_A).name == UNICODE_HINT_NAME_A
    assert reversed_order.root().subkey(UNICODE_HINT_NAME_B).name == UNICODE_HINT_NAME_B


def test_lh_ascii_hash_collision(lh_ascii_hives: tuple) -> None:
    forward, reversed_order, offsets = lh_ascii_hives

    raw, index_name = _raw_index_cells(forward)
    assert index_name == "HashLeaf"
    # The two entries genuinely store the same hash on disk.
    hash_a = struct.unpack("<I", raw[8:12])[0]
    hash_b = struct.unpack("<I", raw[16:20])[0]
    assert hash_a == hash_b == regf.hashname(HASH_NAME_A)

    for hive in (forward, reversed_order):
        root = hive.root()
        assert isinstance(root._subkey_list, regf.HashLeaf)

        enumerated = {key.name for key in root.subkeys()}
        assert enumerated == {HASH_NAME_A, HASH_NAME_B}

        first = root.subkey(HASH_NAME_A)
        second = root.subkey(HASH_NAME_B)
        assert first.name == HASH_NAME_A
        assert second.name == HASH_NAME_B
        assert first is not second

        # Case folding changes neither bucket nor final identity.
        assert root.subkey(HASH_NAME_A.lower()).name == HASH_NAME_A
        assert root.subkey(HASH_NAME_B.lower()).name == HASH_NAME_B
        assert root.subkey(HASH_NAME_B.upper()).name == HASH_NAME_B

        # An absent name in the same hash bucket must not match either cell.
        with pytest.raises(RegistryKeyNotFoundError):
            root.subkey(HASH_NAME_ABSENT)

        assert root.subkey(HASH_NAME_A) is first
        assert root.subkey(HASH_NAME_B) is second
        assert root._cache[HASH_NAME_A.lower()] is first
        assert root._cache[HASH_NAME_B.lower()] is second

    assert reversed_order.root().subkey(HASH_NAME_A).name == HASH_NAME_A
    assert reversed_order.root().subkey(HASH_NAME_B).name == HASH_NAME_B
    assert {key.name for key in reversed_order.root().subkeys()} == set(offsets)


def test_lh_unicode_hash_collision(lh_unicode_hives: tuple) -> None:
    forward, reversed_order, _ = lh_unicode_hives

    raw, index_name = _raw_index_cells(forward)
    assert index_name == "HashLeaf"
    hash_a = struct.unpack("<I", raw[8:12])[0]
    hash_b = struct.unpack("<I", raw[16:20])[0]
    assert hash_a == hash_b == regf.hashname(UNICODE_HASH_NAME_A)

    for hive in (forward, reversed_order):
        root = hive.root()
        assert sorted(key.name for key in root.subkeys()) == sorted([UNICODE_HASH_NAME_A, UNICODE_HASH_NAME_B])

        first = root.subkey(UNICODE_HASH_NAME_A)
        second = root.subkey(UNICODE_HASH_NAME_B)
        assert first.name == UNICODE_HASH_NAME_A
        assert second.name == UNICODE_HASH_NAME_B
        assert first is not second
        assert root.subkey(UNICODE_HASH_NAME_A) is first
        assert root.subkey(UNICODE_HASH_NAME_B) is second

        with pytest.raises(RegistryKeyNotFoundError):
            root.subkey(HASH_NAME_ABSENT)

    assert reversed_order.root().subkey(UNICODE_HASH_NAME_A).name == UNICODE_HASH_NAME_A
    assert reversed_order.root().subkey(UNICODE_HASH_NAME_B).name == UNICODE_HASH_NAME_B


@pytest.mark.parametrize("index_signature", ["lf", "lh"])
def test_normal_index_lookup_semantics_unchanged(index_signature: str) -> None:
    # Non-colliding entries keep their ordinary lookup/enumeration behaviour.
    names = ("Alpha", "Beta")
    expected_type = regf.FastLeaf if index_signature == "lf" else regf.HashLeaf

    forward = regf.RegistryHive(build_collision_hive(index_signature, names, reverse=False)[0])
    reversed_order = regf.RegistryHive(build_collision_hive(index_signature, names, reverse=True)[0])

    # Enumeration follows on-disk entry order, so reversing the index reverses
    # the iteration order; name-based lookup is unaffected.
    assert [key.name for key in forward.root().subkeys()] == list(names)
    assert [key.name for key in reversed_order.root().subkeys()] == list(reversed(names))

    for hive in (forward, reversed_order):
        root = hive.root()
        assert isinstance(root._subkey_list, expected_type)
        assert root.subkey("alpha").name == "Alpha"
        assert root.subkey("BETA").name == "Beta"
        with pytest.raises(RegistryKeyNotFoundError):
            root.subkey("Gamma")
