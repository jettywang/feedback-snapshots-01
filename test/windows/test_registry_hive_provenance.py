"""Registry hive cell provenance: stable vs volatile storage evidence.

The registry hive maps cells through two independent storage areas.  A cell
index's low 31 bits are only unique within one storage area; the high bit
selects stable (0) or volatile (1).  These tests build the smallest possible
hive mapping on top of an in-memory data layer to demonstrate that the same
low index resolves to different bytes in each store, that one-sided absence is
reported without ever consulting the other store, and that three failure
modes stay distinguishable:

* a map entry whose page is not resident (RegistryCellPagedOut)
* an index beyond the store's hive range (RegistryIndexOutOfRange)
* a key that simply does not exist (KeyError)
"""

import struct
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from volatility3.framework import contexts, exceptions
from volatility3.framework.layers import physical, registry

# Two independent 4 KiB pages back the two storage areas of the minimal hive.
STABLE_PAGE = 0x10000
VOLATILE_PAGE = 0x20000
MEMORY_SIZE = 0x30000

# The shared low cell index exercised by every scenario below.
LOW_INDEX = 0x00000020
STABLE_INDEX = LOW_INDEX
VOLATILE_INDEX = LOW_INDEX | registry.VOLATILE_BIT

# Distinct marker bytes placed at the same low index in each store.
STABLE_MARKER = b"STABLE-STORE-CELL"
VOLATILE_MARKER = b"VOLATILE-STORE-CELL"

# The volatile store is deliberately shorter, so an in-range stable index can
# be out of range on the volatile side without either page being missing.
STABLE_LENGTH = 0x1000
VOLATILE_LENGTH = 0x0200
OUT_OF_RANGE_INDEX = 0x00000800


class _FaultingTableArray:
    """A directory's Table array whose entries cannot be read from memory."""

    def __getitem__(self, index: int):
        raise exceptions.InvalidAddressException(
            "memory", STABLE_PAGE, "Map table page not resident"
        )


class _SparseTableArray:
    """A Table array with one mapped page; every other index is paged out."""

    def __init__(self, entry):
        self._entry = entry

    def __getitem__(self, index: int):
        if index != 0:
            raise exceptions.InvalidAddressException(
                "memory",
                STABLE_PAGE + index * 0x1000,
                f"Map table page {index} not resident",
            )
        return self._entry


class _PresentMapEntry:
    """An HMAP_ENTRY stand-in mapping directly onto a physical page."""

    def __init__(self, block_offset: int) -> None:
        self._block_offset = block_offset

    def get_block_offset(self) -> int:
        return self._block_offset


def _build_memory() -> bytearray:
    memory = bytearray(MEMORY_SIZE)
    memory[STABLE_PAGE + LOW_INDEX : STABLE_PAGE + LOW_INDEX + len(STABLE_MARKER)] = (
        STABLE_MARKER
    )
    memory[
        VOLATILE_PAGE + LOW_INDEX : VOLATILE_PAGE + LOW_INDEX + len(VOLATILE_MARKER)
    ] = VOLATILE_MARKER
    return memory


def _storage(length: int, entry, *, faulting: bool = False):
    table_array = _FaultingTableArray() if faulting else _SparseTableArray(entry)
    directory_entry = SimpleNamespace(Table=table_array)
    return SimpleNamespace(
        Length=length, Map=SimpleNamespace(Directory=[directory_entry])
    )


def _build_hive(*, stable_faulting: bool = False, volatile_faulting: bool = False):
    """Constructs a RegistryHive without a kernel image or symbol download.

    Only the attributes exercised by cell translation are populated; everything
    normally read from _CMHIVE is supplied directly.
    """
    context = contexts.Context()
    memory = _build_memory()
    context.layers.add_layer(
        physical.BufferDataLayer(context, "layer_memory", "memory", bytes(memory))
    )

    hive = registry.RegistryHive.__new__(registry.RegistryHive)
    # LinearlyMappedLayer/interface bookkeeping that the real constructor sets.
    hive._context = context
    hive._config_path = "hive"
    hive._name = "test-hive"
    hive._metadata = {}
    hive._base_layer = "memory"
    hive._page_size = 1 << 12
    hive._minaddr = 0
    hive._hive_maxaddr_non_volatile = STABLE_LENGTH
    hive._hive_maxaddr_volatile = VOLATILE_LENGTH
    hive._maxaddr = registry.VOLATILE_BIT | VOLATILE_LENGTH

    stable_storage = _storage(
        STABLE_LENGTH,
        _PresentMapEntry(STABLE_PAGE),
        faulting=stable_faulting,
    )
    volatile_storage = _storage(
        VOLATILE_LENGTH,
        _PresentMapEntry(VOLATILE_PAGE),
        faulting=volatile_faulting,
    )
    hive.hive = SimpleNamespace(Storage=[stable_storage, volatile_storage])
    hive._cmhive_name = r"\TestHive"
    # A non-regf base block makes root_cell_offset fall back to 0x20, matching
    # the low cell index used throughout these scenarios.
    bad_signature = Mock()
    bad_signature.cast.return_value = "bad!"
    hive._base_block = SimpleNamespace(Signature=bad_signature)
    context.config["hive.base_layer"] = "memory"
    context.layers.add_layer(hive)
    return hive


def test_same_low_index_resolves_to_distinct_stores():
    hive = _build_hive()

    stable = hive.cell_provenance(STABLE_INDEX)
    volatile = hive.cell_provenance(VOLATILE_INDEX)

    assert stable.cell_offset == volatile.cell_offset == LOW_INDEX
    assert stable.store == registry.STABLE_STORE
    assert volatile.store == registry.VOLATILE_STORE
    assert stable.is_volatile is False
    assert volatile.is_volatile is True
    assert stable.mapped_offset == STABLE_PAGE + LOW_INDEX
    assert volatile.mapped_offset == VOLATILE_PAGE + LOW_INDEX
    assert stable.memory_layer == volatile.memory_layer == "memory"

    # The bytes actually read back differ even though the low index matches.
    context = hive._context
    stable_bytes = context.layers.read(
        "memory", stable.mapped_offset, len(STABLE_MARKER)
    )
    volatile_bytes = context.layers.read(
        "memory", volatile.mapped_offset, len(VOLATILE_MARKER)
    )
    assert stable_bytes == STABLE_MARKER
    assert volatile_bytes == VOLATILE_MARKER
    assert stable_bytes != volatile_bytes


def test_volatile_bit_is_never_stripped_for_cross_store_lookup():
    hive = _build_hive()

    # Asking for the volatile index must never return the stable page, even
    # though masking the high bit would produce an identical low index.
    volatile = hive.cell_provenance(VOLATILE_INDEX)
    assert volatile.mapped_offset >= VOLATILE_PAGE
    assert hive._translate(VOLATILE_INDEX) == VOLATILE_PAGE + LOW_INDEX
    assert hive._translate(STABLE_INDEX) == STABLE_PAGE + LOW_INDEX


def test_paged_out_map_entry_is_distinct_from_range_and_absence():
    hive = _build_hive(stable_faulting=True)

    with pytest.raises(registry.RegistryCellPagedOut) as excinfo:
        hive.cell_provenance(STABLE_INDEX)
    paged = excinfo.value
    assert isinstance(paged, registry.RegistryInvalidIndex)
    assert paged.cell_index == STABLE_INDEX
    assert paged.store == registry.STABLE_STORE

    # An index beyond the volatile store's range is a separate failure class.
    with pytest.raises(registry.RegistryIndexOutOfRange) as excinfo:
        hive.cell_provenance(OUT_OF_RANGE_INDEX | registry.VOLATILE_BIT)
    out_of_range = excinfo.value
    assert isinstance(out_of_range, registry.RegistryInvalidIndex)
    assert not isinstance(out_of_range, registry.RegistryCellPagedOut)
    assert out_of_range.cell_index == OUT_OF_RANGE_INDEX | registry.VOLATILE_BIT
    assert out_of_range.store == registry.VOLATILE_STORE


def test_one_sided_missing_does_not_fall_back_to_the_other_store():
    # The volatile page is absent while the stable page holds valid data at
    # the same low index.  The volatile lookup must fail in its own store
    # rather than silently returning the stable cell.
    hive = _build_hive(volatile_faulting=True)

    with pytest.raises(registry.RegistryCellPagedOut) as excinfo:
        hive.cell_provenance(VOLATILE_INDEX)
    assert excinfo.value.store == registry.VOLATILE_STORE

    stable = hive.cell_provenance(STABLE_INDEX)
    assert stable.store == registry.STABLE_STORE
    stable_bytes = hive._context.layers.read(
        "memory", stable.mapped_offset, len(STABLE_MARKER)
    )
    assert stable_bytes == STABLE_MARKER


def test_mapping_reports_paged_out_and_valid_segments_separately():
    page_aligned_index = 0x00000000
    faulting = _build_hive(stable_faulting=True)

    # ignore_errors drops only the non-resident segment instead of fabricating
    # a cross-store mapping or raising while other segments stay readable.
    assert (
        list(
            faulting.mapping(
                page_aligned_index, faulting._page_size, ignore_errors=True
            )
        )
        == []
    )
    with pytest.raises(registry.RegistryCellPagedOut):
        list(faulting.mapping(page_aligned_index, faulting._page_size))

    present = _build_hive()
    (segment,) = list(present.mapping(page_aligned_index, present._page_size))
    original_offset, chunk_length, mapped_offset, mapped_length, layer = segment
    assert original_offset == page_aligned_index
    assert chunk_length == mapped_length == present._page_size
    assert mapped_offset == STABLE_PAGE
    assert layer == "memory"

    # A read spanning two pages keeps the resident first page's provenance
    # and only skips the paged-out second page.
    partial = list(
        present.mapping(page_aligned_index, present._page_size * 2, ignore_errors=True)
    )
    assert len(partial) == 1
    assert partial[0][2] == STABLE_PAGE


def test_regular_key_lookup_still_returns_the_confirmed_node():
    hive = _build_hive()

    root = Mock()
    root.vol.type_name = "nt!_CM_KEY_NODE"
    root.get_subkeys.return_value = []

    subkey = Mock()
    subkey.get_name.return_value = "ConfirmedKey"
    subkey.vol.type_name = "nt!_CM_KEY_NODE"
    root.get_subkeys.return_value = [subkey]

    hive.get_node = Mock(return_value=root)
    result = hive.get_key("ConfirmedKey")

    assert result is subkey
    hive.get_node.assert_called_once_with(hive.root_cell_offset)

    # A genuinely missing key remains a plain KeyError, never an index error.
    with pytest.raises(KeyError):
        hive.get_key("DoesNotExist")


def test_get_node_provenance_distinguishes_unreadable_cell_bytes():
    hive = _build_hive(stable_faulting=True)
    with pytest.raises(registry.RegistryCellPagedOut):
        hive.get_node_provenance(STABLE_INDEX)


def test_cell_provenance_round_trips_through_helpers():
    hive = _build_hive()
    provenance = hive.cell_provenance(VOLATILE_INDEX)
    assert struct.pack(">I", provenance.cell_index) == struct.pack(">I", VOLATILE_INDEX)
    assert provenance.hive_name == r"\TestHive"
    assert provenance.directory_index == 0
    assert provenance.table_index == 0
    assert provenance.suboffset == LOW_INDEX


def _node_on_hive(hive, cell_index):
    """A minimal StructType stand-in carrying vol.offset/layer_name like a node."""
    node = SimpleNamespace(
        vol=SimpleNamespace(offset=cell_index + 4, layer_name=hive.name),
        _context=hive._context,
    )
    return node


def test_node_and_value_helpers_report_their_own_store():
    from volatility3.framework.symbols.windows.extensions import registry as ext

    hive = _build_hive()

    stable_node = _node_on_hive(hive, STABLE_INDEX)
    volatile_node = _node_on_hive(hive, VOLATILE_INDEX)

    # Bind the unbound extension methods to the lightweight stand-ins.
    stable_provenance = ext.CM_KEY_NODE.get_provenance(stable_node)
    volatile_provenance = ext.CM_KEY_NODE.get_provenance(volatile_node)

    assert ext.CM_KEY_NODE.get_cell_index(stable_node) == STABLE_INDEX
    assert ext.CM_KEY_NODE.get_cell_index(volatile_node) == VOLATILE_INDEX
    assert ext.CM_KEY_NODE.get_volatile(stable_node) is False
    assert ext.CM_KEY_NODE.get_volatile(volatile_node) is True
    assert stable_provenance.store == registry.STABLE_STORE
    assert volatile_provenance.store == registry.VOLATILE_STORE
    assert stable_provenance.mapped_offset == STABLE_PAGE + LOW_INDEX
    assert volatile_provenance.mapped_offset == VOLATILE_PAGE + LOW_INDEX

    value = _node_on_hive(hive, VOLATILE_INDEX)
    value_provenance = ext.CM_KEY_VALUE.get_provenance(value)
    assert ext.CM_KEY_VALUE.get_volatile(value) is True
    assert value_provenance.cell_index == VOLATILE_INDEX
    assert value_provenance.memory_layer == "memory"


def test_node_helper_rejects_non_registry_layers():
    from volatility3.framework.symbols.windows.extensions import registry as ext

    hive = _build_hive()
    foreign = _node_on_hive(hive, STABLE_INDEX)
    foreign.vol.layer_name = "memory"
    with pytest.raises(TypeError):
        ext.CM_KEY_NODE.get_provenance(foreign)
