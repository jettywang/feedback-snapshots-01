"""Bit-level regression tests for Linux PROT_NONE page-table handling.

Each test writes real page tables and known data bytes into a sparse physical
memory layer, then asks the public Intel translation layer to map a virtual
address.  The expected physical address is computed from the bit layout each
layer class declares (``page_shift``, ``_structure``, ``_maxphyaddr``) and from
the PROT_NONE encoding, never from the layer's own PFN helpers.

Four leaf conditions are covered:

* a normal present entry, whose PFN is stored directly;
* a software PROT_NONE entry, whose present bit is clear, whose PROT_NONE bit
  is set, and whose PFN field is stored inverted;
* an entry that is not present at all (a real page fault);
* an entry that is present but whose backing physical page is absent from the
  capture.  This is a capture limitation, not a process protection request,
  and the layer must not present it as PROT_NONE.
"""

import struct
from typing import Dict, Iterable, List, Tuple

import pytest

from volatility3.framework import contexts, exceptions, interfaces
from volatility3.framework.layers import intel

PAGE_SHIFT = 12
PAGE_SIZE = 1 << PAGE_SHIFT
PAGE_MASK = PAGE_SIZE - 1

PRESENT = 1 << 0
RW = 1 << 1
USER = 1 << 2
ACCESSED = 1 << 5
DIRTY = 1 << 6
PSE = 1 << 7
PROTNONE = 1 << 8
PAT_LARGE = 1 << 12
NX = 1 << 63

DTB = 0x100000
KNOWN = b"KNOB\x00\x01\x02\x03"

DEFAULT_VADDR = {
    intel.LinuxIntel: 0x1234_0000,
    intel.LinuxIntelPAE: 0x1234_0000,
    intel.LinuxIntel32e: 0x1234_5678_0000,
}
# The same pages with virtual bits throughout the offset.  Bit 12 is chosen
# explicitly because a bad PFN low bit is otherwise hidden by the page offset
# being OR-ed onto the translated frame.
OFFSET_VADDR = {
    intel.LinuxIntel: 0x1234_0ABC,
    intel.LinuxIntelPAE: 0x1234_0ABC,
    intel.LinuxIntel32e: 0x1234_5678_0ABC,
}
OFFSETS = [
    pytest.param(DEFAULT_VADDR, 0, id="offset0"),
    pytest.param(OFFSET_VADDR, 0xABC, id="offset"),
]


class SparsePhysicalLayer(interfaces.layers.DataLayerInterface):
    """A physical layer that stores only the pages a test populated."""

    def __init__(self, context, config_path, name):
        super().__init__(context, config_path, name)
        self._pages: Dict[int, bytes] = {}

    def add_bytes(self, address: int, data: bytes) -> None:
        remaining = memoryview(data)
        current = address
        while remaining:
            base = current & ~PAGE_MASK
            offset = current - base
            chunk = min(len(remaining), PAGE_SIZE - offset)
            page = bytearray(self._pages.get(base, bytes(PAGE_SIZE)))
            page[offset : offset + chunk] = remaining[:chunk]
            self._pages[base] = bytes(page)
            current += chunk
            remaining = remaining[chunk:]

    def entry(self, table_address: int, index: int, value: int, width: int) -> None:
        size = width // 8
        self.add_bytes(table_address + index * size, value.to_bytes(size, "little"))

    @property
    def minimum_address(self) -> int:
        return 0

    @property
    def maximum_address(self) -> int:
        return (1 << 52) - 1

    def is_valid(self, offset: int, length: int = 1) -> bool:
        if length < 0 or offset < 0:
            return False
        first = offset & ~PAGE_MASK
        last = (offset + length - 1) & ~PAGE_MASK if length else first
        return all(page in self._pages for page in range(first, last + 1, PAGE_SIZE))

    def read(self, offset: int, length: int, pad: bool = False) -> bytes:
        result = bytearray()
        current = offset
        remaining = length
        while remaining > 0:
            base = current & ~PAGE_MASK
            page = self._pages.get(base)
            if page is None:
                raise exceptions.InvalidAddressException(self.name, current)
            chunk = page[current - base : current - base + remaining]
            if not chunk:
                raise exceptions.InvalidAddressException(self.name, current)
            result += chunk
            current += len(chunk)
            remaining -= len(chunk)
        return bytes(result)

    def write(self, offset: int, data: bytes) -> None:
        raise NotImplementedError

    @property
    def dependencies(self) -> List[str]:
        return []


def entry_width(layer_class) -> int:
    return 8 * struct.calcsize(layer_class._entry_format)


def pfn_mask(layer_class) -> int:
    """The PFN field as declared by the layer's physical-address width."""
    return ~PAGE_MASK & ((1 << layer_class._maxphyaddr) - 1)


def max_pfn(layer_class) -> int:
    return ((1 << layer_class._maxphyaddr) - 1) >> PAGE_SHIFT


def virtual_indices(
    vaddr: int, structure: Iterable[Tuple[str, int, bool]]
) -> List[int]:
    """Return the per-level page-table index for a virtual address."""
    structure = list(structure)
    position = sum(bits for _, bits, _ in structure) + PAGE_SHIFT - 1
    indices = []
    for _, bits, _ in structure:
        indices.append((vaddr >> (position - bits + 1)) & ((1 << bits) - 1))
        position -= bits
    return indices


def large_page_bits(layer_class, level: int) -> int:
    """Number of virtual address bits covered by a page at ``level``."""
    structure = list(layer_class._structure)
    consumed = sum(bits for _, bits, _ in structure[: level + 1])
    return sum(bits for _, bits, _ in structure) + PAGE_SHIFT - consumed


def aligned_pfn(layer_class, large_level) -> int:
    """Highest PFN representable in the declared width, aligned for the mode."""
    pfn = max_pfn(layer_class)
    if large_level is not None:
        unit = 1 << (large_page_bits(layer_class, large_level) - PAGE_SHIFT)
        pfn &= ~(unit - 1)
    return pfn


def expected_physical(vaddr, pfn, large_level, layer_class) -> int:
    bits = (
        large_page_bits(layer_class, large_level)
        if large_level is not None
        else PAGE_SHIFT
    )
    return (pfn << PAGE_SHIFT) | (vaddr & ((1 << bits) - 1))


def build_layer(
    layer_class,
    *,
    vaddr=None,
    pfn=None,
    large_level=None,
    protnone=False,
    pat=False,
    nx=False,
    extra_entry_bits=0,
    add_data=True,
):
    """Build a page-table tree and return the translating layer.

    The returned tuple is ``(layer, sparse, expected, stored_entry,
    canonical_entry)``.  ``stored_entry`` is exactly what was written to the
    leaf table; ``canonical_entry`` is the entry before any PROT_NONE
    inversion.
    """
    if vaddr is None:
        vaddr = DEFAULT_VADDR[layer_class]
    if pfn is None:
        pfn = aligned_pfn(layer_class, large_level)
    leaf_level = len(layer_class._structure) - 1 if large_level is None else large_level

    flags = PRESENT | RW | USER | ACCESSED | DIRTY
    if protnone:
        flags &= ~PRESENT
        flags |= PROTNONE
    if large_level is not None:
        flags |= PSE
    if pat:
        flags |= PAT_LARGE
    if nx and entry_width(layer_class) > 32:
        flags |= NX

    canonical = (pfn << PAGE_SHIFT) | flags | extra_entry_bits
    # Linux stores a PROT_NONE PFN inverted; flags (including NX/PAT) are not
    # part of the PFN field and must be left alone.
    stored = canonical ^ pfn_mask(layer_class) if protnone else canonical

    context = contexts.Context()
    sparse = SparsePhysicalLayer(context, "memory", "memory")
    context.layers.add_layer(sparse)
    config_path = "test"
    join = interfaces.configuration.path_join
    context.config[join(config_path, "memory_layer")] = "memory"
    context.config[join(config_path, "page_map_offset")] = DTB

    indices = virtual_indices(vaddr, layer_class._structure)
    tables = [DTB + level * PAGE_SIZE for level in range(len(layer_class._structure))]
    width = entry_width(layer_class)
    for level in range(len(layer_class._structure)):
        if level == leaf_level:
            sparse.entry(tables[level], indices[level], stored, width)
            break
        sparse.entry(
            tables[level],
            indices[level],
            tables[level + 1] | PRESENT | RW,
            width,
        )

    expected = expected_physical(vaddr, pfn, large_level, layer_class)
    if add_data:
        sparse.add_bytes(expected, KNOWN)

    layer = layer_class(context, config_path=config_path, name="virtual")
    return layer, sparse, expected, stored, canonical


def leaf_state(layer, vaddr) -> str:
    """Classify the leaf using only public layer behaviour.

    ``capture-hole`` is deliberately distinct from a page-table protection
    state: the entry resolves, but the backing bytes are missing from the
    capture.  A non-present PTE raises ``PagedInvalidAddressException`` while a
    missing backing page raises the plain ``InvalidAddressException``.
    """
    if layer.is_valid(vaddr):
        return "readable"
    try:
        layer.translate(vaddr)
    except exceptions.PagedInvalidAddressException:
        return "not-mapped"
    except exceptions.InvalidAddressException:
        return "capture-hole"
    return "capture-hole"


CLASSES = [
    pytest.param(intel.LinuxIntel, id="intel32"),
    pytest.param(intel.LinuxIntelPAE, id="pae"),
    pytest.param(intel.LinuxIntel32e, id="intel32e"),
]


def page_modes(layer_class):
    modes = [(None, False)]
    for level, (_, _, large) in enumerate(layer_class._structure):
        if large:
            modes.extend([(level, False), (level, True)])
    return modes


def mode_cases():
    cases = []
    for case in CLASSES:
        layer_class = case.values[0]
        for large_level, pat in page_modes(layer_class):
            name = "small" if large_level is None else f"large{large_level}"
            cases.append(
                pytest.param(
                    layer_class,
                    large_level,
                    pat,
                    id=f"{case.id}-{name}-pat{int(pat)}",
                )
            )
    return cases


MODE_CASES = mode_cases()


@pytest.mark.parametrize("addresses, offset", OFFSETS)
@pytest.mark.parametrize("layer_class, large_level, pat", MODE_CASES)
def test_present_page_maps_from_direct_pfn(
    layer_class, large_level, pat, addresses, offset
):
    """A normal present entry maps from the PFN stored directly in the entry."""
    vaddr = addresses[layer_class]
    layer, _, expected, stored, canonical = build_layer(
        layer_class, vaddr=vaddr, large_level=large_level, pat=pat
    )
    assert stored == canonical
    assert layer.translate(vaddr)[0] == expected
    assert layer.read(vaddr, len(KNOWN)) == KNOWN


@pytest.mark.parametrize("addresses, offset", OFFSETS)
@pytest.mark.parametrize("layer_class, large_level, pat", MODE_CASES)
def test_protnone_page_maps_from_single_inversion(
    layer_class, large_level, pat, addresses, offset
):
    """A PROT_NONE entry maps only after its inverted PFN field is restored once."""
    pfn = aligned_pfn(layer_class, large_level)
    vaddr = addresses[layer_class]
    layer, _, expected, stored, canonical = build_layer(
        layer_class,
        vaddr=vaddr,
        pfn=pfn,
        large_level=large_level,
        pat=pat,
        protnone=True,
    )
    mask = pfn_mask(layer_class)
    # For a large entry bit 12 is PAT, so it is not part of the PFN field.
    field = mask & ~PAT_LARGE if large_level is not None else mask

    # The entry really is inverted: present is clear and PROT_NONE is set.
    assert stored & PROTNONE and not stored & PRESENT
    assert stored & mask == ~canonical & mask

    # Decoding the stored PFN field directly, or inverting it twice, is wrong.
    assert (stored & field) >> PAGE_SHIFT != pfn
    assert (((stored ^ mask) ^ mask) & field) >> PAGE_SHIFT == (
        stored & field
    ) >> PAGE_SHIFT
    # Exactly one inversion yields the PFN the test wrote into the entry.
    assert ((stored ^ mask) & field) >> PAGE_SHIFT == pfn

    assert layer.translate(vaddr)[0] == expected
    assert layer.read(vaddr, len(KNOWN)) == KNOWN


@pytest.mark.parametrize("layer_class", CLASSES)
@pytest.mark.parametrize("protnone", [False, True], ids=["present", "protnone"])
def test_small_page_bit_12_is_a_pfn_bit(layer_class, protnone):
    """For 4 KiB entries bit 12 is PFN bit 0, never a PAT flag to strip."""
    pfn = 0x12345  # odd, so PFN bit 0 (entry bit 12) is set
    vaddr = OFFSET_VADDR[layer_class]
    layer, _, expected, stored, _ = build_layer(
        layer_class, vaddr=vaddr, pfn=pfn, protnone=protnone
    )
    assert expected & PAGE_SIZE  # the test really exercises entry bit 12
    assert not stored & PSE
    assert layer.translate(vaddr)[0] == expected
    assert layer.read(vaddr, len(KNOWN)) == KNOWN


@pytest.mark.parametrize("layer_class", CLASSES)
@pytest.mark.parametrize("protnone", [False, True], ids=["present", "protnone"])
def test_high_pfn_uses_the_full_declared_width(layer_class, protnone):
    """The highest page frame in the declared physical width must survive."""
    pfn = max_pfn(layer_class)
    vaddr = OFFSET_VADDR[layer_class]
    layer, _, expected, _, _ = build_layer(
        layer_class, vaddr=vaddr, pfn=pfn, protnone=protnone
    )
    assert expected >> layer_class._maxphyaddr == 0
    assert layer.translate(vaddr)[0] == expected
    assert layer.read(vaddr, len(KNOWN)) == KNOWN


@pytest.mark.parametrize(
    "layer_class, width",
    [
        pytest.param(intel.LinuxIntel, 32, id="32"),
        pytest.param(intel.LinuxIntelPAE, 40, id="40"),
        pytest.param(intel.LinuxIntel32e, 46, id="46"),
    ],
)
@pytest.mark.parametrize("protnone", [False, True], ids=["present", "protnone"])
def test_declared_physical_width_is_honored(monkeypatch, layer_class, width, protnone):
    """Every declared MAXPHYADDR bit is part of the PFN, and no bit above it is."""
    monkeypatch.setattr(layer_class, "_maxphyaddr", width)
    pfn = (1 << (width - PAGE_SHIFT)) - 1
    bits = 8 * struct.calcsize(layer_class._entry_format)
    ignored = (1 << width) if width < bits else 0
    vaddr = OFFSET_VADDR[layer_class]
    layer, _, expected, stored, canonical = build_layer(
        layer_class,
        vaddr=vaddr,
        pfn=pfn,
        protnone=protnone,
        extra_entry_bits=ignored,
    )
    assert expected == ((pfn << PAGE_SHIFT) | (vaddr & PAGE_MASK))
    # The top PFN bit really is carried by the entry.
    assert expected & (1 << (width - 1))
    if ignored:
        # A bit above MAXPHYADDR is preserved as an entry flag but excluded
        # from the physical page number.
        assert stored & ignored and canonical & ignored
    assert layer.translate(vaddr)[0] == expected
    assert layer.read(vaddr, len(KNOWN)) == KNOWN
    # A register-width mask would truncate the top PFN bit on 32-bit PAE.
    if width > layer_class._bits_per_register:
        truncated = expected & ((1 << layer_class._bits_per_register) - 1)
        assert truncated != expected


@pytest.mark.parametrize(
    "layer_class", [intel.LinuxIntelPAE, intel.LinuxIntel32e], ids=["pae", "intel32e"]
)
@pytest.mark.parametrize("protnone", [False, True], ids=["present", "protnone"])
def test_nx_bit_is_not_mixed_into_the_pfn(layer_class, protnone):
    """NX is a flag; it must not flip or truncate the physical page number."""
    pfn = 0x12345
    vaddr = OFFSET_VADDR[layer_class]
    layer, _, expected, stored, _ = build_layer(
        layer_class, vaddr=vaddr, pfn=pfn, protnone=protnone, nx=True
    )
    assert stored & NX
    assert not pfn_mask(layer_class) & NX
    assert layer.translate(vaddr)[0] == expected
    assert layer.read(vaddr, len(KNOWN)) == KNOWN


@pytest.mark.parametrize("layer_class", CLASSES)
@pytest.mark.parametrize("protnone", [False, True], ids=["present", "protnone"])
def test_large_page_pat_is_not_part_of_the_pfn(layer_class, protnone):
    """Bit 12 of a large entry is PAT, including when the PFN is inverted."""
    for level, (_, _, large) in enumerate(layer_class._structure):
        if not large:
            continue
        for pat in (False, True):
            pfn = aligned_pfn(layer_class, level)
            vaddr = OFFSET_VADDR[layer_class]
            layer, _, expected, stored, _ = build_layer(
                layer_class,
                vaddr=vaddr,
                pfn=pfn,
                large_level=level,
                protnone=protnone,
                pat=pat,
            )
            assert stored & PSE
            assert layer.translate(vaddr)[0] == expected
            assert layer.read(vaddr, len(KNOWN)) == KNOWN


@pytest.mark.parametrize("layer_class", CLASSES)
@pytest.mark.parametrize(
    "protnone, add_data, expected_state",
    [
        pytest.param(False, True, "readable", id="present-backed"),
        pytest.param(True, True, "readable", id="protnone-backed"),
        pytest.param(False, False, "capture-hole", id="present-missing"),
        pytest.param(True, False, "capture-hole", id="protnone-missing"),
    ],
)
def test_readability_state(layer_class, protnone, add_data, expected_state):
    """Report readability and the address basis for each leaf state."""
    layer, _, expected, stored, _ = build_layer(
        layer_class, protnone=protnone, add_data=add_data
    )
    vaddr = DEFAULT_VADDR[layer_class]
    assert leaf_state(layer, vaddr) == expected_state
    if add_data:
        assert layer.translate(vaddr)[0] == expected
        assert layer.read(vaddr, len(KNOWN)) == KNOWN
    else:
        # The page table still resolves to the declared physical address, but
        # the capture does not hold the page.  This is not a PROT_NONE state.
        assert layer._translate(vaddr)[0] == expected
        assert not layer.is_valid(vaddr)
        with pytest.raises(exceptions.InvalidAddressException) as info:
            layer.read(vaddr, len(KNOWN))
        assert not isinstance(info.value, exceptions.PagedInvalidAddressException)
        assert stored & PRESENT or protnone


@pytest.mark.parametrize("layer_class", CLASSES)
def test_missing_physical_page_is_not_protnone(layer_class):
    """An absent capture page is a capture hole, not a process protection request."""
    layer, _, expected, stored, canonical = build_layer(
        layer_class, protnone=False, add_data=False
    )
    vaddr = DEFAULT_VADDR[layer_class]
    assert stored == canonical
    assert stored & PRESENT  # the process asked for a normal present page
    assert not stored & PROTNONE
    assert layer._translate(vaddr)[0] == expected
    assert leaf_state(layer, vaddr) == "capture-hole"
    with pytest.raises(exceptions.InvalidAddressException):
        layer.read(vaddr, len(KNOWN))


@pytest.mark.parametrize("layer_class", CLASSES)
def test_unmapped_pte_is_a_page_fault(layer_class):
    """A non-present, non-PROTNONE entry is a genuine page fault."""
    layer, sparse, _, _, _ = build_layer(layer_class, add_data=False)
    vaddr = DEFAULT_VADDR[layer_class]
    leaf = len(layer_class._structure) - 1
    indices = virtual_indices(vaddr, layer_class._structure)
    tables = [DTB + level * PAGE_SIZE for level in range(len(layer_class._structure))]
    sparse.entry(tables[leaf], indices[leaf], 0, entry_width(layer_class))
    assert leaf_state(layer, vaddr) == "not-mapped"
    with pytest.raises(exceptions.PagedInvalidAddressException):
        layer.translate(vaddr)
    with pytest.raises(exceptions.PagedInvalidAddressException):
        layer.read(vaddr, len(KNOWN))
