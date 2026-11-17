from __future__ import annotations

import unicodedata
from typing import TYPE_CHECKING

import pytest

from dissect.apfs.c_apfs import c_apfs
from dissect.apfs.exception import FileNotFoundError
from dissect.apfs.objects.fs import INode, _hash_filename, _normalize_filename
from dissect.apfs.util import cmp_fs_dir, cmp_fs_dir_hash

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator

    from dissect.apfs.cursor import Cursor

DIR_OID = 2

# Distinct, mutually non-equivalent names whose 22-bit APFS directory hash lands in the same bucket. The
# pair is used for two-entry bucket checks; the triple forms a three-entry bucket where a binary search
# lands on the middle entry, forcing the lookup to walk backwards to the bucket start. All collisions are
# verified against the production hash for both case sensitive and case insensitive volumes.
COLLISION_FIRST = "n17818"
COLLISION_SECOND = "n30606"
COLLISION_TRIPLE = ("z46728", "z61936", "z80404")

# Layouts: (is_case_insensitive, is_normalization_insensitive). Hashed directory keys are used whenever
# either insensitivity flag is set, matching the volume logic in ``INode.get``.
LAYOUTS = [
    pytest.param(False, False, id="case-sensitive-beta"),
    pytest.param(False, True, id="case-sensitive-normalization-insensitive"),
    pytest.param(True, False, id="case-insensitive"),
]


def _bucket_hash(name: str, case_insensitive: bool) -> int:
    """The 22-bit directory hash bucket of a name."""
    return (_hash_filename(name, case_insensitive) << c_apfs.J_DREC_HASH_SHIFT) & c_apfs.J_DREC_HASH_MASK


def _drec_key(name: str, name_hash: int, hashed: bool) -> bytes:
    encoded = name.encode() + b"\x00"
    obj_id_and_type = DIR_OID | (c_apfs.APFS_TYPE.DIR_REC.value << c_apfs.OBJ_TYPE_SHIFT)
    if hashed:
        name_len_and_hash = name_hash | len(encoded)
        return c_apfs.j_drec_hashed_key(
            hdr=c_apfs.j_key(obj_id_and_type=obj_id_and_type),
            name_len_and_hash=name_len_and_hash,
            name=encoded,
        ).dumps()

    return c_apfs.j_drec_key(
        hdr=c_apfs.j_key(obj_id_and_type=obj_id_and_type),
        name_len=len(encoded),
        name=encoded,
    ).dumps()


def _drec_val(file_id: int) -> bytes:
    return c_apfs.j_drec_val(file_id=file_id, date_added=0, flags=c_apfs.DT.REG).dumps()


class FakeCursor:
    """Minimal cursor mimicking ``dissect.apfs.cursor.Cursor`` over an in-memory ordered key list."""

    def __init__(self, records: list[tuple[bytes, bytes]], cmp_func: Callable[[object, bytes], int]):
        self._entries = records
        self._cmp_func = cmp_func
        self._idx = -1

    def search(self, key: object, exact: bool = False, cmp: Callable[[object, bytes], int] | None = None) -> FakeCursor:
        cmp_func = cmp or self._cmp_func
        lo, hi = 0, len(self._entries) - 1
        res = 1
        mid = 0
        while lo <= hi:
            mid = (lo + hi) // 2
            res = cmp_func(key, self._entries[mid][0])
            if res == 0:
                break
            if res < 0:
                lo = mid + 1
            else:
                hi = mid - 1

        if exact:
            if res != 0:
                raise KeyError(f"Key not found: {key!r}")
        elif res > 0:
            mid -= 1

        self._idx = mid
        return self

    def key(self) -> bytes:
        return self._entries[self._idx][0]

    def value(self) -> bytes:
        return self._entries[self._idx][1]

    def next(self) -> bool:
        if self._idx + 1 >= len(self._entries):
            return False
        self._idx += 1
        return True

    def prev(self) -> bool:
        if self._idx <= 0:
            return False
        self._idx -= 1
        return True


class FakeVolume:
    """In-memory volume exposing only the surface ``INode.get`` relies on."""

    def __init__(self, case_insensitive: bool, normalization_insensitive: bool, entries: list[tuple[str, int]]):
        self.is_case_insensitive = case_insensitive
        self.is_normalization_insensitive = normalization_insensitive
        hashed = case_insensitive or normalization_insensitive

        records = []
        for name, file_id in entries:
            name_hash = _bucket_hash(name, case_insensitive) if hashed else 0
            records.append((_drec_key(name, name_hash, hashed), _drec_val(file_id)))

        self._entries = sorted(records, key=lambda record: record[0])

    def cursor(self) -> Cursor:
        cmp = cmp_fs_dir_hash if self.is_case_insensitive or self.is_normalization_insensitive else cmp_fs_dir
        return FakeCursor(self._entries, cmp)

    def _records(self, oid: int, type_: c_apfs.APFS_TYPE) -> Iterator[tuple[c_apfs.APFS_TYPE, bytes, bytes]]:
        del oid, type_
        for key, value in self._entries:
            yield c_apfs.APFS_TYPE.DIR_REC, key, value


def _make_directory(
    entries: list[tuple[str, int]],
    case_insensitive: bool,
    normalization_insensitive: bool,
) -> INode:
    volume = FakeVolume(case_insensitive, normalization_insensitive, entries)
    directory = INode(volume, DIR_OID)
    # The in-memory volume only models directory records, so treat every constructed inode as a directory
    directory.is_dir = lambda: True
    return directory


def test_collision_fixture_is_valid():
    for case_insensitive in (False, True):
        assert _bucket_hash(COLLISION_FIRST, case_insensitive) == _bucket_hash(COLLISION_SECOND, case_insensitive)
        assert _normalize_filename(COLLISION_FIRST, case_insensitive) != _normalize_filename(
            COLLISION_SECOND, case_insensitive
        )

        triple_buckets = {_bucket_hash(name, case_insensitive) for name in COLLISION_TRIPLE}
        assert len(triple_buckets) == 1
        assert len({_normalize_filename(name, case_insensitive) for name in COLLISION_TRIPLE}) == 3


@pytest.mark.parametrize("case_insensitive,normalization_insensitive", LAYOUTS)
def test_composed_and_decomposed_names(case_insensitive, normalization_insensitive):
    hashed = case_insensitive or normalization_insensitive
    nfc_name = "café"
    nfd_name = unicodedata.normalize("NFD", nfc_name)
    assert nfc_name != nfd_name

    directory = _make_directory([(nfc_name, 100)], case_insensitive, normalization_insensitive)

    if hashed:
        # Hash placement and final comparison follow the same NFD rules, so either form resolves to the
        # same inode while the stored name is preserved verbatim
        assert directory.get(nfc_name).file_id == 100
        assert directory.get(nfd_name).file_id == 100
        assert directory.get(nfc_name).name == nfc_name
        assert directory.get(nfd_name).name == nfc_name
    else:
        # Beta case sensitive volumes are purely byte exact: no normalization equivalence
        assert directory.get(nfc_name).file_id == 100
        with pytest.raises(FileNotFoundError):
            directory.get(nfd_name)


@pytest.mark.parametrize("case_insensitive,normalization_insensitive", LAYOUTS)
def test_decomposed_stored_name_lookup(case_insensitive, normalization_insensitive):
    hashed = case_insensitive or normalization_insensitive
    nfd_name = unicodedata.normalize("NFD", "café")
    nfc_name = unicodedata.normalize("NFC", nfd_name)

    directory = _make_directory([(nfd_name, 101)], case_insensitive, normalization_insensitive)

    if hashed:
        assert directory.get(nfd_name).name == nfd_name
        assert directory.get(nfc_name).file_id == 101
        assert directory.get(nfc_name).name == nfd_name
    else:
        assert directory.get(nfd_name).file_id == 101
        with pytest.raises(FileNotFoundError):
            directory.get(nfc_name)


@pytest.mark.parametrize("case_insensitive,normalization_insensitive", LAYOUTS)
def test_casefold_length_change(case_insensitive, normalization_insensitive):
    # "ß" casefolds to "ss", changing the folded length
    stored = "straße"
    directory = _make_directory([(stored, 102)], case_insensitive, normalization_insensitive)

    if case_insensitive:
        hit = directory.get("STRASSE")
        assert hit.file_id == 102
        assert hit.name == stored
        assert directory.get("strasse").file_id == 102
    else:
        with pytest.raises(FileNotFoundError):
            directory.get("STRASSE")
        assert directory.get(stored).file_id == 102


@pytest.mark.parametrize("case_insensitive,normalization_insensitive", LAYOUTS)
def test_hash_collision_rejects_other_inode(case_insensitive, normalization_insensitive):
    hashed = case_insensitive or normalization_insensitive
    if not hashed:
        pytest.skip("Unhashed beta volumes have no hash buckets")

    # The only entry in the bucket is a non-equivalent name that merely shares the target's hash. The
    # two-stage lookup must not accept the other inode's name.
    directory = _make_directory([(COLLISION_SECOND, 200)], case_insensitive, normalization_insensitive)
    with pytest.raises(FileNotFoundError):
        directory.get(COLLISION_FIRST)
    assert directory.get(COLLISION_SECOND).file_id == 200


@pytest.mark.parametrize("case_insensitive,normalization_insensitive", LAYOUTS)
def test_hash_collision_bucket_walk(case_insensitive, normalization_insensitive):
    hashed = case_insensitive or normalization_insensitive
    if not hashed:
        pytest.skip("Unhashed beta volumes have no hash buckets")

    # Both names share a bucket. The equivalent target is stored first; a query landing on the second
    # entry via binary search must walk backwards and still resolve to the correct inode.
    entries = [(COLLISION_FIRST, 100), (COLLISION_SECOND, 200)]
    directory = _make_directory(entries, case_insensitive, normalization_insensitive)

    hit = directory.get(COLLISION_FIRST)
    assert hit.file_id == 100
    assert hit.name == COLLISION_FIRST

    hit = directory.get(COLLISION_SECOND)
    assert hit.file_id == 200
    assert hit.name == COLLISION_SECOND


@pytest.mark.parametrize("case_insensitive,normalization_insensitive", LAYOUTS)
def test_bucket_walk_backwards_from_mid_bucket_landing(case_insensitive, normalization_insensitive):
    hashed = case_insensitive or normalization_insensitive
    if not hashed:
        pytest.skip("Unhashed beta volumes have no hash buckets")

    # Three distinct, mutually non-equivalent names share one bucket. A binary search over a three-entry
    # bucket lands on its middle entry, so resolving the first entry requires walking backwards to the
    # bucket start before scanning it.
    entries = [(name, 300 + index) for index, name in enumerate(COLLISION_TRIPLE)]
    directory = _make_directory(entries, case_insensitive, normalization_insensitive)

    for index, name in enumerate(COLLISION_TRIPLE):
        hit = directory.get(name)
        assert hit.file_id == 300 + index
        assert hit.name == name

    # A name that shares no bucket with any entry still misses, even though buckets are walked fully
    with pytest.raises(FileNotFoundError):
        directory.get("absent")


@pytest.mark.parametrize("case_insensitive,normalization_insensitive", LAYOUTS)
def test_bucket_boundary_stops_backwards_walk(case_insensitive, normalization_insensitive):
    hashed = case_insensitive or normalization_insensitive
    if not hashed:
        pytest.skip("Unhashed beta volumes have no hash buckets")

    # A genuinely lower-hash name precedes the collision bucket. The backwards walk must stop at the bucket
    # boundary instead of treating the preceding bucket's entry as a collision candidate.
    preceding = "low0"
    triple_bucket = _bucket_hash(COLLISION_TRIPLE[0], case_insensitive)
    assert _bucket_hash(preceding, case_insensitive) < triple_bucket

    entries = [(preceding, 90), *[(name, 300 + index) for index, name in enumerate(COLLISION_TRIPLE)]]
    directory = _make_directory(entries, case_insensitive, normalization_insensitive)

    assert directory.get(preceding).file_id == 90
    for index, name in enumerate(COLLISION_TRIPLE):
        assert directory.get(name).file_id == 300 + index


@pytest.mark.parametrize("case_insensitive,normalization_insensitive", LAYOUTS)
def test_equivalent_and_collision_in_same_bucket(case_insensitive, normalization_insensitive):
    hashed = case_insensitive or normalization_insensitive
    if not hashed:
        pytest.skip("Unhashed beta volumes have no hash buckets")

    nfc_name = COLLISION_FIRST
    # A casefold equivalent (only relevant on case insensitive layouts) shares the bucket without being
    # byte identical, while the colliding name points at a different inode.
    folded_equivalent = nfc_name.upper()

    entries = [(nfc_name, 100), (COLLISION_SECOND, 200)]
    directory = _make_directory(entries, case_insensitive, normalization_insensitive)

    if case_insensitive:
        # Upper-case query must match the lower-case inode, never the colliding neighbour
        hit = directory.get(folded_equivalent)
        assert hit.file_id == 100
        assert hit.name == nfc_name
    else:
        # On case sensitive volumes the upper-case form is a genuinely different, absent name
        with pytest.raises(FileNotFoundError):
            directory.get(folded_equivalent)

    # The colliding neighbour remains independently reachable and never shadows the equivalent entry
    assert directory.get(COLLISION_SECOND).file_id == 200


@pytest.mark.parametrize("case_insensitive,normalization_insensitive", LAYOUTS)
def test_iterdir_preserves_stored_names(case_insensitive, normalization_insensitive):
    nfc_name = "café"
    nfd_name = unicodedata.normalize("NFD", nfc_name)
    entries = [(nfc_name, 100), (nfd_name, 101), ("plain", 102)]

    directory = _make_directory(entries, case_insensitive, normalization_insensitive)
    names = {entry.name: entry.file_id for entry in directory.iterdir()}

    # Enumeration never rewrites on-disk names: both normalization forms are retained
    assert names[nfc_name] == 100
    assert names[nfd_name] == 101
    assert names["plain"] == 102


@pytest.mark.parametrize("case_insensitive,normalization_insensitive", LAYOUTS)
def test_missing_name_raises(case_insensitive, normalization_insensitive):
    directory = _make_directory([("a", 1), ("b", 2)], case_insensitive, normalization_insensitive)
    with pytest.raises(FileNotFoundError):
        directory.get("missing")
