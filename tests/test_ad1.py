from __future__ import annotations

import hashlib
import struct
import zlib
from datetime import datetime, timezone
from io import BytesIO
from typing import TYPE_CHECKING, BinaryIO

import pytest

from dissect.evidence.ad1 import ad1
from dissect.evidence.ad1.ad1 import EntryType, find_files
from dissect.evidence.ad1.c_ad1 import c_ad1
from tests._utils import absolute_path

if TYPE_CHECKING:
    from pathlib import Path


def test_ad1(ad1_basic: BinaryIO) -> None:
    """Test if we can parse a basic non-segmented AD1 file with no file hierarchy."""
    fs = ad1.AD1(ad1_basic)
    assert fs.segment(0).header.magic == b"ADSEGMENTEDFILE\x00"

    assert fs.root.is_dir()
    assert fs.root.listdir() == ["E:"]

    file = fs.get("E:/AD1_test/doc1.txt")
    assert file.is_file()
    assert file.size == 17
    assert file.atime == datetime(2017, 3, 31, 18, 2, 31, 189682, tzinfo=timezone.utc)
    assert file.open().read() == b"Inhoud document 1"


def test_ad1_long(ad1_long: BinaryIO) -> None:
    """Test if we can parse a basic non-segmented AD1 file with long file names."""
    fs = ad1.AD1(ad1_long)

    assert fs.segment(0).header.magic == b"ADSEGMENTEDFILE\x00"
    assert fs.root.is_dir()

    assert [file.name for file in fs.root.children] == ["E:"]

    assert [file.name for file in fs.get("E:").children] == [
        "testdatamap 2 met spaties en een heel stuk langer",
    ]

    assert [file.name for file in fs.get("E:/testdatamap 2 met spaties en een heel stuk langer").iterdir()] == [
        "een lange filenaam 1 met spaties.txt",
        "Een nog langere bestandsnaam met nog meer tekens en 12345.txt",
    ]

    entry = fs.get("E:/testdatamap 2 met spaties en een heel stuk langer").children[0]
    assert entry.name == "een lange filenaam 1 met spaties.txt"
    assert entry.open().read() == (
        b"masdhdslkfjasdfjlksadjflkjsda;lfj\r\nasdflk\r\na;lsdkf\r\n"
        b";lasdklf;lkasd\r\n;lk\r\nfask;ldkf\r\n;lka\r\nsd;lkf\r\n"
        b"asdfasdaflkjsd;lkg;dfshglkdksfhg;ljsdflgjs;dlkkjg'qwjer'pgtoks\r\n"
        b"ddasd'dgkls'dfkjg\r\nsd'g;lkksd'f';gkjsd\r\n[fkgli'erjrg';ksd\r\n"
        b"'g'asldjg';askg\r\nkqe\r\n-["
    )
    md5sum = hashlib.md5(entry.open().read())
    assert md5sum.hexdigest() == entry.md5


def test_ad1_compressed(ad1_compressed: BinaryIO) -> None:
    """Test if we can parse a non-segmented AD1 file with standard zlib compression."""
    fs = ad1.AD1(ad1_compressed)

    assert fs.segment(0).header.magic == b"ADSEGMENTEDFILE\x00"

    assert fs.get("/").listdir() == ["E:"]
    assert fs.get("E:/AD1_test").listdir() == ["doc1.txt", "doc2.txt"]
    assert fs.get("E:/AD1_test/doc1.txt").open().read() == b"Inhoud document 1"


@pytest.mark.parametrize(
    ("path", "expected_files"),
    [
        pytest.param(
            "_data/ad1/pcbje/text-and-pictures.ad1",
            [
                "text-and-pictures.ad1",
                "text-and-pictures.ad2",
                "text-and-pictures.ad3",
                "text-and-pictures.ad4",
            ],
            id="segmented-simple",
        ),
        pytest.param(
            "_data/ad1/encrypted-passphrase/encrypted.ad1",
            [
                "encrypted.ad1",
                "encrypted.ad2",
                "encrypted.ad3",
                "encrypted.ad4",
                "encrypted.ad5",
                "encrypted.ad6",
                "encrypted.ad7",
                "encrypted.ad8",
                "encrypted.ad9",
                "encrypted.ad10",
                "encrypted.ad11",
                "encrypted.ad12",
                "encrypted.ad13",
            ],
            id="segmented-natural-sorting",
        ),
    ],
)
def test_ad1_find_files(path: str, expected_files: list[str]) -> None:
    """Test if we correctly find and order segmented AD1 files and do not find .txt or .csv artifact files."""
    files = find_files(absolute_path(path))
    assert [file.name for file in files] == expected_files


def test_ad1_segmented(ad1_segmented: list[Path]) -> None:
    """Test if we can parse segmented AD1 files.

    References:
        - https://github.com/pcbje/pyad1/tree/master/test_data
    """
    fs = ad1.AD1(ad1_segmented)

    assert len(fs.fh) == 4
    assert fs.segment(0).number == 1
    assert fs.segment(0).count == 4
    assert fs.segment(0).size == 0x200000 - 512

    assert fs.logical_image.version == 4
    assert fs.logical_image.name == "C:\\Users\\pcbje\\Desktop\\Data"

    dir = fs.get("C:/Users/pcbje/Desktop/Data/Pictures")
    assert dir.is_dir()
    assert not dir.is_symlink()
    assert not dir.is_file()
    assert dir.name == "Pictures"
    assert dir.type == EntryType.Directory
    assert dir.size == 0
    assert dir.btime == datetime(2018, 5, 2, 7, 34, 11, 284926, tzinfo=timezone.utc)
    assert dir.mtime == datetime(2018, 5, 2, 7, 42, 39, 841574, tzinfo=timezone.utc)
    assert dir.ctime == datetime(2018, 5, 2, 7, 42, 39, 841574, tzinfo=timezone.utc)
    assert dir.atime == datetime(2018, 5, 2, 7, 46, 59, 164650, tzinfo=timezone.utc)
    assert dir.listdir() == [
        "0-0-581-Hydrangeas.jpg",
        "1-0-858-Chrysanthemum.jpg",
        "2-0-826-Desert.jpg",
        "4-0-757-Jellyfish.jpg",
        "5-0-762-Koala.jpg",
        "6-0-548-Lighthouse.jpg",
        "7-0-759-Penguins.jpg",
    ]

    picture = fs.get("C:/Users/pcbje/Desktop/Data/Pictures/5-0-762-Koala.jpg")
    assert picture.is_file()
    assert not picture.is_dir()
    assert not picture.is_symlink()
    assert picture.btime == datetime(2018, 1, 28, 7, 18, 0, tzinfo=timezone.utc)
    assert picture.mtime == datetime(2018, 5, 2, 7, 42, 34, 287014, tzinfo=timezone.utc)
    assert picture.ctime == datetime(2018, 5, 2, 7, 42, 34, 287014, tzinfo=timezone.utc)
    assert picture.atime == datetime(2018, 5, 2, 7, 42, 35, 611785, tzinfo=timezone.utc)

    buf = picture.open().read()
    assert picture.name == "5-0-762-Koala.jpg"
    assert picture.size == 780831
    assert len(buf) == 780831
    assert picture.sha1 == "9c3dcb1f9185a314ea25d51aed3b5881b32f420c"
    assert hashlib.sha1(buf).hexdigest() == "9c3dcb1f9185a314ea25d51aed3b5881b32f420c"


def test_ad1_segmented_find_files(ad1_segmented: list[Path]) -> None:
    """Test that providing a single segment file finds all segments in the same directory."""
    fs = ad1.AD1(ad1_segmented[0])

    assert fs.fh == ad1_segmented


def test_ad1_close_with_fh(ad1_basic: BinaryIO) -> None:
    """Verify that AD1 does not close file-like objects passed to it."""
    fs = ad1.AD1(ad1_basic)
    assert len(fs._segments) == 1
    assert fs._segment_lru == [0]

    fs.close()
    assert fs._segments == {}
    assert fs._segment_lru == []

    # The file-like object passed to AD1 should not be closed by AD1
    assert not ad1_basic.closed


def test_ad1_close_with_paths(ad1_segmented: list[Path]) -> None:
    """Verify that AD1 closes file handles opened from paths."""
    fs = ad1.AD1(ad1_segmented)

    num_segments = len(fs._segments)
    assert num_segments > 0

    # Store references to all file handles
    fhs = [fs._segments[idx].fh for idx in range(num_segments)]

    fs.close()

    # Verify all file handles are closed
    for fh in fhs:
        assert fh.closed
    assert fs._segments == {}
    assert fs._segment_lru == []


def test_ad1_context_manager_with_fh(ad1_basic: BinaryIO) -> None:
    """Verify context manager closes AD1 but not the file-like object passed to it."""
    with ad1.AD1(ad1_basic) as fs:
        assert isinstance(fs, ad1.AD1)

    assert fs._segments == {}
    assert fs._segment_lru == []

    # The file-like object should not be closed by AD1's context manager
    assert not ad1_basic.closed


def test_adcrypt_passphrase(ad1_encrypted_passphrase: list[Path]) -> None:
    """Test if we can decrypt ADCRYPT AD1 images, in this example a segmented AD1 logical image."""
    fs = ad1.AD1(ad1_encrypted_passphrase)

    assert fs.is_adcrypt()
    assert fs.is_locked()

    with pytest.raises(ValueError, match="AD1 container is locked by ADCRYPT"):
        fs.get("/")

    with pytest.raises(ValueError, match="Unable to unlock: HMAC verification of passphrase failed"):
        fs.unlock(passphrase="asdf")

    fs.unlock(passphrase="password")

    assert fs.adcrypt.key.hex() == "9030a43f29689a045e815cf4f0ad82b68850063b414f2797f0897e188f98d7b4"

    assert fs.get("C:/Users/User/Downloads").listdir() == [
        "7z2501-x64.exe",
        "desktop.ini",
        "Exterro_FTK_Imager_(x64)-4.7.3.81.exe",
        "hans-veth-8y--BAFlC9c-unsplash.jpg",
        "marc-olivier-jodoin-tauPAnOIGvE-unsplash.jpg",
        "marek-szturc-8Ou3EZmTMWA-unsplash.jpg",
        "milo-weiler-1AIYdIb3O5M-unsplash.jpg",
    ]

    for file in fs.get("C:/Users/User/Downloads").iterdir():
        buf = file.open().read()
        assert len(buf) == file.size
        assert hashlib.sha1(buf).hexdigest() == file.sha1


def test_adcrypt_certificate(ad1_encrypted_certificate: list[Path]) -> None:
    """Test if we can decrypt ADCRYPT AD1 images, in this example a segmented AD1 logical image."""
    fs = ad1.AD1(ad1_encrypted_certificate)

    assert fs.is_adcrypt()
    assert fs.is_locked()

    with pytest.raises(ValueError, match="AD1 container is locked by ADCRYPT"):
        fs.get("/")

    with pytest.raises(ValueError, match="Unable to unlock: HMAC verification of passphrase failed"):
        fs.unlock(passphrase="asdf")

    fs.unlock(private_key=absolute_path("_data/ad1/encrypted-certificate/key"))

    assert fs.adcrypt.key.hex() == "6cc0a9f94f944381cc51be474e5da6178059324bb457a87e0035b80f80ff9d4b"

    assert fs.get("C:/Users/User/Downloads").listdir() == [
        "desktop.ini",
        "hans-veth-8y--BAFlC9c-unsplash.jpg",
        "key.pem",
        "marc-olivier-jodoin-tauPAnOIGvE-unsplash.jpg",
        "marek-szturc-8Ou3EZmTMWA-unsplash.jpg",
        "milo-weiler-1AIYdIb3O5M-unsplash.jpg",
        "programs",
    ]

    for file in fs.get("C:/Users/User/Downloads").iterdir():
        if file.is_dir():
            continue

        buf = file.open().read()
        assert len(buf) == file.size
        assert hashlib.sha1(buf).hexdigest() == file.sha1

    assert fs.get("C:/Users/User/Downloads/programs").listdir() == [
        "7z2501-x64.exe",
        "Exterro_FTK_Imager_(x64)-4.7.3.81.exe",
    ]


def test_ad1_segment_lru(ad1_segmented: list[Path], monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ad1, "MAX_OPEN_SEGMENTS", 2)

    fs = ad1.AD1(ad1_segmented)
    assert fs._segment_lru == [3, 0]

    fs.segment(2)
    assert fs._segment_lru == [0, 2]

    fs.segment(1)
    assert fs._segment_lru == [2, 1]

    picture = fs.get("C:/Users/pcbje/Desktop/Data/Pictures/5-0-762-Koala.jpg")
    assert hashlib.sha1(picture.open().read()).hexdigest() == "9c3dcb1f9185a314ea25d51aed3b5881b32f420c"


# Synthetic AD1 builder for identity and duplicate path tests.

_EVIDENCE_ROOT = b"C:\\evidence"


def _file_entry_bytes(
    *,
    name: bytes,
    type: EntryType,
    next: int = 0,
    child: int = 0,
    meta: int = 0,
    zlib_meta: int = 0,
    parent_index: int = 0,
) -> bytes:
    entry = c_ad1.FileEntry(
        next=next,
        child=child,
        meta=meta,
        zlib_meta=zlib_meta,
        size=0,
        type=type,
        name_len=len(name),
        name=name,
        parent_index=parent_index,
    )
    return bytes(entry)


class _SyntheticNode:
    def __init__(
        self,
        name: bytes,
        type: EntryType,
        content: bytes = b"",
        parent_index: int = 0,
    ) -> None:
        self.name = name
        self.type = type
        self.content = content
        self.parent_index = parent_index
        self.children: list[_SyntheticNode] = []
        self.offset = 0

    @property
    def size(self) -> int:
        return 56 + len(self.name)


def build_duplicate_path_ad1() -> bytes:
    """Build a minimal AD1 image with duplicate and anomalous entries."""
    header_size = 92 + len(_EVIDENCE_ROOT)

    same_parent_a = _SyntheticNode(b"dup.txt", EntryType.File, b"alpha-content")
    same_parent_b = _SyntheticNode(b"dup.txt", EntryType.File, b"beta-content")
    case_variant = _SyntheticNode(b"Dup.txt", EntryType.File, b"gamma-content")
    other_dir = _SyntheticNode(b"other", EntryType.Directory)
    other_parent = _SyntheticNode(b"dup.txt", EntryType.File, b"delta-content")
    orphan = _SyntheticNode(b"orphan.bin", EntryType.File, b"orphan-content", parent_index=0xDEAD)
    other_dir.children = [other_parent]

    roots = [same_parent_a, same_parent_b, case_variant, other_dir, orphan]
    physical = [*roots, other_parent]

    offset = header_size
    for node in physical:
        node.offset = offset
        offset += node.size

    chunks: dict[int, tuple[int, int, bytes]] = {}
    metadata: dict[int, int] = {}
    for node in physical:
        if node.type != EntryType.File:
            continue

        chunk_table_offset = offset
        data_offset = chunk_table_offset + 16
        compressed = zlib.compress(node.content)
        meta_offset = data_offset + len(compressed)
        chunks[node.offset] = (chunk_table_offset, data_offset, compressed)
        metadata[node.offset] = meta_offset
        offset = meta_offset + 20 + len(str(len(node.content))) + 20 + 32 + 20 + 40

    def serialize_chain(nodes: list[_SyntheticNode]) -> dict[int, bytes]:
        result = {}
        for idx, node in enumerate(nodes):
            following = nodes[idx + 1].offset if idx + 1 < len(nodes) else 0
            child = node.children[0].offset if node.children else 0
            zlib_meta, meta = 0, 0
            if node.type == EntryType.File:
                zlib_meta = chunks[node.offset][0]
                meta = metadata[node.offset]
            result[node.offset] = _file_entry_bytes(
                name=node.name,
                type=node.type,
                next=following,
                child=child,
                meta=meta,
                zlib_meta=zlib_meta,
                parent_index=node.parent_index,
            )
        return result

    entries: dict[int, bytes] = {}
    entries.update(serialize_chain(roots))
    entries.update(serialize_chain(other_dir.children))

    buf = bytearray(offset)

    logical = bytes(
        c_ad1.LogicalImageHeader(
            magic=b"ADLOGICALIMAGE\x00\x00",
            version=4,
            unk1=1,
            chunk_size=65536,
            metadata_offset=0,
            first_file_offset=roots[0].offset,
            name_len=len(_EVIDENCE_ROOT),
            unk_magic=b"AD\x00\x00",
            name_offset=92,
            attr_guid_offset=0,
            unk2=0,
            locs_guid_offset=0,
            unk3=0,
            name=_EVIDENCE_ROOT,
        )
    )
    assert len(logical) == header_size
    buf[:header_size] = logical

    for entry_offset, data in entries.items():
        buf[entry_offset : entry_offset + len(data)] = data

    for node in physical:
        if node.type != EntryType.File:
            continue

        chunk_table_offset, data_offset, compressed = chunks[node.offset]
        chunk_table = bytes(c_ad1.FileEntryChunks(num_chunks=1, chunks=[data_offset]))
        assert len(chunk_table) == 16
        buf[chunk_table_offset : chunk_table_offset + 16] = chunk_table
        buf[data_offset : data_offset + len(compressed)] = compressed

        meta_offset = metadata[node.offset]
        items = [
            (c_ad1.MetaType.FileSize, str(len(node.content)).encode()),
            (c_ad1.MetaType.MD5, hashlib.md5(node.content).hexdigest().encode()),
            (c_ad1.MetaType.SHA1, hashlib.sha1(node.content).hexdigest().encode()),
        ]
        sizes = [20 + len(data) for _, data in items]
        for idx, (meta_type, data) in enumerate(items):
            following = meta_offset + sizes[idx] if idx + 1 < len(items) else 0
            item = bytes(c_ad1.FileMeta(next=following, category=0, type=meta_type, len=len(data), data=data))
            buf[meta_offset : meta_offset + len(item)] = item
            meta_offset += len(item)

    segment_header = bytes(
        c_ad1.SegmentedFileHeader(
            magic=b"ADSEGMENTEDFILE\x00",
            unk1=1,
            unk2=2,
            segment_number=1,
            segment_count=1,
            segment_size=512 + offset,
            logical_image_offset=512,
            padding=b"\x00" * 468,
        )
    )
    return segment_header + bytes(buf)


@pytest.fixture
def ad1_duplicate_paths(tmp_path: Path) -> ad1.AD1:
    path = tmp_path / "duplicates.ad1"
    path.write_bytes(build_duplicate_path_ad1())
    return ad1.AD1(path)


def test_ad1_duplicate_display_path_is_ambiguous(ad1_duplicate_paths: ad1.AD1) -> None:
    """Duplicate names under one parent stay distinct and path lookup reports both."""
    fs = ad1_duplicate_paths

    candidates = fs.entries_for_path("C:/evidence/dup.txt")
    assert len(candidates) == 2
    assert [entry.name for entry in candidates] == ["dup.txt", "dup.txt"]
    assert candidates[0].offset != candidates[1].offset
    assert all(entry.parent is fs.get("C:/evidence") for entry in candidates)

    with pytest.raises(ad1.AmbiguousEntryError) as exc_info:
        fs.get("C:/evidence/dup.txt")

    error = exc_info.value
    assert error.path == "C:/evidence/dup.txt"
    assert [entry.offset for entry in error.candidates] == [entry.offset for entry in candidates]


def test_ad1_duplicate_entries_open_independently(ad1_duplicate_paths: ad1.AD1) -> None:
    """Each duplicate entry has its own content and hash metadata."""
    fs = ad1_duplicate_paths
    first, second = fs.entries_for_path("C:/evidence/dup.txt")

    first_content = first.open().read()
    second_content = second.open().read()

    assert first_content == b"alpha-content"
    assert second_content == b"beta-content"
    assert first_content != second_content
    assert first.md5 == hashlib.md5(first_content).hexdigest()
    assert second.md5 == hashlib.md5(second_content).hexdigest()
    assert first.sha1 == hashlib.sha1(first_content).hexdigest()
    assert second.sha1 == hashlib.sha1(second_content).hexdigest()

    # Opening through the identity returns the same entry regardless of path.
    assert fs.entry_by_offset(first.offset) is first
    assert fs.open_by_offset(first.offset).read() == first_content
    assert fs.open_by_offset(second.offset).read() == second_content


def test_ad1_case_and_parent_distinguish_entries(ad1_duplicate_paths: ad1.AD1) -> None:
    """Case variants and same names under different parents are separate cases."""
    fs = ad1_duplicate_paths

    assert fs.get("C:/evidence/Dup.txt").open().read() == b"gamma-content"
    assert fs.get("C:/evidence/other/dup.txt").open().read() == b"delta-content"

    # The differently cased entry is not part of the same-parent ambiguity.
    assert len(fs.entries_for_path("C:/evidence/Dup.txt")) == 1
    assert len(fs.entries_for_path("C:/evidence/other/dup.txt")) == 1

    identities = {entry.offset for entry in fs.iter_entries(include_virtual=False)}
    assert {leaf.offset for leaf in fs.entries_for_path("C:/evidence/dup.txt")} <= identities
    assert fs.entry_by_offset(fs.get("C:/evidence/Dup.txt").offset).name == "Dup.txt"


def test_ad1_anomalous_parent_keeps_own_identity(ad1_duplicate_paths: ad1.AD1) -> None:
    """A damaged parent relation does not borrow a same-named entry elsewhere."""
    fs = ad1_duplicate_paths
    orphan = fs.get("C:/evidence/orphan.bin")

    assert orphan.declared_parent_offset == 0xDEAD
    assert orphan.parent is fs.get("C:/evidence")
    assert fs.entry_by_offset(orphan.offset) is orphan
    assert orphan.open().read() == b"orphan-content"
    assert orphan.md5 == hashlib.md5(b"orphan-content").hexdigest()

    anomalies = [anomaly for anomaly in fs.anomalies if anomaly.offset == orphan.offset]
    assert [anomaly.kind for anomaly in anomalies] == [ad1.ANOMALY_DECLARED_PARENT_MISSING]
    assert anomalies[0].declared_parent == 0xDEAD

    # No other entry may claim the orphan's identity or its declared parent.
    assert all(entry.offset != orphan.offset for entry in fs.entries_for_path("C:/evidence/dup.txt"))
    assert all(entry.offset != 0xDEAD for entry in fs.iter_entries())


def test_ad1_entry_identity_enumeration(ad1_duplicate_paths: ad1.AD1) -> None:
    """Enumeration is identity based and exposes parent/child and hash metadata."""
    fs = ad1_duplicate_paths

    physical = list(fs.iter_entries(include_virtual=False))
    assert [entry.offset for entry in physical] == [103, 166, 229, 292, 419, 353]
    assert [entry.offset for entry in fs.entries] == [entry.offset for entry in fs.iter_entries()]

    # Identity keyed enumeration must not collapse entries that share a path.
    assert len({entry.offset for entry in physical}) == len(physical)
    paths = [entry.path for entry in physical]
    assert paths.count("C:/evidence/dup.txt") == 2

    for entry in physical:
        assert entry.entry_id == entry.offset
        if entry.is_file():
            assert entry.size == len(entry.open().read())
        assert fs.get_by_offset(entry.offset) is entry

    with pytest.raises(ad1.FileNotFoundError):
        fs.entry_by_offset(0xFFFF)


def test_ad1_duplicate_path_open_shortcut_rejects_ambiguity(ad1_duplicate_paths: ad1.AD1) -> None:
    """The convenience open path surfaces ambiguity instead of returning bytes."""
    fs = ad1_duplicate_paths

    with pytest.raises(ad1.AmbiguousEntryError) as exc_info:
        fs.open("C:/evidence/dup.txt")

    assert {entry.offset for entry in exc_info.value.candidates} == {
        entry.offset for entry in fs.entries_for_path("C:/evidence/dup.txt")
    }

    # Explicit identity opening remains available for each candidate.
    for entry in exc_info.value.candidates:
        assert fs.open_by_offset(entry.offset).read() == entry.open().read()
        assert fs.open(entry.offset).read() == entry.open().read()
        assert fs.get(entry.offset) is entry


def test_ad1_shared_child_is_reported(ad1_duplicate_paths: ad1.AD1) -> None:
    """A child linked from two parents is reported, not silently re-parented."""
    data = bytearray(build_duplicate_path_ad1())

    # Make the 'other' directory point at the first same-parent duplicate,
    # which is already owned by the synthetic evidence root.
    shared_offset = 166
    struct.pack_into("<Q", data, 512 + 292 + 8, shared_offset)

    fs_shared = ad1.AD1(BytesIO(bytes(data)))
    anomalies = [entry for entry in fs_shared.anomalies if entry.kind == ad1.ANOMALY_SHARED_CHILD]
    # Both the linked entry and its following sibling are already owned by
    # another parent; each is reported by identity, and neither is re-parented.
    assert [anomaly.offset for anomaly in anomalies] == [shared_offset, 229]
    assert all(anomaly.parent == 292 for anomaly in anomalies)

    # The first observed containment wins; the entry keeps one parent and is
    # not indexed twice under different identities.
    shared = fs_shared.entry_by_offset(shared_offset)
    assert shared.parent is fs_shared.get("C:/evidence")
    assert sum(1 for entry in fs_shared.entries if entry.offset == shared_offset) == 1
    assert shared.open().read() == b"beta-content"


def test_ad1_cycle_does_not_hang_or_overwrite(ad1_duplicate_paths: ad1.AD1) -> None:
    """A cyclic sibling chain is bounded and does not overwrite another entry."""
    data = bytearray(build_duplicate_path_ad1())
    struct.pack_into("<Q", data, 512 + 103, 103)

    fs_cycle = ad1.AD1(BytesIO(bytes(data)))
    assert [entry for entry in fs_cycle.anomalies if entry.kind == ad1.ANOMALY_CYCLE]
    assert len(fs_cycle.entries) < len(ad1_duplicate_paths.entries)


def test_ad1_multi_image_alias_keeps_single_identity(ad1_encrypted_passphrase: list[Path]) -> None:
    """A multi-image logical root is one browse entry with two lookup identities."""
    fs = ad1.AD1(ad1_encrypted_passphrase)
    fs.unlock(passphrase="password")

    downloads = fs.get("C:/Users/User/Downloads")
    physical_offset = fs.logical_image.header.first_file_offset

    assert fs.anomalies == []
    assert fs.get_by_offset(physical_offset) is downloads
    assert fs.entry_by_offset(downloads.offset) is downloads
    assert fs.get_by_offset(physical_offset).parent is fs.get("C:/Users/User")

    # The children's declared parent points at the physical directory offset
    # and must resolve to the same browse entry, not create a new one.
    child = fs.get("C:/Users/User/Downloads/desktop.ini")
    assert child.declared_parent_offset == physical_offset
    assert child.declared_parent is downloads
    assert all(fs._entry_index[entry.offset] is entry for entry in downloads.children)


def test_ad1_identity_api_requires_unlocked_container(ad1_encrypted_passphrase: list[Path]) -> None:
    """Identity enumeration and lookup keep the ADCRYPT lock contract."""
    fs = ad1.AD1(ad1_encrypted_passphrase)

    with pytest.raises(ValueError, match="AD1 container is locked by ADCRYPT"):
        fs.entry_by_offset(0)

    with pytest.raises(ValueError, match="AD1 container is locked by ADCRYPT"):
        fs.entries_for_path("/")

    assert fs.entries == []
    assert fs.anomalies == []

    fs.unlock(passphrase="password")
    assert len(fs.entries) > 0
