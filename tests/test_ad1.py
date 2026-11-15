from __future__ import annotations

import hashlib
import struct
import zlib
from datetime import datetime, timezone
from io import BytesIO
from itertools import pairwise
from typing import TYPE_CHECKING, BinaryIO

import pytest

from dissect.evidence.ad1 import ad1
from dissect.evidence.ad1.ad1 import EntryOrigin, EntryType, MetaType, find_files
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


EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


def ad1_file(name: str, data: bytes = b"", meta: list[tuple[int, MetaType, bytes]] | None = None) -> dict:
    """Return a file entry specification for :func:`build_ad1`."""
    meta = [(3, MetaType.FileSize, str(len(data)).encode()), *(meta or [])]
    return {"name": name, "type": EntryType.File, "data": data, "meta": meta}


def ad1_dir(
    name: str, children: list[dict] | None = None, meta: list[tuple[int, MetaType, bytes]] | None = None
) -> dict:
    """Return a directory entry specification for :func:`build_ad1`."""
    return {"name": name, "type": EntryType.Directory, "children": children or [], "meta": meta or []}


def build_ad1(image_name: str, entries: list[dict]) -> BytesIO:
    """Build a minimal in-memory AD1v4 image with the given top-level entries."""
    name = image_name.encode()
    stream = bytearray(b"\x00" * (92 + len(name)))  # Logical image header, filled in later

    def emit_meta_chain(specs: list[tuple[int, MetaType, bytes]]) -> int:
        offsets = []
        for category, meta_type, data in specs:
            offsets.append(len(stream))
            stream.extend(struct.pack("<QIII", 0, category, int(meta_type), len(data)))
            stream.extend(data)
        for current, following in pairwise(offsets):
            struct.pack_into("<Q", stream, current, following)
        return offsets[0] if offsets else 0

    def emit_entry(spec: dict) -> int:
        child_offsets = [emit_entry(child) for child in spec.get("children", [])]
        for current, following in pairwise(child_offsets):
            struct.pack_into("<Q", stream, current, following)
        child_offset = child_offsets[0] if child_offsets else 0

        data = spec.get("data", b"")
        zlib_meta = 0
        if data:
            chunk_offset = len(stream)
            stream.extend(zlib.compress(data))
            # The meta chain directly follows the compressed data and terminates the chunk list
            meta_offset = emit_meta_chain(spec.get("meta", []))
            zlib_meta = len(stream)
            stream.extend(struct.pack("<QQ", 1, chunk_offset))
        else:
            meta_offset = emit_meta_chain(spec.get("meta", []))

        entry_offset = len(stream)
        entry_name = spec["name"].encode()
        stream.extend(
            struct.pack(
                "<QQQQQII", 0, child_offset, meta_offset, zlib_meta, len(data), int(spec["type"]), len(entry_name)
            )
        )
        stream.extend(entry_name)
        stream.extend(struct.pack("<Q", 0))  # parent_index
        return entry_offset

    root_offsets = [emit_entry(spec) for spec in entries]
    for current, following in pairwise(root_offsets):
        struct.pack_into("<Q", stream, current, following)
    first_file_offset = root_offsets[0] if root_offsets else 0

    header = struct.pack(
        "<16sIIIQQI",
        b"ADLOGICALIMAGE\x00\x00",
        4,  # version
        1,  # unk1
        65536,  # chunk_size
        0,  # metadata_offset
        first_file_offset,
        len(name),
    )
    header += struct.pack("<4sQQQQQ", b"AD\x00\x00", 92, 0, 0, 0, 0)
    header += name
    stream[0 : len(header)] = header

    segment = struct.pack(
        "<16sIIIIQI",
        b"ADSEGMENTEDFILE\x00",
        1,  # unk1
        2,  # unk2
        1,  # segment_number
        1,  # segment_count
        512 + len(stream),  # segment_size
        512,  # logical_image_offset
    )
    segment += b"\x00" * (512 - len(segment))
    return BytesIO(segment + bytes(stream))


def test_ad1_virtual_root_entries(ad1_basic: BinaryIO) -> None:
    """Test that synthesized root entries are marked as such and carry their provenance."""
    fs = ad1.AD1(ad1_basic)

    assert fs.root.is_virtual()
    assert fs.root.origin == EntryOrigin.SYNTHESIZED

    drive = fs.get("E:")
    assert drive.is_virtual()
    assert drive.origin == EntryOrigin.SYNTHESIZED
    assert drive.source == "E:\\AD1_test"
    assert drive.reason is not None
    assert drive.offset < 0

    folder = fs.get("E:/AD1_test")
    assert folder.is_virtual()
    assert folder.source == "E:\\AD1_test"
    assert folder.reason is not None

    # Synthesized entries have stable, independent identities and no inherited metadata
    assert folder.offset < 0
    assert len({fs.root.offset, drive.offset, folder.offset}) == 3
    assert folder.meta == {}
    assert folder.md5 is None
    assert folder.sha1 is None
    assert folder.atime == folder.ctime == folder.mtime == folder.btime == EPOCH

    file = fs.get("E:/AD1_test/doc1.txt")
    assert not file.is_virtual()
    assert file.origin == EntryOrigin.EVIDENCE
    assert file.offset > 0
    assert file.open().read() == b"Inhoud document 1"


def test_ad1_multi_source_virtual_entries() -> None:
    """Test provenance of synthesized roots in a multi-source image.

    The sample image contains two kinds of root sources (a drive letter and a UNC root)
    and a name conflict: the real "C:" root entry is also part of the source path of the
    second source.
    """
    fs = ad1.AD1(
        build_ad1(
            "Custom Content Image([Multi])",
            [
                ad1_dir(
                    "C:",
                    meta=[(5, MetaType.DateCreated, b"20200102T030405")],
                    children=[
                        ad1_dir("Windows", children=[ad1_file("system.ini", b"[boot]\r\nshell=explorer.exe")]),
                    ],
                ),
                ad1_dir(
                    "Public:C:\\Users\\Public",
                    meta=[
                        (5, MetaType.DateCreated, b"20210607T080910"),
                        (1, MetaType.MD5, b"0123456789abcdef0123456789abcdef"),
                        (0, MetaType.PosixPermissions, b"0755"),
                    ],
                    children=[ad1_file("report.txt", b"multi source report")],
                ),
                ad1_dir(
                    "exports:\\\\server\\share\\exports",
                    children=[ad1_file("data.bin", b"\x00\x01\x02\x03")],
                ),
            ],
        )
    )

    root = fs.get("/")
    assert root.is_virtual()

    # The real "C:" root is reused for the synthesized path, not duplicated
    assert root.listdir() == ["C:", "\\\\server\\share"]

    c = fs.get("C:")
    assert not c.is_virtual()
    assert c.origin == EntryOrigin.EVIDENCE
    assert c.offset >= 0
    assert c.btime == datetime(2020, 1, 2, 3, 4, 5, tzinfo=timezone.utc)
    assert c.listdir() == ["Windows", "Users"]

    # "Users" is synthesized to complete the second source path
    users = fs.get("C:/Users")
    assert users.is_virtual()
    assert users.origin == EntryOrigin.SYNTHESIZED
    assert users.source == "C:\\Users\\Public"
    assert users.reason is not None
    assert users.offset < 0
    assert users.meta == {}
    assert users.md5 is None
    assert users.sha1 is None
    assert users.atime == users.ctime == users.mtime == users.btime == EPOCH

    # The real entry keeps its own identity and metadata under its leaf name
    public = fs.get("C:/Users/Public")
    assert not public.is_virtual()
    assert public.origin == EntryOrigin.EVIDENCE
    assert public.offset >= 0
    assert public.source == "C:\\Users\\Public"
    assert public.btime == datetime(2021, 6, 7, 8, 9, 10, tzinfo=timezone.utc)
    assert public.md5 == "0123456789abcdef0123456789abcdef"
    assert MetaType.PosixPermissions in public.meta

    # The UNC root is synthesized as a single node
    share = fs.get("\\\\server\\share")
    assert share.is_virtual()
    assert share.source == "\\\\server\\share\\exports"
    assert share.offset < 0
    assert share.offset != users.offset

    exports = fs.get("\\\\server\\share/exports")
    assert not exports.is_virtual()
    assert exports.source == "\\\\server\\share\\exports"

    # Regular file content reads are unaffected
    assert fs.get("C:/Windows/system.ini").open().read() == b"[boot]\r\nshell=explorer.exe"
    assert fs.get("C:/Users/Public/report.txt").open().read() == b"multi source report"
    assert fs.get("\\\\server\\share/exports/data.bin").open().read() == b"\x00\x01\x02\x03"


@pytest.mark.parametrize("image_name", ["Data", "C:", ""])
def test_ad1_incomplete_root_path(image_name: str) -> None:
    """Test that incomplete logical image root paths still yield a browsable tree."""
    fs = ad1.AD1(build_ad1(image_name, [ad1_file("file.txt", b"data")]))

    if image_name:
        assert fs.root.listdir() == [image_name]
        entry = fs.get(image_name)
        assert entry.is_virtual()
        assert entry.source == image_name
        assert fs.get(f"{image_name}/file.txt").open().read() == b"data"
    else:
        assert fs.root.listdir() == ["file.txt"]
        assert fs.get("file.txt").open().read() == b"data"
