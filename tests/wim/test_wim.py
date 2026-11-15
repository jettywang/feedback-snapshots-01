from __future__ import annotations

import gzip
import hashlib
import io
import struct
from typing import TYPE_CHECKING

import pytest
from dissect.util.compression.lzxpress_huffman import decompress

from dissect.archive.exception import CorruptArchiveError, FileNotFoundError
from dissect.archive.wim.wim import WIM, CompressedStream, StreamStatus
from tests._tools.wim._synth import Node, StreamSpec, build_wim
from tests._util import absolute_path

if TYPE_CHECKING:
    from dissect.archive.wim.wim import Image


@pytest.mark.parametrize(
    ("path", "chunk_size"),
    [
        ("_data/wim/basic4k.wim.gz", 0x1000),
        ("_data/wim/basic8k.wim.gz", 0x2000),
        ("_data/wim/basic16k.wim.gz", 0x4000),
        ("_data/wim/basic32k.wim.gz", 0x8000),
    ],
)
def test_wim(path: str, chunk_size: int) -> None:
    with gzip.open(absolute_path(path)) as fh:
        wim = WIM(fh)
        assert wim.header.CompressionSize == chunk_size

        resource = next(iter(wim.resources.values()))
        assert resource.open().chunk_size == chunk_size

        stream = CompressedStream(
            wim.fh, resource.offset, resource.size, resource.original_size, decompress, chunk_size
        )
        assert resource.wim.header.CompressionSize == stream.chunk_size
        assert resource.open().read() == stream.read()

        images = list(wim.images())
        assert len(images) == 1

        image = images[0]
        assert sorted(image.root.listdir().keys()) == ["ads.txt", "dir", "file.txt", "link.txt"]

        entry = image.get("file.txt")
        assert entry.is_file()
        assert not entry.is_dir()
        assert not entry.is_reparse_point()
        assert len(entry.streams) == 1
        assert entry.size() == 70
        assert hashlib.sha1(entry.open().read()).hexdigest() == "0aaa8266648364d68b67be77c53f708a77fda84c"

        entry = image.get("ads.txt")
        assert entry.is_file()
        assert not entry.is_dir()
        assert not entry.is_reparse_point()
        assert len(entry.streams) == 2
        assert entry.size() == 30
        assert entry.size("spookystream") == 38
        assert hashlib.sha1(entry.open().read()).hexdigest() == "8e2dbd4ff0c5e125b445ded476f5bb9637e115a6"
        assert hashlib.sha1(entry.open("spookystream").read()).hexdigest() == "0fb3109183dc351670bec54bebe6406ad016315e"

        entry = image.get("link.txt")
        assert entry.is_file()
        assert not entry.is_dir()
        assert entry.is_reparse_point()
        assert entry.is_mount_point()
        assert entry.reparse_point.print_name == "C:\\dir\\another.txt"

        entry = image.get("dir")
        assert not entry.is_file()
        assert entry.is_dir()
        assert not entry.is_reparse_point()
        assert sorted(entry.listdir().keys()) == ["another.txt"]

        entry = image.get("dir/another.txt")
        assert entry.is_file()
        assert not entry.is_dir()
        assert not entry.is_reparse_point()
        assert len(entry.streams) == 1
        assert entry.size() == 60
        assert hashlib.sha1(entry.open().read()).hexdigest() == "1fc83a896287fe48f6d42d8d04f88f6dc90c0c45"


def _image(data: bytes) -> Image:
    return next(WIM(io.BytesIO(data)).images())


def test_stream_evidence_default_and_named_streams() -> None:
    data = build_wim(
        Node(
            "",
            children=[
                Node("default.txt", content=b"default contents"),
                Node(
                    "ads.txt",
                    streams=[
                        StreamSpec("", b"default data"),
                        StreamSpec("hidden", b"named stream data"),
                    ],
                ),
            ],
        ),
        [b"SD0"],
    )

    image = _image(data)
    evidence = image.iter_streams()

    by_path = {stream.path: stream for stream in evidence}
    assert set(by_path) == {"default.txt", "ads.txt", "ads.txt:hidden"}
    assert by_path["default.txt"].name == ""
    assert by_path["default.txt"].is_default
    assert by_path["default.txt"].open().read() == b"default contents"
    assert by_path["ads.txt"].open().read() == b"default data"
    assert by_path["ads.txt:hidden"].open().read() == b"named stream data"
    assert by_path["ads.txt:hidden"].logical_size == len(b"named stream data")
    assert all(stream.status == StreamStatus.READABLE for stream in by_path.values())


def test_stream_evidence_shared_resource_keeps_identity() -> None:
    shared = b"shared payload"
    data = build_wim(
        Node(
            "",
            children=[
                Node("a.txt", streams=[StreamSpec("", shared)]),
                Node("b.txt", streams=[StreamSpec("", shared), StreamSpec("alt", shared)]),
            ],
        )
    )

    streams = list(_image(data).iter_streams())
    assert [stream.path for stream in streams] == ["a.txt", "b.txt", "b.txt:alt"]
    assert len({stream.resource_id for stream in streams}) == 1
    assert [stream.open().read() for stream in streams] == [shared, shared, shared]


def test_stream_evidence_duplicate_names_are_not_collapsed() -> None:
    data = build_wim(
        Node(
            "",
            children=[
                Node(
                    "dup.txt",
                    streams=[
                        StreamSpec("", b"default"),
                        StreamSpec("report", b"first named"),
                        StreamSpec("report", b"second named"),
                    ],
                )
            ],
        )
    )

    entry = _image(data).get("dup.txt")
    evidence = entry.stream_evidence()
    assert [stream.name for stream in evidence] == ["", "report", "report"]
    assert [stream.open().read() for stream in evidence] == [b"default", b"first named", b"second named"]

    # The convenience mapping cannot represent both; opening by ambiguous name must not
    # silently pick one of the two.
    with pytest.raises(CorruptArchiveError):
        entry.open("report")


def test_stream_evidence_missing_resource_is_not_an_empty_file() -> None:
    missing = StreamSpec("", b"missing payload")
    data = build_wim(
        Node("", children=[Node("missing.txt", streams=[StreamSpec("", b"present"), missing])]),
        omit_resources={hashlib.sha1(b"missing payload").digest()},
    )

    entry = _image(data).get("missing.txt")
    present, absent = entry.stream_evidence()
    assert present.readable
    assert absent.status == StreamStatus.MISSING
    assert absent.resource_id_hex == hashlib.sha1(b"missing payload").hexdigest()

    report = WIM(io.BytesIO(data)).scan_streams(verify=True)
    assert report.summary()["missing"] == 1
    assert [stream.path for stream in report.unreadable] == ["missing.txt"]
    with pytest.raises(FileNotFoundError):
        absent.open()


def test_stream_evidence_zero_hash_is_not_a_stream() -> None:
    data = build_wim(
        Node("", children=[Node("empty.txt", streams=[StreamSpec("", None, hash=b"\x00" * 20)])]),
    )

    entry = _image(data).get("empty.txt")
    (stream,) = entry.stream_evidence()
    assert stream.status == StreamStatus.NO_RESOURCE
    assert not stream.readable
    assert stream.logical_size == 0
    with pytest.raises(FileNotFoundError):
        stream.open()


def test_stream_evidence_missing_table_means_no_stream() -> None:
    data = build_wim(Node("", children=[Node("dir", children=[Node("file.txt", content=b"x")])]))

    entry = _image(data).get("dir")
    assert entry.is_dir()
    assert entry.stream_evidence() == []
    assert entry.streams == {}


def test_stream_table_overrun_does_not_swallow_next_entry() -> None:
    first = StreamSpec("", b"first payload")
    second = b"second payload"
    # The first entry claims one stream while a second directory entry follows immediately.
    # The stream table must not read that entry's header as a stream.
    data = build_wim(
        Node(
            "",
            children=[
                Node("first.txt", streams=[first], declared_streams=1),
                Node("second.txt", content=second),
            ],
        )
    )

    image = _image(data)
    assert [entry.name for entry in image.iter_entries()] == [None, "first.txt", "second.txt"]

    first_entry = image.get("first.txt")
    assert first_entry.stream_evidence()[0].open().read() == b"first payload"

    second_entry = image.get("second.txt")
    assert second_entry.stream_evidence()[0].open().read() == second


def test_stream_entry_beyond_declared_bounds_is_malformed() -> None:
    # A stream that claims a length larger than the remaining metadata must be reported as
    # malformed, not opened as an empty or zero-filled file.
    spec = StreamSpec("", b"payload", length=0x10000)
    data = build_wim(Node("", children=[Node("bad.txt", streams=[spec])]))

    entry = _image(data).get("bad.txt")
    (stream,) = entry.stream_evidence()
    assert stream.status == StreamStatus.MALFORMED
    assert not stream.scanned
    assert not stream.readable
    with pytest.raises(CorruptArchiveError):
        stream.open()

    report = WIM(io.BytesIO(data)).scan_streams()
    assert report.summary()["malformed"] == 1
    assert report.unreadable[0].path == "bad.txt"


def test_scan_streams_reports_every_stream() -> None:
    data = build_wim(
        Node(
            "",
            children=[
                Node("plain.txt", content=b"plain"),
                Node("named.txt", streams=[StreamSpec("", b"a"), StreamSpec("x", b"b")]),
            ],
        )
    )

    report = WIM(io.BytesIO(data)).scan_streams(verify=True)
    assert len(report) == 3
    assert report.ok
    assert [stream.path for stream in report.scanned] == ["plain.txt", "named.txt", "named.txt:x"]
    assert all(stream.verified for stream in report)
    assert report.summary()["total"] == 3


def test_duplicate_stream_name_can_be_opened_by_index() -> None:
    data = build_wim(
        Node(
            "",
            children=[
                Node(
                    "dup.txt",
                    streams=[StreamSpec("report", b"first"), StreamSpec("report", b"second")],
                )
            ],
        )
    )

    entry = _image(data).get("dup.txt")
    assert entry.open("report", index=0).read() == b"first"
    assert entry.open("report", index=1).read() == b"second"


def test_verify_detects_corrupted_resource_content() -> None:
    path = "_data/wim/basic4k.wim.gz"
    with gzip.open(absolute_path(path)) as fh:
        raw = bytearray(fh.read())

    wim = WIM(io.BytesIO(raw))
    resource = wim.resources[bytes.fromhex("0aaa8266648364d68b67be77c53f708a77fda84c")]
    raw[resource.offset] ^= 0xFF

    report = WIM(io.BytesIO(bytes(raw))).scan_streams(verify=True)
    corrupt = [stream for stream in report if stream.status == StreamStatus.CORRUPT]
    assert [stream.path for stream in corrupt] == ["file.txt"]
    assert "digest" in corrupt[0].error
    assert not report.ok


def test_scan_reports_unreadable_image_metadata() -> None:
    path = "_data/wim/basic4k.wim.gz"
    with gzip.open(absolute_path(path)) as fh:
        raw = bytearray(fh.read())

    wim = WIM(io.BytesIO(raw))
    metadata = wim._images[0]
    raw[metadata.offset + 40] ^= 0xFF

    report = WIM(io.BytesIO(bytes(raw))).scan_streams(verify=True)
    assert report.summary()["image_errors"] == 1
    assert report.summary()["images_scanned"] == 0
    assert report.streams == []
    assert report.image_errors
    assert not report.ok


def test_forged_stream_name_span_does_not_hide_next_entry() -> None:
    root = Node(
        "",
        children=[
            Node("first.txt", streams=[StreamSpec("", b"first data")]),
            Node("second.txt", content=b"second data"),
        ],
    )
    data = bytearray(build_wim(root))

    wim = WIM(io.BytesIO(data))
    image = next(wim.images())
    metadata = wim._images[0]
    first = image.get("first.txt")
    stream_offset = metadata.offset + first.streams_start

    # Inflate the stream name length and the stream length together, so the name bytes are
    # borrowed from the following directory entry's header.
    struct.pack_into("<q", data, stream_offset, 80)
    struct.pack_into("<H", data, stream_offset + 36, 40)

    image = next(WIM(io.BytesIO(bytes(data))).images())
    assert [entry.name for entry in image.iter_entries()] == [None, "first.txt", "second.txt"]
    assert [stream.status for stream in image.get("first.txt").stream_evidence()] == [StreamStatus.MALFORMED]
    assert image.get("second.txt").open().read() == b"second data"
