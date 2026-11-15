from __future__ import annotations

import gzip
import hashlib

import pytest
from dissect.util.compression.lzxpress_huffman import decompress

from dissect.archive.wim.wim import WIM, CompressedStream, ContentReferenceStatus
from tests._util import absolute_path


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


def test_wim_relationships_on_real_image() -> None:
    with gzip.open(absolute_path("_data/wim/basic4k.wim.gz")) as fh:
        wim = WIM(fh)
        image = next(wim.images())
        view = image.relationships()

        # The fixture has no HardLink identifiers, so identical-content paths must not become a group.
        assert view.hardlink_groups == {}
        assert image.get("file.txt").entry.HardLink == 0

        # Each path stays its own entry, including both security references of the same descriptor.
        records = {record.path: record for record in view.entries}
        assert set(records) == {"", "ads.txt", "dir", "dir\\another.txt", "file.txt", "link.txt"}
        assert records["file.txt"].security_id == records["dir\\another.txt"].security_id
        assert records["file.txt"].entry is not records["dir\\another.txt"].entry

        # The security table is addressed by index; descriptor bytes come from the real security block.
        assert records["file.txt"].security.index == records["file.txt"].security_id
        assert records["file.txt"].security.descriptor == image.security.descriptors[records["file.txt"].security_id]
        assert records["ads.txt"].security.descriptor != records["file.txt"].security.descriptor

        # Content references resolve back to concrete rows in the resource table.
        entry = image.get("ads.txt")
        references = records["ads.txt"].content
        assert {reference.stream_name for reference in references} == {"", "spookystream"}
        for reference in references:
            assert reference.status is ContentReferenceStatus.RESOLVED
            resource = wim.resource_entries[reference.resource_index]
            assert resource.hash == reference.hash
        assert entry.size("spookystream") == 38

        # The metadata resource itself is identifiable, and its content is not any file stream.
        assert view.metadata_resource_index is not None
        assert wim.resource_entries[view.metadata_resource_index].is_metadata
        assert view.metadata_hash not in {reference.hash for reference in records["file.txt"].content}
