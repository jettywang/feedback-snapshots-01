from __future__ import annotations

import gzip
import hashlib
import io
from typing import TYPE_CHECKING

import pytest

from dissect.archive.exception import (
    AmbiguousStreamError,
    CorruptWimError,
    FileNotFoundError,
    StreamUnavailableError,
)
from dissect.archive.wim import WIM, StreamState
from tests._tools.wim._synth import ZERO_HASH, build_wim, directory_entry, stream_entry
from tests._util import absolute_path

if TYPE_CHECKING:
    from dissect.archive.wim import DirectoryEntry

ALPHA = b"alpha default content"
BRAVO = b"bravo named stream content"
CHARLIE = b"charlie shared content"


def _hash(data: bytes) -> bytes:
    return hashlib.sha1(data).digest()


def _wim(entries: list[dict], extra_resources: dict[bytes, bytes] | None = None) -> WIM:
    return WIM(io.BytesIO(build_wim(entries, extra_resources=extra_resources)))


def _resources(*contents: bytes) -> dict[bytes, bytes]:
    return {_hash(content): content for content in contents}


def _root_entries(wim: WIM) -> dict[str, DirectoryEntry]:
    return {entry.name: entry for entry in next(wim.images()).root.iterdir()}


def test_default_and_named_streams_are_separate_identities() -> None:
    entries = [
        {
            "name": "multi.txt",
            "streams": [("", _hash(ALPHA)), ("evil", _hash(BRAVO))],
        }
    ]
    wim = _wim(entries, _resources(ALPHA, BRAVO))
    entry = _root_entries(wim)["multi.txt"]

    # Two declared streams, each with its own identity.
    assert len(entry.streams) == 2
    assert entry.streams.names() == ["", "evil"]

    default = entry.streams[""]
    named = entry.streams["evil"]
    assert default.is_default
    assert not default.is_named
    assert named.is_named
    assert not named.is_default
    assert default.resource_hash == _hash(ALPHA)
    assert named.resource_hash == _hash(BRAVO)

    assert entry.open().read() == ALPHA
    assert entry.open("evil").read() == BRAVO
    assert entry.size() == len(ALPHA)
    assert entry.size("evil") == len(BRAVO)

    for stream in entry.streams:
        assert stream.state is StreamState.OK
        assert stream.readable


def test_streams_sharing_a_resource_keep_their_own_identity() -> None:
    entries = [
        {
            "name": "shared.txt",
            "streams": [
                ("", _hash(ALPHA)),
                ("named", _hash(ALPHA)),
                ("third", _hash(ALPHA)),
            ],
        }
    ]
    wim = _wim(entries, _resources(ALPHA))
    entry = _root_entries(wim)["shared.txt"]

    assert len(entry.streams) == 3
    names = [stream.name for stream in entry.streams]
    assert names == ["", "named", "third"]

    # Same resource, but each stream remains a distinct record with its own index.
    assert {stream.resource_hash for stream in entry.streams} == {_hash(ALPHA)}
    assert len({stream.index for stream in entry.streams}) == 3
    for stream in entry.streams:
        assert stream.open().read() == ALPHA
        assert stream.size == len(ALPHA)


def test_duplicate_stream_names_are_not_hidden() -> None:
    entries = [
        {
            "name": "dup.txt",
            "streams": [("evil", _hash(ALPHA)), ("evil", _hash(BRAVO))],
        }
    ]
    wim = _wim(entries, _resources(ALPHA, BRAVO))
    entry = _root_entries(wim)["dup.txt"]

    # Iteration and length expose both, so nothing is silently dropped.
    assert len(entry.streams) == 2
    assert [stream.name for stream in entry.streams] == ["evil", "evil"]
    assert entry.streams.duplicates() == {"evil": entry.streams.get_all("evil")}

    all_streams = entry.streams.get_all("evil")
    assert [stream.resource_hash for stream in all_streams] == [_hash(ALPHA), _hash(BRAVO)]

    # Mapping access refuses to pick a winner for an ambiguous name.
    with pytest.raises(AmbiguousStreamError):
        entry.streams["evil"]
    with pytest.raises(AmbiguousStreamError):
        entry.open("evil")

    # And the evidence report still carries every stream.
    evidence = list(wim.stream_evidence())
    assert [record.resource_hash for record in evidence] == [_hash(ALPHA), _hash(BRAVO)]
    assert all(record.scanned for record in evidence)


def test_duplicate_default_stream_names_are_not_hidden() -> None:
    # Even the empty name can occur twice; it must not collapse to a single "default" stream.
    data = build_wim(
        [
            {
                "name": "two-defaults.txt",
                "streams": [("", _hash(ALPHA)), ("", _hash(BRAVO))],
            }
        ],
        extra_resources=_resources(ALPHA, BRAVO),
    )
    entry = _root_entries(WIM(io.BytesIO(data)))["two-defaults.txt"]

    assert entry.streams.names() == ["", ""]
    assert all(stream.is_default for stream in entry.streams)
    assert [stream.resource_hash for stream in entry.streams] == [_hash(ALPHA), _hash(BRAVO)]

    with pytest.raises(AmbiguousStreamError):
        entry.open()


def test_missing_and_empty_resources_are_reported_not_hidden() -> None:
    entries = [
        {
            "name": "broken.txt",
            "streams": [("", _hash(ALPHA)), ("gone", _hash(BRAVO))],
        },
        {"name": "empty.txt", "streams": [("", ZERO_HASH)]},
        {"name": "no-streams.txt", "attributes": 0x10, "hash": ZERO_HASH, "streams": []},
        {"name": "zero-byte.txt", "hash": ZERO_HASH, "streams": []},
    ]
    wim = _wim(entries, _resources(ALPHA))
    root = _root_entries(wim)

    broken = root["broken.txt"]
    gone = broken.streams["gone"]
    assert gone.state is StreamState.MISSING_RESOURCE
    assert not gone.readable
    assert gone.size is None
    with pytest.raises(StreamUnavailableError):
        gone.open()

    empty = root["empty.txt"].streams[""]
    assert empty.state is StreamState.EMPTY
    assert empty.open().read() == b""

    # A declared default stream with an empty hash is not the same as no stream at all.
    assert len(root["empty.txt"].streams) == 1
    assert len(root["no-streams.txt"].streams) == 0

    # A zero-byte regular file still has a default stream, albeit an empty one.
    zero_byte = root["zero-byte.txt"].streams[""]
    assert zero_byte.state is StreamState.EMPTY
    assert zero_byte.open().read() == b""

    evidence = {record.path: record for record in wim.stream_evidence() if record.name == ""}
    assert evidence["broken.txt"].status == "scanned"
    assert evidence["broken.txt"].scanned
    assert evidence["empty.txt"].status == "empty"
    assert evidence["empty.txt"].readable
    assert evidence["empty.txt"].digest == hashlib.sha1(b"").digest()

    # The missing-stream record is neither "scanned" nor reported as a clean, empty file.
    gone_evidence = next(record for record in wim.stream_evidence() if record.name == "gone")
    assert gone_evidence.status == "missing-resource"
    assert not gone_evidence.scanned
    assert gone_evidence.error is not None


def test_stream_table_does_not_read_the_next_entry() -> None:
    # evil.txt lies about its stream count: it declares two streams but only one follows. Without
    # a bound, the next directory entry (>= 102 bytes) would be parsed as an unnamed stream of
    # evil.txt because its first eight bytes read as a plausible length.
    entries = [
        {
            "name": "evil.txt",
            "streams": [("", _hash(ALPHA))],
            "stream_count": 2,
        },
        {"name": "after.txt", "streams": [("", _hash(BRAVO))]},
    ]
    wim = _wim(entries, _resources(ALPHA, BRAVO))
    root = _root_entries(wim)

    evil = root["evil.txt"]
    assert evil.truncated
    assert evil.stream_error is not None
    assert [stream.name for stream in evil.streams] == [""]

    # The following entry stays intact and keeps its own content.
    after = root["after.txt"]
    assert not after.truncated
    assert [stream.name for stream in after.streams] == [""]
    assert after.open().read() == BRAVO


def test_stream_entry_length_must_fit_its_name() -> None:
    name = "a-long-stream-name"
    content = ALPHA
    header = directory_entry("short.txt")
    entry = directory_entry("short.txt", streams=[(name, _hash(content))])
    # The well-formed stream entry fits its name exactly, aligned after the entry header.
    assert entry[len(header) :] == stream_entry(name, _hash(content))

    # A stream entry whose declared length is shorter than its own name must be rejected: otherwise
    # the parser would read the next entry's bytes as part of this stream.
    data = build_wim(
        [
            {"name": "short.txt", "streams": [(name, _hash(content), 40)]},
            {"name": "after.txt", "streams": [("", _hash(BRAVO))]},
        ],
        extra_resources=_resources(content, BRAVO),
    )

    wim = WIM(io.BytesIO(data))
    root = _root_entries(wim)
    entry = root["short.txt"]
    assert entry.truncated
    assert isinstance(entry.stream_error, CorruptWimError)
    assert entry.streams.names() == []

    # The entry boundary is still known from the name, so iteration continues at the next entry,
    # which is not consumed as a stream of the corrupt one.
    assert entry.end == entry.stream_start + len(stream_entry(name, _hash(content)))
    assert root["after.txt"].open().read() == BRAVO


def test_truncated_resource_is_not_a_clean_scan() -> None:
    entries = [{"name": "short.txt", "streams": [("", _hash(ALPHA))]}]
    data = bytearray(build_wim(entries, extra_resources=_resources(ALPHA)))
    wim = WIM(io.BytesIO(bytes(data)))
    resource = _root_entries(wim)["short.txt"].streams[""].resource
    assert resource is not None

    # Leave the file intact but make the resource entry claim more data than the file holds, so the
    # resource table still parses while the stream's content cannot be read in full.
    table_offset = wim.header.OffsetTable.Offset
    table_size = int.from_bytes(wim.header.OffsetTable.Size, "little")
    for index in range(table_size // 50):
        row = table_offset + index * 50
        if bytes(data[row + 30 : row + 50]) == resource.hash:
            data[row : row + 7] = (resource.size + 1024).to_bytes(7, "little")
            break
    else:  # pragma: no cover - the resource must be in the table
        raise AssertionError("resource not found in table")

    wim = WIM(io.BytesIO(bytes(data)))
    stream = _root_entries(wim)["short.txt"].streams[""]
    assert stream.state is StreamState.OK  # the resource row is still resolvable
    with pytest.raises(StreamUnavailableError):
        stream.open()
    assert not stream.readable
    with pytest.raises(StreamUnavailableError):
        stream.scan()

    evidence = next(iter(wim.stream_evidence()))
    assert not evidence.scanned
    assert evidence.error is not None
    assert evidence.status == "unreadable"


def test_stream_helpers_and_recursive_enumeration() -> None:
    entries = [
        {
            "name": "a.txt",
            "streams": [("", _hash(ALPHA)), ("evil", _hash(BRAVO))],
        },
        {"name": "b.txt", "streams": [("", _hash(CHARLIE))]},
    ]
    wim = _wim(entries, _resources(ALPHA, BRAVO, CHARLIE))
    root = _root_entries(wim)

    assert root["a.txt"].stream("evil").name == "evil"
    with pytest.raises(FileNotFoundError):
        root["a.txt"].stream("nope")

    # Recursive enumeration walks the image and returns every stream in declaration order.
    names = [(stream.path, stream.name) for stream in next(wim.images()).iter_streams()]
    assert names == [("a.txt", ""), ("a.txt", "evil"), ("b.txt", "")]

    # The evidence report agrees, and every record can be read back.
    assert [(record.path, record.name) for record in wim.stream_evidence()] == names


def test_stream_entries_are_eight_byte_aligned() -> None:
    # Odd-sized names produce stream entries that need padding to the next 8-byte boundary; the
    # declared length covers that padding, and the next entry starts after it.
    names = ["a", "bb", "ccc", "dddd"]
    entries = [
        {
            "name": "many.txt",
            "streams": [
                (name, _hash(content)) for name, content in zip(names, [ALPHA, BRAVO, CHARLIE, ALPHA], strict=True)
            ],
        }
    ]
    wim = _wim(entries, _resources(ALPHA, BRAVO, CHARLIE))
    entry = _root_entries(wim)["many.txt"]

    assert entry.streams.names() == names
    for stream in entry.streams:
        assert stream.offset % 8 == 0
        assert stream.declared_size % 8 == 0
        assert entry.open(stream.name).read() in (ALPHA, BRAVO, CHARLIE)

    # Each stream begins exactly at the previous stream's end.
    offsets = [stream.offset for stream in entry.streams]
    ends = [stream.offset + stream.declared_size for stream in entry.streams]
    assert offsets[1:] == ends[:-1]


def test_stream_length_pointing_past_entry_is_rejected() -> None:
    # A stream entry whose declared length reaches past the next directory entry would let the
    # parser swallow it. Only the first entry's stream is corrupt; the following entry must still
    # be readable in full.
    data = build_wim(
        [
            {"name": "evil.txt", "streams": [("evil", _hash(ALPHA), 8 * 16)]},
            {"name": "after.txt", "streams": [("", _hash(BRAVO))]},
        ],
        extra_resources=_resources(ALPHA, BRAVO),
    )

    wim = WIM(io.BytesIO(data))
    root = _root_entries(wim)
    evil = root["evil.txt"]
    assert evil.truncated
    assert isinstance(evil.stream_error, CorruptWimError)
    # The first stream entry is never handed out with a length the parser did not verify.
    assert evil.streams.names() == []
    # Iteration resumes after the corrupt stream's real extent, so the next entry survives intact.
    assert evil.end == evil.stream_start + len(stream_entry("evil", _hash(ALPHA)))
    assert root["after.txt"].open().read() == BRAVO


def test_real_fixture_streams_scan_independently() -> None:
    with gzip.open(absolute_path("_data/wim/basic4k.wim.gz")) as fh:
        wim = WIM(fh)
        image = next(wim.images())
        entry = image.get("ads.txt")

        assert entry.streams.names() == ["", "spookystream"]
        assert entry.streams[""].scan().hex() == "8e2dbd4ff0c5e125b445ded476f5bb9637e115a6"
        assert entry.streams["spookystream"].scan().hex() == "0fb3109183dc351670bec54bebe6406ad016315e"

        # Every legal stream reports as scanned, with an exact digest of its own content.
        for record in wim.stream_evidence():
            if record.state in (StreamState.OK, StreamState.EMPTY):
                assert record.scanned, record
            assert record.size == len(record.stream.open().read())

        # A directory with an all-zero entry hash has no stream, not an empty one.
        assert len(image.get("dir").streams) == 0
        with pytest.raises(FileNotFoundError):
            image.get("dir").open()
