from __future__ import annotations

import gzip
from dataclasses import replace

import pytest

from dissect.apfs.apfs import APFS
from dissect.apfs.c_apfs import c_apfs
from dissect.apfs.identity import (
    ContentFingerprint,
    ContentStatus,
    ExtentRange,
    FileIdentity,
    NameEvidence,
    StreamIdentity,
    StreamStatus,
    VolumeIdentity,
    analyze_identities,
    build_file_identity,
)
from dissect.apfs.objects.fs import INode
from tests.conftest import absolute_path

BLOCK_SIZE = 4096


def _volume() -> VolumeIdentity:
    return VolumeIdentity(
        uuid="00000000-0000-0000-0000-000000000001",
        name="Identity",
        index=0,
        block_size=BLOCK_SIZE,
    )


def _extent(logical: int, physical_block: int, length: int = BLOCK_SIZE) -> ExtentRange:
    return ExtentRange(
        logical_start=logical,
        length=length,
        physical_block=physical_block,
        physical_start=physical_block * BLOCK_SIZE,
        crypto_id=0,
    )


class _FakeINode(INode):
    """INode that does not touch a real volume, for extraction-free identity tests."""

    def __init__(self, oid: int, sibling_id: int | None = None, *, nlink: int = 1, is_file: bool = True):
        self.volume = None
        self.oid = oid
        self.sibling_id = sibling_id
        self._nlink = nlink
        self._is_file = is_file

    @property
    def inode(self) -> object:
        return type("InodeValue", (), {"parent_id": 2, "nlink": self._nlink, "private_id": self.oid})()

    def is_file(self) -> bool:
        return self._is_file


def _identity(
    oid: int,
    *,
    sibling_id: int | None = None,
    private_id: int | None = None,
    names: tuple[NameEvidence, ...] = (),
    extents: tuple[ExtentRange, ...] = (),
    size: int | None = None,
    stream_id: int | None = None,
    nlink: int = 1,
    sha256: str | None = None,
) -> FileIdentity:
    if not names:
        names = (NameEvidence(name=f"file{oid}", parent_oid=2, sibling_id=sibling_id, sources=("INODE.NAME",)),)

    streams = ()
    if extents or size:
        streams = (
            StreamIdentity(
                stream_id=stream_id if stream_id is not None else (private_id or oid),
                kind="data",
                name=None,
                size=size,
                extents=extents,
                status=StreamStatus.OK if extents else StreamStatus.MISSING,
            ),
        )

    content = ContentFingerprint(status=ContentStatus.OK, size=size, sha256=sha256) if sha256 else None

    return FileIdentity(
        volume=_volume(),
        oid=oid,
        sibling_id=sibling_id,
        private_id=private_id if private_id is not None else oid,
        name_records=names,
        streams=streams,
        content=content,
        inode=_FakeINode(oid, sibling_id, nlink=nlink),
    )


def test_hardlink_uses_sibling_records() -> None:
    """Multiple names on one OID are a hard link only when SIBLING_LINK records support them."""
    names = (
        NameEvidence(name="file", parent_oid=19, sibling_id=21, sources=("SIBLING_LINK",)),
        NameEvidence(name="hardlink", parent_oid=2, sibling_id=22, sources=("SIBLING_LINK",)),
    )
    files = [
        _identity(20, sibling_id=21, names=names, extents=(_extent(0, 100),), size=BLOCK_SIZE, nlink=2),
        _identity(20, sibling_id=22, names=names, extents=(_extent(0, 100),), size=BLOCK_SIZE, nlink=2),
    ]

    view = analyze_identities(_volume(), files)

    assert len(view.hardlinks) == 1
    relation = view.hardlinks[0]
    assert relation.oid == 20
    assert relation.sibling_ids == (21, 22)
    assert list(relation.evidence) == [
        "SIBLING_LINK:oid=20:sibling_id=21",
        "SIBLING_LINK:oid=20:sibling_id=22",
    ]
    assert view.extent_relations == ()
    assert view.content_matches == ()


def test_missing_sibling_record_is_not_inferred_from_name() -> None:
    """A missing sibling record leaves the name unresolved; no hard link is synthesized."""
    supported = NameEvidence(name="file", parent_oid=19, sibling_id=21, sources=("SIBLING_LINK",))
    missing = NameEvidence(
        name=None,
        parent_oid=None,
        sibling_id=22,
        sources=(),
        resolved=False,
        reason="missing SIBLING_LINK record for sibling_id 22",
    )
    files = [
        _identity(20, sibling_id=21, names=(supported,), extents=(_extent(0, 100),), size=BLOCK_SIZE, nlink=2),
        _identity(20, sibling_id=22, names=(missing,), extents=(_extent(0, 100),), size=BLOCK_SIZE, nlink=2),
    ]

    view = analyze_identities(_volume(), files)

    assert view.hardlinks == ()
    assert view.by_oid(20, 21).names == ("file",)
    assert view.by_oid(20, 22).names == ()
    assert view.by_oid(20, 22).name is None
    assert view.by_oid(20, 22).unresolved_names[0].sibling_id == 22
    assert view.by_oid(20, 22).unresolved_names[0].resolved is False
    assert any(observation.scope == "name" and observation.sibling_id == 22 for observation in view.unresolved)


def test_clone_with_partial_overwrite() -> None:
    """A clone has a different private_id but still shares some physical extents."""
    original = _identity(
        30,
        extents=(_extent(0, 200), _extent(BLOCK_SIZE, 201), _extent(2 * BLOCK_SIZE, 202)),
        size=3 * BLOCK_SIZE,
    )
    clone = _identity(
        31,
        extents=(_extent(0, 200), _extent(BLOCK_SIZE, 300), _extent(2 * BLOCK_SIZE, 202)),
        size=3 * BLOCK_SIZE,
    )

    view = analyze_identities(_volume(), [original, clone])

    assert view.hardlinks == ()
    assert len(view.clones) == 1
    relation = view.clones[0]
    assert relation.kind.value == "clone"
    assert relation.left.oid == 30
    assert relation.left.private_id == 30
    assert relation.right.oid == 31
    assert relation.right.private_id == 31
    assert [(item.physical_start, item.length) for item in relation.shared] == [
        (200 * BLOCK_SIZE, BLOCK_SIZE),
        (202 * BLOCK_SIZE, BLOCK_SIZE),
    ]

    # The middle block was overwritten in the clone, so each side has a file-private logical range there.
    assert [(item.start, item.length) for item in relation.left_unshared] == [(BLOCK_SIZE, BLOCK_SIZE)]
    assert [(item.start, item.length) for item in relation.right_unshared] == [(BLOCK_SIZE, BLOCK_SIZE)]
    assert any("FILE_EXTENT:stream=30" in evidence for evidence in relation.evidence)
    assert any("FILE_EXTENT:stream=31" in evidence for evidence in relation.evidence)


def test_same_content_independent_file_is_not_a_clone() -> None:
    """Equal content with no shared extent or sibling record stays a content-only observation."""
    left = _identity(40, extents=(_extent(0, 400),), size=BLOCK_SIZE, sha256="a" * 64)
    right = _identity(41, extents=(_extent(0, 401),), size=BLOCK_SIZE, sha256="a" * 64)

    view = analyze_identities(_volume(), [left, right])

    assert view.clones == ()
    assert view.hardlinks == ()
    assert len(view.content_matches) == 1
    match = view.content_matches[0]
    assert match.sha256 == "a" * 64
    assert match.kind.value == "same-content-independent"
    assert "FILE_EXTENT:no-overlap" in match.evidence
    assert "No sibling record or shared extent record" in match.note
    assert match.left.private_id != match.right.private_id


def test_unreadable_stream_does_not_create_relation() -> None:
    """Two identical hashes with unreadable extents cannot become a clone or a confirmed shared stream."""

    def identity(oid: int, stream_id: int, status: StreamStatus, error: str) -> FileIdentity:
        return FileIdentity(
            volume=_volume(),
            oid=oid,
            sibling_id=None,
            private_id=oid,
            name_records=(NameEvidence(name=f"file{oid}", parent_oid=2, sibling_id=None, sources=("INODE.NAME",)),),
            streams=(
                StreamIdentity(
                    stream_id=stream_id,
                    kind="data",
                    name=None,
                    size=BLOCK_SIZE,
                    extents=(),
                    status=status,
                    error=error,
                ),
            ),
            content=ContentFingerprint(status=ContentStatus.OK, size=BLOCK_SIZE, sha256="b" * 64),
            inode=_FakeINode(oid),
        )

    view = analyze_identities(
        _volume(),
        [
            identity(50, 50, StreamStatus.UNREADABLE, "failed to read FILE_EXTENT records: OSError"),
            identity(51, 51, StreamStatus.MISSING, "extents cover 0 of 4096 bytes"),
        ],
    )

    assert view.clones == ()
    assert view.hardlinks == ()
    assert len(view.content_matches) == 1
    assert "FILE_EXTENT:incomplete" in view.content_matches[0].evidence
    assert {observation.scope for observation in view.unresolved} == {"stream"}


def test_shared_stream_id_is_reported_separately() -> None:
    """Overlapping extents on the same stream ID are a shared-stream relation."""
    left = _identity(60, extents=(_extent(0, 500),), size=BLOCK_SIZE)
    right = _identity(61, extents=(_extent(0, 500),), size=BLOCK_SIZE, stream_id=60)

    view = analyze_identities(_volume(), [left, right])

    assert view.clones == ()
    assert len(view.shared_streams) == 1
    relation = view.shared_streams[0]
    assert relation.kind.value == "shared-stream"
    assert all(item.left_stream_id == item.right_stream_id == 60 for item in relation.shared)


class _FakeVolume:
    """Minimal volume surface needed by ``build_file_identity``."""

    def __init__(self, records: dict[tuple[int, c_apfs.APFS_TYPE], list[tuple[bytes, bytes]]]):
        self.records_map = records
        self.is_sealed = False
        self.uuid = "00000000-0000-0000-0000-000000000002"
        self.name = "Synthetic"
        self.index = 0
        self.container = type("Container", (), {"block_size": BLOCK_SIZE})()
        self.broken_types: set[tuple[int, c_apfs.APFS_TYPE]] = set()

    def _records(self, oid: int, type: c_apfs.APFS_TYPE) -> object:
        key = (oid, type)
        if key in self.broken_types:
            raise OSError("simulated read failure")
        if key not in self.records_map:
            if not any(record_oid == oid for record_oid, _ in self.records_map):
                # Behave like a B-tree lookup that runs past the end.
                raise KeyError(f"No records for {oid}")
            # No records of this type for an existing inode: an empty iteration, like the B-tree range scan.
            return

        for raw_key, raw_value in self.records_map[key]:
            yield type, raw_key, raw_value


def _inode_value(
    oid: int, private_id: int, *, parent_id: int, nlink: int, size: int, include_name: bool = True
) -> tuple[bytes, bytes]:
    inode = c_apfs.j_inode_val()
    inode.parent_id = parent_id
    inode.private_id = private_id
    inode.mode = 0o100644
    inode.nlink = nlink
    inode.internal_flags = 0x8000

    xfields = []
    if include_name:
        xfields.append((c_apfs.INO_EXT_TYPE.NAME, c_apfs.XF.DO_NOT_COPY, b"name\x00"))
    if size:
        dstream = c_apfs.j_dstream()
        dstream.size = size
        xfields.append((c_apfs.INO_EXT_TYPE.DSTREAM, c_apfs.XF.SYSTEM_FIELD, dstream.dumps()))

    field_data = b""
    fields = []
    for x_type, x_flags, data in xfields:
        field = c_apfs.x_field()
        field.x_type = x_type
        field.x_flags = x_flags
        field.x_size = len(data)
        fields.append(field)
        field_data += data + b"\x00" * (-len(data) % 8)

    blob = c_apfs.xf_blob()
    blob.xf_num_exts = len(fields)
    blob.xf_used_data = len(field_data)
    blob.xf_exts = fields
    blob.xf_data = field_data

    return b"", inode.dumps() + blob.dumps()


def _sibling_value(oid: int, sibling_id: int, parent_id: int, name: str) -> tuple[bytes, bytes]:
    key = c_apfs.j_sibling_key()
    key.hdr.obj_id_and_type = (oid & c_apfs.OBJ_ID_MASK) | (
        c_apfs.APFS_TYPE.SIBLING_LINK.value << c_apfs.OBJ_TYPE_SHIFT
    )
    key.sibling_id = sibling_id

    value = c_apfs.j_sibling_val()
    value.parent_id = parent_id
    value.name_len = len(name) + 1
    value.name = name.encode() + b"\x00"
    return key.dumps(), value.dumps()


def _extent_value(private_id: int, logical: int, physical: int, length: int) -> tuple[bytes, bytes]:
    key = c_apfs.j_file_extent_key()
    key.hdr.obj_id_and_type = (private_id & c_apfs.OBJ_ID_MASK) | (
        c_apfs.APFS_TYPE.FILE_EXTENT.value << c_apfs.OBJ_TYPE_SHIFT
    )
    key.logical_addr = logical

    value = c_apfs.j_file_extent_val()
    value.len_and_flags = length
    value.phys_block_num = physical
    value.crypto_id = 0
    return key.dumps(), value.dumps()


def test_identity_extraction_from_records() -> None:
    """Extract sibling, DSTREAM and FILE_EXTENT evidence from records without touching a disk image."""
    records = {
        (70, c_apfs.APFS_TYPE.INODE): [
            (b"", _inode_value(70, 70, parent_id=19, nlink=2, size=BLOCK_SIZE)[1]),
        ],
        (70, c_apfs.APFS_TYPE.SIBLING_LINK): [
            _sibling_value(70, 21, 19, "first"),
            _sibling_value(70, 22, 2, "second"),
        ],
        (70, c_apfs.APFS_TYPE.FILE_EXTENT): [
            _extent_value(70, 0, 700, BLOCK_SIZE),
        ],
    }
    volume = _FakeVolume(records)

    identity = build_file_identity(volume, INode(volume, 70), check_content=False)

    assert identity.oid == 70
    assert identity.private_id == 70
    assert identity.names == ("first", "second", "name")
    assert [(record.name, record.sources) for record in identity.name_records] == [
        ("first", ("SIBLING_LINK",)),
        ("second", ("SIBLING_LINK",)),
        ("name", ("INODE.NAME",)),
    ]
    stream = identity.data_stream
    assert stream.stream_id == 70
    assert stream.size == BLOCK_SIZE
    assert stream.status == StreamStatus.OK
    assert [(extent.logical_start, extent.physical_block) for extent in stream.extents] == [(0, 700)]


def test_unreadable_extent_records_are_reported() -> None:
    """A stream whose extent records cannot be read is marked unreadable, not inferred."""
    volume = _FakeVolume(
        {
            (71, c_apfs.APFS_TYPE.INODE): [
                (b"", _inode_value(71, 71, parent_id=2, nlink=1, size=BLOCK_SIZE)[1]),
            ],
        }
    )
    volume.broken_types.add((71, c_apfs.APFS_TYPE.FILE_EXTENT))

    identity = build_file_identity(volume, INode(volume, 71), check_content=False)

    assert identity.data_stream is not None
    assert identity.data_stream.status == StreamStatus.UNREADABLE
    assert identity.data_stream.extents == ()
    assert "simulated read failure" in identity.data_stream.error


def test_real_image_hardlink_and_independent_content() -> None:
    """The bundled image exposes one hard link and independent equal-content files."""
    with gzip.open(absolute_path("_data/case_insensitive.bin.gz"), "rb") as fh:
        container = APFS(fh)
        volume = container.volumes[0]

        view = volume.identity_view(
            paths=["dir/file", "hardlink", "dir/compressed-zlib-xattr", "dir/compressed-lzvn-xattr"]
        )

        assert len(view.hardlinks) == 1
        assert view.hardlinks[0].sibling_ids == (21, 22)
        assert {name.name for name in view.hardlinks[0].names} == {"file", "hardlink"}

        # Same content, different private IDs, no shared extents: a content-only relation.
        assert view.clones == ()
        assert len(view.content_matches) == 1
        match = view.content_matches[0]
        assert {match.left.oid, match.right.oid} == {36, 39}
        assert match.left.private_id == 36
        assert match.right.private_id == 39

        summary = view.short_summary()
        kinds = [relation["kind"] for relation in summary["relations"]]
        assert kinds == ["hardlink", "same-content-independent"]


def test_file_identity_open_returns_normal_stream() -> None:
    """``FileIdentity.open`` returns the same bytes as the original inode read path."""
    with gzip.open(absolute_path("_data/case_insensitive.bin.gz"), "rb") as fh:
        container = APFS(fh)
        volume = container.volumes[0]

        node = volume.get("dir/file")
        identity = node.identity(check_content=False)

        assert identity.open().read() == node.open().read() == b"\xef\xa3\xbf File System\n"
        assert identity.data_stream.stream_id == node.private_id
        assert identity.data_stream.status == StreamStatus.OK

        # A cloned sibling identity must still read through the same data stream.
        sibling = volume.get("hardlink").identity(check_content=False)
        assert sibling.private_id == identity.private_id
        assert sibling.open().read() == identity.open().read()


def test_locked_volume_fails_before_building_view() -> None:
    """An encrypted, locked volume raises the existing unlock error instead of returning a partial view."""
    from dissect.apfs.exception import Error

    with gzip.open(absolute_path("_data/encrypted.bin.gz"), "rb") as fh:
        container = APFS(fh)
        volume = container.volumes[0]

        with pytest.raises(Error, match="unlock"):
            volume.identity_view(paths=["dir/file"])


def test_xattr_stream_open() -> None:
    """An xattr data stream preserved in the view remains readable."""
    with gzip.open(absolute_path("_data/case_insensitive.bin.gz"), "rb") as fh:
        container = APFS(fh)
        volume = container.volumes[0]

        identity = volume.get("dir/resourcefork").identity(check_content=False)
        assert len(identity.streams) == 1
        stream = identity.streams[0]
        assert stream.kind == "xattr"
        assert stream.name == "com.apple.ResourceFork"
        assert identity.open_stream(stream.stream_id).read() == b"Resource fork data\n"


def test_partial_stream_is_reported() -> None:
    """A stream with fewer extent bytes than its declared size is reported as partial."""
    identity = FileIdentity(
        volume=_volume(),
        oid=80,
        sibling_id=None,
        private_id=80,
        name_records=(NameEvidence(name="short", parent_oid=2, sibling_id=None, sources=("INODE.NAME",)),),
        streams=(
            StreamIdentity(
                stream_id=80,
                kind="data",
                name=None,
                size=2 * BLOCK_SIZE,
                extents=(_extent(0, 800),),
                status=StreamStatus.PARTIAL,
            ),
        ),
        content=None,
        inode=_FakeINode(80),
    )

    view = analyze_identities(_volume(), [identity])

    observation = next(item for item in view.unresolved if item.scope == "stream")
    assert observation.reference_id == 80
    assert "extents cover 4096 of 8192 bytes" in observation.reason


def test_same_content_and_same_name_do_not_form_hardlink() -> None:
    """Equal content and equal names are still not a hard link without sibling records."""
    left = _identity(90, extents=(_extent(0, 900),), size=BLOCK_SIZE, sha256="c" * 64)
    right = _identity(91, extents=(_extent(0, 901),), size=BLOCK_SIZE, sha256="c" * 64)

    view = analyze_identities(_volume(), [left, right])

    assert view.hardlinks == ()
    assert len(view.content_matches) == 1
    assert view.content_matches[0].left.oid == 90
    assert view.content_matches[0].right.oid == 91


def test_combined_short_metadata_for_all_three_relations() -> None:
    """One small record set shows a hard link, a partial-overwrite clone and an independent equal-content pair."""
    records: dict[tuple[int, c_apfs.APFS_TYPE], list[tuple[bytes, bytes]]] = {}

    def add_inode(
        oid: int, private_id: int, *, size: int, nlink: int, parent_id: int = 2, include_name: bool = True
    ) -> None:
        records.setdefault((oid, c_apfs.APFS_TYPE.INODE), []).append(
            (
                b"",
                _inode_value(
                    oid,
                    private_id,
                    parent_id=parent_id,
                    nlink=nlink,
                    size=size,
                    include_name=include_name,
                )[1],
            )
        )

    def add_extents(private_id: int, extents: tuple[tuple[int, int], ...]) -> None:
        records.setdefault((private_id, c_apfs.APFS_TYPE.FILE_EXTENT), []).extend(
            _extent_value(private_id, logical, physical, BLOCK_SIZE) for logical, physical in extents
        )

    # Hard link: one inode, two sibling records, one private_id.
    add_inode(100, 100, size=BLOCK_SIZE, nlink=2, parent_id=19, include_name=False)
    records[(100, c_apfs.APFS_TYPE.SIBLING_LINK)] = [
        _sibling_value(100, 11, 19, "original"),
        _sibling_value(100, 12, 2, "linked"),
    ]
    add_extents(100, ((0, 4000),))

    # Clone: distinct inode/private_id, first and third blocks shared, middle block overwritten.
    add_inode(101, 101, size=3 * BLOCK_SIZE, nlink=1)
    add_extents(101, ((0, 1000), (BLOCK_SIZE, 1001), (2 * BLOCK_SIZE, 1002)))
    add_inode(102, 102, size=3 * BLOCK_SIZE, nlink=1)
    add_extents(102, ((0, 1000), (BLOCK_SIZE, 2001), (2 * BLOCK_SIZE, 1002)))

    # Independent files: equal content hash, no shared extents and no sibling records.
    add_inode(103, 103, size=BLOCK_SIZE, nlink=1)
    add_extents(103, ((0, 3000),))
    add_inode(104, 104, size=BLOCK_SIZE, nlink=1)
    add_extents(104, ((0, 3001),))

    volume = _FakeVolume(records)
    identities = [
        build_file_identity(volume, INode(volume, 100, 11), check_content=False),
        build_file_identity(volume, INode(volume, 100, 12), check_content=False),
        build_file_identity(volume, INode(volume, 101), check_content=False),
        build_file_identity(volume, INode(volume, 102), check_content=False),
        build_file_identity(volume, INode(volume, 103), check_content=False),
        build_file_identity(volume, INode(volume, 104), check_content=False),
    ]

    # Content hashes are extra evidence only; attach them explicitly for the independent pair.
    identities[4] = replace(
        identities[4],
        content=ContentFingerprint(status=ContentStatus.OK, size=BLOCK_SIZE, sha256="d" * 64),
    )
    identities[5] = replace(
        identities[5],
        content=ContentFingerprint(status=ContentStatus.OK, size=BLOCK_SIZE, sha256="d" * 64),
    )

    view = analyze_identities(_volume(), identities)
    summary = view.short_summary()

    assert [relation["kind"] for relation in summary["relations"]] == [
        "hardlink",
        "clone",
        "same-content-independent",
    ]

    hardlink = summary["relations"][0]
    assert hardlink["oid"] == 100
    assert hardlink["sibling_ids"] == [11, 12]
    assert hardlink["evidence"] == [
        "SIBLING_LINK:oid=100:sibling_id=11",
        "SIBLING_LINK:oid=100:sibling_id=12",
    ]

    clone_relation = view.clones[0]
    assert (clone_relation.left.oid, clone_relation.left.private_id) == (101, 101)
    assert (clone_relation.right.oid, clone_relation.right.private_id) == (102, 102)
    assert [item.physical_start for item in clone_relation.shared] == [1000 * BLOCK_SIZE, 1002 * BLOCK_SIZE]
    assert [(item.start, item.length) for item in clone_relation.left_unshared] == [(BLOCK_SIZE, BLOCK_SIZE)]
    assert [(item.start, item.length) for item in clone_relation.right_unshared] == [(BLOCK_SIZE, BLOCK_SIZE)]

    content_relation = view.content_matches[0]
    assert (content_relation.left.oid, content_relation.right.oid) == (103, 104)
    assert content_relation.evidence[0].startswith("content:sha256=")

    # Every file keeps its own volume-scoped inode identity.
    assert {file["oid"] for file in summary["files"]} == {100, 101, 102, 103, 104}
    assert all(file["private_id"] is not None for file in summary["files"])
    hardlink_rows = [file for file in summary["files"] if file["oid"] == 100]
    assert [(row["sibling_id"], row["private_id"]) for row in hardlink_rows] == [(11, 100), (12, 100)]
    assert [row["names"] for row in hardlink_rows] == [["original", "linked"], ["original", "linked"]]
    assert all(row["content_sha256"] == "d" * 64 for row in summary["files"] if row["oid"] in (103, 104))
