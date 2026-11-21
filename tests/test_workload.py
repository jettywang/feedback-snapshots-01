import pytest

import py7zr
from py7zr.exceptions import DecompressionBombError
from py7zr.io import Py7zBytesIO, WriterFactory

# Two solid blocks with distinctive member sizes, so that prefix sums
# inside a block are unambiguous.
BLOCK_A_SIZES = [100, 200, 400, 800]
BLOCK_B_SIZES = [1000, 2000, 4000, 8000]


def _payload(size: int, seed: int) -> bytes:
    return bytes((seed + i) % 251 for i in range(size))


def _make_two_block_archive(path):
    """Write a solid archive whose members live in two solid blocks."""
    with py7zr.SevenZipFile(path, "w") as archive:
        for i, size in enumerate(BLOCK_A_SIZES):
            archive.writestr(_payload(size, i), f"a{i}.bin")
    # appending adds the new members as a second solid block
    with py7zr.SevenZipFile(path, "a") as archive:
        for i, size in enumerate(BLOCK_B_SIZES):
            archive.writestr(_payload(size, 10 + i), f"b{i}.bin")
    return path


class RecordingFactory(WriterFactory):
    """Fake WriterFactory that records every output stream py7zr starts."""

    def __init__(self):
        self.created: list[str] = []
        self.products: dict[str, Py7zBytesIO] = {}

    def create(self, filename: str) -> Py7zBytesIO:
        self.created.append(filename)
        product = Py7zBytesIO(filename, 1 << 30)
        self.products[filename] = product
        return product


@pytest.mark.api
def test_workload_first_member_of_solid_block(tmp_path):
    archive_path = _make_two_block_archive(tmp_path / "solid.7z")
    with py7zr.SevenZipFile(archive_path) as archive:
        assert archive.archiveinfo().blocks == 2
        # the first member of a block is reached without touching anything else
        assert archive.get_extract_workload(["a0.bin"]) == BLOCK_A_SIZES[0]
        assert archive.get_extract_workload(["b0.bin"]) == BLOCK_B_SIZES[0]


@pytest.mark.api
def test_workload_later_member_counts_solid_prefix(tmp_path):
    archive_path = _make_two_block_archive(tmp_path / "solid.7z")
    with py7zr.SevenZipFile(archive_path) as archive:
        # a2.bin sits third in its block: the two preceding members must be
        # decompressed to reach it, the trailing a3.bin must not.
        assert archive.get_extract_workload(["a2.bin"]) == sum(BLOCK_A_SIZES[:3])
        assert archive.get_extract_workload(["b1.bin"]) == sum(BLOCK_B_SIZES[:2])


@pytest.mark.api
def test_workload_cross_block_selection(tmp_path):
    archive_path = _make_two_block_archive(tmp_path / "solid.7z")
    with py7zr.SevenZipFile(archive_path) as archive:
        # each block contributes the prefix up to its last selected member
        expected = sum(BLOCK_A_SIZES[:2]) + sum(BLOCK_B_SIZES[:3])
        assert archive.get_extract_workload(["a1.bin", "b2.bin"]) == expected
        # a block without selected members costs nothing
        assert archive.get_extract_workload(["b2.bin"]) == sum(BLOCK_B_SIZES[:3])
        # no selection means everything
        assert archive.get_extract_workload() == sum(BLOCK_A_SIZES) + sum(BLOCK_B_SIZES)


@pytest.mark.api
def test_max_workload_accepts_at_limit(tmp_path):
    archive_path = _make_two_block_archive(tmp_path / "solid.7z")
    with py7zr.SevenZipFile(archive_path) as archive:
        workload = archive.get_extract_workload(["a2.bin"])
        factory = RecordingFactory()
        with py7zr.SevenZipFile(archive_path, max_workload=workload) as guarded:
            guarded.extract(targets=["a2.bin"], factory=factory)
        assert factory.created == ["a2.bin"]
        assert factory.products["a2.bin"].read() == _payload(BLOCK_A_SIZES[2], 2)


@pytest.mark.api
def test_max_workload_rejects_before_any_output(tmp_path):
    archive_path = _make_two_block_archive(tmp_path / "solid.7z")
    with py7zr.SevenZipFile(archive_path) as archive:
        workload = archive.get_extract_workload(["a2.bin"])
    factory = RecordingFactory()
    with py7zr.SevenZipFile(archive_path, max_workload=workload - 1) as guarded:
        with pytest.raises(DecompressionBombError):
            guarded.extract(targets=["a2.bin"], factory=factory)
    # the rejected request never started any output stream
    assert factory.created == []
    assert factory.products == {}


@pytest.mark.api
def test_max_workload_rejects_before_any_file_output(tmp_path):
    archive_path = _make_two_block_archive(tmp_path / "solid.7z")
    with py7zr.SevenZipFile(archive_path) as archive:
        workload = archive.get_extract_workload(["a2.bin"])
    outdir = tmp_path / "out"
    with py7zr.SevenZipFile(archive_path, max_workload=workload - 1) as guarded:
        with pytest.raises(DecompressionBombError):
            guarded.extract(path=outdir, targets=["a2.bin"])
    assert not list(outdir.rglob("*"))


@pytest.mark.api
def test_max_workload_reject_then_accept_after_reset(tmp_path):
    archive_path = _make_two_block_archive(tmp_path / "solid.7z")
    with py7zr.SevenZipFile(archive_path) as archive:
        workload = archive.get_extract_workload(["a2.bin"])
    factory = RecordingFactory()
    with py7zr.SevenZipFile(archive_path, max_workload=workload - 1) as guarded:
        with pytest.raises(DecompressionBombError):
            guarded.extract(targets=["a2.bin"], factory=factory)
        guarded.max_workload = workload
        guarded.reset()
        guarded.extract(targets=["a2.bin"], factory=factory)
    assert factory.created == ["a2.bin"]
