import hashlib
import io
import pathlib

import pytest

import py7zr
import py7zr.io
from py7zr.exceptions import CrcError, DecompressionBombError

testdata_path = pathlib.Path(__file__).parent.joinpath("data")


@pytest.mark.files
def test_recording_receiver_commits_complete_members():
    """A complete member is closed first and only then committed."""
    factory = py7zr.io.RecordingWriterFactory()
    with py7zr.SevenZipFile(testdata_path.joinpath("test_1.7z").open(mode="rb")) as archive:
        archive.extractall(factory=factory)

    assert factory.committed() == ["scripts/py7zr", "setup.cfg", "setup.py"]
    assert factory.cancelled() == []
    for filename in factory.committed():
        events = factory.events(filename)
        assert events[-2:] == ["close", "commit"]
        assert "cancel" not in events
        assert events.count("commit") == 1
        assert events.count("close") == 1
        # The receiver got the whole payload before close.
        assert sum(call[2] for call in factory.calls if call[0] == filename and call[1] == "write") > 0


@pytest.mark.files
def test_recording_receiver_distinguishes_close_failure():
    """A receiver that rejects a member on close is cancelled, not committed."""
    factory = py7zr.io.RecordingWriterFactory(fail_on_close={"setup.cfg"})
    with py7zr.SevenZipFile(testdata_path.joinpath("test_1.7z").open(mode="rb")) as archive:
        with pytest.raises(OSError, match="receiver rejected"):
            archive.extractall(factory=factory)

    assert factory.committed() == ["scripts/py7zr"]
    assert factory.cancelled() == ["setup.cfg"]
    assert factory.events("setup.cfg")[-1] == "cancel"
    assert "commit" not in factory.events("setup.cfg")


@pytest.mark.files
def test_member_interrupted_mid_write_is_cancelled_not_committed():
    """A receiver failure halfway through a member cancels it; nothing is published."""

    class BreakingIO(py7zr.io.RecordingIO):
        def __init__(self, filename, calls):
            super().__init__(filename, calls)

        def write(self, s):
            super().write(s)
            raise OSError("storage connection dropped")

    class BreakingFactory(py7zr.io.RecordingWriterFactory):
        def create(self, filename):
            product = BreakingIO(filename, self.calls)
            self.products[filename] = product
            return product

    factory = BreakingFactory()
    archive = py7zr.SevenZipFile(testdata_path.joinpath("test_1.7z").open(mode="rb"))
    with pytest.raises(OSError, match="storage connection dropped"):
        archive.extractall(factory=factory)
    archive.close()

    assert factory.committed() == []
    assert factory.cancelled() == ["scripts/py7zr"]
    events = factory.events("scripts/py7zr")
    assert events == ["write", "cancel"]
    assert "close" not in events
    assert "commit" not in events


@pytest.mark.files
def test_extraction_abort_cancels_only_started_members():
    """A budget abort cancels in-flight members without committing them."""
    factory = py7zr.io.RecordingWriterFactory()
    archive = py7zr.SevenZipFile(testdata_path.joinpath("mblock_1.7z").open(mode="rb"), max_extract_size=10000)
    with pytest.raises(DecompressionBombError):
        archive.extractall(factory=factory)
    archive.close()

    cancelled = factory.cancelled()
    assert "C/7zArcIn.c" in cancelled
    assert set(cancelled).isdisjoint(factory.committed())


@pytest.mark.files
def test_crc_failure_cancels_member_without_close():
    """A member that fails its CRC check is cancelled, never closed/committed."""
    factory = py7zr.io.RecordingWriterFactory()
    archive = py7zr.SevenZipFile(testdata_path.joinpath("crc_corrupted.7z"), "r")
    with pytest.raises(CrcError):
        archive.extractall(factory=factory)
    archive.close()

    assert factory.committed() == []
    assert factory.cancelled() == ["src/scripts/py7zr"]
    events = factory.events("src/scripts/py7zr")
    assert "close" not in events
    assert "commit" not in events
    assert events[-1] == "cancel"


@pytest.mark.unit
def test_memio_status_tracks_commit_and_cancel():
    factory = py7zr.io.RecordingWriterFactory()

    committed = py7zr.io.MemIO("done.txt", factory)
    with committed.open("wb") as handle:
        handle.write(b"payload")
    assert committed.committed is True
    assert committed.status is py7zr.io.MemberStatus.COMMITTED
    assert factory.events("done.txt") == ["write", "close", "commit"]

    cancelled = py7zr.io.MemIO("partial.txt", factory)
    with pytest.raises(RuntimeError):
        with cancelled.open("wb") as handle:
            handle.write(b"hal")
            raise RuntimeError("interrupted")
    assert cancelled.committed is False
    assert cancelled.status is py7zr.io.MemberStatus.CANCELLED
    assert factory.events("partial.txt") == ["write", "cancel"]


@pytest.mark.unit
def test_receiver_commit_failure_cancels_member():
    class CommitFails(py7zr.Py7zIO):
        def __init__(self):
            self._buf = io.BytesIO()
            self.cancelled = False
            self.close_called = False

        def write(self, s):
            return self._buf.write(s)

        def read(self, size=None):
            return self._buf.read(size)

        def seek(self, offset, whence=0):
            return self._buf.seek(offset, whence)

        def flush(self):
            pass

        def size(self):
            return self._buf.getbuffer().nbytes

        def close(self):
            self.close_called = True

        def commit(self):
            raise OSError("backend rejected commit")

        def cancel(self):
            self.cancelled = True

    class Factory(py7zr.WriterFactory):
        def __init__(self):
            self.product = None

        def create(self, filename):
            self.product = CommitFails()
            return self.product

    factory = Factory()
    memio = py7zr.io.MemIO("payload.bin", factory)
    with pytest.raises(OSError, match="backend rejected commit"):
        with memio.open("wb") as handle:
            handle.write(b"payload")

    assert factory.product.close_called is True
    assert factory.product.cancelled is True
    assert memio.status is py7zr.io.MemberStatus.CANCELLED


@pytest.mark.files
def test_legacy_memory_factories_still_work():
    """Factories written before commit/cancel existed keep their behaviour."""
    bytes_factory = py7zr.io.BytesIOFactory(64)
    with py7zr.SevenZipFile(testdata_path.joinpath("test_1.7z").open(mode="rb")) as archive:
        archive.extractall(factory=bytes_factory)
    assert bytes_factory.get("setup.cfg").read().startswith(b"[flake8]")

    hash_factory = py7zr.io.HashIOFactory()
    with py7zr.SevenZipFile(testdata_path.joinpath("github_14.7z").open(mode="rb")) as archive:
        archive.extractall(factory=hash_factory)
    expected = hashlib.sha256(b"Hello GitHub issue #14.\n").digest()
    assert hash_factory.get("github_14").read() == expected

    null_factory = py7zr.io.NullIOFactory()
    with py7zr.SevenZipFile(testdata_path.joinpath("zerosize.7z").open(mode="rb")) as archive:
        archive.extractall(factory=null_factory)


@pytest.mark.files
def test_legacy_close_only_receiver_still_works():
    """A pre-existing receiver that only overrides close() still finalizes."""

    class LegacyIO(py7zr.Py7zIO):
        def __init__(self):
            self._buf = io.BytesIO()
            self.closed = False

        def write(self, s):
            return self._buf.write(s)

        def read(self, size=None):
            return self._buf.read(size)

        def seek(self, offset, whence=0):
            return self._buf.seek(offset, whence)

        def flush(self):
            pass

        def size(self):
            return self._buf.getbuffer().nbytes

        def close(self):
            self.closed = True

    class LegacyFactory(py7zr.WriterFactory):
        def __init__(self):
            self.products = []

        def create(self, filename):
            product = LegacyIO()
            self.products.append(product)
            return product

    factory = LegacyFactory()
    with py7zr.SevenZipFile(testdata_path.joinpath("github_14.7z").open(mode="rb")) as archive:
        archive.extractall(factory=factory)
    assert len(factory.products) == 1
    assert factory.products[0].closed is True
