#!/usr/bin/env python
#
#    Pure python p7zr implementation
#    Copyright (C) 2019-2024 Hiroshi Miura
#
#    This library is free software; you can redistribute it and/or
#    modify it under the terms of the GNU Lesser General Public
#    License as published by the Free Software Foundation; either
#    version 2.1 of the License, or (at your option) any later version.
#
#    This library is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
#    Lesser General Public License for more details.
#
#    You should have received a copy of the GNU Lesser General Public
#    License along with this library; if not, write to the Free Software
#    Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
import hashlib
import io
from abc import ABC, abstractmethod
from collections.abc import Collection
from enum import Enum


class MemberStatus(Enum):
    """Lifecycle state of one member written through a :class:`WriterFactory`.

    The value is exposed by :attr:`MemIO.status` so a receiver, or code that
    owns the factory, can tell a durable member from a discarded one. The
    states are entered in this order:

    ``PENDING``
        A :class:`Py7zIO` was created but py7zr has not started writing.
    ``WRITING``
        Member data is being written.
    ``COMMITTED``
        py7zr wrote the whole member, its integrity check passed,
        :meth:`Py7zIO.close` returned normally and :meth:`Py7zIO.commit`
        was called.
    ``CANCELLED``
        The member was abandoned. :meth:`Py7zIO.commit` was not called;
        :meth:`Py7zIO.cancel` was called instead when the receiver had
        already been created.
    """

    PENDING = "pending"
    WRITING = "writing"
    COMMITTED = "committed"
    CANCELLED = "cancelled"


class Py7zIO(ABC):
    """Abstract binary stream that receives one extracted archive member.

    Objects of this type are created by a :class:`WriterFactory` passed as
    ``factory`` to :meth:`py7zr.SevenZipFile.extract` or
    :meth:`py7zr.SevenZipFile.extractall`. The interface is similar to
    :class:`typing.BinaryIO` with an additional :meth:`size` method.

    py7zr may extract members in worker threads, so implementations should
    be thread-safe.

    A receiver created by :meth:`WriterFactory.create` ends in exactly one of
    two ways: the member is complete and the archive integrity check passed,
    then :meth:`close` runs and, if it returns, :meth:`commit` follows; or
    something failed, then :meth:`cancel` runs instead and :meth:`commit` is
    never called. Both hooks are optional no-ops, so a subclass that only
    overrides ``write``/``close`` keeps its previous behaviour.
    """

    @abstractmethod
    def write(self, s: bytes | bytearray) -> int:
        """Receive the next chunk of the member's data.

        Called repeatedly while the member is decompressed; append *s* to
        whatever was written before.

        :return: The number of bytes written.
        """
        pass

    @abstractmethod
    def read(self, size: int | None = None) -> bytes:
        """Return up to *size* bytes, or all remaining data when *size* is ``None``."""
        pass

    @abstractmethod
    def seek(self, offset: int, whence: int = 0) -> int:
        """Change the stream position, as :meth:`io.IOBase.seek`.

        :return: The new absolute position.
        """
        pass

    @abstractmethod
    def flush(self) -> None:
        """Flush buffered data, if any."""
        pass

    @abstractmethod
    def size(self) -> int:
        """Return the number of bytes written so far."""
        pass

    def close(self) -> None:
        """Finalize one fully received member.

        Called by py7zr once after all of the member's data has been written
        and its integrity check (CRC, and the folder digest when available)
        has passed. Override to validate the payload, flush buffers, or apply
        the receiver's own final checks before the member is published.

        Raising from ``close`` rejects the member: py7zr then calls
        :meth:`cancel` instead of :meth:`commit` and propagates the
        exception, so a receiver that cannot finalize a payload is never
        reported as archived. The default implementation is a no-op for
        backward compatibility with receivers written before this hook
        existed.

        :raises Exception: To reject an otherwise complete member.
        """
        return None

    def commit(self) -> None:
        """Publish a member after both sides succeeded.

        py7zr calls this once, immediately after :meth:`close` returns
        normally, and only when the archive's integrity check passed and the
        receiver accepted the payload. Implementations should make the data
        durably visible here, or record the success, but must not receive
        more member data afterwards.

        ``commit`` is never called for a member whose decompression failed,
        whose CRC check failed, whose :meth:`close` raised, or whose
        ``write``/``flush`` raised. :meth:`cancel` is called instead.
        The default implementation is a no-op so receivers without
        transactional support keep working.

        py7zr does not use the return value. An exception raised by
        ``commit`` marks the member failed: py7zr calls :meth:`cancel`,
        propagates the exception, and never retries the commit.
        """
        return None

    def cancel(self) -> None:
        """Discard an incomplete or rejected member.

        Called at most once for a member that was created by
        :meth:`WriterFactory.create` but did not reach :meth:`commit`, for
        example after a decompression error, a CRC mismatch, an interrupted
        extraction, a failure in :meth:`close`, or a failure in
        :meth:`commit` itself. Implementations should delete partial data or
        leave it marked as uncommitted; they must not publish it.

        ``cancel`` is the only lifecycle call a partially written member
        receives after the failure. In particular, :meth:`close` is not
        called for a member that failed before its data was complete.
        The default implementation is a no-op for backward compatibility.
        """
        return None


class HashIO(Py7zIO):
    def __init__(self, filename):
        self.filename = filename
        self.hash = hashlib.sha256()
        self._size: int = 0

    def write(self, s: bytes | bytearray) -> int:
        self._size += len(s)
        self.hash.update(s)
        return len(s)

    def read(self, length: int | None = None) -> bytes:
        return self.hash.digest()

    def seek(self, offset: int, whence: int = 0) -> int:
        return 0

    def flush(self) -> None:
        pass

    def size(self) -> int:
        return self._size


class Py7zBytesIO(Py7zIO):
    def __init__(self, filename: str, limit: int):
        self.filename = filename
        self.limit = limit
        self._buffer = io.BytesIO()

    def write(self, s: bytes | bytearray) -> int:
        if self.size() < self.limit:
            return self._buffer.write(s)
        else:
            return 0

    def read(self, size: int | None = None) -> bytes:
        return self._buffer.read(size)

    def seek(self, offset: int, whence: int = 0) -> int:
        return self._buffer.seek(offset, whence)

    def flush(self) -> None:
        return self._buffer.flush()

    def size(self) -> int:
        current_pos = self._buffer.tell()
        self._buffer.seek(0, io.SEEK_END)
        size = self._buffer.tell()
        self._buffer.seek(current_pos)
        return size


class WriterFactory(ABC):
    """Abstract factory that creates a :class:`Py7zIO` object for each extracted member.

    Pass an instance as ``factory`` to :meth:`py7zr.SevenZipFile.extract` or
    :meth:`py7zr.SevenZipFile.extractall` to receive member data in memory or
    stream it elsewhere instead of writing files to disk.
    See :ref:`advanced_usage` for examples.

    Each member created by :meth:`create` goes through one of two lifecycles:

    * complete member: data is written, the archive integrity check passes,
      :meth:`Py7zIO.close` returns normally, then :meth:`Py7zIO.commit` is
      called exactly once;
    * failed member: if writing, the integrity check, :meth:`Py7zIO.close`
      or :meth:`Py7zIO.commit` fails, :meth:`Py7zIO.cancel` is called
      instead, at most once, and :meth:`Py7zIO.commit` is not called.

    A member that fails before any data arrives is not passed a
    ``cancel`` call if :meth:`create` was never reached for it. The
    factory therefore needs no extra bookkeeping to remain compatible with
    receivers that were written before ``commit``/``cancel`` existed.
    """

    @abstractmethod
    def create(self, filename: str) -> Py7zIO:
        """Return a new :class:`Py7zIO` object that will receive the member *filename*.

        :param filename: The member's output path, using ``/`` as separator.
            Directories and special files are skipped, so this is only called
            for regular files and symbolic links.
        """
        pass


class HashIOFactory(WriterFactory):
    def __init__(self):
        self.products = {}

    def create(self, filename: str) -> Py7zIO:
        product = HashIO(filename)
        self.products[filename] = product
        return product

    def get(self, filename: str) -> Py7zIO:
        return self.products[filename]


class BytesIOFactory(WriterFactory):

    def __init__(self, limit: int):
        self.limit = limit
        self.products: dict[str, Py7zBytesIO] = {}

    def create(self, filename: str) -> Py7zIO:
        product = Py7zBytesIO(filename, self.limit)
        self.products[filename] = product
        return product

    def get(self, filename):
        return self.products[filename]


class NullIOFactory(WriterFactory):
    def __init__(self):
        pass

    def create(self, filename: str) -> Py7zIO:
        return NullIO()


class RecordingIO(Py7zIO):
    """Test receiver that records lifecycle calls without storing payload data.

    Every call is appended to the shared *calls* list of the owning
    :class:`RecordingWriterFactory` as ``(filename, event)``. The events are
    ``"write"``, ``"flush"``, ``"close"``, ``"commit"`` and ``"cancel"``.
    ``write`` entries also carry the byte count as a third tuple item.

    The receiver never persists anything, so it is suitable for asserting
    which callbacks py7zr produced for complete and failed members. Set
    ``fail_on_close`` to simulate a receiver that rejects a complete payload
    during :meth:`close`.
    """

    def __init__(self, filename: str, calls: list[tuple], fail_on_close: bool = False):
        self.filename = filename
        self._calls = calls
        self._fail_on_close = fail_on_close
        self._size = 0

    def write(self, s: bytes | bytearray) -> int:
        self._size += len(s)
        self._calls.append((self.filename, "write", len(s)))
        return len(s)

    def read(self, size: int | None = None) -> bytes:
        return b""

    def seek(self, offset: int, whence: int = 0) -> int:
        return offset

    def flush(self) -> None:
        self._calls.append((self.filename, "flush"))

    def size(self) -> int:
        return self._size

    def close(self) -> None:
        self._calls.append((self.filename, "close"))
        if self._fail_on_close:
            raise OSError(f"receiver rejected {self.filename!r} on close")

    def commit(self) -> None:
        self._calls.append((self.filename, "commit"))

    def cancel(self) -> None:
        self._calls.append((self.filename, "cancel"))


class RecordingWriterFactory(WriterFactory):
    """Factory for :class:`RecordingIO` that keeps the call log.

    *fail_on_close* names members whose receiver raises from ``close`` so
    tests can distinguish a committed member from one the receiver rejected.
    """

    def __init__(self, fail_on_close: Collection[str] | None = None):
        self.calls: list[tuple] = []
        self.products: dict[str, RecordingIO] = {}
        self._fail_on_close = set(fail_on_close or ())

    def create(self, filename: str) -> Py7zIO:
        product = RecordingIO(filename, self.calls, filename in self._fail_on_close)
        self.products[filename] = product
        return product

    def events(self, filename: str) -> list[str]:
        """Return the recorded event names for *filename*, in call order."""
        return [event for name, event, *_ in self.calls if name == filename]

    def committed(self) -> list[str]:
        """Return the member names that reached ``commit``."""
        return [name for name, event, *_ in self.calls if event == "commit"]

    def cancelled(self) -> list[str]:
        """Return the member names that reached ``cancel``."""
        return [name for name, event, *_ in self.calls if event == "cancel"]


class MemIO:
    """pathlib.Path-like IO class to write memory.

    Adapts a :class:`Py7zIO` returned by a :class:`WriterFactory` to the
    file-like interface used by the extraction worker, and drives the
    receiver lifecycle: :meth:`Py7zIO.close` runs when the member's data is
    complete, :meth:`Py7zIO.commit` only after a successful close, and
    :meth:`Py7zIO.cancel` on any failure. The resulting :attr:`status` is
    available to code that holds the :class:`MemIO` (for example a factory
    or the worker), while the receiver itself observes the hook calls.
    """

    def __init__(self, fname: str, factory: WriterFactory):
        self._buf: Py7zIO | None = None
        self._closed = True
        self._status = MemberStatus.PENDING
        self.fname = fname
        self.factory = factory

    @property
    def mode(self) -> str:
        return self._mode

    @property
    def name(self) -> str:
        return self.fname

    @property
    def closed(self) -> bool:
        return self._closed

    @property
    def status(self) -> MemberStatus:
        """Return the lifecycle state of this member."""
        return self._status

    @property
    def committed(self) -> bool:
        """Return ``True`` only when the receiver committed this member."""
        return self._status is MemberStatus.COMMITTED

    def size(self) -> int:
        return self.__sizeof__()

    def __sizeof__(self) -> int:
        if self._buf is None:
            return -1
        return self._buf.size()

    def flush(self) -> None:
        if self._buf is not None:
            self._buf.flush()

    def write(self, s: bytes | bytearray) -> int:
        if self._buf is None:
            return -1
        if self._status is MemberStatus.PENDING:
            self._status = MemberStatus.WRITING
        return self._buf.write(s)

    def read(self, length: int | None = None) -> bytes:
        if self._buf is None:
            return b""
        if length is not None:
            return self._buf.read(length)
        else:
            return self._buf.read()

    def _cancel(self) -> None:
        if self._status in (MemberStatus.COMMITTED, MemberStatus.CANCELLED):
            return
        self._status = MemberStatus.CANCELLED
        self._closed = True
        if self._buf is not None:
            try:
                self._buf.cancel()
            except Exception:
                # Keep the failure that caused the cancellation as the one
                # reported to the caller.
                pass

    def close(self) -> None:
        """Finalize the receiver, then commit it.

        ``close`` is only reached after the worker wrote the whole member and
        the archive's integrity check passed. The receiver's
        :meth:`Py7zIO.close` runs first; if it returns normally py7zr calls
        :meth:`Py7zIO.commit`. Any failure in either hook cancels the member
        and is re-raised, so a rejected member is never reported as
        committed.
        """
        if self._status is MemberStatus.COMMITTED:
            return
        if self._status is MemberStatus.CANCELLED:
            return
        self._closed = True
        if self._buf is None:
            # No receiver was ever created, so there is nothing to publish
            # or discard.
            return
        try:
            # The rewind exists so that seekable factory products (e.g.
            # BytesIOFactory) can be read back after extraction.  A non-seekable
            # destination (such as zipfile.ZipFile.open, see issue #703) cannot
            # be rewound and must not be asked to.
            if getattr(self._buf, "seekable", lambda: True)():
                self._buf.seek(0)
            self._buf.close()
            self._buf.commit()
        except Exception:
            self._cancel()
            raise
        else:
            self._status = MemberStatus.COMMITTED

    def seek(self, offset: int, whence: int = 0) -> int:
        if self._buf is None:
            return -1
        return self._buf.seek(offset, whence)

    def open(self, mode: str = "w"):
        self._mode = mode
        self._closed = False
        self._status = MemberStatus.PENDING
        if self._buf is None:
            self._buf = self.factory.create(self.fname)
        else:
            self._buf.seek(0)
        return self

    @property
    def parent(self):
        return self

    def __enter__(self):
        return self

    def abort(self) -> None:
        """Discard this member without calling the receiver's ``close``.

        Used by the extraction worker when a member cannot be published, for
        example because its CRC check failed after the data was written.
        """
        self._cancel()

    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type is None:
            self.close()
        else:
            # Extraction failed (e.g. CRC or decompression error) before the
            # member was complete; tell the receiver to discard it. A
            # partially written member must never be reported as committed.
            self._cancel()


class NullIO(Py7zIO):
    """pathlib.Path-like IO class of /dev/null"""

    def __init__(self):
        pass

    def write(self, data):
        return len(data)

    def read(self, length=None):
        if length is not None:
            return bytes(length)
        else:
            return b""

    def close(self):
        pass

    def flush(self):
        pass

    def open(self, mode=None):
        return self

    @property
    def parent(self):
        return self

    def mkdir(self):
        return None

    def seek(self, offset: int, whence: int = 0) -> int:
        return offset

    def size(self):
        return 0

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        pass


class BufferOverflow(Exception):
    pass


class Buffer:
    def __init__(self, size: int = 16):
        self._buf = bytearray(size)
        self._buflen = 0
        self.view = memoryview(self._buf[0:0])

    def add(self, data: bytes | bytearray | memoryview):
        length = len(data)
        self._buf[self._buflen :] = data
        self._buflen += length
        self.view = memoryview(self._buf[0 : self._buflen])

    def reset(self) -> None:
        self._buflen = 0
        self.view = memoryview(self._buf[0:0])

    def set(self, data: bytes | bytearray | memoryview) -> None:
        length = len(data)
        self._buf[0:] = data
        self._buflen = length
        self.view = memoryview(self._buf[0:length])

    def get(self) -> bytearray:
        val = self._buf[: self._buflen]
        self.reset()
        return val

    def __len__(self) -> int:
        return self._buflen

    def __bytes__(self):
        return bytes(self._buf[0 : self._buflen])
