# Copyright (C) 2019-2022  Chris Lalancette <clalancette@gmail.com>

# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation;
# version 2.1 of the License.

# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.

# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

"""PyCdlibIO class."""

import io

from pycdlib import inode
from pycdlib import pycdlibexception

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import array
    import ctypes  # noqa: F401
    from mmap import mmap
    import pickle  # noqa: F401
    from typing import Any, List, Optional, Tuple, Union  # noqa: F401
    # Used as the buffer-protocol parameter type for readinto.  Python 3.12+
    # has collections.abc.Buffer (PEP 688), but the override already needs a
    # Liskov suppression on every Python anyway, so enumerate the common
    # writable-buffer concrete types and keep the type uniform across all
    # versions.
    Buffer = bytearray | memoryview | array.array | mmap
    # NOTE: this import has to be here to avoid circular deps
    from pycdlib import dr as dr_module  # noqa: F401  pylint: disable=cyclic-import


class PyCdlibIO(io.RawIOBase):
    """
    The class that implements the user-facing python io-style context manager.
    Since ISOs are generally only readable, this is only a readable context
    manager.
    """
    __slots__ = ('_ctxt', '_fp', '_length', '_offset', '_open', '_startpos',
                 '_chunks', '_head_record', '_logical_block_size')

    def __init__(self, ino, logical_block_size, head_record=None):
        # type: (inode.Inode, int, Optional[dr_module.DirectoryRecord]) -> None
        super().__init__()
        self._ctxt = inode.InodeOpenData(ino, logical_block_size)
        self._open = True
        # head_record is set for an ISO9660 / Joliet file, whose data may be
        # spread over a multi-extent data_continuation chain.  UDF File
        # Entries always live in a single Inode and pass None, in which case
        # the whole Inode is the one and only chunk.
        self._head_record = head_record
        self._logical_block_size = logical_block_size
        self._chunks = []  # type: List[Tuple[int, int]]

    def __enter__(self):
        # _fp is the real file descriptor.  _length is the logical length
        # of the file.  _offset is the logical offset of this context
        # into the file.  _startpos is the absolute offset of the start of
        # this file into the backing file.  _chunks is a list of
        # (absolute byte start, length) pairs describing each contiguous run
        # of the file in file order, so streaming reads use exactly the same
        # interpretation as get_file_from_iso_fp.
        (self._fp, inode_length) = self._ctxt.__enter__()
        self._startpos = self._fp.tell()
        self._offset = 0

        self._chunks = []
        if self._head_record is None:
            self._chunks.append((self._startpos, inode_length))
        else:
            record = self._head_record
            while record is not None:
                if record.inode is None or record.data_length == 0:
                    # A legal zero-length final record contributes no bytes;
                    # it still terminates the chain by having no continuation.
                    break
                # In parse mode every chunk has its own Inode positioned at
                # the chunk's extent; in the mastered mode all chunks share
                # one Inode and data_extent_offset gives the block offset
                # into its extent run.  Resolve the absolute backing
                # position from the record's own Inode either way.
                chunk_inode = record.inode
                if chunk_inode.original_data_location == chunk_inode.DATA_ON_ORIGINAL_ISO:
                    chunk_start = chunk_inode.orig_extent_loc * self._logical_block_size
                else:
                    chunk_start = self._startpos + record.data_extent_offset * self._logical_block_size
                self._chunks.append((chunk_start, record.data_length))
                record = record.data_continuation

        self._length = sum(chunk_length for _, chunk_length in self._chunks)
        return self

    def _resolve_offset(self, offset):
        # type: (int) -> Tuple[int, int]
        """
        Translate a logical offset within the file into an absolute backing
        file position and the number of bytes available from that position to
        the end of the contiguous chunk that contains it.

        Args:
            offset: The logical byte offset into the file.
        Returns:
            A tuple of (absolute position in the backing file, bytes remaining
            in the containing chunk).
        """
        remaining = offset
        for chunk_start, chunk_length in self._chunks:
            if remaining < chunk_length:
                return chunk_start + remaining, chunk_length - remaining
            remaining -= chunk_length
        # At or past EOF: point at the end of the last chunk with nothing left.
        if self._chunks:
            chunk_start, chunk_length = self._chunks[-1]
            return chunk_start + chunk_length, 0
        return self._startpos, 0

    def _read_up_to(self, readsize):
        # type: (int) -> bytes
        """
        Read up to readsize logical bytes starting at the current offset,
        crossing multi-extent chunk boundaries as needed.

        Args:
            readsize: The maximum number of bytes to read.
        Returns:
            The bytes read; fewer than readsize only at EOF.
        """
        parts = []  # type: List[bytes]
        while readsize > 0 and self._offset < self._length:
            position, chunk_remaining = self._resolve_offset(self._offset)
            this_read = min(readsize, chunk_remaining)
            # _fp is the ISO's shared file descriptor; any other pycdlib
            # operation (a second open_file_from_iso, write_fp, an
            # internal _seek_to_extent, ...) can move its position
            # between our reads.  Re-seek to the start of our slice on
            # every read rather than trust accumulated state.
            self._fp.seek(position)
            data = self._fp.read(this_read)
            if not data:
                break
            parts.append(data)
            got = len(data)
            self._offset += got
            readsize -= got
        return b''.join(parts)

    def read(self, size=None):
        # type: (Optional[int]) -> bytes
        """
        Read and return up to size bytes.

        Args:
            size: Optional parameter to read size number of bytes; if None or
                negative, all remaining bytes in the file will be read
        Returns:
            The number of bytes requested or the rest of the data left in the file,
            whichever is smaller.  If the file is at or past EOF, returns an empty
            bytestring.
        """
        if not self._open:
            raise pycdlibexception.PyCdlibInvalidInput('I/O operation on closed file.')

        if self._offset >= self._length:
            return b''

        if size is None or size < 0:
            data = self.readall()
        else:
            data = self._read_up_to(min(self._length - self._offset, size))

        return data

    def readall(self):
        # type: () -> bytes
        """
        Read and return the remaining bytes in the file.

        Returns:
            The rest of the data left in the file.  If the file is at or past EOF,
            returns an empty bytestring.
        """
        if not self._open:
            raise pycdlibexception.PyCdlibInvalidInput('I/O operation on closed file.')

        readsize = self._length - self._offset
        if readsize > 0:
            data = self._read_up_to(readsize)
        else:
            data = b''

        return data

    def readinto(self, b):  # type: ignore[override]
        # type: (Buffer) -> int
        """
        Read bytes into a pre-allocated, writable buffer.

        Args:
            b: A writable bytes-like object to read into.
        Returns:
            The number of bytes read and stored into the buffer.  This is 0 if
            the file is at or past EOF.
        """
        if not self._open:
            raise pycdlibexception.PyCdlibInvalidInput('I/O operation on closed file.')

        readsize = self._length - self._offset
        if readsize > 0:
            mv = memoryview(b)
            m = mv.cast('B')
            data = self._read_up_to(min(readsize, len(m)))
            n = len(data)
            m[:n] = data
        else:
            n = 0

        return n

    def seek(self, offset, whence=0):
        # type: (int, int) -> int
        """
        Change the stream position to byte offset offset.  The offset is
        interpreted relative to the position indicated by whence.  Valid values
        for whence are:

        * 0 -- start of stream (the default); offset should be zero or positive
        * 1 -- current stream position; offset may be negative
        * 2 -- end of stream; offset is usually negative

        Args:
            offset: The byte offset to seek to.
            whence: The position in the file to start from (0 for start, 1 for
                current, 2 for end)
        Returns:
            The new absolute position.
        """
        if not self._open:
            raise pycdlibexception.PyCdlibInvalidInput('I/O operation on closed file.')

        if isinstance(offset, float):
            raise pycdlibexception.PyCdlibInvalidInput('an integer is required')

        if whence == 0:
            # From beginning of file
            if offset < 0:
                raise pycdlibexception.PyCdlibInvalidInput('Invalid offset value (must be positive)')
            self._offset = offset
        elif whence == 1:
            # From current file position
            if self._offset + offset < 0:
                raise pycdlibexception.PyCdlibInvalidInput('Invalid offset value (cannot seek before start of file)')
            self._offset += offset
        elif whence == 2:
            # From end of file
            if offset < 0 and abs(offset) > self._length:
                raise pycdlibexception.PyCdlibInvalidInput('Invalid offset value (cannot seek before start of file)')
            self._offset = self._length + offset
        else:
            raise pycdlibexception.PyCdlibInvalidInput('Invalid value for whence (options are 0, 1, and 2)')

        # Position the shared backing descriptor at the resolved location so a
        # subsequent raw read starts in the right chunk.
        position, _ = self._resolve_offset(min(self._offset, self._length))
        self._fp.seek(position, 0)

        return self._offset

    def tell(self):
        # type: () -> int
        """
        Return the current stream position.

        Returns:
            The current stream position.
        """
        if not self._open:
            raise pycdlibexception.PyCdlibInvalidInput('I/O operation on closed file.')
        return self._offset

    def length(self):
        # type: () -> int
        """
        Return the length of the current file.

        Returns:
            The length of the file.
        """
        if not self._open:
            raise pycdlibexception.PyCdlibInvalidInput('I/O operation on closed file.')
        return self._length

    def readable(self):
        # type: () -> bool
        """
        Determine whether this file is readable.

        Returns:
            True in all cases.
        """
        if not self._open:
            raise pycdlibexception.PyCdlibInvalidInput('I/O operation on closed file.')
        return True

    def seekable(self):
        # type: () -> bool
        """
        Determine whether this file is seekable.

        Returns:
            True in all cases.
        """
        if not self._open:
            raise pycdlibexception.PyCdlibInvalidInput('I/O operation on closed file.')
        return True

    def close(self):
        # type: () -> None
        """
        Close this file stream.

        Returns:
            Nothing.
        """
        self._open = False
        self._ctxt.__exit__()

    def __exit__(self, *args):
        self._ctxt.__exit__()
