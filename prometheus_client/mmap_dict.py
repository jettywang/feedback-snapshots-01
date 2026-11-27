import json
import mmap
import os
import struct
import time
from typing import List

try:
    import fcntl
except ImportError:
    fcntl = None

_INITIAL_MMAP_SIZE = 1 << 16
_pack_integer_func = struct.Struct(b'i').pack
_pack_two_doubles_func = struct.Struct(b'dd').pack
_pack_session_func = struct.Struct(b'I').pack
_unpack_integer = struct.Struct(b'i').unpack_from
_unpack_two_doubles = struct.Struct(b'dd').unpack_from
_unpack_session = struct.Struct(b'I').unpack_from

# The four padding bytes between the used-count header and the first entry are
# ignored by older readers, so they are safe to use for a write-session token.
# A value of 0 means "no session recorded" (a file written by an older client).
_SESSION_OFFSET = 4
_SESSION_SIZE = 4
_SESSION_MAX = (1 << 32) - 1


# struct.pack_into has atomicity issues because it will temporarily write 0 into
# the mmap, resulting in false reads to 0 when experiencing a lot of writes.
# Using direct assignment solves this issue.


def _pack_two_doubles(data, pos, value, timestamp):
    data[pos:pos + 16] = _pack_two_doubles_func(value, timestamp)


def _pack_integer(data, pos, value):
    data[pos:pos + 4] = _pack_integer_func(value)


def new_session_id():
    """Return a non-zero token identifying one write session.

    Tokens are drawn from the time and the process id, which makes them
    distinct across restarts of a process that reuses a pid. They are not
    security credentials: their only job is to tell two writers of the same
    metric file apart.
    """
    token = (time.time_ns() ^ (os.getpid() << 32)) & _SESSION_MAX
    return token or 1


def _write_session_token(data, session_id):
    data[_SESSION_OFFSET:_SESSION_OFFSET + _SESSION_SIZE] = _pack_session_func(session_id)


def _read_session_token(data):
    return _unpack_session(data, _SESSION_OFFSET)[0]


class _FileLock:
    """An exclusive advisory lock on a metric file's descriptor.

    ``flock`` locks are per open file description, so a writer holding one in
    one process and cleanup taking one in another serialize with each other.
    The lock is held for the lifetime of the object and released on close,
    which is what lets a writer keep a session "open" while it is alive.
    """

    def __init__(self, fileno):
        self._fileno = fileno

    def acquire(self, wait=0.0):
        """Take the lock, waiting up to ``wait`` seconds for a holder to finish."""
        if fcntl is None:
            return True
        deadline = time.monotonic() + wait
        while True:
            try:
                fcntl.flock(self._fileno, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError:
                if time.monotonic() >= deadline:
                    return False
                time.sleep(0.001)
            else:
                return True

    def release(self):
        if fcntl is None:
            return
        try:
            fcntl.flock(self._fileno, fcntl.LOCK_UN)
        except OSError:
            pass


class _LockedReader:
    """A metric file opened for reclamation, maybe with its writer lock held.

    Keeps the descriptor and lock alive until ``close`` so that no writer can
    attach to (or write into) the file between the ownership check and the
    unlink performed by the caller. ``same_file`` is False when the path no
    longer names the inode that was opened, so unlinking the path would
    remove a newer file instead of this one.
    """

    def __init__(self, fd, lock, session_id, locked, same_file):
        self._fd = fd
        self._lock = lock
        self.session_id = session_id
        self.locked = locked
        self.same_file = same_file

    def close(self):
        if self._fd is not None:
            if self.locked:
                self._lock.release()
            os.close(self._fd)
            self._fd = None

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        self.close()


def _read_session_from_fd(fd):
    """Read the write-session token from an open descriptor, if any."""
    try:
        try:
            header = os.pread(fd, 8, 0)
        except AttributeError:  # Windows has no pread.
            os.lseek(fd, 0, os.SEEK_SET)
            header = os.read(fd, 8)
    except OSError:
        return None
    if len(header) < 8:
        return None
    session_id = _read_session_token(header)
    return session_id or None


def read_session_from_file(filename):
    """Return the write-session token recorded in ``filename``, if any.

    Returns ``None`` for files written by a client that predates sessions, or
    that do not exist.
    """
    try:
        fd = os.open(filename, os.O_RDONLY)
    except OSError:
        return None
    try:
        return _read_session_from_fd(fd)
    finally:
        os.close(fd)


def _fd_matches_path(fd, filename):
    try:
        held = os.fstat(fd)
        current = os.stat(filename)
    except OSError:
        return False
    return (held.st_dev, held.st_ino) == (current.st_dev, current.st_ino)


class _Reclaimed(Exception):
    """Raised internally when a file is unlinked between open and lock."""


def _read_all_values(data, used=0):
    """Yield (key, value, timestamp, pos). No locking is performed."""

    if used <= 0:
        # If not valid `used` value is passed in, read it from the file.
        used = _unpack_integer(data, 0)[0]

    pos = 8

    while pos < used:
        encoded_len = _unpack_integer(data, pos)[0]
        # check we are not reading beyond bounds
        if encoded_len + pos > used:
            raise RuntimeError('Read beyond file size detected, file is corrupted.')
        pos += 4
        encoded_key = data[pos:pos + encoded_len]
        padded_len = encoded_len + (8 - (encoded_len + 4) % 8)
        pos += padded_len
        value, timestamp = _unpack_two_doubles(data, pos)
        yield encoded_key.decode('utf-8'), value, timestamp, pos
        pos += 16


class MmapedDict:
    """A dict of doubles, backed by an mmapped file.

    The file starts with a 4 byte int, indicating how much of it is used.
    Then a 4 byte write-session token (0 when written by an older client).
    There's then a number of entries, consisting of a 4 byte int which is the
    size of the next field, a utf-8 encoded string key, padding to a 8 byte
    alignment, and then a 8 byte float which is the value and a 8 byte float
    which is a UNIX timestamp in seconds.

    Not thread safe.
    """

    def __init__(self, filename, read_mode=False, session_id=None, lock=True):
        self._fname = filename
        self._f = None
        self._m = None
        self._lock = None
        self._lock_held = False
        self.session_id = None
        # A cleanup can unlink this file in the window between opening it and
        # taking its lock. Retry against the path a couple of times so the
        # writer lands on whichever incarnation is current when it settles.
        for attempt in range(3):
            try:
                self._open(read_mode, session_id, lock)
                return
            except _Reclaimed:
                self._release()
                if attempt == 2:
                    raise FileNotFoundError(
                        'metric file was reclaimed by cleanup while opening it') from None

    def _open(self, read_mode, session_id, lock):
        self._f = open(self._fname, 'rb' if read_mode else 'a+b')
        capacity = os.fstat(self._f.fileno()).st_size
        if capacity == 0:
            self._f.truncate(_INITIAL_MMAP_SIZE)
            capacity = _INITIAL_MMAP_SIZE
        self._capacity = capacity
        self._m = mmap.mmap(self._f.fileno(), self._capacity,
                            access=mmap.ACCESS_READ if read_mode else mmap.ACCESS_WRITE)
        self._positions = {}
        self._used = _unpack_integer(self._m, 0)[0]
        if self._used == 0:
            self._used = 8
            _pack_integer(self._m, 0, self._used)
        elif not read_mode:
            for key, _, _, pos in self._read_all_values():
                self._positions[key] = pos
        if lock and not read_mode:
            # Cleanup holds the lock only briefly; wait it out so a writer that
            # starts during a reclaim lands on the current file.
            self.acquire_lock(wait=0.05)
        if read_mode:
            self.session_id = _read_session_token(self._m) or None
            return
        if self._lock is None or self._lock_held:
            self.session_id = self._adopt_session(session_id)
        else:
            # An incumbent writer owns this file; its data is not ours to relabel.
            self.session_id = _read_session_token(self._m) or None
            return
        if lock and self._unlinked():
            raise _Reclaimed()

    def _unlinked(self):
        """True when the locked path no longer names the file we hold."""
        try:
            current = os.stat(self._fname)
        except OSError:
            return True
        held = os.fstat(self._f.fileno())
        return (current.st_dev, current.st_ino) != (held.st_dev, held.st_ino)

    def _release(self):
        self.release_lock()
        if self._m is not None:
            self._m.close()
            self._m = None
        if self._f is not None:
            self._f.close()
            self._f = None

    def _adopt_session(self, session_id):
        """Record this writer as the file's current session."""
        if session_id is None:
            session_id = new_session_id()
        _write_session_token(self._m, session_id)
        return session_id

    def acquire_lock(self, wait=0.0):
        """Take the file's exclusive writer lock. Returns False if held elsewhere."""
        if self._lock is None:
            self._lock = _FileLock(self._f.fileno())
        self._lock_held = self._lock.acquire(wait)
        return self._lock_held

    def release_lock(self):
        if self._lock is not None:
            self._lock.release()
            self._lock_held = False

    @staticmethod
    def open_for_cleanup(filename):
        """Open a metric file for a reclamation attempt.

        Returns a ``_LockedReader`` describing the file, or ``None`` when it
        does not exist. The reader reports whether an active writer currently
        holds the file, so the caller can decide how to proceed.
        """
        try:
            fd = os.open(filename, os.O_RDONLY)
        except OSError:
            return None
        lock = _FileLock(fd)
        locked = lock.acquire()
        session_id = _read_session_from_fd(fd)
        return _LockedReader(fd, lock, session_id, locked, _fd_matches_path(fd, filename))

    @staticmethod
    def read_all_values_from_file(filename):
        with open(filename, 'rb') as infp:
            # Read the first block of data, including the first 4 bytes which tell us
            # how much of the file (which is preallocated to _INITIAL_MMAP_SIZE bytes) is occupied.
            data = infp.read(mmap.PAGESIZE)
            if not data:
                # __init__ creates the file and only truncates it to
                # _INITIAL_MMAP_SIZE afterwards, so a reader can observe it while
                # it is still empty; a process dying in that window can also leave
                # an empty file behind for good. Treat it as a file with nothing
                # recorded in it yet, mirroring the `capacity == 0` case in
                # __init__, rather than failing to unpack a header that isn't
                # there. Anything longer than this is left to fail loudly.
                return iter(())
            used = _unpack_integer(data, 0)[0]
            if used > len(data):  # Then read in the rest, if needed.
                data += infp.read(used - len(data))
        return _read_all_values(data, used)

    def _init_value(self, key):
        """Initialize a value. Lock must be held by caller."""
        encoded = key.encode('utf-8')
        # Pad to be 8-byte aligned.
        padded = encoded + (b' ' * (8 - (len(encoded) + 4) % 8))
        value = struct.pack(f'i{len(padded)}sdd'.encode(), len(encoded), padded, 0.0, 0.0)
        while self._used + len(value) > self._capacity:
            self._capacity *= 2
            self._grow()
        self._m[self._used:self._used + len(value)] = value

        # Update how much space we've used.
        self._used += len(value)
        _pack_integer(self._m, 0, self._used)
        self._positions[key] = self._used - 16

    def _grow(self):
        """Grow the mapping, re-reading the file if it was reclaimed meanwhile.

        A cleanup can unlink and recreate the file while this writer holds an
        old descriptor. That new file belongs to a later session, so this
        writer must not keep writing into the detached one.
        """
        self._f.truncate(self._capacity)
        self._m = mmap.mmap(self._f.fileno(), self._capacity, access=mmap.ACCESS_WRITE)
        on_disk = _unpack_integer(self._m, 0)[0]
        if (on_disk < 8
                or _read_session_token(self._m) != self.session_id
                or self._unlinked()):
            raise FileNotFoundError(
                'metric file was reclaimed by cleanup while this writer was active')

    def _read_all_values(self):
        """Yield (key, value, pos). No locking is performed."""
        return _read_all_values(data=self._m, used=self._used)

    def read_all_values(self):
        """Yield (key, value, timestamp). No locking is performed."""
        for k, v, ts, _ in self._read_all_values():
            yield k, v, ts

    def read_value(self, key):
        if key not in self._positions:
            self._init_value(key)
        pos = self._positions[key]
        return _unpack_two_doubles(self._m, pos)

    def write_value(self, key, value, timestamp):
        if key not in self._positions:
            self._init_value(key)
        pos = self._positions[key]
        _pack_two_doubles(self._m, pos, value, timestamp)

    def close(self):
        if self._f:
            self.release_lock()
            self._m.close()
            self._m = None
            self._f.close()
            self._f = None


def mmap_key(metric_name: str, name: str, labelnames: List[str], labelvalues: List[str], help_text: str) -> str:
    """Format a key for use in the mmap file."""
    # ensure labels are in consistent order for identity
    labels = dict(zip(labelnames, labelvalues))
    return json.dumps([metric_name, name, labels, help_text], sort_keys=True)
