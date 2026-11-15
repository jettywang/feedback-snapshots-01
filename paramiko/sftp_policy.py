"""
Server-side permission policy for SFTP file creation.

The classes here are intended for multi-user SFTP servers which translate
SFTP paths onto a local filesystem.  They keep the server's permission policy
and the client's requested attributes separate, and merge both into the actual
``os.open`` call used to create a file.  They never create a file with wide
permissions and tighten it later with ``chmod``.

Permission semantics implemented by `SFTPPermissionPolicy`:

* New file (``O_CREAT``, with or without ``O_EXCL``): created directly with
  ``default_file_mode`` if the client omitted ``mode``, or with the client's
  ``mode`` intersected with ``allowed_file_mode``.  Special bits are
  discarded.  The owner is always the server process; client uid/gid and
  extended attributes from the open request are ignored.
* Exclusive create (``O_CREAT | O_EXCL``): the same mode rules, and an
  existing path is never opened or modified.
* Existing file (``O_CREAT`` without ``O_EXCL`` and no ``O_TRUNC``): opened
  without changing its mode; the open-time mode is ignored.
* Truncation (``O_TRUNC``): may replace the contents of an existing file only
  when ``allow_truncate`` is true.  For a newly created file truncation is
  meaningless (it is already empty).  Denial happens before opening, so a
  denied request cannot modify a file or leave an empty one behind.
* Later ``SETSTAT``/``FSETSTAT``: permission bits may change only when
  ``allow_chmod`` is true and only to bits inside ``allowed_file_mode``.
  Ownership and extended-attribute changes are always denied.  Size changes
  require ``allow_setstat_size``.  Timestamp changes are allowed because they
  do not expand access.

The process umask is never modified.  Creation still honours the umask that
the process already has, so the actual mode can only be *narrower* than the
policy result; it can never be wider.  Two sessions may use different
policies concurrently without influencing each other.

Each policy object is owned by one interface/session.
"""

import errno
import os
import stat

from paramiko.common import o600, o700
from paramiko.sftp import SFTP_FAILURE, SFTP_OK, SFTP_PERMISSION_DENIED
from paramiko.sftp_attr import SFTPAttributes
from paramiko.sftp_handle import SFTPHandle
from paramiko.sftp_server import SFTPServer
from paramiko.sftp_si import SFTPServerInterface


_MODE_MASK = 0o777
_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_ACCMODE = getattr(os, "O_ACCMODE", os.O_RDONLY | os.O_WRONLY | os.O_RDWR)
# Descriptor-based metadata calls are POSIX-only; elsewhere fall back to the
# path (the interface still runs with one elevated-privilege server account).
_HAS_FD_METADATA = os.name == "posix"


class SFTPPermissionPolicy:
    """
    Immutable permission policy for one SFTP session.

    A policy stores no process-global state.  Create one policy per session
    (or per user) and pass it to `RestrictedSFTPServerInterface`; concurrent
    sessions may use different policies without influencing each other.

    :param int default_file_mode:
        mode used when a create request does not carry a mode.  It is capped
        by ``allowed_file_mode``.
    :param int allowed_file_mode:
        maximum mode bits a client may get for a regular file.
    :param int default_directory_mode:
        mode used when a mkdir request does not carry a mode.
    :param int allowed_directory_mode:
        maximum mode bits a client may get for a directory.
    :param bool allow_truncate:
        whether ``O_TRUNC`` may truncate an existing file.
    :param bool allow_chmod:
        whether an established file may be chmod'ed later, within the policy
        cap.
    :param bool allow_setstat_size:
        whether ``SETSTAT``/``FSETSTAT`` size requests may resize a file.
    """

    def __init__(
        self,
        default_file_mode=o600,
        allowed_file_mode=o600,
        default_directory_mode=o700,
        allowed_directory_mode=o700,
        allow_truncate=False,
        allow_chmod=False,
        allow_setstat_size=False,
    ):
        self._allowed_file_mode = (
            stat.S_IMODE(allowed_file_mode) & _MODE_MASK
        )
        self._default_file_mode = (
            stat.S_IMODE(default_file_mode) & self._allowed_file_mode
        )
        self._allowed_directory_mode = (
            stat.S_IMODE(allowed_directory_mode) & _MODE_MASK
        )
        self._default_directory_mode = (
            stat.S_IMODE(default_directory_mode)
            & self._allowed_directory_mode
        )
        self._allow_truncate = bool(allow_truncate)
        self._allow_chmod = bool(allow_chmod)
        self._allow_setstat_size = bool(allow_setstat_size)

    @property
    def allowed_file_mode(self):
        """Maximum permission bits for a regular file."""
        return self._allowed_file_mode

    @property
    def default_file_mode(self):
        """Default permission bits for a newly created regular file."""
        return self._default_file_mode

    @property
    def allowed_directory_mode(self):
        """Maximum permission bits for a directory."""
        return self._allowed_directory_mode

    @property
    def default_directory_mode(self):
        """Default permission bits for a newly created directory."""
        return self._default_directory_mode

    @property
    def allow_truncate(self):
        """Whether ``O_TRUNC`` may truncate an existing file."""
        return self._allow_truncate

    @property
    def allow_chmod(self):
        """Whether later permission changes are allowed."""
        return self._allow_chmod

    @property
    def allow_setstat_size(self):
        """Whether later size changes are allowed."""
        return self._allow_setstat_size

    def creation_mode(self, attr):
        """
        Return the final mode for a newly created regular file.

        The client's requested mode is only a request: it is intersected with
        the server's allowed mode, and special bits are discarded.  An absent
        mode uses `default_file_mode`.
        """
        if attr is not None and (
            attr._flags & SFTPAttributes.FLAG_PERMISSIONS
        ):
            requested = attr.st_mode
        else:
            requested = self._default_file_mode
        return stat.S_IMODE(requested) & self._allowed_file_mode

    def directory_creation_mode(self, attr):
        """
        Return the final mode for a newly created directory.

        Works like `creation_mode`, but uses the directory defaults and cap.
        """
        if attr is not None and (
            attr._flags & SFTPAttributes.FLAG_PERMISSIONS
        ):
            requested = attr.st_mode
        else:
            requested = self._default_directory_mode
        return stat.S_IMODE(requested) & self._allowed_directory_mode

    def mode_change_allowed(self, mode):
        """
        Return true if a client-requested chmod stays inside the policy.
        """
        return self._allow_chmod and not (
            stat.S_IMODE(mode) & ~self._allowed_file_mode
        )


def _validate_open_flags(flags):
    known = (
        os.O_WRONLY
        | os.O_RDWR
        | os.O_APPEND
        | os.O_CREAT
        | os.O_TRUNC
        | os.O_EXCL
    )
    # Some platforms add housekeeping flags (O_BINARY on Windows, O_CLOEXEC
    # here and there); those are harmless and should not fail a request.
    ignorable = (
        getattr(os, "O_BINARY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | _NOFOLLOW
    )
    if flags & ~(known | ignorable):
        raise OSError(errno.EINVAL, os.strerror(errno.EINVAL))
    write_access = (flags & _ACCMODE) in (os.O_WRONLY, os.O_RDWR)
    if flags & os.O_TRUNC and not write_access:
        raise OSError(errno.EACCES, os.strerror(errno.EACCES))
    if flags & os.O_APPEND and not write_access:
        raise OSError(errno.EACCES, os.strerror(errno.EACCES))
    if flags & os.O_EXCL and not flags & os.O_CREAT:
        raise OSError(errno.EINVAL, os.strerror(errno.EINVAL))
    return write_access


def _identity(fd):
    """Return the (device, inode) identity of an open descriptor."""
    st = os.fstat(fd)
    return st.st_dev, st.st_ino


def _unlink_if_identity(path, identity):
    """
    Remove ``path`` only if it still names the created inode.
    """
    try:
        path_stat = os.lstat(path)
    except OSError:
        return
    if (path_stat.st_dev, path_stat.st_ino) != identity:
        return
    try:
        os.unlink(path)
    except OSError:
        pass


def _open_fd(path, flags, attr, policy):
    """
    Perform the actual create/open action and return ``(fd, created)``.

    The creation call supplies the final mode to ``os.open``.  No later chmod
    is used, so the path is visible with its restricted mode from the instant
    the kernel creates it.
    """
    _validate_open_flags(flags)
    open_flags = flags | _NOFOLLOW | getattr(os, "O_BINARY", 0)

    if flags & os.O_CREAT:
        mode = policy.creation_mode(attr)
        if mode == 0:
            # A blank mode (the client explicitly sent 0 and the policy cap
            # allows nothing) has no legitimate use here; refuse before
            # touching the filesystem.
            raise OSError(errno.EACCES, os.strerror(errno.EACCES), path)
        # Always probe with O_EXCL: the mode is applied atomically at
        # creation, and an existing path is never opened by this call.
        probe_flags = (open_flags | os.O_EXCL) & ~os.O_TRUNC
        try:
            return os.open(path, probe_flags, mode), True
        except OSError as e:
            if e.errno != errno.EEXIST or flags & os.O_EXCL:
                raise
        # The path already existed.  Never create anything here, never chmod
        # it, and honour the truncation policy before opening.
        if flags & os.O_TRUNC and not policy.allow_truncate:
            raise OSError(errno.EACCES, os.strerror(errno.EACCES), path)
        existing_flags = open_flags & ~(os.O_CREAT | os.O_EXCL)
        try:
            return os.open(path, existing_flags), False
        except OSError as e:
            # The path vanished between the probe and the open.  Retry the
            # O_EXCL creation once; ordinary create semantics are preserved
            # and no file is ever visible with a wider mode.
            if e.errno != errno.ENOENT:
                raise
            return os.open(path, probe_flags, mode), True

    if flags & os.O_TRUNC and not policy.allow_truncate:
        raise OSError(errno.EACCES, os.strerror(errno.EACCES), path)
    return os.open(path, open_flags), False


def open_restricted_file(
    path,
    flags,
    attr,
    policy,
    handle_factory=None,
    created_callback=None,
):
    """
    Open or create ``path`` under ``policy`` and return an `.SFTPHandle`.

    This is the low-level entry point used by
    `RestrictedSFTPServerInterface.open`.  The server policy and the client
    request are merged into the ``os.open`` mode used for creation.

    If creation succeeded but handle construction fails, the new path is
    removed again (only if it still names the same inode); an existing file
    is never removed.

    :param str path: local filesystem path.
    :param int flags: SFTP-converted ``os`` flags.
    :param .SFTPAttributes attr: client attributes from the open request.
    :param .SFTPPermissionPolicy policy: policy for this session.
    :param callable handle_factory:
        ``(fd, path, flags, policy, created) -> .SFTPHandle``.  Defaults to
        `RestrictedSFTPHandle`.  The factory takes ownership of ``fd``; on
        failure it must close ``fd`` before raising (as
        `RestrictedSFTPHandle` does).
    :param callable created_callback:
        optional ``(path, mode)`` audit hook invoked immediately after the
        kernel creates a new file, before a handle is returned.  It can
        observe the path at its first visible state.
    :return: a new `.SFTPHandle`.
    :raises OSError: if the open or creation fails.
    """
    if handle_factory is None:
        handle_factory = RestrictedSFTPHandle
    fd = None
    created = False
    identity = None
    handed_off = False
    try:
        fd, created = _open_fd(path, flags, attr, policy)
        if created:
            identity = _identity(fd)
        if created and created_callback is not None:
            created_callback(path, stat.S_IMODE(os.fstat(fd).st_mode))
        handed_off = True
        return handle_factory(fd, path, flags, policy, created)
    except Exception:
        if created and identity is not None:
            _unlink_if_identity(path, identity)
        if fd is not None and not handed_off:
            try:
                os.close(fd)
            except OSError:
                pass
        raise


class RestrictedSFTPHandle(SFTPHandle):
    """
    `SFTPHandle` which owns its descriptor and enforces a permission policy.

    ``stat`` and file I/O use the already-open descriptor, so a later rename
    or replacement of the path cannot redirect them.  ``chattr`` (used by
    both ``FSETSTAT`` and path-based ``SETSTAT``) applies the policy from
    `SFTPPermissionPolicy`: a client may narrow or re-apply a mode inside the
    server cap, but may not add bits outside it, change ownership, change
    extended attributes, or resize the file unless the policy allows it.
    """

    def __init__(
        self, fd, path, flags, policy, created=False, *args, **kwargs
    ):
        super().__init__(flags, *args, **kwargs)
        self.filename = path
        self.path = path
        self.policy = policy
        self.created = created
        self._open_flags = flags
        self._fd = fd
        try:
            self._file = os.fdopen(fd, self._fdopen_mode(flags))
        except Exception:
            try:
                os.close(fd)
            except OSError:
                pass
            raise
        access = flags & _ACCMODE
        if access in (os.O_RDONLY, os.O_RDWR):
            self.readfile = self._file
        if access in (os.O_WRONLY, os.O_RDWR):
            self.writefile = self._file

    @staticmethod
    def _fdopen_mode(flags):
        access = flags & _ACCMODE
        if access == os.O_RDWR:
            return "a+b" if flags & os.O_APPEND else "r+b"
        if access == os.O_WRONLY:
            return "ab" if flags & os.O_APPEND else "wb"
        return "rb"

    def stat(self):
        try:
            return SFTPAttributes.from_stat(os.fstat(self._fd))
        except OSError as e:
            return SFTPServer.convert_errno(e.errno)

    def chattr(self, attr):
        flags = getattr(attr, "_flags", 0)
        if flags & (
            SFTPAttributes.FLAG_UIDGID | SFTPAttributes.FLAG_EXTENDED
        ):
            return SFTP_PERMISSION_DENIED
        if flags & SFTPAttributes.FLAG_PERMISSIONS:
            if not self.policy.mode_change_allowed(attr.st_mode):
                return SFTP_PERMISSION_DENIED
        try:
            if flags & SFTPAttributes.FLAG_PERMISSIONS:
                mode = stat.S_IMODE(attr.st_mode)
                if _HAS_FD_METADATA:
                    os.fchmod(self._fd, mode)
                else:
                    os.chmod(self.path, mode)
            if flags & SFTPAttributes.FLAG_AMTIME:
                times = (attr.st_atime, attr.st_mtime)
                if _HAS_FD_METADATA:
                    os.utime(self._fd, times)
                else:
                    os.utime(self.path, times)
            if flags & SFTPAttributes.FLAG_SIZE:
                if _HAS_FD_METADATA:
                    os.ftruncate(self._fd, attr.st_size)
                else:
                    self._file.truncate(attr.st_size)
        except OSError as e:
            return SFTPServer.convert_errno(e.errno)
        return SFTP_OK


class RestrictedSFTPServerInterface(SFTPServerInterface):
    """
    A rooted `SFTPServerInterface` with policy-enforced file creation.

    ``root`` confines all served paths.  The interface implements the common
    file and metadata requests needed for a read/write SFTP session; symlink
    creation is deliberately unsupported because a symlink can escape the
    rooted tree and bypass the permission policy.

    Each instance owns exactly one `SFTPPermissionPolicy`.  When registering
    a subsystem handler, pass a distinct policy for each user/session; no
    process umask or other global state is touched.
    """

    def __init__(
        self,
        server,
        root,
        policy=None,
        created_hook=None,
        *args,
        **kwargs,
    ):
        super().__init__(server, *args, **kwargs)
        self.root = os.path.realpath(root)
        self.policy = policy or SFTPPermissionPolicy()
        self._created_hook = created_hook

    # ...path mapping...
    def _realpath(self, path, follow=False):
        canonical = self.canonicalize(path)
        relative = canonical.lstrip("/")
        full = os.path.normpath(os.path.join(self.root, relative))
        if follow:
            full = os.path.realpath(full)
        else:
            # Resolve the parent through symlinks, but keep the final
            # component unresolved so O_NOFOLLOW can refuse a symlinked
            # target for creating/modifying operations.
            parent = os.path.realpath(os.path.dirname(full))
            full = os.path.join(parent, os.path.basename(full))
        try:
            inside = os.path.commonpath([self.root, full]) == self.root
        except ValueError:
            inside = False
        if not inside:
            raise OSError(errno.EACCES, os.strerror(errno.EACCES), path)
        return full

    def _convert(self, func):
        try:
            return func()
        except OSError as e:
            return SFTPServer.convert_errno(e.errno)

    # ...file creation...
    def open(self, path, flags, attr):
        try:
            return open_restricted_file(
                self._realpath(path),
                flags,
                attr,
                self.policy,
                handle_factory=self._make_handle,
                created_callback=self._file_created,
            )
        except OSError as e:
            return SFTPServer.convert_errno(e.errno)

    def _make_handle(self, fd, path, flags, policy, created):
        return RestrictedSFTPHandle(fd, path, flags, policy, created)

    def _file_created(self, path, mode):
        """
        Audit hook called after the kernel creates a new file.

        Subclasses may override this to observe the path at its first visible
        state.  ``mode`` is taken from the open descriptor; the file has not
        been chmod'ed and no SFTP handle has been returned yet.  Raising here
        is safe: the newly created path is cleaned up and the request fails.
        """
        if self._created_hook is not None:
            self._created_hook(path, mode)

    # ...read-only metadata...
    def list_folder(self, path):
        def run():
            full = self._realpath(path, follow=True)
            out = []
            for name in os.listdir(full):
                entry = os.path.join(full, name)
                attr = SFTPAttributes.from_stat(os.stat(entry), name)
                out.append(attr)
            return out

        return self._convert(run)

    def stat(self, path):
        return self._convert(
            lambda: SFTPAttributes.from_stat(
                os.stat(self._realpath(path, follow=True))
            )
        )

    def lstat(self, path):
        return self._convert(
            lambda: SFTPAttributes.from_stat(
                os.lstat(self._realpath(path))
            )
        )

    # ...name operations...
    def remove(self, path):
        def run():
            os.remove(self._realpath(path))
            return SFTP_OK

        return self._convert(run)

    def rename(self, oldpath, newpath):
        def run():
            old = self._realpath(oldpath)
            new = self._realpath(newpath)
            if os.path.exists(new):
                return SFTP_FAILURE
            os.rename(old, new)
            return SFTP_OK

        return self._convert(run)

    def posix_rename(self, oldpath, newpath):
        def run():
            old = self._realpath(oldpath)
            new = self._realpath(newpath)
            os.rename(old, new)
            return SFTP_OK

        return self._convert(run)

    def mkdir(self, path, attr):
        mode = self.policy.directory_creation_mode(attr)

        def run():
            os.mkdir(self._realpath(path), mode)
            return SFTP_OK

        return self._convert(run)

    def rmdir(self, path):
        def run():
            os.rmdir(self._realpath(path))
            return SFTP_OK

        return self._convert(run)

    # ...metadata updates...
    def chattr(self, path, attr):
        flags = getattr(attr, "_flags", 0)
        if flags & (
            SFTPAttributes.FLAG_UIDGID | SFTPAttributes.FLAG_EXTENDED
        ):
            return SFTP_PERMISSION_DENIED
        if flags & SFTPAttributes.FLAG_PERMISSIONS:
            if not self.policy.mode_change_allowed(attr.st_mode):
                return SFTP_PERMISSION_DENIED
        if flags & SFTPAttributes.FLAG_SIZE:
            if not self.policy.allow_setstat_size:
                return SFTP_PERMISSION_DENIED

        open_flags = os.O_RDONLY | _NOFOLLOW
        if flags & SFTPAttributes.FLAG_SIZE:
            open_flags = os.O_RDWR | _NOFOLLOW
        try:
            full = self._realpath(path)
            fd = os.open(full, open_flags)
        except OSError as e:
            return SFTPServer.convert_errno(e.errno)
        handle = RestrictedSFTPHandle(
            fd, full, open_flags, self.policy, created=False
        )
        try:
            return handle.chattr(attr)
        finally:
            handle.close()
