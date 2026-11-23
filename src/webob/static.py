import mimetypes
import os
import stat as stat_module

from webob import exc
from webob.dec import wsgify
from webob.response import Response

__all__ = [
    "FileApp",
    "DirectoryApp",
    "FileIter",
    "FileIterRange",
    "FileOwnershipPolicy",
    "FilePolicy",
    "FileStorage",
    "OwnershipPolicy",
]

mimetypes._winreg = None  # do not load mimetypes from windows registry
mimetypes.add_type(
    "text/javascript", ".js"
)  # stdlib default is application/x-javascript
mimetypes.add_type("image/x-icon", ".ico")  # not among defaults

BLOCK_SIZE = 1 << 16


def _identity(stat_result):
    """Return the stable identity of a stat result.

    Device and inode together identify the object that was opened, without
    relying on the path used to reach it.
    """

    return (getattr(stat_result, "st_dev", None), getattr(stat_result, "st_ino", None))


def _is_regular(stat_result):
    mode = getattr(stat_result, "st_mode", None)

    if mode is None:
        # A custom storage may only provide the fields used by the policy.
        return True

    return stat_module.S_ISREG(mode)


def _is_within(path, root):
    path = os.path.normcase(os.path.abspath(path))
    root = os.path.normcase(os.path.abspath(root))

    if path == root:
        return True

    if not root.endswith(os.sep):
        root += os.sep

    return path.startswith(root)


def _as_paths(paths):
    if paths is None:
        return ()

    if isinstance(paths, (str, bytes, os.PathLike)):
        return (paths,)

    return tuple(paths)


def _realpath(storage, path):
    if storage is not None and hasattr(storage, "realpath"):
        return storage.realpath(path)

    return os.path.realpath(path)


def _stat(storage, path):
    if storage is not None and hasattr(storage, "stat"):
        return storage.stat(path)

    return os.stat(path)


def _identity_of(storage, stat_result):
    if storage is not None and hasattr(storage, "identity"):
        return storage.identity(stat_result)

    return _identity(stat_result)


def _bind_policy(storage, policy, root):
    if policy.root is not None:
        root = policy.root

    if storage is not None:
        if not hasattr(storage, "stat"):
            return policy.bind(root)

        try:
            root_device = storage.stat(_realpath(storage, root)).st_dev
        except Exception:
            # A substitute need not describe the mount root itself.  Do not
            # mix in the real filesystem's device identity.
            return policy.bind(root)

        return policy.bind(root, root_device)

    try:
        root_device = os.stat(os.path.realpath(root)).st_dev
    except OSError:
        root_device = None

    return policy.bind(root, root_device)


def _share_paths(storage, policy, shared_files):
    for shared_path in _as_paths(shared_files):
        stat_result = None
        real_path = None

        if storage is not None:
            try:
                real_path = _realpath(storage, os.path.abspath(shared_path))
            except Exception:
                real_path = None

            if real_path is not None and hasattr(storage, "stat"):
                try:
                    stat_result = storage.stat(real_path)
                except Exception:
                    stat_result = None

        policy.share(os.fspath(shared_path), stat_result, real_path)


class FileStorage:
    """Filesystem operations used by a policy-aware :class:`FileApp`.

    This is a small seam for tests and for deployments whose files are not
    ordinary local paths.  A substitute needs ``open(path)``, ``stat(path)``
    and ``fstat(file)``; ``realpath(path)`` and ``identity(stat_result)`` are
    optional.

    ``open`` must return a binary file-like object.  ``stat`` and ``fstat``
    must return objects with ``st_dev`` and ``st_ino`` attributes.  The usual
    size and modification fields are used for response metadata when present.
    """

    def open(self, path):
        return open(path, "rb")

    def stat(self, path):
        return os.stat(path)

    def fstat(self, file):
        return os.fstat(file.fileno())

    def realpath(self, path):
        return os.path.realpath(path)

    def identity(self, stat_result):
        """Return the comparable object identity for ``stat_result``."""

        return _identity(stat_result)


class FileOwnershipPolicy:
    """Restrict a static mount to files owned by that mount.

    A file is owned when its real path is inside ``root`` and it lives on the
    same device (volume) as the mount.  ``shared_files`` names individual
    files that administrators have explicitly approved even when they live
    outside the mount.  Each shared file is bound to the identity observed
    when it is registered, so replacing it with another object does not
    silently inherit the approval.

    ``root`` is normally filled in by :class:`DirectoryApp`.  It can also be
    supplied explicitly, together with ``root_device`` when the device
    identity comes from an external storage layer.

    Shared files may be registered or withdrawn while the application is
    running with :meth:`share` and :meth:`revoke`.  Withdrawal is observed
    before the next body byte is produced.
    """

    def __init__(
        self,
        root=None,
        mount=None,
        shared_files=(),
        shared=None,
        allowed_files=None,
        approved_files=None,
        root_device=None,
    ):
        if root is None:
            root = mount

        for extra in (allowed_files, approved_files, shared):
            if extra is not None:
                shared_files = _as_paths(shared_files) + _as_paths(extra)

        self.root = os.path.realpath(root) if root is not None else None
        self.root_device = root_device
        self._shared = {}
        self._pending = []

        for path in _as_paths(shared_files):
            if self.root is None and not os.path.isabs(os.fspath(path)):
                # The mount root is not known yet; resolve when it is bound.
                self._pending.append(path)
            else:
                self.share(path)

    def identity(self, stat_result):
        """Return the comparable identity of a stat result.

        A policy used with a custom :class:`FileStorage` may override this
        when the storage reports identities that are not ``st_dev`` and
        ``st_ino``.
        """

        return _identity(stat_result)

    def bind(self, root, root_device=None):
        """Bind this policy to a mount root.

        A root that was supplied explicitly is kept.  The policy is updated
        in place so registrations made through the object held by the
        application take effect immediately.
        """

        if self.root is None:
            self.root = os.path.realpath(root)

        if root_device is not None:
            self.root_device = root_device

        if self._pending:
            pending, self._pending = self._pending, []

            for path in pending:
                if not os.path.isabs(os.fspath(path)):
                    path = os.path.join(self.root, os.fspath(path))

                self.share(path)

        return self

    @property
    def shared_files(self):
        """The paths currently approved by this policy."""

        return tuple(self._shared) + tuple(self._pending)

    def share(self, path, stat_result=None, real_path=None):
        """Approve the object currently at ``path``.

        The object's identity is recorded at this moment.  Replacing the
        file afterwards requires calling ``share`` again.  ``stat_result``
        and ``real_path`` may describe an object supplied by a custom
        storage; otherwise the local filesystem is inspected.
        """

        path = os.fspath(path)

        if not os.path.isabs(path) and self.root is not None:
            path = os.path.join(self.root, path)

        path = os.path.abspath(path)

        if real_path is None:
            real_path = os.path.realpath(path)

        try:
            if stat_result is None:
                stat_result = os.stat(real_path)

            identity = self.identity(stat_result)
        except OSError:
            identity = None

        self._shared[path] = (real_path, identity)
        return self

    # Natural spellings for administration code.
    approve = share
    register = share

    def revoke(self, path):
        """Withdraw a previously registered shared path."""

        path = os.fspath(path)

        if not os.path.isabs(path) and self.root is not None:
            path = os.path.join(self.root, path)

        path = os.path.abspath(path)
        real_path = os.path.realpath(path)

        for registered, (registered_real_path, _identity_value) in list(
            self._shared.items()
        ):
            if registered == path or registered_real_path == real_path:
                del self._shared[registered]

        return self

    unshare = revoke

    def allows(self, path, file_stat=None, real_path=None):
        """Return whether the object behind ``path`` is owned by the mount.

        ``file_stat`` should describe the object that was actually opened.
        ``real_path`` may be supplied by the caller to avoid resolving the
        path a second time.
        """

        if real_path is None:
            real_path = os.path.realpath(path)

        approved = self._shared.get(path)

        if approved is None:
            for approved_path, entry in self._shared.items():
                if entry[0] == real_path:
                    approved = entry
                    break
        else:
            real_path = approved[0]

        if approved is not None:
            approved_real_path, identity = approved

            if identity is None:
                return False

            if file_stat is not None and self.identity(file_stat) != identity:
                return False

            return True

        if self.root is None or not _is_within(real_path, self.root):
            return False

        if self.root_device is not None and file_stat is not None:
            device = getattr(file_stat, "st_dev", None)

            if device is not None and device != self.root_device:
                return False

        return True

    check = allows
    is_allowed = allows
    allow = allows


class FileApp:
    """An application that will send the file at the given filename.

    Adds a mime type based on `mimetypes.guess_type()`.

    Pass ``ownership_policy`` to require that the object actually opened is
    owned by the mount.  Pass ``storage`` to supply the filesystem
    operations; see :class:`FileStorage`.
    """

    def __init__(
        self,
        filename,
        ownership_policy=None,
        policy=None,
        file_policy=None,
        shared_files=None,
        shared=None,
        allowed_files=None,
        approved_files=None,
        storage=None,
        **kw,
    ):
        if ownership_policy is None:
            ownership_policy = policy or file_policy

        shared_files = _shared_arguments(
            shared_files, shared, allowed_files, approved_files
        )

        self.filename = filename
        content_type, content_encoding = mimetypes.guess_type(filename)
        kw.setdefault("content_type", content_type)
        kw.setdefault("content_encoding", content_encoding)
        kw.setdefault("accept_ranges", "bytes")
        self.kw = kw
        # Used for testing purpose
        self._open = open
        self._storage = storage
        self.ownership_policy = _coerce_policy(ownership_policy)

        if self.ownership_policy is not None or shared_files:
            if self.ownership_policy is None:
                self.ownership_policy = FileOwnershipPolicy()

            directory = os.path.dirname(os.path.abspath(filename)) or os.sep
            self._bind_policy(self.ownership_policy, directory)
            self._share_paths(shared_files)

    @property
    def storage(self):
        """The filesystem operations used when an ownership policy is set."""

        return self._storage

    @storage.setter
    def storage(self, storage):
        self._storage = storage

    def set_ownership_policy(self, policy, storage=None):
        """Attach or replace the ownership policy used for this file.

        The policy is expected to have a mount root, either supplied when it
        was created or bound by :class:`DirectoryApp`.
        """

        self.ownership_policy = _coerce_policy(policy)

        if storage is not None:
            self._storage = storage

        if self.ownership_policy is not None and self.ownership_policy.root is None:
            directory = os.path.dirname(os.path.abspath(self.filename)) or os.sep
            self._bind_policy(self.ownership_policy, directory)

        return self

    def _policy_open(self):
        if self._storage is not None:
            return self._storage.open(self.filename)

        # Honour the historical _open override as well as the storage seam.
        if self._open is not open:
            return self._open(self.filename, "rb")

        return open(self.filename, "rb")

    def _policy_fstat(self, file):
        storage = self._storage

        if storage is not None and hasattr(storage, "fstat"):
            return storage.fstat(file)

        if hasattr(file, "fileno"):
            return os.fstat(file.fileno())

        stat_method = getattr(file, "stat", None)

        if stat_method is not None:
            return stat_method()

        raise OSError("The opened object does not expose its identity")

    def _bind_policy(self, policy, root):
        return _bind_policy(self._storage, policy, root)

    def _share_paths(self, shared_files):
        return _share_paths(self._storage, self.ownership_policy, shared_files)

    def _policy_stat(self, path):
        return _stat(self._storage, path)

    def _policy_realpath(self, path):
        return _realpath(self._storage, path)

    def _identity(self, stat_result):
        return _identity_of(self._storage, stat_result)

    def _still_owned(self, file, identity):
        policy = self.ownership_policy

        if policy is None:
            return True

        try:
            current = self._policy_fstat(file)
        except OSError:
            return False

        if self._identity(current) != identity or not _is_regular(current):
            return False

        try:
            path_stat = self._policy_stat(self.filename)
        except OSError:
            return False

        if self._identity(path_stat) != identity or not _is_regular(path_stat):
            return False

        try:
            real_path = self._policy_realpath(self.filename)
        except OSError:
            return False

        # The policy may have been narrowed or the shared registration
        # withdrawn since the response was generated.
        return policy.allows(self.filename, current, real_path)

    @wsgify
    def __call__(self, req):
        if req.method not in ("GET", "HEAD"):
            return exc.HTTPMethodNotAllowed("You cannot %s a file" % req.method)

        if self.ownership_policy is not None:
            return self._policy_response()

        try:
            stat = os.stat(self.filename)
        except OSError as e:
            msg = f"Can't open {self.filename!r}: {e}"
            return exc.HTTPNotFound(comment=msg)

        try:
            file = self._open(self.filename, "rb")
        except OSError as e:
            msg = "You are not permitted to view this file (%s)" % e
            return exc.HTTPForbidden(msg)

        if "wsgi.file_wrapper" in req.environ:
            app_iter = req.environ["wsgi.file_wrapper"](file, BLOCK_SIZE)
        else:
            app_iter = FileIter(file)

        return Response(
            app_iter=app_iter,
            content_length=stat.st_size,
            last_modified=stat.st_mtime,
            # @@ etag
            **self.kw,
        ).conditional_response_app

    def _policy_response(self):
        try:
            file = self._policy_open()
        except OSError:
            return Response(status=404)

        try:
            file_stat = self._policy_fstat(file)
        except OSError:
            _close_quietly(file)
            return Response(status=404)

        if not _is_regular(file_stat):
            _close_quietly(file)
            return Response(status=403)

        try:
            real_path = self._policy_realpath(self.filename)
            path_stat = self._policy_stat(self.filename)
        except OSError:
            _close_quietly(file)
            return Response(status=404)

        identity = self._identity(file_stat)

        # The path must still name the object that was actually opened.
        if (
            self._identity(path_stat) != identity
            or not _is_regular(path_stat)
            or not self.ownership_policy.allows(self.filename, file_stat, real_path)
        ):
            _close_quietly(file)
            return Response(status=403)

        app_iter = FileIter(file, verify=lambda: self._still_owned(file, identity))

        response_kw = dict(self.kw)
        response_kw["content_length"] = getattr(file_stat, "st_size", None)
        response_kw["last_modified"] = getattr(file_stat, "st_mtime", None)

        # A wrapper would read the descriptor without the guarded iterator.
        return Response(
            app_iter=app_iter,
            **response_kw,
        ).conditional_response_app


class FileIter:
    def __init__(self, file, verify=None):
        self.file = file
        self._verify = verify
        self._closed = False

    def close(self):
        if self._closed:
            return

        self._closed = True

        try:
            self.file.close()
        except Exception:
            pass

    def app_iter_range(self, seek=None, limit=None, block_size=None):
        """Iter over the content of the file.

        You can set the `seek` parameter to read the file starting from a
        specific position.

        You can set the `limit` parameter to read the file up to specific
        position.

        Finally, you can change the number of bytes read at once by setting the
        `block_size` parameter.
        """

        return FileIterRange(self, seek=seek, limit=limit, block_size=block_size)

    __iter__ = app_iter_range


class FileIterRange:
    """Explicit range iterator which always closes the source file.

    Unlike a generator, ``close`` releases the file even when iteration was
    never started, which matters for ``HEAD`` and for clients which abandon a
    range response.
    """

    def __init__(self, file_iter, seek=None, limit=None, block_size=None):
        self.file_iter = file_iter
        self.seek = seek
        self.limit = limit
        self.block_size = BLOCK_SIZE if block_size is None else block_size
        self._started = False
        self._done = False

    def __iter__(self):
        return self

    def _start(self):
        if self._started:
            return True

        # Approval is confirmed immediately before the first read, after the
        # response headers were generated.  A storage change now stops the
        # body instead of exposing an unapproved object.
        verify = self.file_iter._verify

        if verify is not None and not verify():
            self.close()
            return False

        self._started = True

        if self.seek:
            self.file_iter.file.seek(self.seek)

            if self.limit is not None:
                self.limit -= self.seek

        return True

    def __next__(self):
        if self._done:
            raise StopIteration

        if not self._start():
            raise StopIteration

        data = self.file_iter.file.read(
            min(self.block_size, self.limit)
            if self.limit is not None
            else self.block_size
        )

        if not data:
            self.close()
            raise StopIteration

        if self.limit is not None:
            self.limit -= len(data)

            if self.limit <= 0:
                self.close()

        return data

    next = __next__

    def close(self):
        self._done = True
        self.file_iter.close()


class DirectoryApp:
    """An application that serves up the files in a given directory.

    This will serve index files (by default ``index.html``), or set
    ``index_page=None`` to disable this.  If you set
    ``hide_index_with_redirect=True`` (it defaults to False) then
    requests to, e.g., ``/index.html`` will be redirected to ``/``.

    To customize `FileApp` instances creation (which is what actually
    serves the responses), override the `make_fileapp` method.

    Pass ``ownership_policy`` to require that every served object is owned
    by this mount.  ``shared_files`` is a convenience for registering files
    that administrators have approved outside the mount; relative paths are
    interpreted below the mount.  ``storage`` supplies the filesystem
    operations used by the policy; see :class:`FileStorage`.
    """

    def __init__(
        self,
        path,
        index_page="index.html",
        hide_index_with_redirect=False,
        ownership_policy=None,
        policy=None,
        file_policy=None,
        shared_files=None,
        shared=None,
        allowed_files=None,
        approved_files=None,
        storage=None,
        root_device=None,
        **kw,
    ):
        if ownership_policy is None:
            ownership_policy = policy or file_policy

        shared_files = _shared_arguments(
            shared_files, shared, allowed_files, approved_files
        )

        self.path = os.path.abspath(path)
        if not self.path.endswith(os.path.sep):
            self.path += os.path.sep
        if not os.path.isdir(self.path):
            raise OSError("Path does not exist or is not directory: %r" % self.path)
        self.index_page = index_page
        self.hide_index_with_redirect = hide_index_with_redirect
        self.fileapp_kw = kw
        self.storage = storage
        self.ownership_policy = _coerce_policy(ownership_policy)

        if self.ownership_policy is None and shared_files:
            self.ownership_policy = FileOwnershipPolicy()

        if self.ownership_policy is not None:
            _bind_policy(storage, self.ownership_policy, self.path)

            if root_device is not None:
                self.ownership_policy.root_device = root_device

            if shared_files:
                _share_paths(storage, self.ownership_policy, shared_files)

    @property
    def shared_files(self):
        """The paths currently approved by the ownership policy, if any."""

        if self.ownership_policy is None:
            return ()

        return self.ownership_policy.shared_files

    def make_fileapp(self, path):
        return FileApp(path, **self.fileapp_kw)

    def _make_fileapp(self, path):
        app = self.make_fileapp(path)

        if self.ownership_policy is not None and isinstance(app, FileApp):
            app.storage = self.storage
            app.set_ownership_policy(self.ownership_policy)

        return app

    @wsgify
    def __call__(self, req):
        path = os.path.abspath(os.path.join(self.path, req.path_info.lstrip("/")))
        if os.path.isdir(path) and self.index_page:
            return self.index(req, path)
        if (
            self.index_page
            and self.hide_index_with_redirect
            and path.endswith(os.path.sep + self.index_page)
        ):
            new_url = req.path_url.rsplit("/", 1)[0]
            new_url += "/"
            if req.query_string:
                new_url += "?" + req.query_string
            return Response(status=301, location=new_url)
        if not path.startswith(self.path):
            return self._forbidden()
        elif not os.path.isfile(path):
            return self._not_found(path)
        else:
            return self._make_fileapp(path)

    def index(self, req, path):
        index_path = os.path.join(path, self.index_page)
        if not os.path.isfile(index_path):
            return self._not_found(index_path)
        if not req.path_info.endswith("/"):
            url = req.path_url + "/"
            if req.query_string:
                url += "?" + req.query_string
            return Response(status=301, location=url)
        return self._make_fileapp(index_path)

    def _forbidden(self):
        if self.ownership_policy is not None:
            return Response(status=403)

        return exc.HTTPForbidden()

    def _not_found(self, path=None):
        if self.ownership_policy is not None:
            return Response(status=404)

        return exc.HTTPNotFound(comment=path)


OwnershipPolicy = FileOwnershipPolicy
FilePolicy = FileOwnershipPolicy


def _shared_arguments(*values):
    shared = ()

    for value in values:
        if value is not None:
            shared += _as_paths(value)

    return shared


def _coerce_policy(policy):
    if policy is None or policy is False:
        return None

    if policy is True:
        return FileOwnershipPolicy()

    if isinstance(policy, dict):
        return FileOwnershipPolicy(**policy)

    return policy


def _close_quietly(file):
    try:
        file.close()
    except Exception:
        pass
