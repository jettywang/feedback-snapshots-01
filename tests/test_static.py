from io import BytesIO
import os
from os.path import getmtime
import shutil
import stat
import tempfile
from time import gmtime

import pytest

from webob import static
from webob.request import Request, environ_from_url
from webob.response import Response
from webob.util import bytes_


def get_response(app, path="/", **req_kw):
    """Convenient function to query an application"""
    req = Request(environ_from_url(path), **req_kw)

    return req.get_response(app)


def create_file(content, *paths):
    """Convenient function to create a new file with some content"""
    path = os.path.join(*paths)
    with open(path, "wb") as fp:
        fp.write(bytes_(content))

    return path


class TestFileApp:
    def setup_method(self, method):
        fp = tempfile.NamedTemporaryFile(suffix=".py", delete=False)
        self.tempfile = fp.name
        fp.write(b"import this\n")
        fp.close()

    def tearDown(self):
        os.unlink(self.tempfile)

    def test_fileapp(self):
        app = static.FileApp(self.tempfile)
        resp1 = get_response(app)
        assert resp1.content_type in ("text/x-python", "text/plain")
        assert resp1.charset == "UTF-8"
        assert resp1.last_modified.timetuple() == gmtime(getmtime(self.tempfile))
        assert resp1.body == b"import this\n"

        resp2 = get_response(app)
        assert resp2.content_type in ("text/x-python", "text/plain")
        assert resp2.last_modified.timetuple() == gmtime(getmtime(self.tempfile))
        assert resp2.body == b"import this\n"

        resp3 = get_response(app, range=(7, 11))
        assert resp3.status_code == 206
        assert tuple(resp3.content_range)[:2] == (7, 11)
        assert resp3.last_modified.timetuple() == gmtime(getmtime(self.tempfile))
        assert resp3.body == bytes_("this")

    def test_unexisting_file(self):
        app = static.FileApp("/tmp/this/doesnt/exist")
        assert 404 == get_response(app).status_code

    def test_allowed_methods(self):
        app = static.FileApp(self.tempfile)

        # Alias
        def resp(method):
            return get_response(app, method=method)

        assert 200 == resp(method="GET").status_code
        assert 200 == resp(method="HEAD").status_code
        assert 405 == resp(method="POST").status_code
        # Actually any other method is not allowed
        assert 405 == resp(method="xxx").status_code

    def test_exception_while_opening_file(self):
        # Mock the built-in ``open()`` function to allow finner control about
        # what we are testing.
        def open_ioerror(*args, **kwargs):
            raise OSError()

        def open_oserror(*args, **kwargs):
            raise OSError()

        app = static.FileApp(self.tempfile)

        app._open = open_ioerror
        assert 403 == get_response(app).status_code

        app._open = open_oserror
        assert 403 == get_response(app).status_code

    def test_use_wsgi_filewrapper(self):
        class TestWrapper:
            __slots__ = ("file", "block_size")

            def __init__(self, file, block_size):
                self.file = file
                self.block_size = block_size

        environ = environ_from_url("/")
        environ["wsgi.file_wrapper"] = TestWrapper
        app = static.FileApp(self.tempfile)
        app_iter = Request(environ).get_response(app).app_iter

        assert isinstance(app_iter, TestWrapper)
        assert bytes_("import this\n") == app_iter.file.read()
        assert static.BLOCK_SIZE == app_iter.block_size


class TestFileIter:
    def test_empty_file(self):
        fp = BytesIO()
        fi = static.FileIter(fp)
        pytest.raises(StopIteration, next, iter(fi))

    def test_seek(self):
        fp = BytesIO(bytes_("0123456789"))
        i = static.FileIter(fp).app_iter_range(seek=4)

        assert bytes_("456789") == next(i)
        pytest.raises(StopIteration, next, i)

    def test_limit(self):
        fp = BytesIO(bytes_("0123456789"))
        i = static.FileIter(fp).app_iter_range(limit=4)

        assert bytes_("0123") == next(i)
        pytest.raises(StopIteration, next, i)

    def test_limit_and_seek(self):
        fp = BytesIO(bytes_("0123456789"))
        i = static.FileIter(fp).app_iter_range(limit=4, seek=1)

        assert bytes_("123") == next(i)
        pytest.raises(StopIteration, next, i)

    def test_multiple_reads(self):
        fp = BytesIO(bytes_("012"))
        i = static.FileIter(fp).app_iter_range(block_size=1)

        assert bytes_("0") == next(i)
        assert bytes_("1") == next(i)
        assert bytes_("2") == next(i)
        pytest.raises(StopIteration, next, i)

    def test_seek_bigger_than_limit(self):
        fp = BytesIO(bytes_("0123456789"))
        i = static.FileIter(fp).app_iter_range(limit=1, seek=2)

        # XXX: this should not return anything actually, since we are starting
        # to read after the place we wanted to stop.
        assert bytes_("23456789") == next(i)
        pytest.raises(StopIteration, next, i)

    def test_limit_is_zero(self):
        fp = BytesIO(bytes_("0123456789"))
        i = static.FileIter(fp).app_iter_range(limit=0)

        pytest.raises(StopIteration, next, i)


class TestDirectoryApp:
    def setup_method(self, method):
        self.test_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.test_dir)

    def test_empty_directory(self):
        app = static.DirectoryApp(self.test_dir)
        assert 404 == get_response(app).status_code
        assert 404 == get_response(app, "/foo").status_code

    def test_serve_file(self):
        app = static.DirectoryApp(self.test_dir)
        create_file("abcde", self.test_dir, "bar")
        assert 404 == get_response(app).status_code
        assert 404 == get_response(app, "/foo").status_code

        resp = get_response(app, "/bar")
        assert 200 == resp.status_code
        assert bytes_("abcde") == resp.body

    def test_dont_serve_file_in_parent_directory(self):
        # We'll have:
        #   /TEST_DIR/
        #   /TEST_DIR/bar
        #   /TEST_DIR/foo/   <- serve this directory
        create_file("abcde", self.test_dir, "bar")
        serve_path = os.path.join(self.test_dir, "foo")
        os.mkdir(serve_path)
        app = static.DirectoryApp(serve_path)

        # The file exists, but is outside the served dir.
        assert 403 == get_response(app, "/../bar").status_code

    def test_dont_leak_parent_directory_file_existance(self):
        # We'll have:
        #   /TEST_DIR/
        #   /TEST_DIR/foo/   <- serve this directory
        serve_path = os.path.join(self.test_dir, "foo")
        os.mkdir(serve_path)
        app = static.DirectoryApp(serve_path)

        # The file exists, but is outside the served dir.
        assert 403 == get_response(app, "/../bar2").status_code

    def test_file_app_arguments(self):
        app = static.DirectoryApp(self.test_dir, content_type="xxx/yyy")
        create_file("abcde", self.test_dir, "bar")

        resp = get_response(app, "/bar")
        assert 200 == resp.status_code
        assert "xxx/yyy" == resp.content_type

    def test_file_app_factory(self):
        def make_fileapp(*args, **kwargs):
            make_fileapp.called = True

            return Response()

        make_fileapp.called = False

        app = static.DirectoryApp(self.test_dir)
        app.make_fileapp = make_fileapp
        create_file("abcde", self.test_dir, "bar")

        get_response(app, "/bar")
        assert make_fileapp.called

    def test_must_serve_directory(self):
        serve_path = create_file("abcde", self.test_dir, "bar")
        pytest.raises(IOError, static.DirectoryApp, serve_path)

    def test_index_page(self):
        os.mkdir(os.path.join(self.test_dir, "index-test"))
        create_file(bytes_("index"), self.test_dir, "index-test", "index.html")
        app = static.DirectoryApp(self.test_dir)
        resp = get_response(app, "/index-test")
        assert resp.status_code == 301
        assert resp.location.endswith("/index-test/")
        resp = get_response(app, "/index-test?test")
        assert resp.location.endswith("/index-test/?test")
        resp = get_response(app, "/index-test/")
        assert resp.status_code == 200
        assert resp.body == bytes_("index")
        assert resp.content_type == "text/html"
        resp = get_response(app, "/index-test/index.html")
        assert resp.status_code == 200
        assert resp.body == bytes_("index")
        redir_app = static.DirectoryApp(self.test_dir, hide_index_with_redirect=True)
        resp = get_response(redir_app, "/index-test/index.html")
        assert resp.status_code == 301
        assert resp.location.endswith("/index-test/")
        resp = get_response(redir_app, "/index-test/index.html?test")
        assert resp.location.endswith("/index-test/?test")
        page_app = static.DirectoryApp(self.test_dir, index_page="something-else.html")
        assert get_response(page_app, "/index-test/").status_code == 404


class Stat:
    """Minimal stat result used by the storage substitutes."""

    def __init__(self, identity, size=0, mtime=0, mode=None):
        if mode is None:
            mode = stat.S_IFREG | 0o444

        self.st_dev, self.st_ino = identity
        self.st_size = size
        self.st_mtime = mtime
        self.st_mode = mode


class TrackingFile:
    def __init__(self, name, content, stat_result, events):
        self.name = name
        self._buffer = BytesIO(content)
        self._stat = stat_result
        self.closed = False
        self.events = events

    def read(self, size=-1):
        return self._buffer.read(size)

    def seek(self, offset, whence=0):
        return self._buffer.seek(offset, whence)

    def tell(self):
        return self._buffer.tell()

    def fileno(self):
        raise OSError("no real descriptor")

    def stat(self):
        return self._stat

    def close(self):
        if not self.closed:
            self.closed = True
            self.events.append(("closed", self.name))


class SwitchingStorage(static.FileStorage):
    """Storage that changes the reported identity after approval."""

    def __init__(self, files, switched_identity=None):
        self.files = files
        self.switched_identity = switched_identity
        self.opened = []
        self.events = []
        self.switch_all = False
        self.switch_fstat = False
        self.switch_stat = False
        self.switch_after_fstat_calls = None
        self.fail_open = False
        self.fstat_calls = 0
        self.stat_calls = 0

    def _entry(self, path):
        name = os.path.basename(path)

        if name not in self.files:
            raise FileNotFoundError(path)

        return self.files[name]

    def _current(self, entry, source):
        identity = entry["identity"]
        switched = self.switch_all or entry.get("switched")

        if source == "fstat" and (
            self.switch_fstat
            or (
                self.switch_after_fstat_calls is not None
                and self.fstat_calls > self.switch_after_fstat_calls
            )
        ):
            switched = True
        elif source == "stat" and self.switch_stat:
            switched = True

        if switched:
            identity = self.switched_identity or (0, 0)

        return Stat(identity, entry["size"])

    def open(self, path):
        if self.fail_open:
            raise OSError("storage went away")

        entry = self._entry(path)
        opened = TrackingFile(
            os.path.basename(path),
            entry["content"],
            self._current(entry, "fstat"),
            self.events,
        )
        self.opened.append(opened)
        return opened

    def stat(self, path):
        self.stat_calls += 1
        return self._current(self._entry(path), "stat")

    def fstat(self, file):
        self.fstat_calls += 1
        current = self._current(self._entry(file.name), "fstat")
        file._stat = current
        return current

    def realpath(self, path):
        return os.path.realpath(path)


def _register_file(root, relative, content, storage, identity=None):
    path = os.path.join(root, relative)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as fp:
        fp.write(content)

    st = os.stat(path)
    storage.files[os.path.basename(path)] = {
        "content": content,
        "size": len(content),
        "identity": identity or (st.st_dev, st.st_ino),
    }
    return path


def _policy_app(tmp_path, storage, shared=(), mount_name="mount"):
    mount = tmp_path / mount_name
    mount.mkdir(exist_ok=True)
    policy = static.FileOwnershipPolicy(root=str(mount), shared_files=shared)
    return static.DirectoryApp(str(mount), ownership_policy=policy, storage=storage)


def test_policy_serves_files_inside_the_mount(tmp_path):
    content = b"0123456789"
    storage = SwitchingStorage({})
    _register_file(tmp_path / "mount", "inside.txt", content, storage)
    app = _policy_app(tmp_path, storage)

    resp = get_response(app, "/inside.txt")

    assert resp.status_code == 200
    assert resp.body == content
    assert [file.name for file in storage.opened] == ["inside.txt"]
    assert storage.opened[0].closed


def test_policy_refuses_a_shared_file_whose_identity_changed(tmp_path):
    content = b"approved bytes"
    storage = SwitchingStorage({}, switched_identity=(99, 99))
    outside = tmp_path / "outside"
    outside.mkdir()
    shared = outside / "shared.txt"
    shared.write_bytes(content)
    storage.files["shared.txt"] = {
        "content": content,
        "size": len(content),
        "identity": (1, 1),
        "switched": True,
    }
    os.makedirs(str(tmp_path / "mount"), exist_ok=True)
    os.symlink(str(shared), str(tmp_path / "mount" / "shared.txt"))
    app = _policy_app(tmp_path, storage, shared=[str(shared)])

    resp = get_response(app, "/shared.txt")

    assert resp.status_code == 403
    assert resp.body == b""
    assert storage.opened
    assert storage.opened[0].closed


def test_policy_stops_when_identity_changes_between_response_and_body(tmp_path):
    content = b"0123456789"
    storage = SwitchingStorage({})
    _register_file(tmp_path / "mount", "inside.txt", content, storage)
    app = _policy_app(tmp_path, storage)

    resp = get_response(app, "/inside.txt")
    app_iter = resp.app_iter
    storage.switch_all = True
    body = b"".join(app_iter)

    assert body == b""
    assert storage.opened[0].closed
    assert resp.app_iter is app_iter
    assert storage.opened[0]._buffer.tell() == 0


def test_policy_stops_when_only_the_open_file_identity_changes(tmp_path):
    content = b"0123456789"
    storage = SwitchingStorage({})
    _register_file(tmp_path / "mount", "inside.txt", content, storage)
    app = _policy_app(tmp_path, storage)

    resp = get_response(app, "/inside.txt")
    storage.switch_after_fstat_calls = storage.fstat_calls
    body = b"".join(resp.app_iter)

    assert body == b""
    assert storage.opened[0].closed


def test_policy_stops_when_the_path_now_names_another_object(tmp_path):
    content = b"0123456789"
    storage = SwitchingStorage({})
    _register_file(tmp_path / "mount", "inside.txt", content, storage)
    app = _policy_app(tmp_path, storage)

    resp = get_response(app, "/inside.txt")
    storage.switch_stat = True
    storage.switched_identity = (42, 42)
    body = b"".join(resp.app_iter)

    assert body == b""
    assert storage.opened[0].closed


def test_policy_range_request_that_changed_stops_without_bytes(tmp_path):
    content = b"0123456789"
    storage = SwitchingStorage({})
    _register_file(tmp_path / "mount", "inside.txt", content, storage)
    app = _policy_app(tmp_path, storage)

    resp = get_response(app, "/inside.txt", range=(2, 5))
    storage.switch_all = True
    body = b"".join(resp.app_iter)

    assert resp.status_code == 206
    assert body == b""
    assert storage.opened[0].closed


def test_policy_shared_file_is_served_when_identity_matches(tmp_path):
    content = b"shared payload"
    storage = SwitchingStorage({})
    outside = tmp_path / "outside"
    outside.mkdir()
    shared = outside / "shared.txt"
    shared.write_bytes(content)
    st = os.stat(shared)
    storage.files["shared.txt"] = {
        "content": content,
        "size": len(content),
        "identity": (st.st_dev, st.st_ino),
    }
    os.makedirs(str(tmp_path / "mount"), exist_ok=True)
    os.symlink(str(shared), str(tmp_path / "mount" / "shared.txt"))
    app = _policy_app(tmp_path, storage, shared=[str(shared)])

    resp = get_response(app, "/shared.txt")

    assert resp.status_code == 200
    assert resp.body == content
    assert storage.opened[-1].closed


def test_policy_head_uses_the_same_admission(tmp_path):
    content = b"head bytes"
    storage = SwitchingStorage({}, switched_identity=(5, 5))
    outside = tmp_path / "outside"
    outside.mkdir()
    shared = outside / "shared.txt"
    shared.write_bytes(content)
    storage.files["shared.txt"] = {
        "content": content,
        "size": len(content),
        "identity": (1, 1),
        "switched": True,
    }
    os.makedirs(str(tmp_path / "mount"), exist_ok=True)
    os.symlink(str(shared), str(tmp_path / "mount" / "shared.txt"))
    app = _policy_app(tmp_path, storage, shared=[str(shared)])

    resp = get_response(app, "/shared.txt", method="HEAD")

    assert resp.status_code == 403
    assert resp.body == b""


def test_policy_range_and_full_read_use_the_same_approved_object(tmp_path):
    content = b"0123456789"
    storage = SwitchingStorage({})
    _register_file(tmp_path / "mount", "inside.txt", content, storage)
    app = _policy_app(tmp_path, storage)

    full = get_response(app, "/inside.txt")
    full_file = full.app_iter.file
    range_resp = get_response(app, "/inside.txt", range=(2, 5))
    range_file = range_resp.app_iter.file_iter.file

    assert full.status_code == 200
    assert full.body == content
    assert range_resp.status_code == 206
    assert range_resp.body == content[2:5]
    assert full_file is storage.opened[0]
    assert range_file is storage.opened[1]
    assert [file.name for file in storage.opened] == ["inside.txt", "inside.txt"]
    assert all(file.closed for file in storage.opened)


def test_policy_revocation_before_body_produces_no_bytes(tmp_path):
    content = b"to be withdrawn"
    storage = SwitchingStorage({})
    path = _register_file(tmp_path / "mount", "inside.txt", content, storage)
    mount = tmp_path / "mount"
    policy = static.FileOwnershipPolicy(root=str(mount))
    app = static.DirectoryApp(str(mount), ownership_policy=policy, storage=storage)

    resp = get_response(app, "/inside.txt")
    app_iter = resp.app_iter
    policy.revoke(path)
    policy.root = str(tmp_path / "other")
    body = b"".join(app_iter)

    assert body == b""
    assert storage.opened[0].closed


def test_policy_missing_file_does_not_reveal_the_internal_path(tmp_path):
    storage = SwitchingStorage({})
    app = _policy_app(tmp_path, storage)

    resp = get_response(app, "/missing.txt")

    assert resp.status_code == 404
    assert resp.body == b""
    assert str(tmp_path) not in str(resp.headers)


def test_policy_factory_and_redirect_keep_legacy_behaviour(tmp_path):
    (tmp_path / "mount" / "index-test").mkdir(parents=True)

    class RecordingApp:
        def __init__(self, path):
            self.path = path

        def __call__(self, req):
            return Response(b"made", content_type="text/plain")

    calls = []

    def make_fileapp(path):
        calls.append(path)
        return RecordingApp(path)

    app = static.DirectoryApp(str(tmp_path / "mount"))
    app.make_fileapp = make_fileapp
    create_file(b"index", str(tmp_path / "mount"), "index-test", "index.html")

    resp = get_response(app, "/index-test")

    assert resp.status_code == 301
    assert resp.location.endswith("/index-test/")
    assert calls == []


def test_policy_with_real_filesystem_serves_owned_and_shared_files(tmp_path):
    mount = tmp_path / "mount"
    mount.mkdir()
    (mount / "inside.txt").write_bytes(b"owned")
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "shared.txt").write_bytes(b"shared")
    policy = static.FileOwnershipPolicy(
        root=str(mount), shared_files=[str(outside / "shared.txt")]
    )
    app = static.DirectoryApp(str(mount), ownership_policy=policy)
    os.symlink(str(outside / "shared.txt"), str(mount / "shared.txt"))

    owned = get_response(app, "/inside.txt")
    shared = get_response(app, "/shared.txt")

    assert owned.status_code == 200
    assert owned.body == b"owned"
    assert shared.status_code == 200
    assert shared.body == b"shared"


def test_policy_refuses_an_unregistered_symlink_target(tmp_path):
    mount = tmp_path / "mount"
    mount.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.txt").write_bytes(b"secret")
    os.symlink(str(outside / "secret.txt"), str(mount / "escape.txt"))
    app = static.DirectoryApp(
        str(mount), ownership_policy=static.FileOwnershipPolicy()
    )

    resp = get_response(app, "/escape.txt")

    assert resp.status_code == 403
    assert resp.body == b""
    assert b"secret" not in resp.body


def test_policy_shared_file_replaced_after_approval_is_refused(tmp_path):
    mount = tmp_path / "mount"
    mount.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    shared = outside / "shared.txt"
    shared.write_bytes(b"approved")
    policy = static.FileOwnershipPolicy(
        root=str(mount), shared_files=[str(shared)]
    )
    app = static.DirectoryApp(str(mount), ownership_policy=policy)
    os.symlink(str(shared), str(mount / "shared.txt"))
    before = get_response(app, "/shared.txt")
    assert before.status_code == 200

    replacement = outside / "replacement.txt"
    replacement.write_bytes(b"replacement")
    os.replace(str(replacement), str(shared))
    after = get_response(app, "/shared.txt")

    assert after.status_code == 403
    assert after.body == b""


def test_policy_index_page_uses_the_same_admission(tmp_path):
    mount = tmp_path / "mount"
    section = mount / "section"
    section.mkdir(parents=True)
    (section / "index.html").write_bytes(b"<h1>index</h1>")
    policy = static.FileOwnershipPolicy(root=str(mount))
    app = static.DirectoryApp(str(mount), ownership_policy=policy)

    redirect = get_response(app, "/section")
    index = get_response(app, "/section/")
    direct = get_response(app, "/section/index.html")
    head = get_response(app, "/section/", method="HEAD")

    assert redirect.status_code == 301
    assert redirect.location.endswith("/section/")
    assert index.status_code == 200
    assert index.body == b"<h1>index</h1>"
    assert direct.status_code == 200
    assert direct.body == b"<h1>index</h1>"
    assert head.status_code == 200
    assert head.body == b""


def test_policy_does_not_use_an_unaudited_file_wrapper(tmp_path):
    content = b"wrapped"
    storage = SwitchingStorage({})
    _register_file(tmp_path / "mount", "inside.txt", content, storage)
    app = _policy_app(tmp_path, storage)

    class Wrapper:
        used = False

        def __init__(self, file, block_size):
            Wrapper.used = True
            self.file = file

    environ = environ_from_url("/inside.txt")
    environ["wsgi.file_wrapper"] = Wrapper
    resp = Request(environ).get_response(app)

    assert resp.status_code == 200
    assert resp.body == content
    assert Wrapper.used is False
    assert storage.opened[0].closed


def test_policy_deleted_before_body_produces_no_bytes(tmp_path):
    content = b"deleted"
    storage = SwitchingStorage({})
    path = _register_file(tmp_path / "mount", "inside.txt", content, storage)
    app = _policy_app(tmp_path, storage)

    resp = get_response(app, "/inside.txt")
    os.remove(path)
    storage.files.pop("inside.txt")
    body = b"".join(resp.app_iter)

    assert body == b""
    assert storage.opened[0].closed


def test_policy_open_failure_is_clean(tmp_path):
    storage = SwitchingStorage({})
    _register_file(tmp_path / "mount", "inside.txt", b"payload", storage)
    storage.fail_open = True
    app = _policy_app(tmp_path, storage)

    resp = get_response(app, "/inside.txt")

    assert resp.status_code == 404
    assert resp.body == b""


def test_policy_shared_file_removed_from_policy_before_body(tmp_path):
    content = b"approved"
    storage = SwitchingStorage({})
    outside = tmp_path / "outside"
    outside.mkdir()
    shared = outside / "shared.txt"
    shared.write_bytes(content)
    st = os.stat(shared)
    storage.files["shared.txt"] = {
        "content": content,
        "size": len(content),
        "identity": (st.st_dev, st.st_ino),
    }
    os.makedirs(str(tmp_path / "mount"), exist_ok=True)
    os.symlink(str(shared), str(tmp_path / "mount" / "shared.txt"))
    policy = static.FileOwnershipPolicy(
        root=str(tmp_path / "mount"), shared_files=[str(shared)]
    )
    app = static.DirectoryApp(
        str(tmp_path / "mount"), ownership_policy=policy, storage=storage
    )

    resp = get_response(app, "/shared.txt")
    policy.revoke(str(shared))
    body = b"".join(resp.app_iter)

    assert body == b""
    assert storage.opened[0].closed


def test_policy_shared_file_keeps_registration_bound_to_the_approved_object(tmp_path):
    mount = tmp_path / "mount"
    mount.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    original = outside / "shared.txt"
    original.write_bytes(b"approved")
    policy = static.FileOwnershipPolicy(
        root=str(mount), shared_files=[str(original)]
    )
    app = static.DirectoryApp(str(mount), ownership_policy=policy)
    os.symlink(str(original), str(mount / "shared.txt"))
    assert get_response(app, "/shared.txt").status_code == 200

    owned = mount / "owned.txt"
    owned.write_bytes(b"owned")
    os.replace(str(owned), str(original))
    shared = get_response(app, "/shared.txt")

    assert shared.status_code == 403
    assert shared.body == b""


def test_policy_accepts_registry_style_arguments(tmp_path):
    mount = tmp_path / "mount"
    mount.mkdir()
    (mount / "inside.txt").write_bytes(b"inside")
    shared = tmp_path / "shared.txt"
    shared.write_bytes(b"shared")
    policy = static.FilePolicy(mount=str(mount), approved_files=[str(shared)])
    app = static.DirectoryApp(str(mount), file_policy=policy)

    assert get_response(app, "/inside.txt").body == b"inside"
    assert policy.allows(str(shared), os.stat(shared), os.path.realpath(shared))
    policy.revoke(str(shared))
    assert not policy.allows(str(shared), os.stat(shared), os.path.realpath(shared))

    direct = static.FileApp(
        str(mount / "inside.txt"), policy={"root": str(mount)}
    )

    assert get_response(direct).body == b"inside"


def test_policy_shared_listing_reflects_registrations(tmp_path):
    mount = tmp_path / "mount"
    mount.mkdir()
    (mount / "inside.txt").write_bytes(b"inside")
    shared = tmp_path / "shared.txt"
    shared.write_bytes(b"shared")
    app = static.DirectoryApp(str(mount), shared_files=["inside.txt"])

    assert app.shared_files == (str(mount / "inside.txt"),)
    app.ownership_policy.share(str(shared))
    os.symlink(str(shared), str(mount / "linked.txt"))

    assert get_response(app, "/linked.txt").body == b"shared"
    app.ownership_policy.revoke(str(shared))
    assert app.shared_files == (str(mount / "inside.txt"),)
