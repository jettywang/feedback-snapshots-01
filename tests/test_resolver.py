"""Test cases for resolver.py."""

import hashlib
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from in_toto.exceptions import StrictRecordingError
from in_toto.resolver import (
    RESOLVER_FOR_URI_SCHEME,
    FileResolver,
    ReadEvent,
    Resolver,
)
from in_toto.resolver._resolver import _hash_file
from tests.common import TmpDirMixin


class TestResolverHelper(unittest.TestCase):
    def test_hash_file(self):
        """Test normalize file endings."""
        data = b"ab\r\nd\nf\r" * 4096
        fd, filename = tempfile.mkstemp()
        try:
            os.write(fd, data)
            os.close(fd)

            result = _hash_file(filename, "sha256", True)

            normalized = data.replace(b"\r\n", b"\n").replace(b"\r", b"\n")
            expected = hashlib.sha256(normalized).hexdigest()
            self.assertEqual(result, expected)

        finally:
            os.remove(filename)


class TestResolver(unittest.TestCase):
    """Test default and custom resolver registration and dispatch."""

    def test_register(self):
        self.assertFalse(RESOLVER_FOR_URI_SCHEME)  # assert empty

        class Default(Resolver):
            def hash_artifacts(self, uris):
                pass

        class Custom(Resolver):
            def hash_artifacts(self, uris):
                pass

        # uris with: default scheme, non-registered scheme, no scheme
        uris = ["file:path/to/file", "C:\\path\\to\\file", "path/to/file"]

        # Raise if no scheme is registered (default must be registered too)
        for uri in uris:
            with self.assertRaises(KeyError, msg=f"uri={uri}"):
                Resolver.for_uri(uri)

        RESOLVER_FOR_URI_SCHEME["file"] = Default()
        RESOLVER_FOR_URI_SCHEME["custom"] = Custom()

        # Once registered, all uris w/o (registered) scheme resolve to default.
        for uri in uris:
            self.assertIsInstance(Resolver.for_uri(uri), Default, f"uri={uri}")

        self.assertIsInstance(Resolver.for_uri("custom:path"), Custom)
        self.assertIsInstance(Resolver.for_uri("custom"), Default)  # no scheme

        RESOLVER_FOR_URI_SCHEME.clear()


class TestFileResolver(TmpDirMixin, unittest.TestCase):
    """Test hash_artifacts with and without scheme.

    See 'test_runlib' for comprehensive tests of file hash recording.
    """

    @classmethod
    def setUpClass(cls):
        cls.set_up_test_dir()  # tear_down_test_dir is called implicitly
        Path("foo").touch()
        Path("bar").mkdir()
        Path("bar/baz").touch()
        Path("bar/foo").touch()

    def test_hash_artifacts_scheme_no_scheme(self):
        """Assert that hashes are the same with and without scheme."""
        resolver = FileResolver()
        uris = {"foo", "file:foo"}
        result = resolver.hash_artifacts(uris)
        self.assertEqual(result.keys(), uris)
        # pylint: disable=no-value-for-parameter
        self.assertEqual(*result.values())

    def test_hash_artifacts_kwags(self):
        """Assert return values for hash_artifacts with different config."""
        # Test data: kwargs, uris, expected return value (dict keys)
        test_data = [
            ({"base_path": "bar"}, {"file:baz"}, {"file:baz"}),
            ({"lstrip_paths": ["bar/"]}, {"file:bar/baz"}, {"file:baz"}),
            (
                {"exclude_patterns": ["file*", "baz"]},
                {"file:foo", "file:bar"},
                {"file:foo", "file:bar/foo"},
            ),
        ]

        for kwargs, uris, expected_keys in test_data:
            resolver = FileResolver(**kwargs)
            result = resolver.hash_artifacts(uris)
            self.assertEqual(result.keys(), expected_keys)


class TestFileResolverStrict(TmpDirMixin, unittest.TestCase):
    """Test strict file reading with controlled read hooks."""

    @classmethod
    def setUpClass(cls):
        cls.set_up_test_dir()

    def setUp(self):
        self.path = "artifact"
        with open(self.path, "wb") as file:
            file.write(b"original content")

    def tearDown(self):
        for name in ("artifact", "replacement", "artifact.tmp"):
            if os.path.exists(name):
                os.remove(name)

    def _replace_once_at(self, event, data):
        """Return hook that replaces artifact with ``data`` on ``event``."""

        state = {"done": False}

        def hook(read_event):
            if read_event.operation == event and not state["done"]:
                state["done"] = True
                with open("replacement", "wb") as file:
                    file.write(data)
                os.replace("replacement", self.path)

        return hook

    def _truncate_once_at(self, event):
        """Return hook that truncates artifact on ``event``."""

        state = {"done": False}

        def hook(read_event):
            if read_event.operation == event and not state["done"]:
                state["done"] = True
                with open(self.path, "wb") as file:
                    file.write(b"")

        return hook

    def _assert_strict_failure(self, hook, reason):
        resolver = FileResolver(strict=True, read_hook=hook)
        with self.assertRaises(StrictRecordingError) as raise_ctx:
            resolver.hash_artifacts([self.path])

        self.assertEqual(raise_ctx.exception.reason, reason)
        self.assertEqual(raise_ctx.exception.path, self.path)

    def test_stable_file_succeeds_and_matches_non_strict(self):
        resolver = FileResolver(strict=True)
        strict_hashes = resolver.hash_artifacts([self.path])

        non_strict_hashes = FileResolver().hash_artifacts([self.path])
        self.assertEqual(strict_hashes, non_strict_hashes)

        with open(self.path, "rb") as file:
            expected = hashlib.sha256(file.read()).hexdigest()
        self.assertEqual(strict_hashes[self.path]["sha256"], expected)

    def test_path_replaced_with_different_content(self):
        # Replace before reading content. The replacement has different
        # content, so a naive reopen would silently record the new file.
        self._assert_strict_failure(
            self._replace_once_at("open", b"replaced content"),
            "path-replaced",
        )

    def test_path_replaced_with_identical_content(self):
        # Identity, not content, is the binding. Same bytes at a new inode
        # must still fail, which a hash comparison could never detect.
        self._assert_strict_failure(
            self._replace_once_at("open", b"original content"),
            "path-replaced",
        )

    def test_path_replaced_after_all_bytes_read(self):
        self._assert_strict_failure(
            self._replace_once_at("read", b"replaced content"),
            "path-replaced",
        )

    def test_path_replaced_before_final_verification(self):
        self._assert_strict_failure(
            self._replace_once_at("before-verify", b"replaced content"),
            "path-replaced",
        )

    def test_file_truncated_after_first_chunk(self):
        # Use a file with two read chunks so truncation is observed mid-read.
        with open(self.path, "wb") as file:
            file.write(b"first chunk\nsecond chunk\n")

        self._assert_strict_failure(
            self._truncate_once_at("read"), "file-changed"
        )

    def test_file_modified_in_place_after_first_chunk(self):
        with open(self.path, "wb") as file:
            file.write(b"first chunk\nsecond chunk\n")

        state = {"done": False}

        def hook(read_event):
            if read_event.operation == "read" and not state["done"]:
                state["done"] = True
                with open(self.path, "wb") as file:
                    file.write(b"first chunk\nmodified chunk")

        self._assert_strict_failure(hook, "file-changed")

    def test_size_mismatch_is_detected_even_without_mtime(self):
        # Suspend stat change detection to exercise the bytes-read/size check.
        # Truncating before the first chunk means fewer bytes are read than
        # the size observed at open time.
        with mock.patch(
            "in_toto.resolver._resolver._stat_signature", return_value=()
        ):
            self._assert_strict_failure(
                self._truncate_once_at("open"), "size-mismatch"
            )

    def test_path_vanished(self):
        state = {"done": False}

        def hook(read_event):
            if read_event.operation == "open" and not state["done"]:
                state["done"] = True
                os.remove(self.path)

        self._assert_strict_failure(hook, "path-vanished")

    def test_read_hook_can_repeat_reads_event(self):
        # Multiple chunks must each trigger a read event; this guards against
        # accidentally checking only once.
        events = []

        def hook(read_event):
            events.append(read_event.operation)

        with open(self.path, "wb") as file:
            file.write(b"x" * 9000)

        FileResolver(strict=True, read_hook=hook).hash_artifacts([self.path])
        self.assertEqual(events[0], "open")
        self.assertEqual(events[-1], "before-verify")
        self.assertEqual(events.count("read"), 3)

    def test_read_event_fields(self):
        events = []
        FileResolver(strict=True, read_hook=events.append).hash_artifacts(
            [self.path]
        )
        self.assertIsInstance(events[0], ReadEvent)
        self.assertEqual(events[0].fd, events[0].fd)
        self.assertGreater(events[0].fd, 0)
        self.assertEqual(events[0].bytes_read, 0)
        self.assertEqual(events[0].path, self.path)

    def test_symlinked_file_is_recorded_through_link(self):
        if "symlink" not in os.__dict__:
            self.skipTest("symlink is not supported in this platform")

        os.symlink(self.path, "link")
        try:
            hashes = FileResolver(strict=True).hash_artifacts(["link"])
            self.assertEqual(hashes["link"], hashes["link"])
            self.assertIn("link", hashes)
        finally:
            os.remove("link")

    def test_symlink_retargeted_after_open_fails(self):
        if "symlink" not in os.__dict__:
            self.skipTest("symlink is not supported in this platform")

        os.symlink(self.path, "link")
        with open("other", "wb") as file:
            file.write(b"other content")

        state = {"done": False}

        def hook(read_event):
            if read_event.operation == "open" and not state["done"]:
                state["done"] = True
                os.remove("link")
                os.symlink("other", "link")

        try:
            with self.assertRaises(StrictRecordingError) as raise_ctx:
                FileResolver(strict=True, read_hook=hook).hash_artifacts(
                    ["link"]
                )
            self.assertEqual(raise_ctx.exception.reason, "path-replaced")
        finally:
            os.remove("link")
            os.remove("other")

    def test_fifo_is_rejected(self):
        if not hasattr(os, "mkfifo"):
            self.skipTest("mkfifo is not supported in this platform")

        os.mkfifo("fifo")
        try:
            with self.assertRaises(StrictRecordingError) as raise_ctx:
                FileResolver(strict=True).hash_artifacts(["fifo"])
            self.assertEqual(raise_ctx.exception.reason, "not-a-regular-file")
        finally:
            os.remove("fifo")

    def test_missing_file_is_rejected(self):
        with self.assertRaises(StrictRecordingError) as raise_ctx:
            FileResolver(strict=True).hash_artifacts(["missing"])
        self.assertEqual(raise_ctx.exception.reason, "path-missing")


if __name__ == "__main__":
    unittest.main()
