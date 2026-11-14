# Copyright New York University and the in-toto contributors
# SPDX-License-Identifier: Apache-2.0

"""Test cases for DirectoryResolver."""

import os
import tempfile
import unittest
from pathlib import Path

from in_toto.exceptions import PrefixError, StrictRecordingError
from in_toto.resolver import DirectoryResolver, ReadEvent
from tests.common import TmpDirMixin


class TestDirectoryResolver(unittest.TestCase):
    """Test directory resolver implementation."""

    def _mangle_path(self, path):
        return path.replace("\\", "/")

    def test_regular_directory(self):
        path = str(Path(__file__).parent / "resolver" / "dir_resolver")

        resolver = DirectoryResolver(normalize_line_endings=True)
        uri = f"dir:{path}"
        expected_uri = self._mangle_path(uri)

        # Expected hash calculated using:
        # find . -type f | cut -c3- | LC_ALL=C sort | xargs -r sha256sum | sha256sum | cut -f1 -d' '
        expected_artifact_dict = {
            expected_uri: {
                "sha256": "ecdbcdc6bd5d2966ad1f7595874fcd6f505abd3feaa97e27bae74bcb78c38e54"
            }
        }

        artifact_dict = resolver.hash_artifacts([uri])
        self.assertEqual(artifact_dict, expected_artifact_dict)

    def test_regular_directory_with_lstrip(self):
        lstrip_path = (
            f"{self._mangle_path(str(Path(__file__).parent))}/resolver/"
        )
        target_path = str(Path(__file__).parent / "resolver" / "dir_resolver")

        resolver = DirectoryResolver(
            lstrip_paths=[lstrip_path],
            normalize_line_endings=True,
        )

        full_uri = f"dir:{target_path}"
        stripped_uri = "dir:dir_resolver"

        # Expected hash calculated using:
        # find . -type f | cut -c3- | LC_ALL=C sort | xargs -r sha256sum | sha256sum | cut -f1 -d' '
        expected_artifact_dict = {
            stripped_uri: {
                "sha256": "ecdbcdc6bd5d2966ad1f7595874fcd6f505abd3feaa97e27bae74bcb78c38e54"
            }
        }

        artifact_dict = resolver.hash_artifacts([full_uri])
        self.assertEqual(artifact_dict, expected_artifact_dict)

    def test_colliding_lstrips(self):
        lstrip_paths = [
            f"{self._mangle_path(str(Path(__file__).parent))}/resolver/dir_resolver/",
            f"{self._mangle_path(str(Path(__file__).parent))}/resolver/colliding_dir_resolver/",
        ]

        paths = [
            str(Path(__file__).parent / "resolver" / "dir_resolver" / "subdir"),
            str(
                Path(__file__).parent
                / "resolver"
                / "colliding_dir_resolver"
                / "subdir"
            ),
        ]
        uris = [f"dir:{path}" for path in paths]

        resolver = DirectoryResolver(lstrip_paths=lstrip_paths)

        with self.assertRaises(PrefixError):
            resolver.hash_artifacts(uris)

    def test_directory_with_exclude(self):
        path = str(Path(__file__).parent / "resolver" / "dir_resolver")

        resolver = DirectoryResolver(
            exclude_patterns=["README.md"],
            normalize_line_endings=True,
        )

        uri = f"dir:{path}"
        expected_uri = self._mangle_path(uri)

        # Expected hash calculated using:
        # find . -type f | cut -c3- | LC_ALL=C sort | xargs -r sha256sum | sha256sum | cut -f1 -d' '
        expected_artifact_dict = {
            expected_uri: {
                "sha256": "c272da5259699b7bdda998e5c88dd2c5769e6c1cdbb538511f9bd46a0ad527e2"
            }
        }

        artifact_dict = resolver.hash_artifacts([uri])
        self.assertEqual(artifact_dict, expected_artifact_dict)

    def test_non_existent_directory(self):
        resolver = DirectoryResolver()
        with self.assertRaises(ValueError):
            resolver.hash_artifacts(["dir:invalid_dir"])

    def test_actual_and_non_existent_directory(self):
        path = str(Path(__file__).parent / "resolver" / "dir_resolver")

        resolver = DirectoryResolver(
            normalize_line_endings=True,
        )

        uris = ["dir:invalid_dir", f"dir:{path}"]

        with self.assertRaises(ValueError):
            resolver.hash_artifacts(uris)

    def test_actual_and_file(self):
        path = str(Path(__file__).parent / "resolver")

        resolver = DirectoryResolver(
            normalize_line_endings=True,
        )

        uris = [f"dir:{path}/README.md", f"dir:{path}/dir_resolver"]

        with self.assertRaises(ValueError):
            resolver.hash_artifacts(uris)

    def test_empty_dir(self):
        with tempfile.TemporaryDirectory(dir=os.getcwd()) as tmp_dir:
            resolver = DirectoryResolver()

            uri = f"dir:{tmp_dir}"
            expected_uri = self._mangle_path(uri)
            # expected hash is sha256 hash of null input
            # find <empty-dir> -type f | cut -c3- | LC_ALL=C sort | xargs -r sha256sum | sha256sum | cut -f1 -d' '
            expected_artifact_dict = {
                expected_uri: {
                    "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                }
            }

            artifact_dict = resolver.hash_artifacts([uri])
            self.assertEqual(artifact_dict, expected_artifact_dict)


class TestDirectoryResolverStrict(TmpDirMixin, unittest.TestCase):
    """Test strict directory tree recording with controlled read hooks."""

    @classmethod
    def setUpClass(cls):
        cls.set_up_test_dir()

    def setUp(self):
        if self.root().exists():
            self._cleanup_tree(self.root())
        self.root().mkdir()
        Path(self.root(), "a").write_text("a")
        Path(self.root(), "b").write_text("b")

    def tearDown(self):
        if self.root().exists():
            self._cleanup_tree(self.root())

    @staticmethod
    def _cleanup_tree(path):
        for child in sorted(path.rglob("*"), reverse=True):
            if child.is_dir():
                child.rmdir()
            else:
                child.unlink()
        path.rmdir()

    def root(self):
        if not hasattr(self, "_root"):
            self._root = Path(os.path.abspath("tree"))
        return self._root

    def directory(self):
        return self.root().name

    def _hook_that_runs_once(self, event, callback, target):
        state = {"done": False}

        def hook(read_event):
            if (
                read_event.operation == event
                and read_event.path == target
                and not state["done"]
            ):
                state["done"] = True
                callback()

        return hook

    def test_stable_directory_matches_non_strict(self):
        strict = DirectoryResolver(strict=True).hash_artifacts(
            [f"dir:{self.directory()}"]
        )
        non_strict = DirectoryResolver().hash_artifacts(
            [f"dir:{self.directory()}"]
        )
        self.assertEqual(strict, non_strict)

    def test_strict_directory_with_subdirs_and_excludes(self):
        Path(self.root(), "subdir").mkdir()
        Path(self.root(), "subdir", "c").write_text("c")
        Path(self.root(), "ignored.log").write_text("ignored")

        strict = DirectoryResolver(
            strict=True, exclude_patterns=["*.log"]
        ).hash_artifacts([f"dir:{self.directory()}"])
        non_strict = DirectoryResolver(
            exclude_patterns=["*.log"]
        ).hash_artifacts([f"dir:{self.directory()}"])

        self.assertEqual(strict, non_strict)

    def test_strict_file_scheme_directory(self):
        # Strict mode also applies when a directory is passed through the
        # file resolver instead of the dir: resolver.
        from in_toto.resolver import FileResolver

        strict = FileResolver(strict=True).hash_artifacts([self.directory()])
        non_strict = FileResolver().hash_artifacts([self.directory()])
        self.assertEqual(strict, non_strict)

    def test_directory_resolver_rejects_non_directory(self):
        Path(self.root(), "file").write_text("file")
        with self.assertRaises(ValueError):
            DirectoryResolver(strict=True).hash_artifacts(
                [f"dir:{self.directory()}/file"]
            )

    def test_directory_entries_snapshot_event(self):
        events = []
        DirectoryResolver(strict=True, read_hook=events.append).hash_artifacts(
            [f"dir:{self.directory()}"]
        )

        lists = [e for e in events if e.operation == "list"]
        self.assertTrue(lists)
        self.assertEqual(lists[0].entries, ("a", "b"))
        self.assertEqual(lists[0].path, self.directory())
        self.assertIsInstance(lists[0], ReadEvent)
        self.assertEqual(events[-1].operation, "list-verify")

    def test_added_entry_fails(self):
        self._assert_directory_failure(
            "list",
            lambda: Path(self.root(), "new").write_text("new"),
            "directory-entries-changed",
        )

    def test_removed_entry_fails(self):
        self._assert_directory_failure(
            "list",
            lambda: Path(self.root(), "a").unlink(),
            "directory-entries-changed",
        )

    def test_added_and_removed_entry_fails(self):
        self._assert_directory_failure(
            "list",
            lambda: (
                Path(self.root(), "a").unlink(),
                Path(self.root(), "c").write_text("c"),
            ),
            "directory-entries-changed",
        )

    def test_added_directory_fails(self):
        self._assert_directory_failure(
            "list",
            lambda: Path(self.root(), "subdir").mkdir(),
            "directory-entries-changed",
        )

    def test_entry_replaced_by_same_named_file_fails(self):
        def replace():
            Path(self.root(), "a").rename(Path(self.root(), "a.tmp"))
            Path(self.root(), "a").write_text("new a")
            Path(self.root(), "a.tmp").unlink()

        self._assert_directory_failure(
            "list", replace, "directory-entries-changed"
        )

    def test_top_directory_replaced_fails(self):
        def replace():
            other = self.root().parent / "other_tree"
            other.mkdir()
            (other / "a").write_text("a")
            (other / "b").write_text("b")
            old = self.root().parent / "old_tree"
            self.root().rename(old)
            other.rename(self.root())

        self._assert_directory_failure(
            "list",
            replace,
            "directory-replaced",
            target=self.directory(),
        )

    def test_file_changed_after_its_read_is_caught_by_tree_recheck(self):
        def change_after_read():
            # Change a file that was already hashed. The tree re-listing
            # observes its new size/mtime even though no later read touches
            # the file itself.
            Path(self.root(), "b").write_text("modified after reading")

        self._assert_directory_failure(
            "list-verify", change_after_read, "directory-entries-changed"
        )

    def test_change_observed_during_nested_walk_fails(self):
        Path(self.root(), "subdir").mkdir()
        Path(self.root(), "subdir", "c").write_text("c")

        def remove_nested():
            Path(self.root(), "subdir", "c").unlink()

        self._assert_directory_failure(
            "list",
            remove_nested,
            "directory-entries-changed",
            target=f"{self.directory()}/subdir",
        )

    def _assert_directory_failure(self, event, callback, reason, target=None):
        target = target or self.directory()
        hook = self._hook_that_runs_once(event, callback, target)
        resolver = DirectoryResolver(strict=True, read_hook=hook)
        with self.assertRaises(StrictRecordingError) as raise_ctx:
            resolver.hash_artifacts([f"dir:{self.directory()}"])

        self.assertEqual(raise_ctx.exception.reason, reason)


if __name__ == "__main__":
    unittest.main()
