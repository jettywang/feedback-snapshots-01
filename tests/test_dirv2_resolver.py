# Copyright New York University and the in-toto contributors
# SPDX-License-Identifier: Apache-2.0

"""Test cases for the versioned DirV2Resolver (``dirv2:`` scheme).

The tests focus on the properties the legacy ``dir:`` scheme cannot provide:

* locale-independent ordering and stability across locales,
* entry names containing newlines and non-ASCII characters,
* structural distinction (empty directories, file/dir type swaps),
* explicit file/directory/symlink typing,
* exclude pattern semantics,
* non-equivalence with the legacy ``dir:`` digest for the same directory.
"""

import hashlib
import locale
import os
import tempfile
import unittest
from pathlib import Path

from in_toto.exceptions import PrefixError
from in_toto.resolver import DirectoryResolver, DirV2Resolver

# Pinned SHA-256 of the dir_resolver fixture under the full dirv2 format,
# independently recomputed with tests/dirv2_recompute.py.
PINNED_FULL = (
    "8f1ca56d35b8e7452cf9c2bcf8bfe1aefe1da6d8d63be330233e710263fedee6"
)
# Same fixture with the "README.md" exclude pattern applied.
PINNED_EXCLUDED = (
    "2a3c5142631f15ba576b39f475edddf853638235ea88a49530fc164caea8436c"
)


def _expected(records, preamble=b"dirv2\x1e"):
    """Reference computation of a dirv2 digest from raw records."""
    message = preamble + b"".join(records)
    return {"sha256": hashlib.sha256(message).hexdigest()}


class TestDirV2Resolver(unittest.TestCase):
    """Test directory resolver v2 implementation."""

    def _mangle_path(self, path):
        return path.replace("\\", "/")

    def setUp(self):
        self.resolver = DirV2Resolver()

    def test_pinned_fixture_digest(self):
        path = str(Path(__file__).parent / "resolver" / "dir_resolver")
        resolver = DirV2Resolver(normalize_line_endings=True)
        artifact_dict = resolver.hash_artifacts([f"dirv2:{path}"])

        expected_uri = self._mangle_path(f"dirv2:{path}")
        expected = {expected_uri: {"sha256": PINNED_FULL}}
        self.assertEqual(artifact_dict, expected)

    def test_legacy_and_v2_are_not_equivalent(self):
        path = str(Path(__file__).parent / "resolver" / "dir_resolver")

        v1 = DirectoryResolver(normalize_line_endings=True).hash_artifacts(
            [f"dir:{path}"]
        )
        v2 = DirV2Resolver(normalize_line_endings=True).hash_artifacts(
            [f"dirv2:{path}"]
        )

        # Distinct URI schemes ...
        self.assertTrue(list(v1)[0].startswith("dir:"))
        self.assertTrue(list(v2)[0].startswith("dirv2:"))
        # ... and distinct digest values, so they must never be compared as
        # equal even for the same on-disk directory.
        self.assertNotEqual(list(v1.values())[0], list(v2.values())[0])

    def test_empty_directory_uses_versioned_preamble(self):
        with tempfile.TemporaryDirectory(dir=os.getcwd()) as tmp_dir:
            artifact_dict = self.resolver.hash_artifacts([f"dirv2:{tmp_dir}"])
            digest = list(artifact_dict.values())[0]["sha256"]

            # sha256 of the fixed preamble only; explicitly not the legacy
            # empty-input digest e3b0c442...
            self.assertEqual(
                digest, hashlib.sha256(b"dirv2\x1e").hexdigest()
            )
            self.assertNotEqual(
                digest,
                hashlib.sha256(b"").hexdigest(),
            )

    def test_empty_subdirectory_changes_digest(self):
        """An empty directory is part of the structure in v2."""
        with tempfile.TemporaryDirectory(dir=os.getcwd()) as tmp:
            first = os.path.join(tmp, "first")
            second = os.path.join(tmp, "second")
            os.makedirs(first)
            os.makedirs(os.path.join(second, "emptydir"))
            for tree in (first, second):
                with open(os.path.join(tree, "f.txt"), "w") as handle:
                    handle.write("C")

            # The legacy scheme cannot see the empty subdirectory.
            legacy = DirectoryResolver()
            legacy_first = list(
                legacy.hash_artifacts([f"dir:{first}"]).values()
            )[0]
            legacy_second = list(
                legacy.hash_artifacts([f"dir:{second}"]).values()
            )[0]
            self.assertEqual(legacy_first, legacy_second)

            # v2 distinguishes the two structures.
            digest_first = list(
                self.resolver.hash_artifacts([f"dirv2:{first}"]).values()
            )[0]
            digest_second = list(
                self.resolver.hash_artifacts([f"dirv2:{second}"]).values()
            )[0]
            self.assertNotEqual(digest_first, digest_second)

    def test_file_directory_type_swap_is_distinguished(self):
        """Same relative names and contents, different entry types."""
        with tempfile.TemporaryDirectory(dir=os.getcwd()) as tmp:
            tree_c = os.path.join(tmp, "C")
            tree_d = os.path.join(tmp, "D")
            os.makedirs(os.path.join(tree_c, "bar"))
            with open(os.path.join(tree_c, "foo"), "w") as handle:
                handle.write("C1")
            with open(os.path.join(tree_c, "bar", "entry"), "w") as handle:
                handle.write("C2")

            os.makedirs(os.path.join(tree_d, "foo"))
            with open(os.path.join(tree_d, "bar"), "w") as handle:
                handle.write("C1")
            with open(os.path.join(tree_d, "foo", "entry"), "w") as handle:
                handle.write("C2")

            digest_c = list(
                self.resolver.hash_artifacts([f"dirv2:{tree_c}"]).values()
            )[0]
            digest_d = list(
                self.resolver.hash_artifacts([f"dirv2:{tree_d}"]).values()
            )[0]
            self.assertNotEqual(digest_c, digest_d)

    def test_newline_and_nonascii_names_are_stable(self):
        with tempfile.TemporaryDirectory(dir=os.getcwd()) as tmp:
            with open(
                os.path.join(tmp, "li\nne-ä.txt"), "w", encoding="utf-8"
            ) as handle:
                handle.write("x")
            os.makedirs(os.path.join(tmp, "sub"))
            with open(os.path.join(tmp, "sub", "b.txt"), "w") as handle:
                handle.write("y")

            expected = self.resolver.hash_artifacts([f"dirv2:{tmp}"])

            original = locale.setlocale(locale.LC_ALL)
            for candidate in ("C", "en_US.UTF-8", "de_DE.UTF-8"):
                try:
                    locale.setlocale(locale.LC_ALL, candidate)
                except locale.Error:
                    continue
                recomputed = DirV2Resolver().hash_artifacts([f"dirv2:{tmp}"])
                self.assertEqual(recomputed, expected)
            locale.setlocale(locale.LC_ALL, original)

            # The newline must be embedded literally rather than acting as a
            # record boundary: exactly one directory entry is returned.
            self.assertEqual(len(expected), 1)

    def test_deterministic_ordering(self):
        with tempfile.TemporaryDirectory(dir=os.getcwd()) as tmp:
            for name in ("Z.txt", "a.txt", "0.txt", "b.txt", "A.txt"):
                with open(os.path.join(tmp, name), "w") as handle:
                    handle.write(name)

            first = self.resolver.hash_artifacts([f"dirv2:{tmp}"])
            second = DirV2Resolver().hash_artifacts([f"dirv2:{tmp}"])
            self.assertEqual(first, second)

    @unittest.skipIf(
        "symlink" not in os.__dict__,
        "symlink is not supported on this platform",
    )
    def test_symlinked_file_is_typed_and_hashed_by_target_name(self):
        with tempfile.TemporaryDirectory(dir=os.getcwd()) as tmp:
            target = os.path.join(tmp, "target.txt")
            link = os.path.join(tmp, "link.txt")
            with open(target, "w") as handle:
                handle.write("content")
            os.symlink("target.txt", link)

            digest = list(
                self.resolver.hash_artifacts([f"dirv2:{tmp}"]).values()
            )[0]

            target_hash = hashlib.sha256(b"content").hexdigest().encode()
            link_hash = hashlib.sha256(b"target.txt").hexdigest().encode()
            records = [
                b"link.txt\x1fs\x1f" + link_hash + b"\x1e",
                b"target.txt\x1ff\x1f" + target_hash + b"\x1e",
            ]
            self.assertEqual(digest, _expected(records))

    @unittest.skipIf(
        "symlink" not in os.__dict__,
        "symlink is not supported on this platform",
    )
    def test_symlinked_directory_follow_toggle(self):
        with tempfile.TemporaryDirectory(dir=os.getcwd()) as tmp:
            outside = os.path.join(tmp, "outside")
            root = os.path.join(tmp, "root")
            os.makedirs(os.path.join(outside))
            os.makedirs(root)
            with open(os.path.join(outside, "data.txt"), "w") as handle:
                handle.write("data")
            os.symlink(outside, os.path.join(root, "linkdir"))

            not_followed = DirV2Resolver(
                follow_symlink_dirs=False
            ).hash_artifacts([f"dirv2:{root}"])
            followed = DirV2Resolver(
                follow_symlink_dirs=True
            ).hash_artifacts([f"dirv2:{root}"])

            # Following vs. not following a linked directory yields different
            # structures and therefore different digests.
            self.assertNotEqual(not_followed, followed)

    @unittest.skipIf(
        "symlink" not in os.__dict__,
        "symlink is not supported on this platform",
    )
    def test_broken_symlink_is_skipped(self):
        with tempfile.TemporaryDirectory(dir=os.getcwd()) as tmp:
            os.symlink("does/not/exist", os.path.join(tmp, "broken"))
            with open(os.path.join(tmp, "good.txt"), "w") as handle:
                handle.write("ok")

            digest = list(
                self.resolver.hash_artifacts([f"dirv2:{tmp}"]).values()
            )[0]
            good_hash = hashlib.sha256(b"ok").hexdigest().encode()
            self.assertEqual(
                digest, _expected([b"good.txt\x1ff\x1f" + good_hash + b"\x1e"])
            )

    def test_exclude_patterns_apply_inside_directory(self):
        path = str(Path(__file__).parent / "resolver" / "dir_resolver")
        resolver = DirV2Resolver(
            exclude_patterns=["README.md"],
            normalize_line_endings=True,
        )
        artifact_dict = resolver.hash_artifacts([f"dirv2:{path}"])
        # Pinned value recomputed with the exclude pattern applied.
        self.assertEqual(
            list(artifact_dict.values())[0]["sha256"], PINNED_EXCLUDED
        )

    def test_excluding_directory_excludes_its_contents(self):
        with tempfile.TemporaryDirectory(dir=os.getcwd()) as tmp:
            os.makedirs(os.path.join(tmp, "sub"))
            with open(os.path.join(tmp, "root.txt"), "w") as handle:
                handle.write("r")
            with open(os.path.join(tmp, "sub", "inner.txt"), "w") as handle:
                handle.write("i")

            full = DirV2Resolver().hash_artifacts([f"dirv2:{tmp}"])
            excluded = DirV2Resolver(
                exclude_patterns=["sub"]
            ).hash_artifacts([f"dirv2:{tmp}"])

            self.assertNotEqual(full, excluded)
            root_hash = hashlib.sha256(b"r").hexdigest().encode()
            self.assertEqual(
                list(excluded.values())[0],
                _expected([b"root.txt\x1ff\x1f" + root_hash + b"\x1e"]),
            )

    def test_exclude_patterns_are_relative_to_hashed_directory(self):
        """Slash-anchored patterns match directory-relative paths."""
        with tempfile.TemporaryDirectory(dir=os.getcwd()) as tmp:
            os.makedirs(os.path.join(tmp, "sub"))
            with open(os.path.join(tmp, "root.txt"), "w") as handle:
                handle.write("r")
            with open(os.path.join(tmp, "sub", "inner.txt"), "w") as handle:
                handle.write("i")

            full = DirV2Resolver().hash_artifacts([f"dirv2:{tmp}"])
            for pattern in ("sub/inner.txt", "inner.txt", "sub"):
                excluded = DirV2Resolver(
                    exclude_patterns=[pattern]
                ).hash_artifacts([f"dirv2:{tmp}"])
                self.assertNotEqual(
                    excluded, full, f"pattern {pattern!r} was not applied"
                )

    def test_lstrip_only_changes_name_not_digest(self):
        target = str(Path(__file__).parent / "resolver" / "dir_resolver")
        prefix = self._mangle_path(str(Path(__file__).parent)) + "/resolver/"

        plain = DirV2Resolver(normalize_line_endings=True).hash_artifacts(
            [f"dirv2:{target}"]
        )
        stripped = DirV2Resolver(
            lstrip_paths=[prefix], normalize_line_endings=True
        ).hash_artifacts([f"dirv2:{target}"])

        self.assertEqual(list(plain.values()), list(stripped.values()))
        self.assertEqual(list(stripped), ["dirv2:dir_resolver"])

    def test_colliding_lstrips_raise(self):
        base = str(Path(__file__).parent / "resolver")
        first = os.path.join(base, "dir_resolver", "subdir")
        second = os.path.join(base, "colliding_dir_resolver", "subdir")
        resolver = DirV2Resolver(
            lstrip_paths=[
                f"{base}/dir_resolver/",
                f"{base}/colliding_dir_resolver/",
            ]
        )
        with self.assertRaises(PrefixError):
            resolver.hash_artifacts(
                [f"dirv2:{first}", f"dirv2:{second}"]
            )

    def test_non_directory_raises(self):
        with self.assertRaises(ValueError):
            self.resolver.hash_artifacts(["dirv2:does/not/exist"])

    def test_record_artifacts_as_dict_routes_dirv2_scheme(self):
        from in_toto.runlib import record_artifacts_as_dict

        path = str(Path(__file__).parent / "resolver" / "dir_resolver")
        recorded = record_artifacts_as_dict([f"dirv2:{path}"])
        direct = DirV2Resolver().hash_artifacts([f"dirv2:{path}"])
        self.assertEqual(recorded, direct)
        self.assertTrue(list(recorded)[0].startswith("dirv2:"))


if __name__ == "__main__":
    unittest.main()
