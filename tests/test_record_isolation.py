# Copyright New York University and the in-toto contributors
# SPDX-License-Identifier: Apache-2.0

"""Tests for process-global state independence of artifact recording.

Two recordings may run concurrently in the same process with different
``base_path`` values. They must not read each other's files, must not change
the caller's working directory or locale, and must not clobber resolvers
registered in the process-wide ``RESOLVER_FOR_URI_SCHEME`` registry.
"""

import hashlib
import locale
import os
import threading
import unittest
from pathlib import Path

from in_toto.resolver import (
    RESOLVER_FOR_URI_SCHEME,
    DirectoryResolver,
    Resolver,
)
from in_toto.runlib import in_toto_run, record_artifacts_as_dict
from tests.common import SignerStore, TmpDirMixin


def _sha256(data):
    return hashlib.sha256(data).hexdigest()


class _FailingResolver(Resolver):
    """Custom resolver that always raises."""

    SCHEME = "failing"

    def hash_artifacts(self, uris):
        raise RuntimeError("custom resolver failure")


class _NestedResolver(Resolver):
    """Custom resolver that triggers a nested recording."""

    SCHEME = "nested"

    def __init__(self, nested_base_path):
        self._nested_base_path = nested_base_path

    def hash_artifacts(self, uris):
        # A recording triggered from within another recording must build its
        # own resolver registry and leave global state untouched.
        record_artifacts_as_dict(["."], base_path=self._nested_base_path)
        return {}


class TestRecordIsolation(TmpDirMixin, unittest.TestCase):
    """Concurrent and nested recordings stay isolated."""

    @classmethod
    def setUpClass(cls):
        # Capture process-global state before TmpDirMixin changes directories.
        cls.expected_cwd = os.getcwd()
        cls.expected_locale = locale.getlocale(locale.LC_ALL)
        cls.set_up_test_dir()
        cls.signer = SignerStore.rsa

        # Two directories with a same-named but different-content file.
        cls.dir_a = os.path.join(cls.test_dir, "dir_a")
        cls.dir_b = os.path.join(cls.test_dir, "dir_b")
        os.mkdir(cls.dir_a)
        os.mkdir(cls.dir_b)
        cls.content_a = b"alpha contents\n"
        cls.content_b = b"totally different beta contents\n"
        Path(cls.dir_a, "f.txt").write_bytes(cls.content_a)
        Path(cls.dir_b, "f.txt").write_bytes(cls.content_b)
        cls.digest_a = _sha256(cls.content_a)
        cls.digest_b = _sha256(cls.content_b)

    @classmethod
    def tearDownClass(cls):
        cls.tear_down_test_dir()
        # TmpDirMixin restores the original working directory; recordings must
        # not have left the process in any other directory or locale.
        assert os.getcwd() == cls.expected_cwd
        assert locale.getlocale(locale.LC_ALL) == cls.expected_locale

    def tearDown(self):
        # Recordings must never leave their temporary resolvers behind and
        # must not drift out of the test directory while it is active.
        for scheme in ("file", "dir", "ostree", "failing", "nested"):
            self.assertNotIn(scheme, RESOLVER_FOR_URI_SCHEME)
        self.assertEqual(os.getcwd(), self.test_dir)
        self.assertEqual(
            locale.getlocale(locale.LC_ALL), self.expected_locale
        )

    def test_interleaved_base_path_recording(self):
        """Same-named files in two base paths hash to their own directory."""
        barrier = threading.Barrier(2)
        links = {}
        worker_cwds = {}
        errors = []

        def worker(step_name, base_path, expected_digest):
            try:
                barrier.wait()
                links[step_name] = in_toto_run(
                    step_name,
                    ["."],
                    ["."],
                    [],
                    base_path=base_path,
                    signer=self.signer,
                )
                worker_cwds[step_name] = os.getcwd()
                self.assertEqual(
                    links[step_name].signed.products["f.txt"]["sha256"],
                    expected_digest,
                )
            except Exception as exc:  # pragma: no cover - surfaced below
                errors.append(exc)

        threads = [
            threading.Thread(
                target=worker,
                args=("step_a", self.dir_a, self.digest_a),
            ),
            threading.Thread(
                target=worker,
                args=("step_b", self.dir_b, self.digest_b),
            ),
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        self.assertEqual(errors, [])
        self.assertEqual(worker_cwds["step_a"], self.test_dir)
        self.assertEqual(worker_cwds["step_b"], self.test_dir)

        # Each signed link carries the digest of its own directory.
        self.assertEqual(
            links["step_a"].signed.products["f.txt"]["sha256"], self.digest_a
        )
        self.assertEqual(
            links["step_b"].signed.products["f.txt"]["sha256"], self.digest_b
        )
        self.assertNotEqual(self.digest_a, self.digest_b)

    def test_interleaved_directory_digest(self):
        """Directory digests are computed per directory without shared state."""
        expected_a = DirectoryResolver().hash_artifacts([f"dir:{self.dir_a}"])
        expected_b = DirectoryResolver().hash_artifacts([f"dir:{self.dir_b}"])
        self.assertNotEqual(expected_a, expected_b)

        barrier = threading.Barrier(2)
        results = {}
        errors = []

        def worker(uri, expected):
            try:
                barrier.wait()
                results[uri] = record_artifacts_as_dict([uri])
                self.assertEqual(results[uri], expected)
            except Exception as exc:  # pragma: no cover - surfaced below
                errors.append(exc)

        threads = [
            threading.Thread(
                target=worker,
                args=(f"dir:{self.dir_a}", expected_a),
            ),
            threading.Thread(
                target=worker,
                args=(f"dir:{self.dir_b}", expected_b),
            ),
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        self.assertEqual(errors, [])
        self.assertEqual(results[f"dir:{self.dir_a}"], expected_a)
        self.assertEqual(results[f"dir:{self.dir_b}"], expected_b)

    def test_nested_recording_keeps_global_registry(self):
        """A recording nested in a custom resolver leaves global state alone."""
        Path("root_file").write_bytes(b"root\n")
        resolver = _NestedResolver(self.dir_a)
        RESOLVER_FOR_URI_SCHEME[_NestedResolver.SCHEME] = resolver
        try:
            artifacts = record_artifacts_as_dict(
                ["nested:x", "root_file"]
            )
        finally:
            RESOLVER_FOR_URI_SCHEME.pop(_NestedResolver.SCHEME, None)

        self.assertIn("root_file", artifacts)
        # The externally registered resolver is still the same instance.
        self.assertNotIn(_NestedResolver.SCHEME, RESOLVER_FOR_URI_SCHEME)

    def test_failing_custom_resolver_is_cleaned_up(self):
        """A raising resolver propagates and leaves no global state behind."""
        resolver = _FailingResolver()
        RESOLVER_FOR_URI_SCHEME[_FailingResolver.SCHEME] = resolver
        try:
            with self.assertRaises(RuntimeError):
                record_artifacts_as_dict(["failing:something"])
            # The external registration must survive a failed recording.
            self.assertIs(
                RESOLVER_FOR_URI_SCHEME[_FailingResolver.SCHEME], resolver
            )
        finally:
            RESOLVER_FOR_URI_SCHEME.pop(_FailingResolver.SCHEME, None)

        # A plain recording after the failure proves there is no cross-task
        # impact: artifacts still resolve and hash correctly.
        artifacts = record_artifacts_as_dict(["."], base_path=self.dir_a)
        self.assertEqual(artifacts["f.txt"]["sha256"], self.digest_a)


if __name__ == "__main__":
    unittest.main()
