# Copyright New York University and the in-toto contributors
# SPDX-License-Identifier: Apache-2.0

"""
<Program Name>
  test_runlib.py

<Author>
  Lukas Puehringer <lukas.puehringer@nyu.edu>

<Started>
  Dec 01, 2016

<Copyright>
  See LICENSE for licensing information.

<Purpose>
  Test runlib functions.

"""

import contextlib
import hashlib
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import securesystemslib.exceptions
import securesystemslib.formats

import in_toto.exceptions
import in_toto.settings
from in_toto.exceptions import SignatureVerificationError
from in_toto.formats import _check_hash_dict
from in_toto.models.link import (
    FILENAME_FORMAT,
    UNFINISHED_FILENAME_FORMAT,
    Link,
)
from in_toto.models.metadata import Envelope, Metablock
from in_toto.models.record import RecordHandle
from in_toto.resolver import FileResolver
from in_toto.runlib import (
    _subprocess_run_duplicate_streams,
    in_toto_match_products,
    in_toto_record_start,
    in_toto_record_stop,
    in_toto_run,
    record_artifacts_as_dict,
)
from tests.common import SignerStore, TmpDirMixin, VersionedPython


def _apply_exclude_patterns(names, patterns):
    """Temporary bridge from old `runlib._apply_exclude_patterns` with new
    `FileResolver._exclude`.

     TODO: Replace tist once resolver interface evolves
    """
    return [
        n
        for n in names
        if not FileResolver(exclude_patterns=patterns)._exclude(n)
    ]


class TestApplyExcludePatterns(unittest.TestCase):
    """Test _apply_exclude_patterns(names, exclude_patterns)"""

    def test_apply_exclude_explict(self):
        names = ["foo", "bar", "baz"]
        patterns = ["foo", "bar"]
        expected = ["baz"]
        result = _apply_exclude_patterns(names, patterns)
        self.assertListEqual(sorted(result), sorted(expected))

    def test_apply_exclude_all(self):
        names = ["foo", "bar", "baz"]
        patterns = ["*"]
        expected = []
        result = _apply_exclude_patterns(names, patterns)
        self.assertListEqual(sorted(result), sorted(expected))

    def test_apply_exclude_multiple_star(self):
        names = ["foo", "bar", "baz"]
        patterns = ["*a*"]
        expected = ["foo"]
        result = _apply_exclude_patterns(names, patterns)
        self.assertListEqual(result, expected)

    def test_apply_exclude_question_mark(self):
        names = ["foo", "bazfoo", "barfoo"]
        patterns = ["ba?foo"]
        expected = ["foo"]
        result = _apply_exclude_patterns(names, patterns)
        self.assertListEqual(result, expected)

    def test_apply_exclude_seq(self):
        names = ["baxfoo", "bazfoo", "barfoo"]
        patterns = ["ba[xz]foo"]
        expected = ["barfoo"]
        result = _apply_exclude_patterns(names, patterns)
        self.assertListEqual(result, expected)

    def test_apply_exclude_neg_seq(self):
        names = ["baxfoo", "bazfoo", "barfoo"]
        patterns = ["ba[!r]foo"]
        expected = ["barfoo"]
        result = _apply_exclude_patterns(names, patterns)
        self.assertListEqual(result, expected)


class TestRecordArtifactsAsDict(unittest.TestCase, TmpDirMixin):  # noqa: PLR0904, RUF100
    """Test record_artifacts_as_dict(artifacts)."""

    @classmethod
    def setUpClass(cls):
        """Create and change into temp test directory with dummy artifacts.
        |-- bar
        |-- foo
        `-- subdir
            |-- foosub1
            |-- foosub2
            `-- subsubdir
                `-- foosubsub
        """

        # Backup and clear user set exclude patterns and base path
        cls.artifact_exclude_orig = in_toto.settings.ARTIFACT_EXCLUDE_PATTERNS
        cls.artifact_base_path_orig = in_toto.settings.ARTIFACT_BASE_PATH
        in_toto.settings.ARTIFACT_EXCLUDE_PATTERNS = []
        in_toto.settings.ARTIFACT_BASE_PATH = None

        cls.set_up_test_dir()

        # Create files on 3 levels
        os.mkdir("subdir")
        os.mkdir("subdir/subsubdir")

        cls.full_file_path_list = [
            "foo",
            "bar",
            "#esc!",
            "subdir/foosub1",
            "subdir/foosub2",
            "subdir/subsubdir/foosubsub",
        ]

        for path in cls.full_file_path_list:
            with open(path, "w", encoding="utf8") as fp:
                fp.write(path)

    @classmethod
    def tearDownClass(cls):
        """Change back to working dir, remove temp directory, restore settings."""
        cls.tear_down_test_dir()
        in_toto.settings.ARTIFACT_EXCLUDE_PATTERNS = cls.artifact_exclude_orig
        in_toto.settings.ARTIFACT_BASE_PATH = cls.artifact_base_path_orig

    def tearDown(self):
        """Clear the ARTIFACT_EXCLUDES after every test."""
        in_toto.settings.ARTIFACT_EXCLUDE_PATTERNS = []
        in_toto.settings.ARTIFACT_BASE_PATH = None

    def test_bad_base_path_setting(self):
        """Raise exception with bogus base path settings."""
        for base_path in ["path/does/not/exist", 12345, True]:
            in_toto.settings.ARTIFACT_BASE_PATH = base_path
            with self.assertRaises((OSError, ValueError)):
                record_artifacts_as_dict(["."])
            in_toto.settings.ARTIFACT_BASE_PATH = None

            with self.assertRaises((OSError, ValueError)):
                record_artifacts_as_dict(["."], base_path=base_path)

    def test_base_path_is_child_dir(self):
        """Test path of recorded artifacts and cd back with child as base."""
        base_path = "subdir"
        expected_artifacts = sorted(
            ["foosub1", "foosub2", "subsubdir/foosubsub"]
        )

        in_toto.settings.ARTIFACT_BASE_PATH = base_path
        artifacts_dict = record_artifacts_as_dict(["."])
        self.assertListEqual(sorted(artifacts_dict.keys()), expected_artifacts)
        in_toto.settings.ARTIFACT_BASE_PATH = None

        artifacts_dict = record_artifacts_as_dict(["."], base_path=base_path)
        self.assertListEqual(sorted(artifacts_dict.keys()), expected_artifacts)

    def test_base_path_is_parent_dir(self):
        """Test path of recorded artifacts and cd back with parent as base."""
        base_path = ".."
        expected_artifacts = sorted(
            ["foosub1", "foosub2", "subsubdir/foosubsub"]
        )
        os.chdir("subdir/subsubdir")

        in_toto.settings.ARTIFACT_BASE_PATH = base_path
        artifacts_dict = record_artifacts_as_dict(["."])
        self.assertListEqual(sorted(artifacts_dict.keys()), expected_artifacts)
        in_toto.settings.ARTIFACT_BASE_PATH = None

        artifacts_dict = record_artifacts_as_dict(["."], base_path=base_path)
        self.assertListEqual(sorted(artifacts_dict.keys()), expected_artifacts)

        os.chdir(self.test_dir)

    def test_lstrip_paths_valid_prefix_directory(self):
        lstrip_paths = ["subdir/subsubdir/"]
        expected_artifacts = sorted(
            [
                "#esc!",
                "bar",
                "foo",
                "subdir/foosub1",
                "subdir/foosub2",
                "foosubsub",
            ]
        )
        artifacts_dict = record_artifacts_as_dict(
            ["."], lstrip_paths=lstrip_paths
        )
        self.assertListEqual(sorted(artifacts_dict.keys()), expected_artifacts)

    def test_lstrip_paths_substring_prefix_directory(self):
        lstrip_paths = ["subdir/subsubdir/", "subdir/"]
        with self.assertRaises(in_toto.exceptions.PrefixError):
            record_artifacts_as_dict(["."], lstrip_paths=lstrip_paths)

    def test_lstrip_paths_non_unique_key(self):
        os.mkdir("subdir_new")
        path = "subdir_new/foosub1"
        shutil.copy("subdir/foosub1", path)
        lstrip_paths = ["subdir/", "subdir_new/"]
        with self.assertRaises(in_toto.exceptions.PrefixError):
            record_artifacts_as_dict(["."], lstrip_paths=lstrip_paths)
        os.remove(path)
        os.rmdir("subdir_new")

    def test_lstrip_paths_invalid_prefix_directory(self):
        lstrip_paths = ["not/a/directory/"]
        expected_artifacts = sorted(
            [
                "#esc!",
                "bar",
                "foo",
                "subdir/foosub1",
                "subdir/foosub2",
                "subdir/subsubdir/foosubsub",
            ]
        )
        artifacts_dict = record_artifacts_as_dict(
            ["."], lstrip_paths=lstrip_paths
        )
        self.assertListEqual(sorted(artifacts_dict.keys()), expected_artifacts)

    def test_lstrip_paths_valid_prefix_file(self):
        lstrip_paths = ["subdir/subsubdir/"]
        expected_artifacts = sorted(["foosubsub"])
        artifacts_dict = record_artifacts_as_dict(
            ["./subdir/subsubdir/foosubsub"], lstrip_paths=lstrip_paths
        )
        self.assertListEqual(sorted(artifacts_dict.keys()), expected_artifacts)

    def test_lstrip_paths_non_unique_key_file(self):
        os.mkdir("subdir/subsubdir_new")
        path = "subdir/subsubdir_new/foosubsub"
        shutil.copy("subdir/subsubdir/foosubsub", path)
        lstrip_paths = ["subdir/subsubdir/", "subdir/subsubdir_new/"]
        with self.assertRaises(in_toto.exceptions.PrefixError):
            record_artifacts_as_dict(
                [
                    "subdir/subsubdir/foosubsub",
                    "subdir/subsubdir_new/foosubsub",
                ],
                lstrip_paths=lstrip_paths,
            )
        os.remove(path)
        os.rmdir("subdir/subsubdir_new")

    def test_lstrip_paths_valid_unicode_prefix_file(self):
        # Try to create a file with unicode character
        try:
            os.mkdir("ಠ")
            path = "ಠ/foo"
            shutil.copy("foo", path)

            # Attempt to left strip the path now that the file has been created
            lstrip_paths = ["ಠ/"]
            expected_artifacts = sorted(["foo"])
            artifacts_dict = record_artifacts_as_dict(
                ["./ಠ/"], lstrip_paths=lstrip_paths
            )
            self.assertListEqual(
                sorted(artifacts_dict.keys()), expected_artifacts
            )
            os.remove(path)
            os.rmdir("ಠ")
        except OSError:
            # OS doesn't support unicode explicit files
            pass

    def test_empty_artifacts_list_record_nothing(self):
        """Empty list passed. Return empty dict."""
        self.assertDictEqual(record_artifacts_as_dict([]), {})

    def test_not_existing_artifacts_in_list_record_nothing(self):
        """List with not existing artifact passed. Return empty dict."""
        self.assertDictEqual(record_artifacts_as_dict(["baz"]), {})

    def test_record_dot_check_files_hash_dict_schema(self):
        """Traverse dir and subdirs. Record three files."""
        artifacts_dict = record_artifacts_as_dict(["."])

        for val in list(artifacts_dict.values()):
            _check_hash_dict(val)

        self.assertListEqual(
            sorted(artifacts_dict.keys()),
            sorted(self.full_file_path_list),
        )

    @staticmethod
    def _raise_win_dev_mode_error():
        """If the platform is Windows, raises an error that asks the user if
        developer mode is activated."""
        if os.name == "nt":
            raise OSError(
                "Developer mode is required to work with symlinks on "
                "Windows. Is it enabled?"
            )

    @unittest.skipIf(
        "symlink" not in os.__dict__,
        "symlink is not supported in this platform",
    )
    def test_record_symlinked_files(self):
        """Symlinked files are always recorded."""
        # Symlinked **files** are always recorded ...
        link_pairs = [
            ("foo", "foo_link"),
            ("subdir/foosub1", "subdir/foosub2_link"),
            ("subdir/subsubdir/foosubsub", "subdir/subsubdir/foosubsub_link"),
        ]

        # Create links
        for pair in link_pairs:
            # We only use the basename of the file (source) as it is on the same
            # level as the link (target)
            try:
                os.symlink(os.path.basename(pair[0]), pair[1])
            except OSError:
                TestRecordArtifactsAsDict._raise_win_dev_mode_error()
                raise

        # Record files and linked files
        # follow_symlink_dirs does not make a difference as it only concerns linked dirs
        for follow_symlink_dirs in [True, False]:
            artifacts_dict = record_artifacts_as_dict(
                ["."], follow_symlink_dirs=follow_symlink_dirs
            )

            # Test that everything was recorded ...
            self.assertListEqual(
                sorted(artifacts_dict.keys()),
                sorted(
                    self.full_file_path_list + [pair[1] for pair in link_pairs]
                ),
            )

            # ... and the hashes of each link/file pair match
            for pair in link_pairs:
                self.assertDictEqual(
                    artifacts_dict[pair[0]], artifacts_dict[pair[1]]
                )

        for pair in link_pairs:
            os.unlink(pair[1])

    @unittest.skipIf(
        "symlink" not in os.__dict__,
        "symlink is not supported in this platform",
    )
    def test_record_without_dead_symlinks(self):
        """Dead symlinks are never recorded."""

        # Dead symlinks are never recorded ...
        links = [
            "foo_link",
            "subdir/foosub2_link",
            "subdir/subsubdir/foosubsub_link",
        ]

        # Create dead links
        for link in links:
            try:
                os.symlink("does/not/exist", link)
            except OSError:
                TestRecordArtifactsAsDict._raise_win_dev_mode_error()
                raise

        # Record files without dead links
        # follow_symlink_dirs does not make a difference as it only concerns linked dirs
        for follow_symlink_dirs in [True, False]:
            artifacts_dict = record_artifacts_as_dict(
                ["."], follow_symlink_dirs=follow_symlink_dirs
            )

            # Test only the files were recorded ...
            self.assertListEqual(
                sorted(artifacts_dict.keys()),
                sorted(self.full_file_path_list),
            )

        for link in links:
            os.unlink(link)

    @unittest.skipIf(
        "symlink" not in os.__dict__,
        "symlink is not supported in this platform",
    )
    def test_record_follow_symlinked_directories(self):
        """Record files in symlinked dirs if follow_symlink_dirs is True."""

        try:
            # Link to subdir
            os.symlink("subdir", "subdir_link")
        except OSError:
            TestRecordArtifactsAsDict._raise_win_dev_mode_error()
            raise

        link_pairs = [
            ("subdir/foosub1", "subdir_link/foosub1"),
            ("subdir/foosub2", "subdir_link/foosub2"),
            ("subdir/subsubdir/foosubsub", "subdir_link/subsubdir/foosubsub"),
        ]

        # Record with follow_symlink_dirs TRUE
        artifacts_dict = record_artifacts_as_dict(
            ["."], follow_symlink_dirs=True
        )
        # Test that all files were recorded including files in linked subdir ...
        self.assertListEqual(
            sorted(artifacts_dict.keys()),
            sorted(self.full_file_path_list + [pair[1] for pair in link_pairs]),
        )

        # ... and the hashes of each link/file pair match
        for pair in link_pairs:
            self.assertDictEqual(
                artifacts_dict[pair[0]], artifacts_dict[pair[1]]
            )

        # Record with follow_symlink_dirs FALSE (default)
        artifacts_dict = record_artifacts_as_dict(["."])
        self.assertListEqual(
            sorted(artifacts_dict.keys()),
            sorted(self.full_file_path_list),
        )

        os.unlink("subdir_link")

    def test_record_files_and_subdirs(self):
        """Explicitly record files and subdirs."""
        artifacts_dict = record_artifacts_as_dict(["foo", "subdir"])

        for val in list(artifacts_dict.values()):
            _check_hash_dict(val)

        self.assertListEqual(
            sorted(artifacts_dict.keys()),
            sorted(
                [
                    "foo",
                    "subdir/foosub1",
                    "subdir/foosub2",
                    "subdir/subsubdir/foosubsub",
                ]
            ),
        )

    def test_exclude_patterns(self):
        """Test excluding artifacts using passed pattern or setting."""
        excludes_and_results = [
            # Exclude files containing 'foo' everywhere
            (["*foo*"], ["bar", "#esc!"]),
            # Exclude subdirectory and all its contents
            (["subdir"], ["bar", "foo", "#esc!"]),
            # Exclude files 'subdir/foosub1' and 'subdir/foosub2'
            (
                ["*foosub?"],
                ["bar", "foo", "#esc!", "subdir/subsubdir/foosubsub"],
            ),
            # Exclude subsubdirectory and its contents
            (
                ["*subsubdir"],
                ["foo", "bar", "#esc!", "subdir/foosub1", "subdir/foosub2"],
            ),
            (["/**"], []),
            (["*sub*"], ["foo", "bar", "#esc!"]),
            (
                ["**/subdir/subsubdir"],
                ["foo", "bar", "#esc!", "subdir/foosub1", "subdir/foosub2"],
            ),
            (
                ["subdir/foo*"],
                ["bar", "foo", "#esc!", "subdir/subsubdir/foosubsub"],
            ),
            (["**/subdir/"], ["bar", "foo", "#esc!"]),
            (["foo*"], ["bar", "#esc!"]),
            (
                ["**/*1"],
                [
                    "bar",
                    "foo",
                    "#esc!",
                    "subdir/foosub2",
                    "subdir/subsubdir/foosubsub",
                ],
            ),
            (
                ["**/*sub?"],
                ["bar", "foo", "#esc!", "subdir/subsubdir/foosubsub"],
            ),
            (
                ["**/foo*[1-9]"],
                ["bar", "foo", "#esc!", "subdir/subsubdir/foosubsub"],
            ),
            (["**/[a-z][a-z][a-z][a-z][a-z][a-z]/"], ["bar", "foo", "#esc!"]),
            (["/subdir"], ["foo", "bar", "#esc!"]),
            (["subdir/"], ["foo", "bar", "#esc!"]),
            (
                ["/subdir/subsubdir"],
                ["foo", "bar", "#esc!", "subdir/foosub1", "subdir/foosub2"],
            ),
            (
                ["subdir/subsubdir/"],
                ["foo", "bar", "#esc!", "subdir/foosub1", "subdir/foosub2"],
            ),
            (
                ["\\#esc*"],
                [
                    "foo",
                    "bar",
                    "subdir/foosub1",
                    "subdir/foosub2",
                    "subdir/subsubdir/foosubsub",
                ],
            ),
            (
                ["*esc\\!"],
                [
                    "foo",
                    "bar",
                    "subdir/foosub1",
                    "subdir/foosub2",
                    "subdir/subsubdir/foosubsub",
                ],
            ),
            (
                ["/"],
                [
                    "foo",
                    "bar",
                    "#esc!",
                    "subdir/foosub1",
                    "subdir/foosub2",
                    "subdir/subsubdir/foosubsub",
                ],
            ),
        ]

        for exclude_patterns, expected_results in excludes_and_results:
            # Exclude via setting
            in_toto.settings.ARTIFACT_EXCLUDE_PATTERNS = exclude_patterns
            artifacts1 = record_artifacts_as_dict(["."])

            # Exclude via argument
            in_toto.settings.ARTIFACT_EXCLUDE_PATTERNS = None
            artifacts2 = record_artifacts_as_dict(
                ["."], exclude_patterns=exclude_patterns
            )

            self.assertTrue(
                sorted(artifacts1)
                == sorted(artifacts2)
                == sorted(expected_results)
            )

    def test_bad_artifact_exclude_patterns_setting(self):
        """Raise exception with bogus artifact exclude patterns settings."""
        for setting in ["not a list of settings", 12345, True]:
            in_toto.settings.ARTIFACT_EXCLUDE_PATTERNS = setting
            with self.assertRaises(ValueError):
                record_artifacts_as_dict(["."])


class TestLinkCmdExecTimeout(unittest.TestCase):
    """Tests execute_link timing out correctly."""

    def test_timeout(self):
        timeout = 1

        # check if exception is raised
        with self.assertRaises(subprocess.TimeoutExpired):
            # Call execute_link to see if new timeout is respected
            in_toto.runlib.execute_link(
                [sys.executable, "-c", "while True: pass"], True, timeout
            )

        # check if exception is raised
        with self.assertRaises(subprocess.TimeoutExpired):
            # Call execute_link to see if new timeout is respected
            in_toto.runlib.execute_link(
                [sys.executable, "-c", "while True: pass"], False, timeout
            )


class TestSubprocess(unittest.TestCase):
    """Test subprocess standard stream duplication."""

    def test_run_duplicate_streams(self):
        """Test output indeed duplicated."""
        # Command that prints 'foo' to stdout and 'bar' to stderr.
        cmd = [
            sys.executable,
            "-c",
            "import sys; sys.stdout.write('foo'); sys.stderr.write('bar');",
        ]

        # Create and open fake targets for standard streams
        stdout_fd, stdout_fn = tempfile.mkstemp()
        stderr_fd, stderr_fn = tempfile.mkstemp()
        with (
            open(  # noqa: PLW1514, RUF100
                stdout_fn
            ) as fake_stdout_reader,
            os.fdopen(stdout_fd, "w") as fake_stdout_writer,
            open(  # noqa: PLW1514, RUF100
                stderr_fn
            ) as fake_stderr_reader,
            os.fdopen(stderr_fd, "w") as fake_stderr_writer,
        ):
            # Backup original standard streams and redirect to fake targets
            real_stdout = sys.stdout
            real_stderr = sys.stderr
            sys.stdout = fake_stdout_writer
            sys.stderr = fake_stderr_writer

            # Run command
            ret_code, ret_out, ret_err = _subprocess_run_duplicate_streams(
                cmd, 10
            )

            # Rewind fake standard streams
            fake_stdout_reader.seek(0)
            fake_stderr_reader.seek(0)

            # Assert that what was printed and what was returned is correct
            self.assertTrue(ret_out == fake_stdout_reader.read() == "foo")
            self.assertTrue(ret_err == fake_stderr_reader.read() == "bar")
            # Also assert the return value
            self.assertEqual(ret_code, 0)

            # Restore original streams
            sys.stdout = real_stdout
            sys.stderr = real_stderr

        # Remove fake standard streams
        os.remove(stdout_fn)
        os.remove(stderr_fn)

    def test_run_duplicate_streams_return_value(self):
        """Test return code."""
        cmd = [sys.executable, "-c", "import sys; sys.exit(100)"]
        ret_code, _, _ = _subprocess_run_duplicate_streams(cmd, 10)
        self.assertEqual(ret_code, 100)

    def test_run_duplicate_streams_timeout(self):
        """Test timeout."""
        cmd = [sys.executable, "-c", "while True: pass"]
        with self.assertRaises(subprocess.TimeoutExpired):
            _subprocess_run_duplicate_streams(cmd, timeout=-1)


class TestInTotoRun(unittest.TestCase, TmpDirMixin):
    """ "
    Tests runlib.in_toto_run() with different arguments

    Calls in_toto_run library function inside of a temporary directory that
    contains a test artifact and a test keypair

    If the function does not fail it will dump a test step link metadata file
    to the temp dir which is removed after every test.

    """

    @classmethod
    def setUpClass(cls):
        """Create and change into temporary directory, generate key pair and dummy
        material, read key pair."""
        cls.set_up_test_dir()

        cls.step_name = "test_step"
        cls.signer = SignerStore.rsa
        cls.key = SignerStore.rsa_pub

        cls.test_artifact = "test_artifact"
        Path(cls.test_artifact).touch()

    @classmethod
    def tearDownClass(cls):
        cls.tear_down_test_dir()

    def tearDown(self):
        """Remove link file if it was created."""
        with contextlib.suppress(OSError):
            os.remove(
                FILENAME_FORMAT.format(
                    step_name=self.step_name, keyid=self.key["keyid"]
                )
            )

    def test_in_toto_run_verify_signature(self):
        """Successfully run, verify signed metadata."""
        link = in_toto_run(
            self.step_name,
            None,
            None,
            [VersionedPython, "--version"],
            True,
            signer=self.signer,
        )
        link.verify_signature(self.key)

    def test_in_toto_run_no_signature(self):
        """Successfully run, verify empty signature field."""
        link = in_toto_run(
            self.step_name, None, None, [VersionedPython, "--version"]
        )
        self.assertFalse(len(link.signatures))

    def test_in_toto_run_with_byproduct(self):
        """Successfully run, verify recorded byproduct."""
        link = in_toto_run(
            self.step_name,
            None,
            None,
            [VersionedPython, "--version"],
            record_streams=True,
        )

        # this or clause may seem weird, but given that python 2 prints its version
        # to stderr while python3 prints it to stdout we check on both (or add a
        # more verbose if clause)
        stderr_contents = link.signed.byproducts.get("stderr")
        stdout_contents = link.signed.byproducts.get("stdout")
        self.assertTrue(
            "Python" in stderr_contents or "Python" in stdout_contents,
            msg=f"\nSTDERR:\n{stderr_contents}\nSTDOUT:\n{stdout_contents}",
        )

    def test_in_toto_run_without_byproduct(self):
        """Successfully run, verify byproduct is not recorded."""
        link = in_toto_run(
            self.step_name,
            None,
            None,
            [VersionedPython, "--version"],
            record_streams=False,
        )
        self.assertFalse(len(link.signed.byproducts.get("stdout")))

    def test_in_toto_run_compare_dumped_with_returned_link(self):
        """Successfully run, compare dumped link is equal to returned link."""
        link = in_toto_run(
            self.step_name,
            [self.test_artifact],
            [self.test_artifact],
            [VersionedPython, "--version"],
            True,
            signer=self.signer,
        )
        link_dump = Metablock.load(
            FILENAME_FORMAT.format(
                step_name=self.step_name, keyid=self.key["keyid"]
            )
        )
        self.assertEqual(repr(link), repr(link_dump))

    def test_in_toto_run_with_metadata_directory(self):
        """Successfully run with metadata directory,
        compare dumped link is equal to returned link"""
        tmp_dir = os.path.realpath(tempfile.mkdtemp(dir=os.getcwd()))
        link = in_toto_run(
            self.step_name,
            [self.test_artifact],
            [self.test_artifact],
            [VersionedPython, "--version"],
            True,
            signer=self.signer,
            metadata_directory=tmp_dir,
        )
        file_path = os.path.join(
            tmp_dir,
            FILENAME_FORMAT.format(
                step_name=self.step_name, keyid=self.key["keyid"]
            ),
        )
        link_dump = Metablock.load(file_path)
        self.assertEqual(repr(link), repr(link_dump))

    def test_in_toto_run_compare_with_and_without_metadata_directory(self):
        """Successfully run with and without metadata directory,
        compare the signed is equal"""
        tmp_dir = os.path.realpath(tempfile.mkdtemp(dir=os.getcwd()))
        in_toto_run(
            self.step_name,
            [self.test_artifact],
            [self.test_artifact],
            [VersionedPython, "--version"],
            True,
            signer=self.signer,
            metadata_directory=tmp_dir,
        )
        file_path = os.path.join(
            tmp_dir,
            FILENAME_FORMAT.format(
                step_name=self.step_name, keyid=self.key["keyid"]
            ),
        )
        link_dump_with_md = Metablock.load(file_path)

        in_toto_run(
            self.step_name,
            [self.test_artifact],
            [self.test_artifact],
            [VersionedPython, "--version"],
            True,
            signer=self.signer,
        )
        link_dump_without_md = Metablock.load(
            FILENAME_FORMAT.format(
                step_name=self.step_name, keyid=self.key["keyid"]
            )
        )
        self.assertEqual(
            repr(link_dump_with_md.signed), repr(link_dump_without_md.signed)
        )

    def test_in_toto_run_verify_recorded_artifacts(self):
        """Successfully run, verify properly recorded artifacts."""
        link = in_toto_run(
            self.step_name,
            [self.test_artifact],
            [self.test_artifact],
            [VersionedPython, "--version"],
        )
        self.assertEqual(
            list(link.signed.materials.keys()),
            list(link.signed.products.keys()),
            [self.test_artifact],
        )

    def test_in_toto_run_verify_workdir(self):
        """Successfully run, verify cwd."""
        link = in_toto_run(
            self.step_name,
            [],
            [],
            [VersionedPython, "--version"],
            record_environment=True,
        )
        self.assertEqual(
            link.signed.environment["workdir"], os.getcwd().replace("\\", "/")
        )

    def test_normalize_line_endings(self):
        """Test cross-platform line ending normalization."""
        paths = []
        try:
            # Create three artifacts with same content but different line endings
            for line_ending in [b"\n", b"\r", b"\r\n"]:
                fd, path = tempfile.mkstemp()
                paths.append(path)
                os.write(fd, b"hello" + line_ending + b"toto")
                os.close(fd)

            # Call in_toto_run and record artifacts as materials and products
            # with line ending normalization on
            link = in_toto_run(
                self.step_name,
                paths,
                paths,
                [VersionedPython, "--version"],
                normalize_line_endings=True,
            ).signed

            # Check that all three hashes in materials and products are equal
            for artifact_dict in [link.materials, link.products]:
                hash_dicts = list(artifact_dict.values())
                self.assertTrue(hash_dicts[1:] == hash_dicts[:-1])

        # Clean up
        finally:
            for path in paths:
                os.remove(path)

    def test_in_toto_bad_signing_key_format(self):
        """Fail run, passed key is not properly formatted."""
        with self.assertRaises(securesystemslib.exceptions.FormatError):
            in_toto_run(
                self.step_name,
                None,
                None,
                [VersionedPython, "--version"],
                True,
                "this-is-not-a-key",
            )

    def test_nonexistent_directory(self):
        """Fail run, passed metadata_directory not exist."""
        with self.assertRaises(FileNotFoundError):
            in_toto_run(
                self.step_name,
                None,
                None,
                [VersionedPython, "--version"],
                True,
                signer=self.signer,
                metadata_directory="nonexistentDir",
            )

    def test_not_a_directory(self):
        """Fail run, passed metadata_directory is not a directory."""
        fd, path = tempfile.mkstemp()
        os.write(fd, b"hello in-toto")
        os.close(fd)
        # Windows will raise FileNotFoundError instead of NotADirectoryError
        with self.assertRaises((NotADirectoryError, FileNotFoundError)):
            in_toto_run(
                self.step_name,
                None,
                None,
                [VersionedPython, "--version"],
                True,
                signer=self.signer,
                metadata_directory=path,
            )
        os.remove(path)

    @unittest.skipIf(os.name == "nt", "chmod doesn't work properly on Windows")
    def test_in_toto_read_only_metadata_directory(self):
        """Fail run, passed metadata directory is read only"""
        tmp_dir = os.path.realpath(tempfile.mkdtemp())
        # make the directory read only
        os.chmod(tmp_dir, stat.S_IREAD)
        with self.assertRaises(PermissionError):
            in_toto_run(
                self.step_name,
                None,
                None,
                [VersionedPython, "--version"],
                True,
                signer=self.signer,
                metadata_directory=tmp_dir,
            )
        os.rmdir(tmp_dir)

    def test_in_toto_for_dsse(self):
        """Test metadata generation using dsse."""

        link_metadata = in_toto_run(
            self.step_name,
            None,
            None,
            [VersionedPython, "--version"],
            True,
            signer=self.signer,
            use_dsse=True,
        )
        self.assertIsInstance(link_metadata, Envelope)
        link_metadata.verify_signature(self.key)


class TestInTotoRecordStart(unittest.TestCase, TmpDirMixin):
    """ "Test in_toto_record_start(step_name, key, material_list)."""

    @classmethod
    def setUpClass(cls):
        """Create and change into temporary directory, generate key pair and dummy
        material, read key pair."""
        cls.set_up_test_dir()

        cls.signer = SignerStore.rsa
        cls.key = SignerStore.rsa_pub

        cls.step_name = "test_step"
        cls.link_name_unfinished = UNFINISHED_FILENAME_FORMAT.format(
            step_name=cls.step_name, keyid=cls.key["keyid"]
        )

        cls.test_material = "test_material"
        Path(cls.test_material).touch()

    @classmethod
    def tearDownClass(cls):
        cls.tear_down_test_dir()

    def test_UNFINISHED_FILENAME_FORMAT(self):
        """Test if the unfinished filename format."""
        self.assertTrue(
            self.link_name_unfinished
            == ".{}.{:.8}.link-unfinished".format(
                self.step_name, self.key["keyid"]
            )
        )

    def test_create_unfinished_metadata_with_expected_material(self):
        """Test record start creates metadata with expected material."""
        in_toto_record_start(
            self.step_name, [self.test_material], signer=self.signer
        )
        link = Metablock.load(self.link_name_unfinished)
        self.assertEqual(
            list(link.signed.materials.keys()), [self.test_material]
        )
        os.remove(self.link_name_unfinished)

    def test_create_unfinished_metadata_verify_signature(self):
        """Test record start creates metadata with expected signature."""
        in_toto_record_start(
            self.step_name, [self.test_material], signer=self.signer
        )
        link = Metablock.load(self.link_name_unfinished)
        link.verify_signature(self.key)
        os.remove(self.link_name_unfinished)

    def test_no_key_arguments(self):
        """Test record start without passing one required key argument."""
        with self.assertRaises(ValueError):
            in_toto_record_start(
                self.step_name,
                [],
                gpg_keyid=None,
                gpg_use_default=False,
            )

    def test_create_unfinished_metadata_using_dsse(self):
        """Test record start creates metadata using dsse."""
        in_toto_record_start(
            self.step_name,
            [self.test_material],
            signer=self.signer,
            use_dsse=True,
        )
        link_metadata = Envelope.load(self.link_name_unfinished)
        link_metadata.verify_signature(self.key)
        os.remove(self.link_name_unfinished)


class TestInTotoRecordStop(unittest.TestCase, TmpDirMixin):
    """ "Test in_toto_record_stop(step_name, key, product_list)."""

    @classmethod
    def setUpClass(cls):
        """Create and change into temporary directory, generate two key pairs
        and dummy product."""
        cls.set_up_test_dir()

        cls.signer = SignerStore.rsa
        cls.key = SignerStore.rsa_pub
        cls.signer2 = SignerStore.ecdsa
        cls.key2 = SignerStore.ecdsa_pub

        cls.step_name = "test-step"
        cls.link_name = "{}.{:.8}.link".format(cls.step_name, cls.key["keyid"])
        cls.link_name_unfinished = UNFINISHED_FILENAME_FORMAT.format(
            step_name=cls.step_name, keyid=cls.key["keyid"]
        )

        cls.test_product = "test_product"
        Path(cls.test_product).touch()

    @classmethod
    def tearDownClass(cls):
        cls.tear_down_test_dir()

    def test_create_metadata_with_expected_product(self):
        """Test record stop records expected product."""
        in_toto_record_start(self.step_name, [], signer=self.signer)
        in_toto_record_stop(
            self.step_name, [self.test_product], signer=self.signer
        )
        link = Metablock.load(self.link_name)
        self.assertEqual(list(link.signed.products.keys()), [self.test_product])
        os.remove(self.link_name)

    def test_compare_metadata_with_and_without_metadata_directory(self):
        """Test record stop with and without metadata directory,
        compare the expected product"""
        tmp_dir = os.path.realpath(tempfile.mkdtemp(dir=os.getcwd()))
        in_toto_record_start(self.step_name, [], signer=self.signer)
        in_toto_record_stop(
            self.step_name,
            [self.test_product],
            signer=self.signer,
            metadata_directory=tmp_dir,
        )
        link_path = os.path.join(tmp_dir, self.link_name)
        link_with_md = Metablock.load(link_path)

        in_toto_record_start(self.step_name, [], signer=self.signer)
        in_toto_record_stop(
            self.step_name, [self.test_product], signer=self.signer
        )
        link_without_md = Metablock.load(self.link_name)
        self.assertEqual(link_with_md.signed, link_without_md.signed)
        os.remove(link_path)
        os.remove(self.link_name)

    def test_create_metadata_with_expected_cwd(self):
        """Test record start/stop run, verify cwd."""
        in_toto_record_start(
            self.step_name, [], signer=self.signer, record_environment=True
        )
        in_toto_record_stop(
            self.step_name, [self.test_product], signer=self.signer
        )
        link = Metablock.load(self.link_name)
        self.assertEqual(
            link.signed.environment["workdir"], os.getcwd().replace("\\", "/")
        )
        os.remove(self.link_name)

    def test_create_metadata_verify_signature(self):
        """Test record start creates metadata with expected signature."""
        in_toto_record_start(self.step_name, [], signer=self.signer)
        in_toto_record_stop(self.step_name, [], signer=self.signer)
        link = Metablock.load(self.link_name)
        link.verify_signature(self.key)
        os.remove(self.link_name)

    def test_replace_unfinished_metadata(self):
        """Test record stop removes unfinished file and creates link file."""
        in_toto_record_start(self.step_name, [], signer=self.signer)
        in_toto_record_stop(self.step_name, [], signer=self.signer)
        with self.assertRaises(IOError):
            open(self.link_name_unfinished, encoding="utf8")  # noqa: SIM115
        self.assertTrue(os.path.isfile(self.link_name))
        os.remove(self.link_name)

    def test_missing_unfinished_file(self):
        """Test record stop exits on missing unfinished file, no link recorded."""
        with self.assertRaises(IOError):
            in_toto_record_stop(self.step_name, [], signer=self.signer)
        with self.assertRaises(IOError):
            open(self.link_name, encoding="utf8")  # noqa: SIM115

    def test_wrong_signature_in_unfinished_metadata(self):
        """Test record stop exits on wrong signature, no link recorded."""
        in_toto_record_start(self.step_name, [], signer=self.signer)
        link_name = UNFINISHED_FILENAME_FORMAT.format(
            step_name=self.step_name, keyid=self.key["keyid"]
        )
        changed_link_name = UNFINISHED_FILENAME_FORMAT.format(
            step_name=self.step_name, keyid=self.key2["keyid"]
        )
        os.rename(link_name, changed_link_name)
        with self.assertRaises(SignatureVerificationError):
            in_toto_record_stop(self.step_name, [], signer=self.signer2)
        with self.assertRaises(IOError):
            open(self.link_name, encoding="utf8")  # noqa: SIM115
        os.rename(changed_link_name, link_name)
        os.remove(self.link_name_unfinished)

    def test_no_key_arguments(self):
        """Test record stop without passing one required key argument."""
        with self.assertRaises(ValueError):
            in_toto_record_stop(
                self.step_name,
                [],
                gpg_keyid=None,
                gpg_use_default=False,
            )

    def test_normalize_line_endings(self):
        """Test cross-platform line ending normalization."""
        paths = []
        try:
            # Create three artifacts with same content but different line endings
            for line_ending in [b"\n", b"\r", b"\r\n"]:
                fd, path = tempfile.mkstemp()
                paths.append(path)
                os.write(fd, b"hello" + line_ending + b"toto")
                os.close(fd)

            # Call in_toto_record start and stop and record artifacts as
            # materials and products with line ending normalization on
            in_toto_record_start(
                self.step_name,
                paths,
                signer=self.signer,
                normalize_line_endings=True,
            )
            in_toto_record_stop(
                self.step_name,
                paths,
                signer=self.signer,
                normalize_line_endings=True,
            )
            link = Metablock.load(self.link_name).signed

            # Check that all three hashes in materials and products are equal
            for artifact_dict in [link.materials, link.products]:
                hash_dicts = list(artifact_dict.values())
                self.assertTrue(hash_dicts[1:] == hash_dicts[:-1])

        # Clean up
        finally:
            for path in paths:
                os.remove(path)

    def test_nonexistent_directory(self):
        """Test record stop with nonexistent metadata directory"""
        with self.assertRaises(FileNotFoundError):
            in_toto_record_start(self.step_name, [], signer=self.signer)
            in_toto_record_stop(
                self.step_name,
                [],
                signer=self.signer,
                metadata_directory="nonexistentDir",
            )

    def test_not_a_directory(self):
        """Test record stop, passed metadata directory is not a dir"""
        fd, path = tempfile.mkstemp()
        os.write(fd, b"hello in-toto")
        os.close(fd)
        # Windows will raise FileNotFoundError instead of NotADirectoryError
        with self.assertRaises((NotADirectoryError, FileNotFoundError)):
            in_toto_record_start(self.step_name, [], signer=self.signer)
            in_toto_record_stop(
                self.step_name, [], signer=self.signer, metadata_directory=path
            )
        os.remove(path)

    @unittest.skipIf(os.name == "nt", "chmod doesn't work properly on Windows")
    def test_read_only_metadata_directory(self):
        """Test record stop with read only metadata directory"""
        tmp_dir = os.path.realpath(tempfile.mkdtemp())
        # make the directory read only
        os.chmod(tmp_dir, stat.S_IREAD)
        with self.assertRaises(PermissionError):
            in_toto_record_start(self.step_name, [], signer=self.signer)
            in_toto_record_stop(
                self.step_name,
                [],
                signer=self.signer,
                metadata_directory=tmp_dir,
            )
        os.rmdir(tmp_dir)

    def test_created_metadata_using_dsse(self):
        """Test record stop records created metadata with dsse."""
        in_toto_record_start(
            self.step_name, [], signer=self.signer, use_dsse=True
        )
        in_toto_record_stop(
            self.step_name, [self.test_product], signer=self.signer
        )

        link_metadata = Envelope.load(self.link_name)
        link_metadata.verify_signature(self.key)

        link = link_metadata.get_payload()
        self.assertEqual(list(link.products.keys()), [self.test_product])
        os.remove(self.link_name)

    def test_create_metadata_with_command_byproducts_environment(self):
        """Test record stop records expected product."""
        command = ["cp", "src", "dest"]
        byproducts = {
            "stdout": "success",
            "stderr": "errors",
            "return-value": 0,
        }
        environment = {
            "variables": "ENV_NAME=ENV_VALUE",
            "filesystem": "<filesystem info>",
            "workdir": "./",
        }

        in_toto_record_start(
            self.step_name, [], signer=self.signer, record_environment=True
        )
        in_toto_record_stop(
            self.step_name,
            [self.test_product],
            signer=self.signer,
            command=command,
            byproducts=byproducts,
            environment=environment,
        )
        link = Metablock.load(self.link_name)
        self.assertEqual(link.signed.command, command)
        self.assertDictEqual(link.signed.byproducts, byproducts)
        self.assertDictEqual(link.signed.environment, environment)
        os.remove(self.link_name)


class TestInTotoMatchProducts(TmpDirMixin, unittest.TestCase):
    """Basic tests for in_toto_match_products.

    More comprehensive tests for `record_artifacts_as_dict` args exist above.
    """

    @classmethod
    def setUpClass(cls):
        # Create link with some products and some local artifacts in tmp dir:
        # - 'foo' is only in products
        # - 'quux' is not in products
        # - 'baz' is in both, with different hashes
        # - 'bar' is in both, with matching hashes
        cls.set_up_test_dir()  # teardown is called implicitly

        cls.link = Link(
            products={
                "foo": {
                    "sha256": "8a51c03f1ff77c2b8e76da512070c23c5e69813d5c61732b3025199e5f0c14d5"
                },
                "bar": {
                    "sha256": "bb97edb3507a35b119539120526d00da595f14575da261cd856389ecd89d3186"
                },
                "baz": {
                    "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                },
            }
        )
        Path("bar").touch()
        Path("baz").touch()
        Path("quux").touch()

    def test_check(self):
        """Match local artifacts with link products for different kwargs."""
        # Test data:
        # [
        #   (
        #     <passed kwargs>,
        #     <expected return values (only in products, not in products, differ)>
        #   ),
        #   ...
        # ]
        test_data = [
            ({}, ({"foo"}, {"quux"}, {"bar"})),
            (
                {"exclude_patterns": ["ba*"]},
                ({"foo", "bar", "baz"}, {"quux"}, set()),
            ),
            ({"paths": ["baz"]}, ({"foo", "bar"}, set(), set())),
            (
                {
                    "paths": [str(Path("baz").absolute())],
                    "lstrip_paths": [
                        # NOTE: normalize lstrip path to match normalized artifact path
                        # (see in-toto/in-toto#565)
                        f"{Path('baz').absolute().parent}/".replace("\\", "/")
                    ],
                },
                ({"foo", "bar"}, set(), set()),
            ),
        ]

        for kwargs, expected_return_value in test_data:
            self.assertTupleEqual(
                in_toto_match_products(self.link, **kwargs),
                expected_return_value,
                f"unexpected result for **kwargs: {kwargs})",
            )


class TestSigner(unittest.TestCase, TmpDirMixin):
    """Test signer argument in runlib API functions (run, record)."""

    @classmethod
    def setUpClass(cls):
        cls.set_up_test_dir()  # teardown is called implicitly

        cls.rsa_pub = SignerStore.rsa_pub
        cls.rsa_signer = SignerStore.rsa

        cls.ed_pub = SignerStore.ed25519_pub
        cls.ed_signer = SignerStore.ed25519

    def test_run(self):
        # Successfully create, sign and verify link
        link = in_toto_run("foo", [], [], [], signer=self.rsa_signer)
        self.assertIsNone(link.verify_signature(self.rsa_pub))

        # Fail with wrong verification key
        with self.assertRaises(SignatureVerificationError):
            link.verify_signature(self.ed_pub)

        # Fail with bad signer arg
        class NoSigner:
            pass

        with self.assertRaises(ValueError):
            link = in_toto_run("foo", [], [], [], signer=NoSigner())

    def test_record(self):
        # Successfully create, sign and verify link
        in_toto_record_start("bar", [], signer=self.ed_signer)
        in_toto_record_stop("bar", [], signer=self.ed_signer)
        link_name = FILENAME_FORMAT.format(
            step_name="bar", keyid=self.ed_signer.public_key.keyid
        )
        link = Metablock.load(link_name)
        self.assertIsNone(link.verify_signature(self.ed_pub))

        # Fail with wrong verification key
        with self.assertRaises(SignatureVerificationError):
            link.verify_signature(self.rsa_pub)

        # Fail with different signer in start and stop
        in_toto_record_start("baz", [], signer=self.ed_signer)
        with self.assertRaises(OSError):
            in_toto_record_stop("baz", [], signer=self.rsa_signer)


if __name__ == "__main__":
    unittest.main()


class TestInTotoRecordHandle(unittest.TestCase, TmpDirMixin):
    """Test explicit record handles for start/stop session binding."""

    @classmethod
    def setUpClass(cls):
        cls.set_up_test_dir()  # teardown is called implicitly

        cls.signer = SignerStore.rsa
        cls.key = SignerStore.rsa_pub
        cls.other_signer = SignerStore.ecdsa
        cls.other_key = SignerStore.ecdsa_pub

        cls.step_name = "build-step"

    def _make_session(self, name, material_content, token=None):
        """Create a session directory with one material and start a record."""
        os.makedirs(name, exist_ok=True)
        material = os.path.join(name, "material.txt")
        Path(material).write_text(material_content, encoding="utf8")

        kwargs = {"record_token": token} if token is not None else {}
        handle = in_toto_record_start(
            self.step_name,
            [name],
            signer=self.signer,
            **kwargs,
        )
        return handle, material

    def _finish(self, handle, name, product_content):
        """Create a product in the session directory and finish the record."""
        product = os.path.join(name, "product.txt")
        Path(product).write_text(product_content, encoding="utf8")
        return in_toto_record_stop(handle, [name], signer=self.signer)

    def test_interleaved_same_named_sessions_keep_materials_and_products(self):
        """Two interleaved same-name builds must not mix their artifacts."""
        handle_a, material_a = self._make_session("session-a", "A")
        handle_b, material_b = self._make_session("session-b", "B")

        # Both starts happened before either stop, so their unfinished proofs
        # coexist and have distinct session file names.
        self.assertNotEqual(handle_a.unfinished_path, handle_b.unfinished_path)
        self.assertTrue(os.path.isfile(handle_a.unfinished_path))
        self.assertTrue(os.path.isfile(handle_b.unfinished_path))

        # Finish in reverse order to expose name-based cross-talk.
        metadata_b = self._finish(handle_b, "session-b", "product-B")
        metadata_a = self._finish(handle_a, "session-a", "product-A")

        link_a = Metablock.load(handle_a.completed_path)
        link_b = Metablock.load(handle_b.completed_path)
        link_a.verify_signature(self.key)
        link_b.verify_signature(self.key)
        self.assertEqual(link_a.signed, metadata_a.get_payload())
        self.assertEqual(link_b.signed, metadata_b.get_payload())

        self.assertEqual(
            set(link_a.signed.materials), {material_a.replace("\\", "/")}
        )
        self.assertEqual(
            set(link_b.signed.materials), {material_b.replace("\\", "/")}
        )
        self.assertEqual(
            set(link_a.signed.products),
            {
                material_a.replace("\\", "/"),
                os.path.join("session-a", "product.txt").replace("\\", "/"),
            },
        )
        self.assertEqual(
            set(link_b.signed.products),
            {
                material_b.replace("\\", "/"),
                os.path.join("session-b", "product.txt").replace("\\", "/"),
            },
        )

        self.assertFalse(os.path.exists(handle_a.unfinished_path))
        self.assertFalse(os.path.exists(handle_b.unfinished_path))

    def test_default_handles_for_same_name_do_not_collide(self):
        """Two default handles for one step carry independent started state."""
        handle_a, _ = self._make_session("default-a", "A")
        handle_b, _ = self._make_session("default-b", "B")

        self.assertNotEqual(handle_a.token, handle_b.token)
        self.assertNotEqual(handle_a.unfinished_path, handle_b.unfinished_path)
        self.assertNotEqual(handle_a.start_digest, handle_b.start_digest)
        self.assertTrue(os.path.exists(handle_a.unfinished_path))
        self.assertTrue(os.path.exists(handle_b.unfinished_path))

        self._finish(handle_a, "default-a", "PA")
        self._finish(handle_b, "default-b", "PB")

        link_a = Metablock.load(handle_a.completed_path).signed
        link_b = Metablock.load(handle_b.completed_path).signed
        self.assertEqual(set(link_a.materials), {"default-a/material.txt"})
        self.assertEqual(set(link_b.materials), {"default-b/material.txt"})
        self.assertIn("default-a/product.txt", link_a.products)
        self.assertNotIn("default-b/product.txt", link_a.products)
        self.assertIn("default-b/product.txt", link_b.products)
        self.assertNotIn("default-a/product.txt", link_b.products)

    def test_duplicate_record_token_is_rejected(self):
        """A caller-chosen token cannot overwrite another start proof."""
        handle, _ = self._make_session("session-token", "A", "token" + "x" * 16)

        with self.assertRaises(in_toto.exceptions.RecordHandleFormatError):
            in_toto_record_start(
                self.step_name,
                ["session-token"],
                signer=self.signer,
                record_token="token" + "x" * 16,
            )

        self.assertTrue(os.path.exists(handle.unfinished_path))
        self.assertFalse(os.path.exists(handle.completed_path))

    def test_handle_accepts_dict_and_json_roundtrip(self):
        """A handle can be persisted and reloaded by a separate stop task."""
        handle, _ = self._make_session("session-json", "J", "json" + "x" * 16)

        for restored in (
            RecordHandle.from_dict(handle.to_dict()),
            RecordHandle.from_json(handle.to_json()),
        ):
            self.assertEqual(restored, handle)
            self.assertEqual(restored.step_name, self.step_name)
            self.assertEqual(restored.keyid, self.signer.public_key.keyid)

        # Use the restored handle rather than the original object.
        restored = RecordHandle.from_json(handle.to_json())
        metadata = in_toto_record_stop(
            record_handle=restored,
            product_list=["session-json"],
            signer=self.signer,
        )
        self.assertTrue(os.path.exists(handle.completed_path))
        self.assertIsInstance(metadata, Metablock)

    def test_tampered_unfinished_file_preserves_raw_proof(self):
        """A modified unfinished proof must fail and remain diagnosable."""
        handle, _ = self._make_session(
            "session-tamper", "T", "tamper" + "x" * 16
        )

        with open(handle.unfinished_path, "rb") as fp:
            original = fp.read()
        tampered = original + b" "
        self.assertNotEqual(original, tampered)
        Path(handle.unfinished_path).write_bytes(tampered)

        with self.assertRaises(in_toto.exceptions.RecordTamperedError):
            in_toto_record_stop(handle, ["session-tamper"], signer=self.signer)

        # Raw material for diagnosis is untouched, and no completed Link exists.
        self.assertEqual(Path(handle.unfinished_path).read_bytes(), tampered)
        self.assertFalse(os.path.exists(handle.completed_path))

    def test_tampered_materials_with_valid_file_digest_fails(self):
        """A proof that is re-signed for other materials must be rejected."""
        handle, _ = self._make_session(
            "session-resign", "R", "resign" + "x" * 16
        )
        link_metadata = Metablock.load(handle.unfinished_path)
        link_metadata.signed.materials["forged"] = {"sha256": "0" * 64}
        link_metadata = Metablock(signed=link_metadata.signed)
        link_metadata.create_signature(self.signer)
        link_metadata.dump(handle.unfinished_path)

        # The handle is refreshed only in digest terms, not in materials terms,
        # so the materials digest must catch the forged proof.
        forged_handle = RecordHandle.from_dict(
            {
                **handle.to_dict(),
                "start_digest": hashlib.sha256(
                    Path(handle.unfinished_path).read_bytes()
                ).hexdigest(),
            }
        )
        with self.assertRaises(in_toto.exceptions.RecordTamperedError):
            in_toto_record_stop(
                forged_handle, ["session-resign"], signer=self.signer
            )
        self.assertTrue(os.path.exists(forged_handle.unfinished_path))
        self.assertFalse(os.path.exists(handle.completed_path))

    def test_handle_metadata_directory_keeps_session_link_separate(self):
        """metadata_directory affects the completed output, not the handle PKI."""
        handle, _ = self._make_session("session-md", "M", "metadata" + "x" * 16)
        os.makedirs("links")

        in_toto_record_stop(
            handle,
            ["session-md"],
            signer=self.signer,
            metadata_directory="links",
        )

        session_link = Path(handle.completed_path)
        canonical_link = Path("links") / FILENAME_FORMAT.format(
            step_name=self.step_name, keyid=self.key["keyid"]
        )
        self.assertTrue(session_link.exists())
        self.assertTrue(canonical_link.exists())
        self.assertEqual(session_link.read_bytes(), canonical_link.read_bytes())

    def test_stop_with_other_identity_preserves_proof(self):
        """A different signing identity must not consume the record."""
        handle, _ = self._make_session(
            "session-identity", "I", "ident" + "x" * 16
        )

        with self.assertRaises(in_toto.exceptions.RecordIdentityError):
            in_toto_record_stop(
                handle, ["session-identity"], signer=self.other_signer
            )

        self.assertTrue(os.path.exists(handle.unfinished_path))
        self.assertFalse(os.path.exists(handle.completed_path))

        # The bound identity can still finish the record.
        in_toto_record_stop(handle, ["session-identity"], signer=self.signer)
        self.assertTrue(os.path.exists(handle.completed_path))

    def test_stop_from_other_cwd_requires_explicit_base_path(self):
        """Changing working directory without base_path is explicit."""
        handle, _ = self._make_session("session-cwd", "C", "cwd" + "x" * 16)
        os.makedirs("elsewhere")

        original_cwd = os.getcwd()
        try:
            os.chdir("elsewhere")
            with self.assertRaises(
                in_toto.exceptions.RecordWorkingDirectoryError
            ):
                in_toto_record_stop(handle, ["session-cwd"], signer=self.signer)
            self.assertTrue(os.path.exists(handle.unfinished_path))

            # Explicit base_path allows finishing from the other directory.
            in_toto_record_stop(
                handle,
                ["session-cwd"],
                signer=self.signer,
                base_path=original_cwd,
            )
        finally:
            os.chdir(original_cwd)

        self.assertTrue(os.path.exists(handle.completed_path))

    def test_handle_completion_also_writes_canonical_link(self):
        """The canonical link stays discoverable to existing verifiers."""
        handle, _ = self._make_session(
            "session-canonical", "C", "canonical" + "x" * 16
        )
        in_toto_record_stop(handle, ["session-canonical"], signer=self.signer)

        canonical = Path(
            FILENAME_FORMAT.format(
                step_name=self.step_name, keyid=self.key["keyid"]
            )
        )
        self.assertTrue(canonical.exists())
        self.assertEqual(
            canonical.read_bytes(), Path(handle.completed_path).read_bytes()
        )
        Metablock.load(str(canonical)).verify_signature(self.key)

    def test_duplicate_stop_reads_completed_result(self):
        """A retry with the same products returns the completed result."""
        handle, _ = self._make_session("session-retry", "S", "retry" + "x" * 16)
        first = self._finish(handle, "session-retry", "same")
        completed_bytes = Path(handle.completed_path).read_bytes()

        second = in_toto_record_stop(
            handle, ["session-retry"], signer=self.signer
        )

        self.assertEqual(first.get_payload(), second.get_payload())
        self.assertEqual(
            Path(handle.completed_path).read_bytes(), completed_bytes
        )
        Metablock.load(handle.completed_path).verify_signature(self.key)

    def test_write_fault_before_canonical_link_preserves_proof(self):
        """A failure while mirroring leaves the proof and session link safe."""
        handle, _ = self._make_session(
            "session-canonical-fault", "F", "canon-fault" + "x" * 16
        )
        canonical = Path(
            FILENAME_FORMAT.format(
                step_name=self.step_name, keyid=self.key["keyid"]
            )
        )
        if canonical.exists():
            canonical.unlink()

        real_replace = os.replace

        def replace_once(src, dst):
            if os.path.abspath(dst) == os.path.abspath(str(canonical)):
                raise OSError("controlled fault on canonical mirror")
            return real_replace(src, dst)

        with (
            mock.patch("in_toto.runlib.os.replace", side_effect=replace_once),
            self.assertRaises(OSError),
        ):
            in_toto_record_stop(
                handle, ["session-canonical-fault"], signer=self.signer
            )

        self.assertTrue(os.path.exists(handle.completed_path))
        self.assertFalse(canonical.exists())
        self.assertTrue(os.path.exists(handle.unfinished_path))

        # A retry restores the mirror and leaves the session link untouched.
        before = Path(handle.completed_path).read_bytes()
        metadata = in_toto_record_stop(
            handle, ["session-canonical-fault"], signer=self.signer
        )
        self.assertEqual(Path(handle.completed_path).read_bytes(), before)

        self.assertTrue(canonical.exists())
        self.assertTrue(os.path.exists(handle.completed_path))
        self.assertIsNotNone(metadata)
        os.remove(canonical)

    def test_retry_with_directory_products_ignores_record_housekeeping(self):
        """Retry over '.' may read the result though proof files disappeared."""
        handle, _ = self._make_session("session-dot", "D", "dot" + "x" * 16)
        metadata = in_toto_record_stop(handle, ["."], signer=self.signer)

        products = metadata.get_payload().products
        # Default settings exclude '*link*', so record files are not recorded.
        self.assertNotIn(os.path.basename(handle.unfinished_path), products)
        self.assertNotIn(os.path.basename(handle.completed_path), products)

        retry = in_toto_record_stop(handle, ["."], signer=self.signer)
        self.assertEqual(retry.get_payload().products, products)
        Metablock.load(handle.completed_path).verify_signature(self.key)

    def test_duplicate_stop_with_different_products_is_rejected(self):
        """A retry must not splice different products into a completed Link."""
        handle, _ = self._make_session("session-dup", "D", "dup" + "x" * 16)
        self._finish(handle, "session-dup", "first")
        completed_bytes = Path(handle.completed_path).read_bytes()

        os.makedirs("other-products")
        Path("other-products/product.txt").write_text(
            "different", encoding="utf8"
        )
        with self.assertRaises(in_toto.exceptions.RecordAlreadyCompletedError):
            in_toto_record_stop(handle, ["other-products"], signer=self.signer)

        # Completed evidence is unchanged.
        self.assertEqual(
            Path(handle.completed_path).read_bytes(), completed_bytes
        )

    def test_duplicate_stop_with_different_byproducts_is_rejected(self):
        """Retries may not change non-product fields either."""
        handle, _ = self._make_session("session-meta", "M", "meta" + "x" * 16)
        in_toto_record_stop(
            handle,
            ["session-meta"],
            signer=self.signer,
            byproducts={"return-value": 0},
        )

        with self.assertRaises(in_toto.exceptions.RecordAlreadyCompletedError):
            in_toto_record_stop(
                handle,
                ["session-meta"],
                signer=self.signer,
                byproducts={"return-value": 1},
            )

    def test_write_fault_preserves_unfinished_proof_and_no_link(self):
        """A failed completed-link write must not overwrite a partial Link."""
        handle, _ = self._make_session("session-fault", "F", "fault" + "x" * 16)

        with (
            mock.patch(
                "in_toto.models.metadata.Metablock.dump",
                side_effect=OSError("controlled write fault"),
            ),
            self.assertRaises(OSError),
        ):
            in_toto_record_stop(handle, ["session-fault"], signer=self.signer)

        # The unfinished proof remains intact, and no completed Link exists.
        self.assertTrue(os.path.exists(handle.unfinished_path))
        self.assertFalse(os.path.exists(handle.completed_path))
        self.assertFalse(
            [
                name
                for name in os.listdir(".")
                if name.startswith(".in-toto-record-")
            ]
        )

        # Retrying after the fault completes normally.
        metadata = in_toto_record_stop(
            handle, ["session-fault"], signer=self.signer
        )
        self.assertTrue(os.path.exists(handle.completed_path))
        self.assertIsNotNone(metadata)

    def test_partial_target_is_not_left_behind_on_write_fault(self):
        """A failure after staging leaves no partial completed Link."""
        handle, _ = self._make_session(
            "session-partial", "P", "partial" + "x" * 16
        )

        with (
            mock.patch(
                "in_toto.runlib.os.replace",
                side_effect=OSError("controlled fault before replace"),
            ),
            self.assertRaises(OSError),
        ):
            in_toto_record_stop(handle, ["session-partial"], signer=self.signer)

        self.assertFalse(os.path.exists(handle.completed_path))
        self.assertTrue(os.path.exists(handle.unfinished_path))
        self.assertFalse(
            [
                name
                for name in os.listdir(".")
                if name.startswith(".in-toto-record-")
            ]
        )

    def test_step_name_only_stop_rejects_ambiguous_sessions(self):
        """Identical session proofs make a step-name-only stop ambiguous."""
        handle = in_toto_record_start(
            self.step_name,
            ["session-ambiguous"],
            signer=self.signer,
            record_token="ambig" + "a" * 16,
        )
        os.makedirs("session-ambiguous", exist_ok=True)

        # Simulate a backend that duplicated one start proof under another
        # session token. Both session files now carry the same materials.
        duplicate = Path(handle.unfinished_path).with_name(
            f".{self.step_name}.{self.key['keyid'][:8]}.ambig{'b' * 16}"
            ".link-unfinished"
        )
        shutil.copyfile(handle.unfinished_path, duplicate)

        with self.assertRaises(in_toto.exceptions.RecordAmbiguousError):
            in_toto_record_stop(self.step_name, [], signer=self.signer)

        # Nothing was consumed by the refused stop.
        self.assertTrue(os.path.exists(handle.unfinished_path))
        self.assertTrue(duplicate.exists())
        self.assertFalse(os.path.exists(handle.completed_path))

        in_toto_record_stop(handle, ["session-ambiguous"], signer=self.signer)
        self.assertTrue(os.path.exists(handle.completed_path))

    def test_default_start_writes_both_proofs(self):
        """A default start writes session and historical proofs."""
        os.makedirs("session-default", exist_ok=True)
        Path("session-default/material.txt").write_text("D", encoding="utf8")
        handle = in_toto_record_start(
            self.step_name, ["session-default"], signer=self.signer
        )

        legacy = UNFINISHED_FILENAME_FORMAT.format(
            step_name=self.step_name, keyid=self.key["keyid"]
        )
        self.assertTrue(Path(legacy).exists())
        self.assertRegex(
            os.path.basename(handle.unfinished_path),
            r"^\.build-step\.[0-9a-f]{8}\.[0-9a-f]{32}\.link-unfinished$",
        )
        self.assertNotEqual(os.path.basename(handle.unfinished_path), legacy)

        metadata = in_toto_record_stop(
            handle, ["session-default"], signer=self.signer
        )
        self.assertTrue(os.path.exists(handle.completed_path))
        self.assertIsInstance(metadata, Metablock)
        os.remove(handle.completed_path)

    def test_legacy_single_task_still_works(self):
        """The historical step-name-only call style remains compatible."""
        os.makedirs("legacy")
        Path("legacy/material.txt").write_text("L", encoding="utf8")

        in_toto_record_start(self.step_name, ["legacy"], signer=self.signer)
        Path("legacy/product.txt").write_text("P", encoding="utf8")
        in_toto_record_stop(self.step_name, ["legacy"], signer=self.signer)

        link_name = FILENAME_FORMAT.format(
            step_name=self.step_name, keyid=self.key["keyid"]
        )
        link = Metablock.load(link_name)
        link.verify_signature(self.key)
        self.assertIn(
            "legacy/material.txt", link.signed.materials, link.signed.materials
        )
        self.assertIn(
            "legacy/product.txt", link.signed.products, link.signed.products
        )
        os.remove(link_name)

    def test_dsse_handle_sessions_are_bound(self):
        """DSSE sessions also carry materials/products of the right session."""
        os.makedirs("dsse-a")
        os.makedirs("dsse-b")
        Path("dsse-a/material.txt").write_text("A", encoding="utf8")
        Path("dsse-b/material.txt").write_text("B", encoding="utf8")

        handle_a = in_toto_record_start(
            "dsse-step",
            ["dsse-a"],
            signer=self.signer,
            use_dsse=True,
            record_token="dsse" + "a" * 16,
        )
        handle_b = in_toto_record_start(
            "dsse-step",
            ["dsse-b"],
            signer=self.signer,
            use_dsse=True,
            record_token="dsse" + "b" * 16,
        )
        Path("dsse-a/product.txt").write_text("PA", encoding="utf8")
        Path("dsse-b/product.txt").write_text("PB", encoding="utf8")

        in_toto_record_stop(handle_b, ["dsse-b"], signer=self.signer)
        in_toto_record_stop(handle_a, ["dsse-a"], signer=self.signer)

        link_a = Envelope.load(handle_a.completed_path)
        link_b = Envelope.load(handle_b.completed_path)
        link_a.verify_signature(self.key)
        link_b.verify_signature(self.key)
        self.assertEqual(
            set(link_a.get_payload().materials), {"dsse-a/material.txt"}
        )
        self.assertEqual(
            set(link_b.get_payload().materials), {"dsse-b/material.txt"}
        )
        self.assertIn("dsse-a/product.txt", link_a.get_payload().products)
        self.assertNotIn("dsse-b/product.txt", link_a.get_payload().products)
        self.assertIn("dsse-b/product.txt", link_b.get_payload().products)
        self.assertNotIn("dsse-a/product.txt", link_b.get_payload().products)
