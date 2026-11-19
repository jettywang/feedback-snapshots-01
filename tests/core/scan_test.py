import os
import textwrap
from pathlib import Path

import pytest

from detect_secrets.core import scan
from detect_secrets.exceptions import DiffInputLimitExceeded
from detect_secrets.settings import get_settings
from detect_secrets.settings import transient_settings
from detect_secrets.util import git
from detect_secrets.util.path import get_relative_path_if_in_cwd
from testing.mocks import mock_named_temporary_file


class TestGetFilesToScan:
    @staticmethod
    def test_should_scan_specific_non_tracked_file(non_tracked_file):
        assert list(scan.get_files_to_scan(non_tracked_file.name, should_scan_all_files=False))

    @staticmethod
    def test_should_scan_tracked_files_in_directory(non_tracked_file):
        assert (
            get_relative_path_if_in_cwd(non_tracked_file.name) not in set(
                scan.get_files_to_scan(
                    os.path.dirname(non_tracked_file.name),
                    should_scan_all_files=False,
                ),
            )
        )

    @staticmethod
    def test_should_scan_all_files_in_directory_if_flag_is_provided(non_tracked_file):
        assert (
            get_relative_path_if_in_cwd(non_tracked_file.name) in set(
                scan.get_files_to_scan(
                    os.path.dirname(non_tracked_file.name),
                    should_scan_all_files=True,
                ),
            )
        )

    @staticmethod
    def test_handles_each_path_separately(non_tracked_file):
        results = list(
            scan.get_files_to_scan(
                non_tracked_file.name,
                'test_data/short_files',
            ),
        )

        # This implies that the test_data/short_files directory is scanned, because otherwise,
        # it would only be one file. However, at the same time, this test case isn't fragile to
        # additions to this directory.
        assert len(results) > 2

    @staticmethod
    def test_handles_multiple_directories():
        directories = [Path('test_data/short_files'), Path('test_data/files')]
        results = list(scan.get_files_to_scan(*directories))

        for prefix in directories:
            assert len(list(filter(lambda x: x.startswith(str(prefix)), results))) > 1

    @staticmethod
    @pytest.fixture(autouse=True, scope='class')
    def non_tracked_file():
        with mock_named_temporary_file(
            prefix=os.path.join(git.get_root_directory(), 'test_data/'),
        ) as f:
            f.write(b'content does not matter')
            f.seek(0)

            yield f


class TestScanFile:
    @staticmethod
    def test_handles_broken_yaml_gracefully():
        with mock_named_temporary_file(suffix='.yaml') as f:
            f.write(
                textwrap.dedent("""
                metadata:
                    name: {{ .values.name }}
                """)[1:].encode(),
            )
            f.seek(0)

            assert not list(scan.scan_file(f.name))

    @staticmethod
    def test_handles_binary_files_gracefully():
        # NOTE: This suffix needs to be something that isn't in the known file types, as determined
        # by `detect_secrets.util.filetype.determine_file_type`.
        with mock_named_temporary_file(suffix='.woff2') as f:
            f.write(b'\x86')
            f.seek(0)

            assert not list(scan.scan_file(f.name))


SECRET_VALUE = '2b00042f7481c7b056c4b410d28f33cf'


def _make_diff() -> str:
    return textwrap.dedent(f"""
        diff --git a/alpha.py b/alpha.py
        index 1111111..2222222 100644
        --- a/alpha.py
        +++ b/alpha.py
        @@ -1,3 +1,4 @@
         line1
         line2
        +first_secret = "{SECRET_VALUE}"
         line4
        diff --git a/beta.py b/beta.py
        index 3333333..4444444 100644
        --- a/beta.py
        +++ b/beta.py
        @@ -1,3 +1,4 @@
         one
         two
        +second_secret = "{SECRET_VALUE}"
         four
        @@ -10,3 +11,4 @@
         ten
         eleven
        +third_secret = "{SECRET_VALUE}"
         thirteen
        """)[1:]


class TestScanDiffInputLimit:
    @pytest.fixture(autouse=True)
    def configure_diff_scan(self, tmp_path, monkeypatch):
        # The default `is_invalid_file` filter skips paths that don't exist on disk.
        (tmp_path / 'alpha.py').touch()
        (tmp_path / 'beta.py').touch()
        monkeypatch.chdir(tmp_path)

        with transient_settings({
            'plugins_used': [
                {
                    'name': 'HexHighEntropyString',
                    'limit': 3,
                },
            ],
            'filters_used': [],
        }):
            yield

    @staticmethod
    def _write_diff(tmp_path, diff):
        diff_file = tmp_path / 'change.diff'
        diff_file.write_text(diff)
        with open(diff_file) as handle:
            return handle.read()

    @staticmethod
    def test_no_limit_scans_everything_with_original_line_numbers(tmp_path):
        diff = TestScanDiffInputLimit._write_diff(tmp_path, _make_diff())

        results = list(scan.scan_diff(diff))

        assert sorted(
            (secret.filename, secret.line_number)
            for secret in results
        ) == [
            ('alpha.py', 3),
            ('beta.py', 3),
            ('beta.py', 13),
        ]

    @staticmethod
    def test_limit_equal_to_input_size_succeeds(tmp_path):
        raw_diff = _make_diff()
        diff = TestScanDiffInputLimit._write_diff(tmp_path, raw_diff)
        get_settings().configure_diff_input_limit(len(raw_diff.encode('utf-8')))

        results = list(scan.scan_diff(diff))

        assert len(results) == 3
        assert all(secret.line_number for secret in results)

    @staticmethod
    def test_limit_one_byte_over_fails_without_being_confused_with_no_findings(tmp_path):
        raw_diff = _make_diff()
        diff = TestScanDiffInputLimit._write_diff(tmp_path, raw_diff)
        get_settings().configure_diff_input_limit(len(raw_diff.encode('utf-8')) - 1)

        with pytest.raises(DiffInputLimitExceeded) as exc_info:
            list(scan.scan_diff(diff))

        error = exc_info.value
        assert error.reason == 'limit_exceeded'
        assert error.bytes_read < len(raw_diff.encode('utf-8'))
        # The complete first file is reported as covered; the second one is partial.
        assert error.scanned_files == {'alpha.py': (1, 4)}
        assert error.partial_file == 'beta.py'

    @staticmethod
    def test_secrets_from_completed_fragments_are_still_yielded(tmp_path):
        diff = TestScanDiffInputLimit._write_diff(tmp_path, _make_diff())
        # Stop inside the first hunk of beta.py: alpha.py must already be reported.
        cutoff = diff.index('+second_secret')
        get_settings().configure_diff_input_limit(cutoff)

        results = []
        with pytest.raises(DiffInputLimitExceeded) as exc_info:
            for secret in scan.scan_diff(diff):
                results.append(secret)

        assert [(secret.filename, secret.line_number) for secret in results] == [
            ('alpha.py', 3),
        ]
        assert exc_info.value.scanned_files == {'alpha.py': (1, 4)}
        assert exc_info.value.partial_file == 'beta.py'

    @staticmethod
    def test_multiple_hunks_accumulate_against_the_budget(tmp_path):
        diff = TestScanDiffInputLimit._write_diff(tmp_path, _make_diff())
        # The limit is reached after beta.py's first hunk, but before its second one.
        cutoff = diff.index('@@ -10,3')
        get_settings().configure_diff_input_limit(cutoff)

        results = []
        with pytest.raises(DiffInputLimitExceeded) as exc_info:
            for secret in scan.scan_diff(diff):
                results.append(secret)

        # alpha.py fully scanned, beta.py's first hunk fully scanned: two findings,
        # each with its original line number.
        assert sorted(
            (secret.filename, secret.line_number)
            for secret in results
        ) == [
            ('alpha.py', 3),
            ('beta.py', 3),
        ]
        assert exc_info.value.scanned_files == {
            'alpha.py': (1, 4),
            'beta.py': (1, 4),
        }

    @staticmethod
    def test_unreadable_chunk_is_reported_distinctly(tmp_path):
        diff = _make_diff()
        diff_file = tmp_path / 'change.diff'
        diff_file.write_text(diff)

        cutoff = diff.index('+second_secret')
        lines = diff.splitlines(keepends=True)
        fail_after = 0
        consumed = 0
        for line in lines:
            if consumed >= cutoff:
                break
            consumed += len(line.encode('utf-8'))
            fail_after += 1

        class FailingLineIterator:
            """Simulates a diff whose later chunk cannot be read from disk."""

            def __init__(self, handle):
                self._handle = handle
                self.remaining = fail_after

            def __iter__(self):
                return self

            def __next__(self):
                if self.remaining == 0:
                    raise OSError('chunk unreadable')
                self.remaining -= 1
                return next(self._handle)

        with open(diff_file) as handle:
            reader = scan._DiffInputReader(FailingLineIterator(handle), None)
            results = []
            with pytest.raises(DiffInputLimitExceeded) as exc_info:
                for filename, file_lines in scan._iter_lines_from_diff(reader):
                    results.append(filename)

        assert results == ['alpha.py']
        error = exc_info.value
        assert error.reason == 'unreadable_input'
        assert error.partial_file == 'beta.py'
        assert isinstance(error.__cause__, OSError)

    @staticmethod
    def test_partial_file_is_reported_even_without_added_lines(tmp_path):
        (tmp_path / 'only.py').touch()
        diff = textwrap.dedent("""
            diff --git a/only.py b/only.py
            --- a/only.py
            +++ b/only.py
            @@ -1,2 +1,1 @@
            -removed line
             keep
            """)[1:]
        lines = diff.splitlines(keepends=True)
        cutoff = sum(len(line.encode('utf-8')) for line in lines[:5]) + 5
        get_settings().configure_diff_input_limit(cutoff)

        with pytest.raises(DiffInputLimitExceeded) as exc_info:
            list(scan.scan_diff(diff))

        assert exc_info.value.partial_file == 'only.py'
        assert exc_info.value.scanned_files == {}

    @staticmethod
    def test_limit_must_be_a_positive_integer(tmp_path):
        for invalid_value in (0, -1, '100', 1.5, True):
            with pytest.raises(ValueError):
                get_settings().configure_diff_input_limit(invalid_value)

    @staticmethod
    def test_limit_is_serialized_in_settings(tmp_path):
        get_settings().configure_diff_input_limit(1024)

        assert get_settings().json()['diff_input_limit'] == 1024

        get_settings().configure_diff_input_limit(None)
        assert 'diff_input_limit' not in get_settings().json()


@pytest.fixture(autouse=True)
def configure_plugins():
    with transient_settings({
        'plugins_used': [
            {
                'name': 'BasicAuthDetector',
            },
        ],
    }):
        yield
