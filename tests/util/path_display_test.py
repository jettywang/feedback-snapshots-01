import logging
import os

import pytest

from detect_secrets.util.path_display import build_policy_from_specs
from detect_secrets.util.path_display import DisplayPath
from detect_secrets.util.path_display import LogPathSanitizer
from detect_secrets.util.path_display import OUT_OF_SCOPE_ALIAS
from detect_secrets.util.path_display import PathDisplayPolicy


SECRET_CONTENT = 'password = "hunter2hunter2hunter2"\n'


@pytest.fixture
def two_checkouts(tmp_path):
    """
    Two independent checkouts, each containing a same-named file at the same
    project-relative location.
    """
    first_root = tmp_path / 'checkout-one'
    second_root = tmp_path / 'checkout-two'
    first_file = first_root / 'src' / 'config.py'
    second_file = second_root / 'src' / 'config.py'
    outside_file = tmp_path / 'etc' / 'machine-only.txt'

    for path in (first_file, second_file):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(SECRET_CONTENT)
    outside_file.parent.mkdir(parents=True, exist_ok=True)
    outside_file.write_text(SECRET_CONTENT)

    return {
        'first_root': str(first_root),
        'second_root': str(second_root),
        'first_file': str(first_file),
        'second_file': str(second_file),
        'outside_file': str(outside_file),
    }


class TestPathDisplayPolicy:
    @staticmethod
    def test_project_relative_paths_hide_local_prefix(two_checkouts):
        policy = PathDisplayPolicy([
            (two_checkouts['first_root'], 'service'),
            (two_checkouts['second_root'], 'service'),
        ])

        display = policy.display_for(two_checkouts['first_file'])
        assert isinstance(display, DisplayPath)
        assert display.in_scope is True
        assert display.relative_path == os.path.join('src', 'config.py')
        assert display.display_path == 'service/src/config.py'
        assert two_checkouts['first_root'] not in display.display_path

    @staticmethod
    def test_same_named_files_in_two_checkouts_stay_distinguishable(two_checkouts):
        policy = PathDisplayPolicy([
            (two_checkouts['first_root'], 'service'),
            (two_checkouts['second_root'], 'service'),
        ])

        first_display = policy.display_string(two_checkouts['first_file'])
        second_display = policy.display_string(two_checkouts['second_file'])

        assert first_display != second_display
        assert first_display == 'service/src/config.py'
        assert second_display == 'service-2/src/config.py'
        assert set(policy.display_string(path) for path in (
            two_checkouts['first_file'],
            two_checkouts['second_file'],
        )) == {first_display, second_display}

    @staticmethod
    def test_default_alias_uses_root_directory_name(two_checkouts):
        policy = PathDisplayPolicy([two_checkouts['first_root']])

        assert policy.display_string(two_checkouts['first_file']) == (
            'checkout-one/src/config.py'
        )

    @staticmethod
    def test_explicit_aliases_allow_distinct_names(two_checkouts):
        policy = PathDisplayPolicy([
            (two_checkouts['first_root'], 'billing'),
            (two_checkouts['second_root'], 'auth'),
        ])

        assert policy.display_string(two_checkouts['first_file']) == (
            'billing/src/config.py'
        )
        assert policy.display_string(two_checkouts['second_file']) == (
            'auth/src/config.py'
        )

    @staticmethod
    def test_files_outside_every_root_are_marked_out_of_scope(two_checkouts):
        policy = PathDisplayPolicy([
            (two_checkouts['first_root'], 'service'),
        ])

        display = policy.display_for(two_checkouts['outside_file'])
        assert display.in_scope is False
        assert display.alias == OUT_OF_SCOPE_ALIAS
        assert display.display_path == 'out-of-scope/machine-only.txt'
        assert policy.is_in_scope(two_checkouts['outside_file']) is False
        assert policy.is_in_scope(two_checkouts['first_file']) is True
        # No parent directory information may leak for out-of-scope files.
        assert str(two_checkouts['outside_file']).split(os.sep)[-2] not in (
            display.display_path
        )

    @staticmethod
    def test_display_path_survives_checkout_root_move(tmp_path, two_checkouts):
        original_root = two_checkouts['first_root']
        target_file = two_checkouts['first_file']
        policy = PathDisplayPolicy([(original_root, 'service')])
        display_path = policy.display_string(target_file)
        assert display_path == 'service/src/config.py'

        # Simulate the checkout being moved to a brand new location.
        moved_root = str(tmp_path / 'relocated' / 'checkout')
        os.makedirs(os.path.dirname(moved_root), exist_ok=True)
        os.rename(original_root, moved_root)
        moved_file = os.path.join(moved_root, 'src', 'config.py')

        # Re-registering the moved checkout under the same alias keeps the
        # previously emitted display path stable.
        moved_policy = PathDisplayPolicy([(moved_root, 'service')])
        assert moved_policy.display_string(moved_file) == display_path

        # The local-only inverse mapping still points back at a real file, so
        # the finding remains re-verifiable after the move.
        resolved = moved_policy.resolve(display_path)
        assert resolved == os.path.realpath(moved_file)
        assert os.path.isfile(resolved)

    @staticmethod
    def test_resolve_reopens_correct_file_in_each_checkout(two_checkouts):
        policy = PathDisplayPolicy([
            (two_checkouts['first_root'], 'service'),
            (two_checkouts['second_root'], 'service'),
        ])

        first_display = policy.display_string(two_checkouts['first_file'])
        second_display = policy.display_string(two_checkouts['second_file'])

        assert policy.resolve(first_display) == os.path.realpath(
            two_checkouts['first_file'],
        )
        assert policy.resolve(second_display) == os.path.realpath(
            two_checkouts['second_file'],
        )

    @staticmethod
    def test_resolve_rejects_unknown_alias_and_traversal(two_checkouts):
        policy = PathDisplayPolicy([(two_checkouts['first_root'], 'service')])

        assert policy.resolve('unknown-alias/src/config.py') is None
        assert policy.resolve('service/../../etc/passwd') is None
        # A display path needs an alias/relative separator.
        assert policy.resolve('service') is None

    @staticmethod
    def test_remap_results_rewrites_keys_and_nested_filenames(two_checkouts):
        policy = PathDisplayPolicy([(two_checkouts['first_root'], 'service')])
        absolute_path = two_checkouts['first_file']
        results = {
            absolute_path: [
                {
                    'type': 'AWSKeyDetector',
                    'line_number': 1,
                    'filename': absolute_path,
                },
            ],
        }

        remapped = policy.remap_results(results)
        assert list(remapped) == ['service/src/config.py']
        finding = remapped['service/src/config.py'][0]
        assert finding['filename'] == 'service/src/config.py'
        # Non-path fields are preserved.
        assert finding['type'] == 'AWSKeyDetector'
        assert finding['line_number'] == 1
        # The original collection is not mutated.
        assert results[absolute_path][0]['filename'] == absolute_path

    @staticmethod
    def test_remap_results_marks_out_of_scope_files(two_checkouts):
        policy = PathDisplayPolicy([(two_checkouts['first_root'], 'service')])
        outside = two_checkouts['outside_file']
        results = {outside: [{'filename': outside, 'type': 'KeywordDetector'}]}

        remapped = policy.remap_results(results)
        assert list(remapped) == ['out-of-scope/machine-only.txt']
        assert remapped['out-of-scope/machine-only.txt'][0]['filename'] == (
            'out-of-scope/machine-only.txt'
        )

    @staticmethod
    def test_alias_is_sanitized(two_checkouts):
        policy = PathDisplayPolicy([
            (two_checkouts['first_root'], '../etc/secret dir'),
        ])

        display = policy.display_string(two_checkouts['first_file'])
        assert display.startswith('etc-secret-dir/')

    @staticmethod
    def test_build_policy_from_specs(two_checkouts):
        policy = build_policy_from_specs([
            f"{two_checkouts['first_root']}=billing",
            two_checkouts['second_root'],
            '',
        ])

        assert policy.display_string(two_checkouts['first_file']).startswith(
            'billing/',
        )
        assert policy.display_string(two_checkouts['second_file']).startswith(
            'checkout-two/',
        )


class TestLogPathSanitizer:
    @staticmethod
    def _logger_with_stream(policy):
        import io
        logger = logging.getLogger('test-path-display')
        logger.handlers = []
        stream = io.StringIO()
        handler = logging.StreamHandler(stream)
        logger.addHandler(handler)
        logger.setLevel(logging.DEBUG)
        policy.install_log_sanitizer(logger)
        return logger, stream

    @staticmethod
    def test_in_scope_paths_become_display_paths(two_checkouts):
        policy = PathDisplayPolicy([(two_checkouts['first_root'], 'service')])
        logger, stream = TestLogPathSanitizer._logger_with_stream(policy)

        logger.warning('Unable to open file: %s', two_checkouts['first_file'])

        output = stream.getvalue()
        assert 'service/src/config.py' in output
        assert two_checkouts['first_root'] not in output

    @staticmethod
    def test_out_of_scope_absolute_paths_reduced_to_basename(two_checkouts):
        policy = PathDisplayPolicy([(two_checkouts['first_root'], 'service')])
        logger, stream = TestLogPathSanitizer._logger_with_stream(policy)

        logger.info('Touching ' + two_checkouts['outside_file'] + ' now')

        output = stream.getvalue()
        assert two_checkouts['outside_file'] not in output
        assert 'machine-only.txt' in output
        assert 'etc' not in output

    @staticmethod
    def test_unrelated_absolute_path_is_stripped(two_checkouts):
        policy = PathDisplayPolicy([(two_checkouts['first_root'], 'service')])
        sanitizer = LogPathSanitizer(policy)

        sanitized = sanitizer.sanitize('failed reading /etc/ssl/private/key.pem')
        assert '/etc/ssl/private/key.pem' not in sanitized
        assert sanitized == 'failed reading key.pem'

    @staticmethod
    def test_works_with_un_normalized_root_spelling(two_checkouts):
        # Register via the realpath-normalized location, but log a path that
        # uses a non-normalized spelling (symlinked prefix).
        registered_root = os.path.realpath(two_checkouts['first_root'])
        policy = PathDisplayPolicy([(registered_root, 'service')])
        sanitizer = LogPathSanitizer(policy)

        sanitized = sanitizer.sanitize(
            'checking {}'.format(two_checkouts['first_file']),
        )
        assert two_checkouts['first_root'] not in sanitized
        assert 'service/src/config.py' in sanitized
