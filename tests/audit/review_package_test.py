import hashlib
import json
import os
from pathlib import Path
from unittest import mock

import pytest

from detect_secrets.audit.review_package import DuplicateReviewPackageError
from detect_secrets.audit.review_package import export_review_package
from detect_secrets.audit.review_package import import_review_package
from detect_secrets.audit.review_package import ReviewPackageError
from detect_secrets.audit.review_package import review_package
from detect_secrets.audit.review_package import StaleReviewPackageError
from detect_secrets.audit.review_package import WrongReviewPackageError
from detect_secrets.core import baseline
from detect_secrets.core.secrets_collection import SecretsCollection
from detect_secrets.main import main
from detect_secrets.plugins.basic_auth import BasicAuthDetector
from detect_secrets.settings import transient_settings


FIRST_SECRET = 'Zx9Qa2Ws8Edc4Rfv'
SECOND_SECRET = 'T7yU3iO9pL5kJ2hG'
SOURCE_LINE = (
    'a = "http://u1:{}@example.com"; b = "http://u2:{}@example.org"'
).format(FIRST_SECRET, SECOND_SECRET)


@pytest.fixture
def source_dir(tmp_path):
    directory = tmp_path / 'source'
    directory.mkdir()
    (directory / 'two.py').write_text(SOURCE_LINE + '\n')

    previous = os.getcwd()
    os.chdir(str(directory))
    try:
        yield directory
    finally:
        os.chdir(previous)


@pytest.fixture
def baseline_file(source_dir):
    with transient_settings({
        'plugins_used': [
            {'name': 'BasicAuthDetector'},
        ],
        'filters_used': [],
    }):
        secrets = SecretsCollection()
        secrets.scan_file(str(source_dir / 'two.py'))

    assert len(secrets[list(secrets.files)[0]]) == 2
    filename = str(source_dir / '.secrets.baseline')
    baseline.save_to_file(secrets, filename)
    return filename


def test_export_contains_no_secret_or_source_context(tmp_path, baseline_file):
    package_file = str(tmp_path / 'review.json')
    export_review_package(baseline_file, package_file)

    contents = Path(package_file).read_text()
    for forbidden in (
        FIRST_SECRET,
        SECOND_SECRET,
        SOURCE_LINE,
        'example.com',
        'example.org',
        'u1:',
        'u2:',
        'hashed_secret',
    ):
        assert forbidden not in contents

    package = json.loads(contents)
    assert len(package['findings']) == 2
    for finding in package['findings']:
        assert finding['decision'] is None
        assert finding['category'] == BasicAuthDetector.secret_type
        assert finding['evidence']['path'].endswith('two.py')
        assert finding['evidence']['line'] == 1
        assert finding['evidence']['occurrences_on_line'] == 2

    assert {
        finding['evidence']['occurrence'] for finding in package['findings']
    } == {1, 2}
    assert len({finding['finding_id'] for finding in package['findings']}) == 2


def test_offline_review_and_import(tmp_path, source_dir, baseline_file):
    package_file = str(tmp_path / 'review.json')
    export_review_package(baseline_file, package_file)

    # Simulate handing the package to a reviewer with no access to the source.
    reviewer_dir = tmp_path / 'reviewer'
    reviewer_dir.mkdir()
    reviewer_package = reviewer_dir / 'review.json'
    reviewer_package.write_text(Path(package_file).read_text())

    answers = iter(['y', 'n'])
    previous = os.getcwd()
    os.chdir(str(reviewer_dir))
    try:
        reviewed_package = review_package(
            str(reviewer_package),
            input_fn=lambda _: next(answers),
        )
    finally:
        os.chdir(previous)

    assert Path(reviewed_package).parent == reviewer_dir

    result = import_review_package(reviewed_package, baseline_file)
    assert result['real'] == 1
    assert result['false_positive'] == 1

    secrets = baseline.load(baseline.load_from_file(baseline_file), baseline_file)
    labels = sorted(secret.is_secret for _, secret in secrets)
    assert labels == [False, True]


def test_wrong_package_is_rejected(tmp_path, baseline_file):
    package_file = str(tmp_path / 'review.json')
    export_review_package(baseline_file, package_file)

    answers = iter(['y', 'n'])
    reviewed_package = review_package(package_file, input_fn=lambda _: next(answers))

    other_baseline = tmp_path / 'other.baseline'
    other_baseline.write_text(Path(baseline_file).read_text())

    with pytest.raises(WrongReviewPackageError):
        import_review_package(reviewed_package, str(other_baseline))


def test_duplicate_import_is_rejected(tmp_path, baseline_file):
    package_file = str(tmp_path / 'review.json')
    export_review_package(baseline_file, package_file)

    answers = iter(['y', 'n'])
    reviewed_package = review_package(package_file, input_fn=lambda _: next(answers))
    import_review_package(reviewed_package, baseline_file)

    with pytest.raises(DuplicateReviewPackageError):
        import_review_package(reviewed_package, baseline_file)


def test_stale_finding_is_rejected_without_partial_import(tmp_path, source_dir, baseline_file):
    package_file = str(tmp_path / 'review.json')
    export_review_package(baseline_file, package_file)

    answers = iter(['y', 'n'])
    reviewed_package = review_package(package_file, input_fn=lambda _: next(answers))

    # Remove one of the two findings from the line, then re-export to get a
    # package whose findings no longer match the reviewed one.
    (source_dir / 'two.py').write_text('a = {}; b = {}\n'.format(SECOND_SECRET, SECOND_SECRET))
    with transient_settings({
        'plugins_used': [
            {'name': 'BasicAuthDetector'},
        ],
        'filters_used': [],
    }):
        secrets = SecretsCollection()
        secrets.scan_file(str(source_dir / 'two.py'))
    baseline.save_to_file(secrets, baseline_file)

    with pytest.raises(StaleReviewPackageError):
        import_review_package(reviewed_package, baseline_file)

    secrets = baseline.load(baseline.load_from_file(baseline_file), baseline_file)
    assert all(secret.is_secret is None for _, secret in secrets)


def test_tampered_package_is_rejected(tmp_path, baseline_file):
    package_file = str(tmp_path / 'review.json')
    export_review_package(baseline_file, package_file)

    answers = iter(['y', 'n'])
    reviewed_package = review_package(package_file, input_fn=lambda _: next(answers))

    package = json.loads(Path(reviewed_package).read_text())
    package['findings'][0]['evidence']['line'] = 99
    Path(reviewed_package).write_text(json.dumps(package))

    # Even if the reviewer recomputes the unkeyed checksum, the keyed signature
    # and the baseline record's finding index still reject the change.
    payload = json.dumps(
        {
            **{key: value for key, value in package.items() if key != 'integrity'},
            'findings': [
                {key: value for key, value in finding.items() if key != 'decision'}
                for finding in package['findings']
            ],
        },
        sort_keys=True,
        separators=(',', ':'),
    ).encode('utf-8')
    package['integrity']['checksum'] = hashlib.sha256(payload).hexdigest()
    Path(reviewed_package).write_text(json.dumps(package))

    with pytest.raises(ReviewPackageError, match='signature check failed'):
        import_review_package(reviewed_package, baseline_file)


def test_cli_exit_codes(tmp_path, baseline_file):
    package_file = str(tmp_path / 'review.json')
    assert main(['audit', baseline_file, '--export-review', package_file]) == 0

    # Unreviewed packages cannot be imported.
    assert main(['audit', baseline_file, '--import-review', package_file]) == 2

    with mock.patch(
        'detect_secrets.audit.review_package.io.get_user_input',
        side_effect=['y', 'n'],
        create=True,
    ):
        previous = os.getcwd()
        os.chdir(str(tmp_path))
        try:
            assert main(['audit', '--review-package', package_file]) == 0
        finally:
            os.chdir(previous)

    reviewed = str(tmp_path / 'review.reviewed.json')
    assert main(['audit', baseline_file, '--import-review', reviewed]) == 0
    assert main(['audit', baseline_file, '--import-review', reviewed]) == 4
