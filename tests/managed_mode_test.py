"""
Tests for managed mode (`detect_secrets.managed`): when the platform maintains the
scanning service but customers submit their own baselines, managed mode restricts
which third-party plugins and filters a customer policy can load, while keeping
all built-in functionality intact.
"""
import os

import pytest

from detect_secrets import managed
from detect_secrets.core.secrets_collection import SecretsCollection
from detect_secrets.settings import configure_settings_from_baseline
from detect_secrets.settings import get_filters
from detect_secrets.settings import get_plugins
from detect_secrets.settings import get_settings


APPROVED_PLUGIN_PATH = 'file://testing/fake_extensions/approved_extension.py'
DENIED_PLUGIN_PATH = 'file://testing/fake_extensions/denied_extension.py'
APPROVED_FILTER_PATH = (
    'file://testing/fake_extensions/approved_extension.py::should_exclude_approved_fake'
)
DENIED_FILTER_PATH = (
    'file://testing/fake_extensions/denied_extension.py::should_exclude_denied_fake'
)


@pytest.fixture(autouse=True)
def managed_mode():
    managed.enable_managed_mode(
        allowed_plugins=[APPROVED_PLUGIN_PATH],
        allowed_filters=[APPROVED_FILTER_PATH],
    )
    yield
    managed.disable_managed_mode()


@pytest.fixture
def marker_file(tmp_path, monkeypatch):
    filename = str(tmp_path / 'marker.txt')
    monkeypatch.setenv('DETECT_SECRETS_MANAGED_TEST_MARKER', filename)
    return filename


def customer_policy():
    """A customer-submitted policy, declaring both approved and denied extensions."""
    return {
        'plugins_used': [
            {'name': 'ApprovedFakeScanner', 'path': APPROVED_PLUGIN_PATH},
            {'name': 'DeniedFakeScanner', 'path': DENIED_PLUGIN_PATH},
        ],
        'filters_used': [
            {'path': APPROVED_FILTER_PATH},
            {'path': DENIED_FILTER_PATH},
        ],
    }


def read_marker(filename):
    if not os.path.exists(filename):
        return ''

    with open(filename) as f:
        return f.read()


def scan_secret_types(*filenames, num_processors=None):
    secrets = SecretsCollection()
    if num_processors:
        secrets.scan_files(*filenames, num_processors=num_processors)
    else:
        for filename in filenames:
            secrets.scan_file(filename)

    return {secret.type for _, secret in secrets}


class TestPolicyLoading:
    def test_approved_extensions_are_loaded(self, marker_file):
        configure_settings_from_baseline(customer_policy())

        settings = get_settings()
        assert 'ApprovedFakeScanner' in settings.plugins
        assert APPROVED_FILTER_PATH in settings.filters

        # The approved extensions are actually invoked.
        assert 'Approved Fake Secret' in {plugin.secret_type for plugin in get_plugins()}
        assert APPROVED_FILTER_PATH in {function.path for function in get_filters()}
        assert 'approved_extension' in read_marker(marker_file)

    def test_denied_extensions_only_produce_denial_reasons(self, marker_file):
        configure_settings_from_baseline(customer_policy())

        settings = get_settings()
        assert 'DeniedFakeScanner' not in settings.plugins
        assert DENIED_FILTER_PATH not in settings.filters

        denial_reasons = managed.get_denial_reasons()
        assert len(denial_reasons) == 2
        assert any('DeniedFakeScanner' in reason for reason in denial_reasons)
        assert any(DENIED_FILTER_PATH in reason for reason in denial_reasons)

        # The denied extension's code is never executed.
        assert 'denied_extension' not in read_marker(marker_file)

    def test_builtin_functionality_is_preserved(self, marker_file):
        policy = customer_policy()
        policy['filters_used'].append({
            'path': 'detect_secrets.filters.heuristic.is_sequential_string',
        })
        configure_settings_from_baseline(policy)

        settings = get_settings()
        for path in settings.DEFAULT_FILTERS:
            assert path in settings.filters

        # Built-in filters referenced by the policy are not subject to the allowlist.
        assert 'detect_secrets.filters.heuristic.is_sequential_string' in settings.filters
        assert not any('is_sequential_string' in reason for reason in managed.get_denial_reasons())


class TestScanning:
    def test_scan(self, marker_file, tmp_path):
        configure_settings_from_baseline(customer_policy())

        target = tmp_path / 'target.txt'
        target.write_text('approved-fake-secret\ndenied-fake-secret\n')

        assert scan_secret_types(str(target)) == {'Approved Fake Secret'}
        assert 'denied_extension' not in read_marker(marker_file)

    def test_multiprocess_scan(self, marker_file, tmp_path):
        configure_settings_from_baseline(customer_policy())

        filenames = []
        for index, secret in enumerate(['approved-fake-secret', 'denied-fake-secret']):
            filename = tmp_path / f'target{index}.txt'
            filename.write_text(f'{secret}\n')
            filenames.append(str(filename))

        assert scan_secret_types(*filenames, num_processors=2) == {'Approved Fake Secret'}

        marker = read_marker(marker_file)
        assert 'approved_extension' in marker
        assert 'denied_extension' not in marker


def test_managed_mode_disabled_loads_everything(marker_file):
    managed.disable_managed_mode()
    configure_settings_from_baseline(customer_policy())

    settings = get_settings()
    assert 'ApprovedFakeScanner' in settings.plugins
    assert 'DeniedFakeScanner' in settings.plugins
    assert managed.get_denial_reasons() == []

    get_plugins()
    marker = read_marker(marker_file)
    assert 'approved_extension' in marker
    assert 'denied_extension' in marker
