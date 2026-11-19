"""
Migration verification for plugins that were renamed before the v1.0.0 release.

These tests use one shared synthetic scan fixture against baselines from multiple eras, and
produce three independent pieces of evidence:

1. decidable findings: an unambiguous rename loads and rescans deterministically, and already
   audited labels survive the upgrade;
2. entries that explicitly need manual review: configurations the replacement plugin cannot
   accept are quarantined (never silently rewritten);
3. policies that still cannot be loaded: when the replacement plugin is absent from the running
   library, the original entry is preserved and reported for the original reviewer.
"""
import json
from pathlib import Path
from typing import Any
from typing import Dict
from typing import List
from unittest import mock

import pytest

from detect_secrets.core import baseline
from detect_secrets.core.plugins import initialize
from detect_secrets.core.potential_secret import PotentialSecret
from detect_secrets.core.upgrades import v1_0
from detect_secrets.settings import cache_bust
from detect_secrets.settings import transient_settings

SQUARE_SECRET = r'sq0csp-ABCDEFGHIJK_LMNOPQRSTUVWXYZ-0123456789\abcd'
SQUARE_HASH = PotentialSecret.hash_secret(SQUARE_SECRET)
FIXTURE_FILENAME = 'app.env'


@pytest.fixture
def synthetic_project(tmp_path: Path) -> Path:
    """The single synthetic scan fixture shared by every baseline era."""
    (tmp_path / FIXTURE_FILENAME).write_text(f'square_oauth = {SQUARE_SECRET}\n')
    return tmp_path


def _baseline(version: str, plugins_used: List[Dict[str, Any]]) -> Dict[str, Any]:
    return {
        'version': version,
        'plugins_used': plugins_used,
        'results': {},
    }


def _old_baseline_with_audited_finding(version: str) -> Dict[str, Any]:
    baseline_data = _baseline(version, [{'name': 'BasicOAuthDetector'}])
    baseline_data['results'] = {
        FIXTURE_FILENAME: [
            {
                'type': 'Square OAuth Secret',
                'hashed_secret': SQUARE_HASH,
                'is_verified': False,
                'is_secret': True,
                'line_number': 1,
            },
        ],
    }
    return baseline_data


class TestRenameMapping:
    @staticmethod
    @pytest.mark.parametrize('version', ['0.12.0', '0.13.0', '0.14.3'])
    def test_unambiguous_rename_is_applied(version: str) -> None:
        upgraded = baseline.upgrade(_baseline(version, [{'name': 'BasicOAuthDetector'}]))

        assert upgraded['plugins_used'] == [{'name': 'SquareOAuthDetector'}]
        assert upgraded['plugin_upgrades']['renamed'] == [
            {
                'old_name': 'BasicOAuthDetector',
                'new_name': 'SquareOAuthDetector',
                'config': {},
            },
        ]

    @staticmethod
    def test_rename_is_idempotent() -> None:
        once = baseline.upgrade(_baseline('0.14.3', [{'name': 'BasicOAuthDetector'}]))
        twice = json.loads(json.dumps(once))
        v1_0.upgrade(twice)

        assert twice['plugins_used'] == [{'name': 'SquareOAuthDetector'}]
        # Nothing is left to rename on the second pass, so no report is emitted.
        assert 'plugin_upgrades' not in twice

    @staticmethod
    def test_non_renamed_plugins_are_untouched() -> None:
        upgraded = baseline.upgrade(
            _baseline('0.14.3', [{'name': 'AWSKeyDetector'}]),
        )

        assert upgraded['plugins_used'] == [{'name': 'AWSKeyDetector'}]
        assert 'plugin_upgrades' not in upgraded


class TestDecidableFindings:
    @staticmethod
    @pytest.mark.parametrize('version', ['0.12.0', '0.13.0', '0.14.3'])
    def test_renamed_baseline_loads_and_rescans_deterministically(
        version: str,
        synthetic_project: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.chdir(synthetic_project)
        old_baseline = _old_baseline_with_audited_finding(version)

        upgraded = baseline.upgrade(json.loads(json.dumps(old_baseline)))
        config = {
            'plugins_used': upgraded['plugins_used'],
            'filters_used': [],
        }

        cache_bust()
        with transient_settings(config):
            plugin = initialize.from_plugin_classname('SquareOAuthDetector')
            assert plugin.__class__.__name__ == 'SquareOAuthDetector'

            audited = baseline.load(json.loads(json.dumps(upgraded)))
            rescanned = baseline.create('.', should_scan_all_files=True)
            rescanned.merge(audited)
            finding = baseline.format_for_output(rescanned)['results'][FIXTURE_FILENAME][0]

        assert finding['type'] == 'Square OAuth Secret'
        assert finding['hashed_secret'] == SQUARE_HASH
        assert finding['is_secret'] is True

    @staticmethod
    def test_repeated_upgrades_keep_identical_results(
        synthetic_project: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.chdir(synthetic_project)
        original = _old_baseline_with_audited_finding('0.14.3')

        serialized_results = []
        current = json.loads(json.dumps(original))
        for _ in range(3):
            upgraded = baseline.upgrade(current)
            config = {
                'plugins_used': upgraded['plugins_used'],
                'filters_used': [],
            }
            cache_bust()
            with transient_settings(config):
                audited = baseline.load(json.loads(json.dumps(upgraded)))
                rescanned = baseline.create('.', should_scan_all_files=True)
                rescanned.merge(audited)
                serialized_results.append(
                    baseline.format_for_output(rescanned)['results'],
                )
            current = upgraded

        assert serialized_results[0] == serialized_results[1] == serialized_results[2]
        assert serialized_results[0][FIXTURE_FILENAME][0]['is_secret'] is True

    @staticmethod
    def test_baselines_from_every_era_converge_on_same_fixture(
        synthetic_project: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.chdir(synthetic_project)
        era_results = {}
        for version in ['0.12.0', '0.13.0', '0.14.3']:
            upgraded = baseline.upgrade(_old_baseline_with_audited_finding(version))
            config = {
                'plugins_used': upgraded['plugins_used'],
                'filters_used': [],
            }
            cache_bust()
            with transient_settings(config):
                audited = baseline.load(json.loads(json.dumps(upgraded)))
                rescanned = baseline.create('.', should_scan_all_files=True)
                rescanned.merge(audited)
                era_results[version] = baseline.format_for_output(rescanned)['results']

        reference = era_results['0.14.3']
        assert era_results['0.12.0'] == reference
        assert era_results['0.13.0'] == reference


class TestManualReview:
    @staticmethod
    def test_ambiguous_configuration_is_quarantined() -> None:
        old_baseline = _baseline(
            '0.14.3',
            [{'name': 'BasicOAuthDetector', 'legacy_knob': 'no-longer-supported'}],
        )

        upgraded = baseline.upgrade(json.loads(json.dumps(old_baseline)))

        # The entry is not silently rewritten: the reviewer must reconcile the configuration.
        assert upgraded['plugins_used'] == old_baseline['plugins_used']
        review_entry = upgraded['plugin_upgrades']['needs_review'][0]
        assert review_entry['old_name'] == 'BasicOAuthDetector'
        assert review_entry['new_name'] == 'SquareOAuthDetector'
        assert review_entry['config'] == {'legacy_knob': 'no-longer-supported'}
        assert 'SquareOAuthDetector' in review_entry['reason']
        assert upgraded['plugin_upgrades']['renamed'] == []
        assert upgraded['plugin_upgrades']['unloadable'] == []

    @staticmethod
    def test_quarantined_entries_are_distinct_from_decidable_ones() -> None:
        old_baseline = _baseline(
            '0.14.3',
            [
                {'name': 'BasicOAuthDetector'},
                {'name': 'BasicOAuthDetector', 'legacy_knob': 1},
            ],
        )

        upgraded = baseline.upgrade(json.loads(json.dumps(old_baseline)))

        assert upgraded['plugins_used'] == [
            {'name': 'SquareOAuthDetector'},
            {'name': 'BasicOAuthDetector', 'legacy_knob': 1},
        ]
        report = upgraded['plugin_upgrades']
        assert len(report['renamed']) == 1
        assert len(report['needs_review']) == 1
        assert report['unloadable'] == []


class TestUnloadablePolicies:
    @staticmethod
    def test_missing_replacement_plugin_is_reported_and_preserved() -> None:
        old_baseline = _baseline('0.14.3', [{'name': 'BasicOAuthDetector'}])

        with mock.patch.object(
            initialize,
            'from_plugin_classname',
            side_effect=TypeError(),
        ):
            upgraded = baseline.upgrade(json.loads(json.dumps(old_baseline)))

        assert upgraded['plugins_used'] == [{'name': 'BasicOAuthDetector'}]
        unloadable_entry = upgraded['plugin_upgrades']['unloadable'][0]
        assert unloadable_entry['old_name'] == 'BasicOAuthDetector'
        assert unloadable_entry['new_name'] == 'SquareOAuthDetector'
        assert 'SquareOAuthDetector' in unloadable_entry['reason']
        assert upgraded['plugin_upgrades']['renamed'] == []
        assert upgraded['plugin_upgrades']['needs_review'] == []

    @staticmethod
    def test_unloadable_policy_raises_at_initialization() -> None:
        with mock.patch.object(
            initialize,
            'from_plugin_classname',
            side_effect=TypeError(),
        ):
            with pytest.raises(TypeError):
                initialize.from_plugin_classname('SquareOAuthDetector')

    @staticmethod
    def test_report_buckets_are_mutually_exclusive() -> None:
        old_baseline = _baseline(
            '0.14.3',
            [
                {'name': 'BasicOAuthDetector'},
                {'name': 'BasicOAuthDetector', 'legacy_knob': 1},
            ],
        )

        with mock.patch.object(
            initialize,
            'from_plugin_classname',
            side_effect=TypeError(),
        ):
            upgraded = baseline.upgrade(json.loads(json.dumps(old_baseline)))

        report = upgraded['plugin_upgrades']
        bucketed_names = [
            entry['old_name']
            for bucket in report.values()
            for entry in bucket
        ]
        # Both entries land in exactly one bucket, with no duplicates.
        assert sorted(bucketed_names) == ['BasicOAuthDetector', 'BasicOAuthDetector']
        assert len(report['unloadable']) == 2
        assert report['renamed'] == []
        assert report['needs_review'] == []
