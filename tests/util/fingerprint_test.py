import json

import pytest

from detect_secrets.core.potential_secret import PotentialSecret
from detect_secrets.util.fingerprint import Fingerprint
from detect_secrets.util.fingerprint import FingerprintConfig
from detect_secrets.util.fingerprint import FingerprintConfigError
from detect_secrets.util.fingerprint import _Key
from detect_secrets.util.fingerprint import annotate_baseline
from detect_secrets.util.fingerprint import verify_baseline


SECRET = 'AKIAIOSFODNN7EXAMPLE-same-test-value'
SHARED_KEY = 'shared-test-key'


def _key(version, value):
    return _Key(version=version, value=value)


def config(tmp_path, scopes=None, keys=None):
    scopes = scopes or ['company-a']
    keys = keys or [{'version': 1, 'value': SHARED_KEY}]
    path = tmp_path / 'config.json'
    path.write_text(json.dumps({'scopes': scopes, 'keys': keys}))
    return FingerprintConfig.from_file(str(path))


def sample_baseline(secret=SECRET):
    secret_hash = PotentialSecret.hash_secret(secret)
    return {
        'version': '1.5.0',
        'plugins_used': [],
        'filters_used': [],
        'results': {
            'config/app.py': [
                {
                    'type': 'AWS Access Key',
                    'filename': 'config/app.py',
                    'hashed_secret': secret_hash,
                    'line_number': 2,
                },
            ],
        },
    }


class TestFingerprintConfig:
    def test_deterministic_for_same_input(self, tmp_path):
        first = config(tmp_path).create_fingerprint(PotentialSecret.hash_secret(SECRET))
        second = config(tmp_path).create_fingerprint(PotentialSecret.hash_secret(SECRET))

        assert first == second
        assert first.key_version == 1
        assert first.scope == 'company-a'

    def test_different_key_means_different_fingerprint(self, tmp_path):
        shared = PotentialSecret.hash_secret(SECRET)
        a = config(tmp_path, keys=[{'version': 1, 'value': 'key-a'}]).create_fingerprint(shared)
        b = config(tmp_path, keys=[{'version': 1, 'value': 'key-b'}]).create_fingerprint(shared)

        assert a.fingerprint != b.fingerprint

    def test_different_scope_means_different_fingerprint(self, tmp_path):
        shared = PotentialSecret.hash_secret(SECRET)
        a = config(tmp_path, scopes=['company-a']).create_fingerprint(shared)
        b = config(tmp_path, scopes=['company-b']).create_fingerprint(shared)

        assert a.fingerprint != b.fingerprint

    def test_same_key_and_scope_match_across_companies(self, tmp_path):
        shared = PotentialSecret.hash_secret(SECRET)
        first = config(tmp_path, scopes=['approved-scope']).create_fingerprint(shared)

        second_config = FingerprintConfig(
            scopes=['approved-scope'],
            keys=[_key(1, SHARED_KEY)],
        )
        second = second_config.create_fingerprint(shared)

        assert first.fingerprint == second.fingerprint

    def test_scope_must_be_approved(self, tmp_path):
        with pytest.raises(FingerprintConfigError):
            config(tmp_path).create_fingerprint(
                PotentialSecret.hash_secret(SECRET),
                scope='unapproved-scope',
            )

    def test_explicit_scope_required_when_multiple(self, tmp_path):
        multi = config(tmp_path, scopes=['company-a', 'company-b'])
        with pytest.raises(FingerprintConfigError):
            multi.create_fingerprint(PotentialSecret.hash_secret(SECRET))

    def test_rejects_bad_config(self, tmp_path):
        path = tmp_path / 'bad.json'
        path.write_text(json.dumps({'scopes': [], 'keys': []}))
        with pytest.raises(FingerprintConfigError):
            FingerprintConfig.from_file(str(path))

    def test_rejects_duplicate_versions(self, tmp_path):
        with pytest.raises(FingerprintConfigError):
            config(
                tmp_path,
                keys=[
                    {'version': 1, 'value': 'a'},
                    {'version': 1, 'value': 'b'},
                ],
            )


class TestRotation:
    def test_active_key_is_highest_version(self, tmp_path):
        rotated = config(
            tmp_path,
            keys=[
                {'version': 1, 'value': 'old-key'},
                {'version': 2, 'value': 'new-key'},
            ],
        )
        fingerprint = rotated.create_fingerprint(PotentialSecret.hash_secret(SECRET))

        assert fingerprint.key_version == 2

    def test_old_fingerprint_still_verifies_after_rotation(self, tmp_path):
        old = config(tmp_path, keys=[{'version': 1, 'value': 'old-key'}])
        old_fingerprint = old.create_fingerprint(PotentialSecret.hash_secret(SECRET))

        rotated = config(
            tmp_path,
            keys=[
                {'version': 1, 'value': 'old-key'},
                {'version': 2, 'value': 'new-key'},
            ],
        )
        assert rotated.verify_fingerprint(
            PotentialSecret.hash_secret(SECRET),
            old_fingerprint,
        )

    def test_retired_key_fails_verification(self, tmp_path):
        old = config(tmp_path, keys=[{'version': 1, 'value': 'old-key'}])
        old_fingerprint = old.create_fingerprint(PotentialSecret.hash_secret(SECRET))

        rotated = config(tmp_path, keys=[{'version': 2, 'value': 'new-key'}])
        assert not rotated.verify_fingerprint(
            PotentialSecret.hash_secret(SECRET),
            old_fingerprint,
        )

    def test_tampered_fingerprint_fails(self, tmp_path):
        cfg = config(tmp_path)
        fingerprint = cfg.create_fingerprint(PotentialSecret.hash_secret(SECRET))
        tampered = Fingerprint(
            fingerprint='0' * len(fingerprint.fingerprint),
            key_version=fingerprint.key_version,
            scope=fingerprint.scope,
        )

        assert not cfg.verify_fingerprint(PotentialSecret.hash_secret(SECRET), tampered)


class TestBaselineAnnotation:
    def test_local_hash_is_preserved(self, tmp_path):
        baseline = sample_baseline()
        annotated = annotate_baseline(baseline, config(tmp_path))
        entry = annotated['results']['config/app.py'][0]

        assert entry['hashed_secret'] == baseline['results']['config/app.py'][0]['hashed_secret']
        assert entry['outbound_fingerprint'] != entry['hashed_secret']
        assert entry['fingerprint_key_version'] == '1'
        assert entry['fingerprint_scope'] == 'company-a'

    def test_input_baseline_is_not_mutated(self, tmp_path):
        baseline = sample_baseline()
        annotate_baseline(baseline, config(tmp_path))

        assert 'outbound_fingerprint' not in baseline['results']['config/app.py'][0]

    def test_verify_roundtrip(self, tmp_path):
        cfg = config(tmp_path)
        annotated = annotate_baseline(sample_baseline(), cfg)

        matched, total, failures = verify_baseline(annotated, cfg)
        assert (matched, total, failures) == (1, 1, [])

    def test_verify_reports_mismatch_across_tenants(self, tmp_path):
        annotated = annotate_baseline(
            sample_baseline(),
            config(tmp_path, scopes=['company-a']),
        )
        other = config(tmp_path, scopes=['company-b'])

        matched, total, failures = verify_baseline(annotated, other)
        assert matched == 0
        assert total == 1
        assert failures[0]['scope'] == 'company-a'

    def test_annotation_is_stable_across_scans(self, tmp_path):
        cfg = config(tmp_path)
        first = annotate_baseline(sample_baseline(), cfg)
        second = annotate_baseline(sample_baseline(), cfg)

        assert first == second
