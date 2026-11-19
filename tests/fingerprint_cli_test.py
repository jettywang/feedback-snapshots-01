import json

from detect_secrets import main as main_module
from detect_secrets.core.potential_secret import PotentialSecret
from testing.mocks import mock_printer


SECRET = 'AKIAIOSFODNN7EXAMPLE-same-test-value'


def _write_baseline(path):
    baseline = {
        'version': '1.5.0',
        'plugins_used': [],
        'filters_used': [],
        'results': {
            'app.py': [
                {
                    'type': 'AWS Access Key',
                    'filename': 'app.py',
                    'hashed_secret': PotentialSecret.hash_secret(SECRET),
                    'line_number': 1,
                },
            ],
        },
    }
    path.write_text(json.dumps(baseline))


def _write_config(path, scopes, keys):
    path.write_text(json.dumps({'scopes': scopes, 'keys': keys}))


class TestFingerprintCommand:
    def test_annotate_then_verify(self, tmp_path):
        baseline_path = tmp_path / 'baseline.json'
        config_path = tmp_path / 'config.json'
        _write_baseline(baseline_path)
        _write_config(config_path, ['company-a'], [{'version': 1, 'value': 'k1'}])

        with mock_printer(main_module) as printer:
            exit_code = main_module.main(
                [
                    'fingerprint',
                    str(baseline_path),
                    '--config',
                    str(config_path),
                ],
            )

        assert exit_code == 0
        annotated = json.loads(printer.message)
        entry = annotated['results']['app.py'][0]
        assert entry['hashed_secret'] == PotentialSecret.hash_secret(SECRET)
        assert len(entry['outbound_fingerprint']) == 64
        assert entry['fingerprint_scope'] == 'company-a'

        output_path = tmp_path / 'out.json'
        output_path.write_text(printer.message)

        with mock_printer(main_module) as verify_printer:
            exit_code = main_module.main(
                [
                    'fingerprint',
                    str(output_path),
                    '--config',
                    str(config_path),
                    '--verify',
                ],
            )

        assert exit_code == 0
        assert 'verified 1/1' in verify_printer.message

    def test_verify_fails_with_other_tenant_config(self, tmp_path):
        baseline_path = tmp_path / 'baseline.json'
        config_a = tmp_path / 'a.json'
        config_b = tmp_path / 'b.json'
        _write_baseline(baseline_path)
        _write_config(config_a, ['company-a'], [{'version': 1, 'value': 'k1'}])
        _write_config(config_b, ['company-b'], [{'version': 1, 'value': 'k1'}])

        with mock_printer(main_module) as printer:
            assert main_module.main(
                ['fingerprint', str(baseline_path), '--config', str(config_a)],
            ) == 0
        annotated_path = tmp_path / 'annotated.json'
        annotated_path.write_text(printer.message)

        assert main_module.main(
            [
                'fingerprint',
                str(annotated_path),
                '--config',
                str(config_b),
                '--verify',
            ],
        ) == 1

    def test_output_flag_writes_file(self, tmp_path):
        baseline_path = tmp_path / 'baseline.json'
        config_path = tmp_path / 'config.json'
        output_path = tmp_path / 'out.json'
        _write_baseline(baseline_path)
        _write_config(config_path, ['company-a'], [{'version': 1, 'value': 'k1'}])

        exit_code = main_module.main(
            [
                'fingerprint',
                str(baseline_path),
                '--config',
                str(config_path),
                '--output',
                str(output_path),
            ],
        )

        assert exit_code == 0
        assert json.loads(output_path.read_text())['results']['app.py'][0][
            'outbound_fingerprint'
        ]

    def test_missing_config_returns_error(self, tmp_path):
        baseline_path = tmp_path / 'baseline.json'
        _write_baseline(baseline_path)

        exit_code = main_module.main(
            [
                'fingerprint',
                str(baseline_path),
                '--config',
                str(tmp_path / 'missing.json'),
            ],
        )

        assert exit_code == 1

    def test_rotation_keeps_verifying_old_fingerprint(self, tmp_path):
        baseline_path = tmp_path / 'baseline.json'
        v1_config = tmp_path / 'v1.json'
        rotated_config = tmp_path / 'rotated.json'
        _write_baseline(baseline_path)
        _write_config(v1_config, ['company-a'], [{'version': 1, 'value': 'old'}])
        _write_config(
            rotated_config,
            ['company-a'],
            [
                {'version': 1, 'value': 'old'},
                {'version': 2, 'value': 'new'},
            ],
        )

        with mock_printer(main_module) as printer:
            assert main_module.main(
                ['fingerprint', str(baseline_path), '--config', str(v1_config)],
            ) == 0
        old_output = tmp_path / 'old.json'
        old_output.write_text(printer.message)

        assert main_module.main(
            ['fingerprint', str(old_output), '--config', str(rotated_config), '--verify'],
        ) == 0

        with mock_printer(main_module) as printer:
            assert main_module.main(
                ['fingerprint', str(baseline_path), '--config', str(rotated_config)],
            ) == 0
        assert json.loads(printer.message)['results']['app.py'][0][
            'fingerprint_key_version'
        ] == '2'
