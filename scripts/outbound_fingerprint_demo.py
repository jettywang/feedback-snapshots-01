"""
End-to-end demonstration of outbound fingerprints.

Scenario: two companies ("alpha" and "beta") each scan a working directory that
contains the *same* test secret. They keep their local baselines stable across
two scans (so local audit still recognizes old findings), while the outbound
fingerprints sent to the shared aggregation system only collide inside the scope
that both companies have explicitly approved. A key rotation is then rolled
forward, showing that fingerprints minted with the old key still verify.

Run from the repository root:

    .venv/bin/python scripts/outbound_fingerprint_demo.py
"""
import json
import tempfile
from pathlib import Path
from typing import Any
from typing import Dict
from typing import List
from typing import Set
from typing import Tuple

from detect_secrets.core import baseline
from detect_secrets.settings import default_settings
from detect_secrets.util.fingerprint import FingerprintConfig
from detect_secrets.util.fingerprint import annotate_baseline
from detect_secrets.util.fingerprint import verify_baseline

# The same test value is planted in both working directories on purpose.
SHARED_TEST_SECRET = 'AKIAIOSFODNN7EXAMPLE-detect-secrets-fingerprint-demo'
SHARED_KEY = 'aggregation-preshared-test-key'
ROTATED_KEY = 'aggregation-rotated-test-key'


def _write_secret_file(workdir: Path) -> None:
    (workdir / 'app').mkdir()
    (workdir / 'app' / 'settings.py').write_text(
        f'AWS_ACCESS_KEY = "{SHARED_TEST_SECRET}"\n',
    )


def _scan(workdir: Path) -> Dict[str, Any]:
    with default_settings():
        collection = baseline.create(
            str(workdir),
            should_scan_all_files=True,
            root=str(workdir),
        )
        return baseline.format_for_output(collection)


def _write_config(workdir: Path, scopes: List[str], keys: List[Dict[str, Any]]) -> Path:
    path = workdir / 'fingerprint-config.json'
    path.write_text(json.dumps({'scopes': scopes, 'keys': keys}, indent=2))
    return path


def _entries(annotated: Dict[str, Any]) -> List[Dict[str, str]]:
    return [
        entry
        for secrets in annotated['results'].values()
        for entry in secrets
    ]


def _local_hashes(scanned: Dict[str, Any]) -> Set[str]:
    return {entry['hashed_secret'] for entry in _entries(scanned)}


def _outbound_fingerprints(annotated: Dict[str, Any]) -> Set[str]:
    return {entry['outbound_fingerprint'] for entry in _entries(annotated)}


def main() -> int:
    temp_root = Path(tempfile.mkdtemp(prefix='fingerprint-demo-'))
    alpha = temp_root / 'company-alpha'
    beta = temp_root / 'company-beta'
    for workdir in (alpha, beta):
        workdir.mkdir()
        _write_secret_file(workdir)

    alpha_config_path = _write_config(
        alpha,
        scopes=['joint-program', 'company-alpha-internal'],
        keys=[{'version': 1, 'value': SHARED_KEY}],
    )
    beta_config_path = _write_config(
        beta,
        scopes=['joint-program', 'company-beta-internal'],
        keys=[{'version': 1, 'value': SHARED_KEY}],
    )
    alpha_config = FingerprintConfig.from_file(str(alpha_config_path))
    beta_config = FingerprintConfig.from_file(str(beta_config_path))

    # Each company scans twice: the local hashes must stay identical.
    alpha_scan_1 = _scan(alpha)
    alpha_scan_2 = _scan(alpha)
    beta_scan_1 = _scan(beta)
    assert _local_hashes(alpha_scan_1) == _local_hashes(alpha_scan_2)
    assert _local_hashes(alpha_scan_1) == _local_hashes(beta_scan_1)
    finding_count = len(_local_hashes(alpha_scan_1))

    # Approved shared scope: outbound fingerprints must match across companies.
    alpha_joint = annotate_baseline(alpha_scan_1, alpha_config, scope='joint-program')
    beta_joint = annotate_baseline(beta_scan_1, beta_config, scope='joint-program')
    assert _outbound_fingerprints(alpha_joint) == _outbound_fingerprints(beta_joint)

    # Second scan at alpha: same local hashes and same outbound fingerprints.
    alpha_joint_scan_2 = annotate_baseline(
        alpha_scan_2,
        alpha_config,
        scope='joint-program',
    )
    assert _outbound_fingerprints(alpha_joint_scan_2) == _outbound_fingerprints(alpha_joint)

    # Internal scopes are not shared: outbound fingerprints must differ,
    # even though the underlying secrets are identical.
    alpha_internal = annotate_baseline(
        alpha_scan_1,
        alpha_config,
        scope='company-alpha-internal',
    )
    beta_internal = annotate_baseline(
        beta_scan_1,
        beta_config,
        scope='company-beta-internal',
    )
    assert _outbound_fingerprints(alpha_internal).isdisjoint(
        _outbound_fingerprints(beta_internal),
    )
    assert _outbound_fingerprints(alpha_internal).isdisjoint(
        _outbound_fingerprints(alpha_joint),
    )

    # Rotation: config now carries v1 (retiring soon) and v2 (active).
    rotated_config_path = _write_config(
        alpha,
        scopes=['joint-program', 'company-alpha-internal'],
        keys=[
            {'version': 1, 'value': SHARED_KEY},
            {'version': 2, 'value': ROTATED_KEY},
        ],
    )
    rotated = FingerprintConfig.from_file(str(rotated_config_path))

    # Fingerprints minted with v1 still verify while v1 remains configured.
    matched_old, total_old, failures_old = verify_baseline(alpha_joint, rotated)
    assert (matched_old, total_old, failures_old) == (finding_count, finding_count, [])

    # New fingerprints are minted with v2.
    alpha_rotated = annotate_baseline(alpha_scan_2, rotated, scope='joint-program')
    assert {
        entry['fingerprint_key_version'] for entry in _entries(alpha_rotated)
    } == {'2'}
    assert _outbound_fingerprints(alpha_rotated).isdisjoint(
        _outbound_fingerprints(alpha_joint),
    )
    matched_new, total_new, _ = verify_baseline(alpha_rotated, rotated)
    assert (matched_new, total_new) == (finding_count, finding_count)

    # Once v1 is retired, old fingerprints stop verifying.
    retired_config_path = _write_config(
        alpha,
        scopes=['joint-program', 'company-alpha-internal'],
        keys=[{'version': 2, 'value': ROTATED_KEY}],
    )
    retired = FingerprintConfig.from_file(str(retired_config_path))
    matched_retired, total_retired, _ = verify_baseline(alpha_joint, retired)
    assert (matched_retired, total_retired) == (0, finding_count)

    rows = _build_table_rows(
        alpha_joint=alpha_joint,
        alpha_joint_scan_2=alpha_joint_scan_2,
        beta_joint=beta_joint,
        alpha_internal=alpha_internal,
        beta_internal=beta_internal,
        alpha_rotated=alpha_rotated,
    )
    _print_table(rows)
    _print_rotation_checks(
        finding_count=finding_count,
        local_hashes=(
            _local_hashes(alpha_scan_1),
            _local_hashes(alpha_scan_2),
            _local_hashes(beta_scan_1),
        ),
        old_verified=(matched_old, total_old),
        new_verified=(matched_new, total_new),
        retired_verified=(matched_retired, total_retired),
        temp_root=temp_root,
    )
    return 0


def _build_table_rows(
    alpha_joint: Dict[str, Any],
    alpha_joint_scan_2: Dict[str, Any],
    beta_joint: Dict[str, Any],
    alpha_internal: Dict[str, Any],
    beta_internal: Dict[str, Any],
    alpha_rotated: Dict[str, Any],
) -> List[Dict[str, str]]:
    labels = [
        ('alpha joint-program scan 1', alpha_joint),
        ('alpha joint-program scan 2', alpha_joint_scan_2),
        ('beta  joint-program scan 1', beta_joint),
        ('alpha internal scope', alpha_internal),
        ('beta  internal scope', beta_internal),
        ('alpha joint-program rotated v2', alpha_rotated),
    ]
    rows: List[Dict[str, str]] = []
    for label, annotated in labels:
        for entry in _entries(annotated):
            rows.append(
                {
                    'case': label,
                    'secret_type': entry['type'],
                    'hashed_secret': entry['hashed_secret'][:12] + '...',
                    'scope': entry['fingerprint_scope'],
                    'key_version': entry['fingerprint_key_version'],
                    'outbound_fingerprint': entry['outbound_fingerprint'][:12] + '...',
                },
            )
    return rows


def _print_table(rows: List[Dict[str, str]]) -> None:
    headers = [
        'case',
        'secret_type',
        'hashed_secret',
        'scope',
        'key_version',
        'outbound_fingerprint',
    ]
    widths = {
        header: max(len(header), *(len(row[header]) for row in rows))
        for header in headers
    }
    line = '  '.join(header.ljust(widths[header]) for header in headers)
    print('\nOutbound fingerprint matching table')
    print('=' * len(line))
    print(line)
    print('-' * len(line))
    for row in rows:
        print('  '.join(row[header].ljust(widths[header]) for header in headers))


def _print_rotation_checks(
    finding_count: int,
    local_hashes: Tuple[Set[str], Set[str], Set[str]],
    old_verified: Tuple[int, int],
    new_verified: Tuple[int, int],
    retired_verified: Tuple[int, int],
    temp_root: Path,
) -> None:
    alpha_1, alpha_2, beta_1 = local_hashes
    print('\nCheckable results')
    print('-' * 48)
    print(f'findings per scan                        : {finding_count}')
    print(f'local hashes alpha scan1 == alpha scan2 : {alpha_1 == alpha_2}')
    print(f'local hashes alpha == beta              : {alpha_1 == beta_1}')
    print(f'v1 fingerprints verify during rotation  : {old_verified[0]}/{old_verified[1]}')
    print(f'v2 fingerprints verify after rotation   : {new_verified[0]}/{new_verified[1]}')
    print(f'v1 fingerprints after v1 key retired    : {retired_verified[0]}/{retired_verified[1]}')
    print(f'\nArtifacts written under: {temp_root}')


if __name__ == '__main__':
    raise SystemExit(main())
