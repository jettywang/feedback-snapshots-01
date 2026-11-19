"""
Export, review, and import redacted audit packages.

A review package deliberately contains only the information needed to make an
audit decision: the finding category, its evidence location, and an opaque
finding identifier. It never contains the secret value, its hash, the source
line, or any surrounding context. This makes it safe to hand to a reviewer who
does not have access to the original repository.

The package can be reviewed offline (in an empty directory), and the resulting
decisions can be imported back into the original baseline.

A private ledger is maintained next to the baseline. It holds the key used to
derive finding IDs, and the record of imported packages. Finding IDs bind the
category, path, line, per-line occurrence, and the secret hash; this is what
allows duplicate imports and stale findings to be detected without ever
writing a hash (or the secret) into the package.
"""
import hashlib
import hmac
import json
import os
import tempfile
import time
from collections import defaultdict
from secrets import token_hex
from typing import Any
from typing import Callable
from typing import Dict
from typing import List
from typing import Optional
from typing import Set
from typing import Tuple

from . import io
from ..core import baseline
from ..core.potential_secret import PotentialSecret
from ..core.secrets_collection import SecretsCollection
from .common import get_baseline_from_file


PACKAGE_FORMAT = 'detect-secrets/review-package'
LEDGER_FORMAT = 'detect-secrets/review-ledger'
SCHEMA_VERSION = 1

_PACKAGE_KEYS = {
    'format',
    'schema_version',
    'package_id',
    'created_at',
    'source',
    'findings',
    'integrity',
}
_SOURCE_KEYS = {'kind', 'finding_count', 'fingerprint', 'baseline_anchor'}
_FINDING_KEYS = {'finding_id', 'category', 'evidence', 'decision'}
_EVIDENCE_KEYS = {'path', 'line', 'occurrence', 'occurrences_on_line'}
_INTEGRITY_KEYS = {'algorithm', 'checksum', 'digest'}

# Decisions intentionally exclude the original repository question ("should this
# be committed?"), which is easy to misread during an offline review.
_REAL_SECRET = True
_FALSE_POSITIVE = False
_UNREVIEWED = None


class ReviewPackageError(Exception):
    """Base error for invalid or unusable review packages."""
    exit_code = 2


class WrongReviewPackageError(ReviewPackageError):
    """The package is valid, but does not belong to the supplied baseline."""
    exit_code = 3


class DuplicateReviewPackageError(ReviewPackageError):
    """The package, or its decisions, were already imported."""
    exit_code = 4


class StaleReviewPackageError(ReviewPackageError):
    """One or more findings in the package no longer exist in the baseline."""
    exit_code = 5


def export_review_package(
    baseline_filename: str,
    package_filename: str,
) -> Dict[str, Any]:
    """
    Export a redacted review package from a baseline.

    :raises: ReviewPackageError
    :raises: InvalidBaselineError
    """
    secrets = get_baseline_from_file(baseline_filename)

    ledger_filename = _ledger_filename(baseline_filename)
    ledger = _load_ledger(ledger_filename)
    if not ledger['record_id']:
        ledger['record_id'] = f'rec_{token_hex(12)}'
        ledger['finding_key'] = token_hex(32)
        ledger['created_at'] = _utc_now()
        _write_json(ledger_filename, ledger)

    findings = _describe_findings(secrets, ledger['finding_key'])
    if not findings:
        raise ReviewPackageError('There are no findings to export.')

    package: Dict[str, Any] = {
        'format': PACKAGE_FORMAT,
        'schema_version': SCHEMA_VERSION,
        'package_id': f'pkg_{token_hex(12)}',
        'created_at': _utc_now(),
        'source': {
            'kind': 'baseline',
            'finding_count': len(findings),
            'fingerprint': _fingerprint(finding['finding_id'] for finding in findings),
            'baseline_anchor': ledger['record_id'],
        },
        'findings': findings,
    }
    package['integrity'] = _integrity_for(package, ledger['finding_key'])

    _write_json(package_filename, package)
    return package


def review_package(
    package_filename: str,
    output_filename: Optional[str] = None,
    input_fn: Optional[Callable[[str], str]] = None,
) -> str:
    """
    Interactively review a package, without access to the original source files.

    Decisions are written after every answer, so quitting does not discard work.
    Returns the path to the reviewed package.

    :raises: ReviewPackageError
    """
    package = load_review_package(package_filename)
    findings: List[Dict[str, Any]] = package['findings']

    if output_filename is None:
        _, filename = os.path.split(package_filename)
        stem, extension = os.path.splitext(filename)
        output_filename = os.path.abspath(
            os.path.join(
                os.getcwd(),
                f'{stem}.reviewed{extension or ".json"}',
            ),
        )

    io.print_message('Redacted audit review')
    io.print_message('Findings:   {}'.format(len(findings)))
    io.print_message('Package:    {}'.format(package['package_id']))
    io.print_message('No source files or line contents are included.')
    io.print_message('-' * 10)

    get_input = input_fn or io.get_user_input
    index = next(
        (position for position, finding in enumerate(findings) if finding['decision'] is None),
        len(findings),
    )
    if index == len(findings):
        io.print_message('Nothing to review!')
    else:
        while 0 <= index < len(findings):
            finding = findings[index]
            _print_finding(finding, index + 1, len(findings))
            answer = _read_review_answer(get_input)

            if answer is None:      # quit
                break
            elif answer == 'back':
                index = max(0, index - 1)
                continue

            finding['decision'] = answer
            _write_json(output_filename, package)
            index += 1

    _write_json(output_filename, package)
    io.print_message('Saved reviewed package: {}'.format(output_filename))
    return output_filename


def import_review_package(
    package_filename: str,
    baseline_filename: str,
    ledger_filename: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Import review decisions into the original baseline.

    The import is atomic: if any referenced finding no longer exists, no
    decisions are written.

    :raises: ReviewPackageError
    :raises: InvalidBaselineError
    """
    package = load_review_package(package_filename)

    decisions = [
        (finding, _normalize_decision(finding['decision']))
        for finding in package['findings']
    ]
    decisions = [
        (finding, decision)
        for finding, decision in decisions
        if decision is not None
    ]
    if not decisions:
        raise ReviewPackageError('The review package does not contain any audit decisions.')

    ledger_filename = ledger_filename or _ledger_filename(baseline_filename)
    ledger = _load_ledger(ledger_filename)
    if package['source'].get('baseline_anchor') != ledger['record_id']:
        raise WrongReviewPackageError(
            'This review package was exported from a different baseline record. '
            'Import it into the baseline it was exported from.',
        )

    if not hmac.compare_digest(
        str(package['integrity']['digest']),
        _signature_for(package, ledger['finding_key']),
    ):
        raise ReviewPackageError(
            'Review package signature check failed. The package was not produced by this '
            'baseline record, or its findings were modified outside of the review workflow.',
        )

    if package['package_id'] in {
        item['package_id'] for item in ledger['imported_packages']
    }:
        raise DuplicateReviewPackageError(
            'This review package has already been imported (package {}).'.format(
                package['package_id'],
            ),
        )

    secrets = get_baseline_from_file(baseline_filename)
    current = _index_findings(secrets, ledger['finding_key'])

    missing = [
        finding for finding, _ in decisions
        if finding['finding_id'] not in current
    ]
    if missing:
        raise StaleReviewPackageError(
            '{} finding(s) in this review package no longer exist in the baseline:\n{}'.format(
                len(missing),
                '\n'.join('  - {}'.format(_format_finding(finding)) for finding in missing),
            ),
        )

    expected = {
        finding['finding_id']: decision
        for finding, decision in decisions
    }
    if all(
        current[finding_id].is_secret is decision
        for finding_id, decision in expected.items()
    ):
        raise DuplicateReviewPackageError(
            'All decisions in this review package are already recorded in the baseline.',
        )

    for finding, decision in decisions:
        current[finding['finding_id']].is_secret = decision

    baseline.save_to_file(secrets, baseline_filename)

    ledger['imported_packages'].append({
        'package_id': package['package_id'],
        'imported_at': _utc_now(),
        'decisions': len(decisions),
    })
    ledger['updated_at'] = _utc_now()
    _write_json(ledger_filename or _ledger_filename(baseline_filename), ledger)

    real = sum(1 for _, decision in decisions if decision is True)
    false = sum(1 for _, decision in decisions if decision is False)
    io.print_message(
        'Imported {} decision(s) from package {} ({} real, {} false positive).'.format(
            len(decisions),
            package['package_id'],
            real,
            false,
        ),
    )
    io.print_message('Baseline updated: {}'.format(baseline_filename))
    return {
        'package_id': package['package_id'],
        'applied': len(decisions),
        'real': real,
        'false_positive': false,
    }


def load_review_package(filename: str) -> Dict[str, Any]:
    """
    Load and validate a review package.

    Validation is intentionally strict. Unknown fields are rejected so that
    source context cannot be quietly smuggled into a package.

    :raises: ReviewPackageError
    """
    try:
        with open(filename) as f:
            package = json.loads(f.read())
    except (IOError, json.decoder.JSONDecodeError) as e:
        raise ReviewPackageError(f'Unable to read review package: {filename}') from e

    if not isinstance(package, dict):
        raise ReviewPackageError('Review package must be a JSON object.')

    _validate_keys(package, _PACKAGE_KEYS, 'package')
    if package.get('format') != PACKAGE_FORMAT:
        raise ReviewPackageError('This is not a detect-secrets review package.')
    if package.get('schema_version') != SCHEMA_VERSION:
        raise ReviewPackageError(
            'Unsupported review package schema version: {!r}.'.format(
                package.get('schema_version'),
            ),
        )

    for key in ('package_id', 'created_at'):
        if not isinstance(package.get(key), str) or not package[key]:
            raise ReviewPackageError(f'Review package is missing a valid {key!r}.')

    source = package.get('source')
    if not isinstance(source, dict):
        raise ReviewPackageError('Review package is missing a valid source.')
    _validate_keys(source, _SOURCE_KEYS, 'source')
    if source.get('kind') != 'baseline':
        raise ReviewPackageError('Unsupported review package source.')

    findings = package.get('findings')
    if not isinstance(findings, list) or not findings:
        raise ReviewPackageError('Review package does not contain any findings.')

    seen_ids: Set[str] = set()
    for position, finding in enumerate(findings, start=1):
        _validate_finding(finding, position)
        if finding['finding_id'] in seen_ids:
            raise ReviewPackageError(
                'Review package contains a duplicate finding id: {}'.format(
                    finding['finding_id'],
                ),
            )
        seen_ids.add(finding['finding_id'])

    if source.get('finding_count') != len(findings):
        raise ReviewPackageError('Review package finding count does not match its contents.')
    if source.get('fingerprint') != _fingerprint(seen_ids):
        raise ReviewPackageError('Review package finding fingerprint does not match its contents.')
    if not isinstance(source.get('baseline_anchor'), str) or not source['baseline_anchor']:
        raise ReviewPackageError('Review package is missing a baseline anchor.')

    integrity = package.get('integrity')
    if not isinstance(integrity, dict):
        raise ReviewPackageError('Review package is missing an integrity block.')
    _validate_keys(integrity, _INTEGRITY_KEYS, 'integrity')
    if integrity.get('algorithm') != 'hmac-sha256':
        raise ReviewPackageError('Unsupported review package integrity algorithm.')

    # Offline reviewers do not have the signing key, so only the checksum can be
    # verified here. The signature is verified at import time.
    if not hmac.compare_digest(str(integrity.get('checksum')), _checksum_for(package)):
        raise ReviewPackageError(
            'Review package integrity check failed. The package is corrupted.',
        )

    return package


def _describe_findings(
    secrets: SecretsCollection,
    finding_key: str,
) -> List[Dict[str, Any]]:
    by_location: Dict[Tuple[str, int], List[PotentialSecret]] = defaultdict(list)
    for filename, secret in secrets:
        if not secret.line_number:
            raise ReviewPackageError(
                'Cannot export a review package without line numbers. Recreate the baseline.',
            )

        by_location[(filename, secret.line_number)].append(secret)

    findings: List[Dict[str, Any]] = []
    for (filename, line_number), grouped in sorted(by_location.items()):
        # The sort must be deterministic across export and import. Secret hashes are
        # never written to the package; they are only used to order same-line findings.
        grouped.sort(key=lambda secret: (secret.type, secret.secret_hash))
        total = len(grouped)
        for occurrence, secret in enumerate(grouped, start=1):
            # This mirrors the interactive audit flow: already labelled findings are
            # not re-presented. Occurrence numbers still count every finding on the
            # line, so identities remain stable across exports.
            if secret.is_secret is not None:
                continue

            findings.append({
                'finding_id': _finding_id(
                    key=finding_key,
                    filename=filename,
                    category=secret.type,
                    line_number=line_number,
                    occurrence=occurrence,
                    secret_hash=secret.secret_hash,
                ),
                'category': secret.type,
                'evidence': {
                    'path': filename,
                    'line': line_number,
                    'occurrence': occurrence,
                    'occurrences_on_line': total,
                },
                'decision': _UNREVIEWED,
            })

    return findings


def _index_findings(
    secrets: SecretsCollection,
    finding_key: str,
) -> Dict[str, PotentialSecret]:
    output: Dict[str, PotentialSecret] = {}
    by_location: Dict[Tuple[str, int], List[PotentialSecret]] = defaultdict(list)
    for filename, secret in secrets:
        if not secret.line_number:
            continue
        by_location[(filename, secret.line_number)].append(secret)

    for (filename, line_number), grouped in sorted(by_location.items()):
        grouped.sort(key=lambda secret: (secret.type, secret.secret_hash))
        total = len(grouped)
        for occurrence, secret in enumerate(grouped, start=1):
            finding_id = _finding_id(
                key=finding_key,
                filename=filename,
                category=secret.type,
                line_number=line_number,
                occurrence=occurrence,
                secret_hash=secret.secret_hash,
            )
            output[finding_id] = secret

    return output


def _finding_id(
    key: str,
    filename: str,
    category: str,
    line_number: int,
    occurrence: int,
    secret_hash: str,
) -> str:
    """
    Derive an opaque, stable identifier.

    The keyed digest avoids embedding a raw secret hash in the package. The
    identity still changes if the finding moves or disappears, which is what
    makes stale packages detectable.
    """
    payload = '\x00'.join([
        filename,
        category,
        str(line_number),
        str(occurrence),
        secret_hash,
    ]).encode('utf-8')
    return 'f_' + hmac.new(key.encode('utf-8'), payload, hashlib.sha256).hexdigest()[:20]


def _fingerprint(finding_ids: Any) -> str:
    digest = hashlib.sha256()
    digest.update(b'detect-secrets-review-findings-v1\x00')
    for finding_id in sorted(finding_ids):
        digest.update(str(finding_id).encode('utf-8'))
        digest.update(b'\x00')
    return digest.hexdigest()


def _integrity_payload(package: Dict[str, Any]) -> bytes:
    # Decisions are intentionally excluded: the reviewer is expected to change
    # them. The redacted finding metadata, however, must not change.
    findings = [
        {key: value for key, value in finding.items() if key != 'decision'}
        for finding in package['findings']
    ]
    payload = {
        key: value
        for key, value in package.items()
        if key != 'integrity'
    }
    payload['findings'] = findings

    return json.dumps(
        payload,
        sort_keys=True,
        separators=(',', ':'),
        ensure_ascii=False,
    ).encode('utf-8')


def _checksum_for(package: Dict[str, Any]) -> str:
    return hashlib.sha256(_integrity_payload(package)).hexdigest()


def _signature_for(package: Dict[str, Any], key: str) -> str:
    return hmac.new(
        key.encode('utf-8'),
        _integrity_payload(package),
        hashlib.sha256,
    ).hexdigest()


def _integrity_for(package: Dict[str, Any], key: str) -> Dict[str, str]:
    return {
        'algorithm': 'hmac-sha256',
        'checksum': _checksum_for(package),
        'digest': _signature_for(package, key),
    }


def _validate_keys(value: Dict[str, Any], allowed: Set[str], kind: str) -> None:
    unknown = sorted(set(value) - allowed)
    if unknown:
        raise ReviewPackageError(
            'Review package {} contains unexpected field(s): {}.'.format(
                kind,
                ', '.join(unknown),
            ),
        )


def _validate_finding(finding: Any, position: int) -> None:
    if not isinstance(finding, dict):
        raise ReviewPackageError(f'Finding {position} is not an object.')
    _validate_keys(finding, _FINDING_KEYS, f'finding {position}')

    if not isinstance(finding.get('finding_id'), str) or not finding['finding_id']:
        raise ReviewPackageError(f'Finding {position} is missing a finding id.')
    if not isinstance(finding.get('category'), str) or not finding['category']:
        raise ReviewPackageError(f'Finding {position} is missing a category.')

    evidence = finding.get('evidence')
    if not isinstance(evidence, dict):
        raise ReviewPackageError(f'Finding {position} is missing evidence.')
    _validate_keys(evidence, _EVIDENCE_KEYS, f'finding {position} evidence')

    if not isinstance(evidence.get('path'), str) or not evidence['path']:
        raise ReviewPackageError(f'Finding {position} is missing an evidence path.')
    for key in ('line', 'occurrence', 'occurrences_on_line'):
        if not isinstance(evidence.get(key), int) or isinstance(evidence.get(key), bool):
            raise ReviewPackageError(f'Finding {position} has an invalid evidence {key}.')
    if evidence['line'] < 1 or evidence['occurrence'] < 1:
        raise ReviewPackageError(f'Finding {position} has an invalid evidence location.')
    if evidence['occurrences_on_line'] < evidence['occurrence']:
        raise ReviewPackageError(f'Finding {position} has an inconsistent evidence location.')

    _normalize_decision(finding.get('decision'))


def _normalize_decision(value: Any) -> Any:
    if value is None:
        return _UNREVIEWED
    if isinstance(value, bool):
        return _REAL_SECRET if value else _FALSE_POSITIVE
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in ('skip', 'skipped', 'unreviewed'):
            return _UNREVIEWED
        if lowered in ('true', 'yes', 'real', 'real_secret'):
            return _REAL_SECRET
        if lowered in ('false', 'no', 'false_positive'):
            return _FALSE_POSITIVE

    raise ReviewPackageError(
        'Invalid review decision {!r}. Expected true, false, or null.'.format(value),
    )


def _read_review_answer(get_input: Callable[[str], str]) -> Any:
    prompt = 'Is this a real secret? (y)es, (n)o, (s)kip, (b)ack, (q)uit: '
    while True:
        answer = get_input(prompt)
        if not answer:
            continue

        first = answer[0].upper()
        if first == 'Y':
            return _REAL_SECRET
        elif first == 'N':
            return _FALSE_POSITIVE
        elif first == 'S':
            return _UNREVIEWED
        elif first == 'B':
            return 'back'
        elif first == 'Q':
            return None

        io.print_message('Invalid input.')


def _print_finding(finding: Dict[str, Any], current: int, total: int) -> None:
    evidence = finding['evidence']
    io.print_message('Finding:      {} of {}'.format(current, total))
    io.print_message('Category:     {}'.format(finding['category']))
    io.print_message(
        'Evidence:     {}:{} (occurrence {} of {} on this line)'.format(
            evidence['path'],
            evidence['line'],
            evidence['occurrence'],
            evidence['occurrences_on_line'],
        ),
    )
    io.print_message('-' * 10)


def _format_finding(finding: Dict[str, Any]) -> str:
    evidence = finding['evidence']
    return '{} at {}:{} (occurrence {} of {})'.format(
        finding['category'],
        evidence['path'],
        evidence['line'],
        evidence['occurrence'],
        evidence['occurrences_on_line'],
    )


def _ledger_filename(baseline_filename: str) -> str:
    return baseline_filename + '.review-ledger.json'


def _load_ledger(filename: str) -> Dict[str, Any]:
    if not os.path.exists(filename):
        return {
            'format': LEDGER_FORMAT,
            'schema_version': SCHEMA_VERSION,
            'record_id': None,
            'finding_key': None,
            'created_at': None,
            'updated_at': None,
            'imported_packages': [],
        }

    try:
        with open(filename) as f:
            ledger = json.loads(f.read())
    except (IOError, json.decoder.JSONDecodeError) as e:
        raise ReviewPackageError(
            'Unable to read the review ledger next to the baseline: {}'.format(filename),
        ) from e

    if (
        not isinstance(ledger, dict)
        or ledger.get('format') != LEDGER_FORMAT
        or ledger.get('schema_version') != SCHEMA_VERSION
        or not isinstance(ledger.get('imported_packages'), list)
    ):
        raise ReviewPackageError(
            'The review ledger next to the baseline is invalid: {}'.format(filename),
        )

    if ledger.get('record_id') is not None and not isinstance(ledger['record_id'], str):
        raise ReviewPackageError(
            'The review ledger next to the baseline is invalid: {}'.format(filename),
        )
    if ledger.get('finding_key') is not None and not isinstance(ledger['finding_key'], str):
        raise ReviewPackageError(
            'The review ledger next to the baseline is invalid: {}'.format(filename),
        )

    return ledger


def _write_json(filename: str, data: Dict[str, Any]) -> None:
    directory = os.path.dirname(os.path.abspath(filename))
    descriptor, temporary_filename = tempfile.mkstemp(
        dir=directory,
        prefix='.detect-secrets-review-',
        suffix='.tmp',
    )
    try:
        with os.fdopen(descriptor, 'w') as f:
            f.write(json.dumps(data, indent=2, sort_keys=True, ensure_ascii=False))
            f.write('\n')
        os.replace(temporary_filename, filename)
    finally:
        if os.path.exists(temporary_filename):
            os.unlink(temporary_filename)


def _utc_now() -> str:
    return time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
