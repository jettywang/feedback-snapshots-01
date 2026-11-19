"""
Three-way merge for independently labelled copies of the same baseline.

The merge starts from a common baseline (the "base") and combines the labelled
copies returned by two reviewers. The rules are deliberately conservative:

    * If only one reviewer labelled a secret, that conclusion is preserved.
    * If both reviewers reached the same conclusion, it is preserved.
    * If both reviewers reached different conclusions, the secret is left
      unlabelled (``is_secret`` omitted) so a third reviewer can resolve it.
    * If both reviewers removed the same scan result, it is withdrawn from the
      merged baseline.
    * If only one copy contains the scan result, the difference is ambiguous
      (a deletion or a rescan finding), so it is also left for a third reviewer.

The operation is symmetric. Swapping the two copies produces byte-identical
merged output, including conflict metadata and ordering.
"""
import json
from typing import Any
from typing import Dict
from typing import List
from typing import NamedTuple
from typing import Optional
from typing import Sequence
from typing import Set
from typing import Tuple

from . import io
from ..core import baseline
from ..core.potential_secret import PotentialSecret
from ..core.secrets_collection import SecretsCollection
from ..exceptions import InvalidBaselineError
from ..exceptions import UnableToReadBaselineError


CONFLICT_LABELS = 'conflicting-conclusions'
CONFLICT_PRESENCE = 'present-in-only-one-copy'


class SecretKey(NamedTuple):
    filename: str
    secret_hash: str
    type: str


class MergeConflict(NamedTuple):
    filename: str
    secret_hash: str
    type: str
    line_number: int
    reason: str
    conclusions: Sequence[Optional[bool]]

    def json(self) -> Dict[str, Any]:
        return {
            'filename': self.filename,
            'hashed_secret': self.secret_hash,
            'type': self.type,
            'line_number': self.line_number,
            'reason': self.reason,
            'conclusions': list(self.conclusions),
        }


class RemovedSecret(NamedTuple):
    filename: str
    secret_hash: str
    type: str
    line_number: int

    def json(self) -> Dict[str, Any]:
        return {
            'filename': self.filename,
            'hashed_secret': self.secret_hash,
            'type': self.type,
            'line_number': self.line_number,
        }


class MergeReport:
    def __init__(
        self,
        data: Dict[str, Any],
        secrets: SecretsCollection,
        conflicts: List[MergeConflict],
        removed: List[RemovedSecret],
    ) -> None:
        self.data = data
        self.secrets = secrets
        self.conflicts = conflicts
        self.removed = removed

    @property
    def is_signed_off(self) -> bool:
        return not self.conflicts


def merge_baselines(
    base_filename: str,
    first_copy_filename: str,
    second_copy_filename: str,
) -> MergeReport:
    """
    Merge two reviewed copies of ``base_filename``.

    :raises: UnableToReadBaselineError
    :raises: KeyError
    """
    base_data, base = _load_baseline(base_filename)
    if 'results' not in base_data:
        raise KeyError('results')
    first = _load_baseline(first_copy_filename)[1]
    second = _load_baseline(second_copy_filename)[1]

    merged = SecretsCollection()
    conflicts: List[MergeConflict] = []
    removed: List[RemovedSecret] = []

    base_mapping = _mapping(base)
    first_mapping = _mapping(first)
    second_mapping = _mapping(second)

    all_keys: Set[SecretKey] = set(base_mapping) | set(first_mapping) | set(second_mapping)
    for key in sorted(all_keys):
        base_secret = base_mapping.get(key)
        first_secret = first_mapping.get(key)
        second_secret = second_mapping.get(key)

        # Withdrawn: both reviewers' copies no longer contain the scan result.
        if base_secret and first_secret is None and second_secret is None:
            removed.append(
                RemovedSecret(
                    filename=key.filename,
                    secret_hash=key.secret_hash,
                    type=key.type,
                    line_number=base_secret.line_number,
                ),
            )
            continue

        # Present in exactly one copy: we cannot tell whether this is a
        # withdrawal, a re-scan addition, or an incomplete copy. Escalate.
        if (first_secret is None) != (second_secret is None):
            present = first_secret if first_secret is not None else second_secret
            assert present is not None
            conflict = _make_conflict(
                key,
                present,
                CONFLICT_PRESENCE,
                _conclusions(first_secret, second_secret),
            )
            conflicts.append(conflict)
            _add_unlabelled(merged, key, conflict)
            continue

        assert first_secret is not None and second_secret is not None

        label = _merge_labels(first_secret, second_secret)
        if label is _CONFLICT:
            conflicts.append(
                _make_conflict(
                    key,
                    first_secret,
                    CONFLICT_LABELS,
                    _conclusions(first_secret, second_secret),
                ),
            )
            label = None

        _add_secret(merged, key, base_secret, first_secret, second_secret, label)

    merged_data = dict(base_data)
    merged_data['results'] = merged.json()
    # The base timestamp no longer describes this file; omit it rather than
    # reporting a stale value.
    merged_data.pop('generated_at', None)

    # Always include this block so signed-off clean merges are explicit too.
    merged_data['audit_merge'] = {
        'signed_off': not conflicts,
        'conflicts': [conflict.json() for conflict in conflicts],
        'removed': [secret.json() for secret in removed],
    }

    return MergeReport(
        data=merged_data,
        secrets=merged,
        conflicts=conflicts,
        removed=removed,
    )


def save_merged_baseline(report: MergeReport, filename: str) -> None:
    baseline.save_to_file(report.data, filename)


def print_summary(report: MergeReport) -> None:
    total = len(list(report.secrets))
    resolved = total - len(report.conflicts)
    io.print_message(
        'Merged {total} secret(s): {resolved} resolved, {conflicts} conflict(s), '
        '{removed} withdrawn.'.format(
            total=total,
            resolved=resolved,
            conflicts=len(report.conflicts),
            removed=len(report.removed),
        ),
    )

    if report.is_signed_off:
        io.print_message('Audit status: SIGNED OFF (0 unresolved conflicts).')
        return

    io.print_message(
        'Audit status: NOT SIGNED OFF (unsigned): {count} unresolved conflict(s) '
        'require a third reviewer.'.format(count=len(report.conflicts)),
    )
    for conflict in report.conflicts:
        io.print_message('  {line}'.format(line=_format_conflict(conflict)))


def merge_command(
    base_filename: str,
    first_copy_filename: str,
    second_copy_filename: str,
    output_filename: Optional[str] = None,
) -> MergeReport:
    """
    CLI entrypoint for the merge operation.

    If ``output_filename`` is omitted, the merged baseline is printed to stdout
    so it can be redirected like ``detect-secrets scan``. Conflict information
    then goes to stderr, keeping stdout machine-readable.
    """
    try:
        report = merge_baselines(base_filename, first_copy_filename, second_copy_filename)
    except UnableToReadBaselineError:
        io.print_error('Not a valid baseline file!')
        raise InvalidBaselineError
    except KeyError:
        io.print_error('Not a valid baseline file!')
        raise InvalidBaselineError

    if output_filename:
        save_merged_baseline(report, output_filename)
        print_summary(report)
    else:
        io.print_message(json.dumps(report.data, indent=2))
        _print_conflict_summary_to_stderr(report)

    return report


class _Conflict:
    pass


_CONFLICT = _Conflict()


def _load_baseline(filename: str) -> Tuple[Dict[str, Any], SecretsCollection]:
    data = baseline.upgrade(baseline.load_from_file(filename))
    return data, SecretsCollection.load_from_baseline(data)


def _mapping(secrets: SecretsCollection) -> Dict[SecretKey, PotentialSecret]:
    return {
        SecretKey(
            filename=secret.filename,
            secret_hash=secret.secret_hash,
            type=secret.type,
        ): secret
        for _, secret in secrets
    }


def _conclusion_sort_key(value: Optional[bool]) -> int:
    if value is None:
        return 0
    return 1 if value is False else 2


def _conclusions(
    first: Optional[PotentialSecret],
    second: Optional[PotentialSecret],
) -> Sequence[Optional[bool]]:
    """
    Return both reviewers' conclusions in a stable order.

    A missing secret is represented as ``None`` (same as "not reviewed"), since
    either way no human conclusion exists on that side.
    """
    values: Set[Optional[bool]] = {
        secret.is_secret if secret is not None else None
        for secret in (first, second)
    }
    return sorted(values, key=_conclusion_sort_key)


def _merge_labels(
    first: PotentialSecret,
    second: PotentialSecret,
) -> Any:
    if first.is_secret is None and second.is_secret is None:
        return None
    elif first.is_secret is None:
        return second.is_secret
    elif second.is_secret is None:
        return first.is_secret
    elif first.is_secret == second.is_secret:
        return first.is_secret

    # Both reviewers labelled this secret, and they disagree. The common base
    # does not get a vote: a third reviewer must decide.
    return _CONFLICT


def _make_conflict(
    key: SecretKey,
    secret: PotentialSecret,
    reason: str,
    conclusions: Sequence[Optional[bool]],
) -> MergeConflict:
    return MergeConflict(
        filename=key.filename,
        secret_hash=key.secret_hash,
        type=key.type,
        line_number=secret.line_number,
        reason=reason,
        conclusions=conclusions,
    )


def _line_number(
    base: Optional[PotentialSecret],
    first: PotentialSecret,
    second: PotentialSecret,
) -> int:
    candidates = [
        secret.line_number
        for secret in (base, first, second)
        if secret is not None and secret.line_number
    ]
    return min(candidates) if candidates else 0


def _is_verified(
    base: Optional[PotentialSecret],
    first: PotentialSecret,
    second: PotentialSecret,
) -> bool:
    return any(
        secret.is_verified
        for secret in (base, first, second)
        if secret is not None
    )


def _build_secret(
    key: SecretKey,
    line_number: int,
    label: Optional[bool],
    is_verified: bool,
) -> PotentialSecret:
    data: Dict[str, Any] = {
        'type': key.type,
        'filename': key.filename,
        'hashed_secret': key.secret_hash,
        'line_number': line_number,
        'is_verified': is_verified,
    }
    if label is not None:
        data['is_secret'] = label

    return PotentialSecret.load_secret_from_dict(data)


def _add_secret(
    merged: SecretsCollection,
    key: SecretKey,
    base: Optional[PotentialSecret],
    first: PotentialSecret,
    second: PotentialSecret,
    label: Optional[bool],
) -> None:
    merged[key.filename].add(
        _build_secret(
            key,
            line_number=_line_number(base, first, second),
            label=label,
            is_verified=_is_verified(base, first, second),
        ),
    )


def _add_unlabelled(
    merged: SecretsCollection,
    key: SecretKey,
    conflict: MergeConflict,
) -> None:
    merged[key.filename].add(
        _build_secret(
            key,
            line_number=conflict.line_number,
            label=None,
            is_verified=False,
        ),
    )


def _format_conflict(conflict: MergeConflict) -> str:
    conclusions = ', '.join(
        'not-reviewed' if value is None else str(value)
        for value in conflict.conclusions
    )
    return '{filename}:{line_number} {type} ({hashed_secret}): {reason}; ' \
        'conclusions: [{conclusions}]'.format(
            filename=conflict.filename,
            line_number=conflict.line_number,
            type=conflict.type,
            hashed_secret=conflict.secret_hash,
            reason=conflict.reason,
            conclusions=conclusions,
        )


def _print_conflict_summary_to_stderr(report: MergeReport) -> None:
    if report.is_signed_off:
        return

    io.print_error(
        'Merged with {count} unresolved conflict(s) (NOT SIGNED OFF); '
        'these require a third reviewer.'.format(count=len(report.conflicts)),
    )
    for conflict in report.conflicts:
        io.print_error('  {line}'.format(line=_format_conflict(conflict)))


def refresh_merge_metadata(
    data: Dict[str, Any],
    secrets: SecretsCollection,
) -> Dict[str, Any]:
    """
    Reconcile merge metadata after an interactive audit of a merged baseline.

    Without this, saving the audited file would drop the conflict list, and the
    next `--stats` would silently look signed off. Conflicts that the third
    reviewer has now labelled are removed; anything still unlabelled stays a
    conflict.
    """
    output = dict(data)
    output['results'] = secrets.json()

    metadata = data.get('audit_merge')
    if not metadata:
        return output

    unresolved = {
        SecretKey(
            filename=secret.filename,
            secret_hash=secret.secret_hash,
            type=secret.type,
        )
        for _, secret in secrets
        if secret.is_secret is None
    }

    remaining = [
        conflict
        for conflict in metadata.get('conflicts', [])
        if SecretKey(
            filename=conflict['filename'],
            secret_hash=conflict['hashed_secret'],
            type=conflict['type'],
        ) in unresolved
    ]

    output['audit_merge'] = {
        **metadata,
        'signed_off': not remaining,
        'conflicts': remaining,
    }
    return output
