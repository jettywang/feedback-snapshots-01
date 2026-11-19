"""
An optional append-only decision journal for interactive audit sessions.

The regular audit flow only persists the *latest* label of every finding back to
the baseline. When a post-incident review needs to know *who* decided what, and
*who later reviewed* the same finding, this journal keeps an ordered, append-only
stream of every decision.

A journal is anchored to an agreed baseline through a content hash. Re-opening a
journal reconciles the recorded history against the current baseline before any
new decision is accepted, so drift (e.g. the baseline was changed out-of-band) is
detected rather than silently overwritten.
"""
import hashlib
import json
import os
import tempfile
import time
import uuid
from dataclasses import dataclass
from dataclasses import field
from typing import Any
from typing import Callable
from typing import Dict
from typing import List
from typing import Optional
from typing import Sequence
from typing import Tuple
from typing import TYPE_CHECKING
from typing import Union

from ..core.potential_secret import PotentialSecret
from ..exceptions import BaselineMismatchError
from ..exceptions import DuplicateDecisionError

if TYPE_CHECKING:
    from ..core.secrets_collection import SecretsCollection

JOURNAL_VERSION = '1.0'
SecretKey = Tuple[str, str, str]
BaselineInput = Union['SecretsCollection', Dict[str, Any]]


def secret_key(secret: PotentialSecret) -> SecretKey:
    """Stable identifier of a finding within a baseline (independent of its label)."""
    return (secret.filename, secret.secret_hash, secret.type)


def _canonical_inventory(baseline: BaselineInput) -> Dict[str, Any]:
    """
    The inventory we anchor against: the set of findings (file, hash, type), deliberately
    excluding `is_secret`/`is_verified` labels, since labels are exactly what the journal
    is allowed to change between sessions.
    """
    if isinstance(baseline, dict):
        results = baseline.get('results', {})
    else:
        results = baseline.json()

    inventory: Dict[str, List[Dict[str, Any]]] = {}
    for filename in sorted(results):
        entries = [
            {
                'hashed_secret': str(item['hashed_secret']),
                'type': str(item['type']),
            }
            for item in results[filename]
        ]
        entries.sort(key=lambda item: (item['hashed_secret'], item['type']))
        inventory[filename] = entries

    return inventory


def hash_baseline(baseline: BaselineInput) -> str:
    """A stable fingerprint of a baseline's finding inventory."""
    payload = json.dumps(
        _canonical_inventory(baseline),
        sort_keys=True,
        separators=(',', ':'),
    )
    return hashlib.sha256(payload.encode('utf-8')).hexdigest()


def _default_entry_id() -> str:
    return uuid.uuid4().hex


def _default_timestamp() -> str:
    return time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())


@dataclass(frozen=True)
class Decision:
    """A single reviewer's decision about a single finding."""
    entry_id: str
    reviewer: str
    filename: str
    secret_hash: str
    secret_type: str
    is_secret: Optional[bool]
    timestamp: str

    @property
    def key(self) -> SecretKey:
        return (self.filename, self.secret_hash, self.secret_type)

    def to_dict(self) -> Dict[str, Any]:
        output: Dict[str, Any] = {
            'entry_id': self.entry_id,
            'reviewer': self.reviewer,
            'filename': self.filename,
            'hashed_secret': self.secret_hash,
            'type': self.secret_type,
            'timestamp': self.timestamp,
        }
        if self.is_secret is not None:
            output['is_secret'] = self.is_secret
        return output

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Decision':
        return cls(
            entry_id=str(data['entry_id']),
            reviewer=str(data['reviewer']),
            filename=str(data['filename']),
            secret_hash=str(data['hashed_secret']),
            secret_type=str(data['type']),
            is_secret=data.get('is_secret'),
            timestamp=str(data['timestamp']),
        )


@dataclass
class ReconciliationReport:
    """Outcome of aligning the journal's history with a baseline's current labels."""
    baseline_matches: bool
    expected_hash: str
    actual_hash: str
    applied: List[SecretKey] = field(default_factory=list)
    already_aligned: List[SecretKey] = field(default_factory=list)
    missing: List[SecretKey] = field(default_factory=list)

    @property
    def is_clean(self) -> bool:
        """True when the baseline matches and every recorded finding is present and aligned."""
        return (
            self.baseline_matches
            and not self.missing
            and not self.applied
        )


class DecisionJournal:
    """
    An append-only, baseline-anchored stream of audit decisions.

    Decisions are only persisted through :meth:`save`, which writes atomically: either the
    full journal lands on disk, or the existing file is left untouched.
    """

    def __init__(
        self,
        baseline_hash: str,
        decisions: Optional[Sequence[Decision]] = None,
        version: str = JOURNAL_VERSION,
    ) -> None:
        self.baseline_hash = baseline_hash
        self.decisions: List[Decision] = list(decisions or [])
        self.version = version

    @classmethod
    def for_baseline(
        cls,
        baseline: BaselineInput,
        decisions: Optional[Sequence[Decision]] = None,
    ) -> 'DecisionJournal':
        return cls(baseline_hash=hash_baseline(baseline), decisions=decisions)

    @classmethod
    def load(cls, filename: str) -> 'DecisionJournal':
        """
        :raises: UnableToReadBaselineError, KeyError, json.JSONDecodeError
        """
        with open(filename) as f:
            data = json.loads(f.read())

        return cls(
            baseline_hash=str(data['baseline_hash']),
            version=str(data.get('version', JOURNAL_VERSION)),
            decisions=[Decision.from_dict(item) for item in data.get('decisions', [])],
        )

    def matches_baseline(self, baseline: BaselineInput) -> bool:
        return hash_baseline(baseline) == self.baseline_hash

    @property
    def entry_ids(self) -> List[str]:
        return [decision.entry_id for decision in self.decisions]

    def has_entry(self, entry_id: str) -> bool:
        return entry_id in self.entry_ids

    def record(
        self,
        secret: PotentialSecret,
        reviewer: str,
        is_secret: Optional[bool],
        entry_id: Optional[str] = None,
        timestamp_factory: Callable[[], str] = _default_timestamp,
        entry_id_factory: Callable[[], str] = _default_entry_id,
    ) -> Decision:
        """
        Appends a decision to the in-memory stream.

        :raises: DuplicateDecisionError if an entry with the same id already exists.
        """
        if entry_id is None:
            entry_id = entry_id_factory()

        if self.has_entry(entry_id):
            raise DuplicateDecisionError(entry_id)

        decision = Decision(
            entry_id=entry_id,
            reviewer=reviewer,
            filename=secret.filename,
            secret_hash=secret.secret_hash,
            secret_type=secret.type,
            is_secret=is_secret,
            timestamp=timestamp_factory(),
        )
        self.decisions.append(decision)
        return decision

    def replay(self) -> Dict[SecretKey, Optional[bool]]:
        """
        Collapses the stream into the label each finding should currently carry.
        Later decisions for the same finding win (last-writer-wins).
        """
        current: Dict[SecretKey, Optional[bool]] = {}
        for decision in self.decisions:
            current[decision.key] = decision.is_secret
        return current

    def history_for(self, key: SecretKey) -> List[Decision]:
        """Every decision ever recorded for one finding, in submission order."""
        return [decision for decision in self.decisions if decision.key == key]

    def reconcile(self, baseline: 'SecretsCollection') -> ReconciliationReport:
        """
        Compares the recorded history against the baseline's current labels, without
        mutating anything.
        """
        actual_hash = hash_baseline(baseline)
        expected = self.replay()

        current = {
            secret_key(secret): secret.is_secret
            for _, secret in baseline
        }

        report = ReconciliationReport(
            baseline_matches=actual_hash == self.baseline_hash,
            expected_hash=self.baseline_hash,
            actual_hash=actual_hash,
        )
        for key, expected_label in expected.items():
            if key not in current:
                report.missing.append(key)
            elif current[key] == expected_label:
                report.already_aligned.append(key)
            else:
                report.applied.append(key)

        return report

    def apply_to(self, baseline: 'SecretsCollection') -> ReconciliationReport:
        """
        Aligns the baseline's labels with the recorded history (last-writer-wins).

        :raises: BaselineMismatchError if the baseline's finding inventory differs from
            the journal's anchored baseline.
        """
        report = self.reconcile(baseline)
        if not report.baseline_matches:
            raise BaselineMismatchError(report.expected_hash, report.actual_hash)

        indexed = {
            secret_key(secret): secret
            for _, secret in baseline
        }
        replayed = self.replay()
        for key in report.applied:
            indexed[key].is_secret = replayed[key]

        return report

    def to_dict(self) -> Dict[str, Any]:
        return {
            'version': self.version,
            'baseline_hash': self.baseline_hash,
            'decisions': [decision.to_dict() for decision in self.decisions],
        }

    def save(self, filename: str) -> None:
        """
        Atomically writes the journal: a crash during write leaves any pre-existing file
        (or absence of one) intact, so callers never observe a half-written journal.
        """
        directory = os.path.dirname(os.path.abspath(filename))
        payload = json.dumps(self.to_dict(), indent=2) + '\n'

        temporary_name = ''
        try:
            with tempfile.NamedTemporaryFile(
                mode='w',
                dir=directory,
                delete=False,
            ) as temporary_file:
                temporary_name = temporary_file.name
                temporary_file.write(payload)
                temporary_file.flush()
                os.fsync(temporary_file.fileno())

            os.replace(temporary_name, filename)
        except BaseException:
            if temporary_name and os.path.exists(temporary_name):
                os.unlink(temporary_name)
            raise
