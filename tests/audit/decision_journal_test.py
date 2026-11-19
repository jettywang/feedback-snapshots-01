import json
from unittest import mock

import pytest

from detect_secrets.audit.decision_journal import Decision
from detect_secrets.audit.decision_journal import DecisionJournal
from detect_secrets.audit.decision_journal import hash_baseline
from detect_secrets.audit.decision_journal import secret_key
from detect_secrets.core.secrets_collection import SecretsCollection
from detect_secrets.exceptions import BaselineMismatchError
from detect_secrets.exceptions import DuplicateDecisionError
from testing.factories import potential_secret_factory
from testing.mocks import mock_named_temporary_file


@pytest.fixture
def secret():
    return potential_secret_factory(
        type='AWSKeyDetector',
        filename='config.py',
        secret='first-secret-value',
        line_number=3,
    )


@pytest.fixture
def other_secret():
    return potential_secret_factory(
        type='AWSKeyDetector',
        filename='config.py',
        secret='second-secret-value',
        line_number=7,
    )


@pytest.fixture
def baseline(secret, other_secret) -> SecretsCollection:
    collection = SecretsCollection()
    collection[secret.filename].add(secret)
    collection[other_secret.filename].add(other_secret)
    return collection


@pytest.fixture
def clock():
    ticks = iter([
        '2026-01-01T00:00:00Z',
        '2026-01-01T00:00:01Z',
        '2026-01-01T00:00:02Z',
        '2026-01-01T00:00:03Z',
    ])
    return lambda: next(ticks)


class TestBaselineHashing:
    def test_same_inventory_same_hash(self, baseline, secret, other_secret):
        other = SecretsCollection()
        other[secret.filename].add(secret)
        other[other_secret.filename].add(other_secret)
        assert hash_baseline(baseline) == hash_baseline(other)

    def test_hash_ignores_labels(self, baseline):
        labelled = SecretsCollection.load_from_baseline(
            json.loads(json.dumps({
                'version': '1.4.0',
                'plugins_used': [],
                'results': baseline.json(),
            })),
        )
        for _, secret in labelled:
            secret.is_secret = True

        assert hash_baseline(labelled) == hash_baseline(baseline)

    def test_different_inventory_different_hash(self, baseline, other_secret):
        baseline.data[other_secret.filename].remove(other_secret)
        changed = SecretsCollection()
        changed[other_secret.filename].add(other_secret)

        assert hash_baseline(changed) != hash_baseline(baseline)

    def test_accepts_dict_baseline(self, baseline):
        assert hash_baseline({'results': baseline.json()}) == hash_baseline(baseline)


class TestRecord:
    def test_appends_decision_with_reviewer_and_timestamp(self, baseline, secret, clock):
        journal = DecisionJournal.for_baseline(baseline)
        decision = journal.record(
            secret, reviewer='alice', is_secret=True,
            entry_id='e1', timestamp_factory=clock,
        )

        assert decision.reviewer == 'alice'
        assert decision.is_secret is True
        assert decision.timestamp == '2026-01-01T00:00:00Z'
        assert decision.key == secret_key(secret)
        assert journal.decisions == [decision]

    def test_generates_entry_id_when_not_supplied(self, baseline, secret):
        journal = DecisionJournal.for_baseline(baseline)
        decision = journal.record(secret, reviewer='alice', is_secret=False)
        assert decision.entry_id
        assert journal.has_entry(decision.entry_id)

    def test_duplicate_entry_id_is_rejected(self, baseline, secret, clock):
        journal = DecisionJournal.for_baseline(baseline)
        journal.record(secret, reviewer='alice', is_secret=True,
                       entry_id='dup', timestamp_factory=clock)

        with pytest.raises(DuplicateDecisionError) as excinfo:
            journal.record(secret, reviewer='bob', is_secret=False,
                           entry_id='dup', timestamp_factory=clock)

        assert excinfo.value.entry_id == 'dup'
        assert len(journal.decisions) == 1

    def test_skips_are_recorded_as_none(self, baseline, secret, clock):
        journal = DecisionJournal.for_baseline(baseline)
        decision = journal.record(secret, reviewer='alice', is_secret=None,
                                  entry_id='e1', timestamp_factory=clock)
        assert decision.is_secret is None
        assert 'is_secret' not in decision.to_dict()


class TestTwoReviewers:
    def test_opposite_decisions_both_kept_last_wins(self, baseline, secret, clock):
        journal = DecisionJournal.for_baseline(baseline)

        first = journal.record(secret, reviewer='alice', is_secret=True,
                               entry_id='e1', timestamp_factory=clock)
        second = journal.record(secret, reviewer='bob', is_secret=False,
                                entry_id='e2', timestamp_factory=clock)

        history = journal.history_for(secret_key(secret))
        assert [decision.reviewer for decision in history] == ['alice', 'bob']
        assert [decision.is_secret for decision in history] == [True, False]
        assert history == [first, second]

        # The current label follows the most recent decision, while both stay in history.
        assert journal.replay()[secret_key(secret)] is False

    def test_same_decision_submitted_twice_does_not_duplicate(self, baseline, secret, clock):
        journal = DecisionJournal.for_baseline(baseline)
        journal.record(secret, reviewer='alice', is_secret=True,
                       entry_id='e1', timestamp_factory=clock)

        with pytest.raises(DuplicateDecisionError):
            journal.record(secret, reviewer='alice', is_secret=True,
                           entry_id='e1', timestamp_factory=clock)

        assert len(journal.history_for(secret_key(secret))) == 1


class TestReconcile:
    def test_clean_when_labels_align(self, baseline, secret, clock):
        journal = DecisionJournal.for_baseline(baseline)
        journal.record(secret, reviewer='alice', is_secret=True,
                       entry_id='e1', timestamp_factory=clock)
        secret.is_secret = True

        report = journal.reconcile(baseline)
        assert report.is_clean
        assert report.baseline_matches
        assert report.already_aligned == [secret_key(secret)]
        assert report.applied == []
        assert report.missing == []

    def test_detects_label_drift_without_mutating(self, baseline, secret, clock):
        journal = DecisionJournal.for_baseline(baseline)
        journal.record(secret, reviewer='alice', is_secret=True,
                       entry_id='e1', timestamp_factory=clock)
        secret.is_secret = False

        report = journal.reconcile(baseline)
        assert report.baseline_matches
        assert report.applied == [secret_key(secret)]
        assert not report.is_clean
        assert secret.is_secret is False

    def test_flags_missing_finding(self, baseline, secret, clock):
        journal = DecisionJournal.for_baseline(baseline)
        journal.record(secret, reviewer='alice', is_secret=True,
                       entry_id='e1', timestamp_factory=clock)
        baseline.data[secret.filename].remove(secret)

        report = journal.reconcile(baseline)
        assert report.missing == [secret_key(secret)]
        assert not report.is_clean

    def test_dirty_when_baseline_inventory_mismatches(self, baseline, secret, clock):
        journal = DecisionJournal.for_baseline(baseline)
        journal.record(secret, reviewer='alice', is_secret=True,
                       entry_id='e1', timestamp_factory=clock)
        secret.is_secret = True
        baseline.data[secret.filename].remove(secret)

        report = journal.reconcile(baseline)
        assert not report.baseline_matches
        assert not report.is_clean

    def test_matches_baseline_tracks_anchor(self, baseline, other_secret):
        journal = DecisionJournal.for_baseline(baseline)
        assert journal.matches_baseline(baseline)

        baseline.data[other_secret.filename].remove(other_secret)
        assert not journal.matches_baseline(baseline)


class TestApplyTo:
    def test_replays_history_onto_labels(self, baseline, secret, other_secret, clock):
        journal = DecisionJournal.for_baseline(baseline)
        journal.record(secret, reviewer='alice', is_secret=True,
                       entry_id='e1', timestamp_factory=clock)
        journal.record(secret, reviewer='bob', is_secret=False,
                       entry_id='e2', timestamp_factory=clock)
        journal.record(other_secret, reviewer='alice', is_secret=True,
                       entry_id='e3', timestamp_factory=clock)

        report = journal.apply_to(baseline)

        assert secret.is_secret is False
        assert other_secret.is_secret is True
        assert sorted(report.applied) == sorted([
            secret_key(secret), secret_key(other_secret),
        ])
        assert journal.reconcile(baseline).is_clean

    def test_raises_on_baseline_mismatch(self, baseline, secret, clock):
        journal = DecisionJournal.for_baseline(baseline)
        journal.record(secret, reviewer='alice', is_secret=True,
                       entry_id='e1', timestamp_factory=clock)

        anchored_hash = journal.baseline_hash
        baseline.data[secret.filename].remove(secret)

        with pytest.raises(BaselineMismatchError) as excinfo:
            journal.apply_to(baseline)

        assert excinfo.value.expected_hash == anchored_hash
        assert excinfo.value.actual_hash == hash_baseline(baseline)


class TestPersistence:
    def test_round_trip(self, baseline, secret, clock):
        journal = DecisionJournal.for_baseline(baseline)
        journal.record(secret, reviewer='alice', is_secret=True,
                       entry_id='e1', timestamp_factory=clock)

        with mock_named_temporary_file() as f:
            journal.save(f.name)
            with open(f.name) as saved:
                payload = json.load(saved)

            assert payload['baseline_hash'] == hash_baseline(baseline)
            assert payload['version'] == journal.version
            assert payload['decisions'] == [journal.decisions[0].to_dict()]

            reloaded = DecisionJournal.load(f.name)

        assert reloaded.baseline_hash == journal.baseline_hash
        assert reloaded.decisions == journal.decisions

    def test_failed_write_leaves_existing_file_intact(self, baseline, secret, clock):
        journal = DecisionJournal.for_baseline(baseline)
        journal.record(secret, reviewer='alice', is_secret=True,
                       entry_id='e1', timestamp_factory=clock)

        with mock_named_temporary_file() as f:
            journal.save(f.name)
            original_contents = open(f.name).read()

            journal.record(secret, reviewer='bob', is_secret=False,
                           entry_id='e2', timestamp_factory=clock)

            with mock.patch('detect_secrets.audit.decision_journal.os.replace',
                            side_effect=OSError('disk full')):
                with pytest.raises(OSError):
                    journal.save(f.name)

            # The pre-existing journal is untouched, and no temp file is left behind.
            assert open(f.name).read() == original_contents
            reloaded = DecisionJournal.load(f.name)
            assert [decision.entry_id for decision in reloaded.decisions] == ['e1']

    def test_append_across_sessions(self, baseline, secret, clock):
        with mock_named_temporary_file() as f:
            first = DecisionJournal.for_baseline(baseline)
            first.record(secret, reviewer='alice', is_secret=True,
                         entry_id='e1', timestamp_factory=clock)
            first.save(f.name)

            reloaded = DecisionJournal.load(f.name)
            reloaded.record(secret, reviewer='bob', is_secret=False,
                            entry_id='e2', timestamp_factory=clock)
            reloaded.save(f.name)

            final = DecisionJournal.load(f.name)

        assert [decision.reviewer for decision in final.decisions] == ['alice', 'bob']
        assert final.baseline_hash == first.baseline_hash


class TestDecisionSerialization:
    def test_dict_round_trip(self):
        decision = Decision(
            entry_id='e1',
            reviewer='alice',
            filename='config.py',
            secret_hash='abc123',
            secret_type='AWSKeyDetector',
            is_secret=True,
            timestamp='2026-01-01T00:00:00Z',
        )
        assert Decision.from_dict(decision.to_dict()) == decision

    def test_none_label_round_trip(self):
        decision = Decision(
            entry_id='e1', reviewer='alice', filename='config.py',
            secret_hash='abc123', secret_type='AWSKeyDetector',
            is_secret=None, timestamp='2026-01-01T00:00:00Z',
        )
        assert Decision.from_dict(decision.to_dict()) == decision

    def test_key_identifies_finding_independent_of_label(self):
        decision = Decision(
            entry_id='e1', reviewer='alice', filename='config.py',
            secret_hash='abc123', secret_type='AWSKeyDetector',
            is_secret=None, timestamp='2026-01-01T00:00:00Z',
        )
        assert decision.key == ('config.py', 'abc123', 'AWSKeyDetector')
