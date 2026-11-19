"""End-to-end tests for the optional decision journal wired into interactive audit."""
import json
from unittest import mock

import pytest

from detect_secrets.audit.decision_journal import DecisionJournal
from detect_secrets.core import baseline
from detect_secrets.core.secrets_collection import SecretsCollection
from detect_secrets.exceptions import BaselineMismatchError
from detect_secrets.exceptions import DuplicateDecisionError
from detect_secrets.main import main
from detect_secrets.settings import transient_settings
from testing.mocks import mock_named_temporary_file


@pytest.fixture
def baseline_filename(printer):
    with transient_settings({
        'plugins_used': [
            {'name': 'BasicAuthDetector'},
        ],
    }):
        secrets = SecretsCollection()
        secrets.scan_file('test_data/each_secret.py')

    with mock_named_temporary_file() as f:
        baseline.save_to_file(secrets, f.name)
        yield f.name


def _load_baseline(filename):
    return baseline.load(baseline.load_from_file(filename), filename)


def _run_audit(baseline_filename, journal_filename, reviewer, keys):
    with mock.patch('detect_secrets.audit.io.input') as mocked_input:
        mocked_input.side_effect = list(keys) + ['q']
        main([
            'audit', baseline_filename,
            '--journal', journal_filename,
            '--reviewer', reviewer,
        ])


def _only_secret(collection):
    return list(collection)[0][1]


class TestJournalAudit:
    def test_two_reviewers_opposite_decisions_align_to_history(
        self, baseline_filename, printer,
    ):
        with mock_named_temporary_file() as journal_file:
            journal_filename = journal_file.name

            # First reviewer labels the finding a real secret ("no, don't commit it").
            _run_audit(baseline_filename, journal_filename, 'alice', 'n')
            after_alice = _load_baseline(baseline_filename)
            assert _only_secret(after_alice).is_secret is True

            # Second reviewer re-audits the same finding and reaches the opposite conclusion.
            _run_audit(baseline_filename, journal_filename, 'bob', 'y')
            after_bob = _load_baseline(baseline_filename)

            journal = DecisionJournal.load(journal_filename)
            history = journal.history_for(
                (_only_secret(after_bob).filename,
                 _only_secret(after_bob).secret_hash,
                 _only_secret(after_bob).type),
            )

        assert [entry.reviewer for entry in history] == ['alice', 'bob']
        assert [entry.is_secret for entry in history] == [True, False]

        # The current label matches the latest recorded decision.
        assert _only_secret(after_bob).is_secret is False
        assert journal.reconcile(after_bob).is_clean

        # The on-disk journal keeps both decisions, with distinct entry ids.
        assert len({entry.entry_id for entry in history}) == 2

    def test_duplicate_decision_submitted_twice(self, baseline_filename, printer):
        with mock_named_temporary_file() as journal_file:
            journal_filename = journal_file.name
            _run_audit(baseline_filename, journal_filename, 'alice', 'n')

            journal = DecisionJournal.load(journal_filename)
            original_entry_id = journal.decisions[0].entry_id
            secret = _only_secret(_load_baseline(baseline_filename))

            # Replaying the exact same submission must be rejected, not double-recorded.
            with pytest.raises(DuplicateDecisionError):
                journal.record(
                    secret, reviewer='alice', is_secret=True,
                    entry_id=original_entry_id,
                )

            assert len(journal.decisions) == 1

    def test_journal_save_failure_leaves_baseline_and_journal_clear(
        self, baseline_filename, printer,
    ):
        with mock_named_temporary_file() as journal_file:
            journal_filename = journal_file.name
            _run_audit(baseline_filename, journal_filename, 'alice', 'n')

            baseline_before = open(baseline_filename).read()
            journal_before = open(journal_filename).read()

            # The journal is persisted before the baseline. If it fails, the baseline must
            # not be rewritten and the existing journal must remain the previous version.
            with mock.patch(
                'detect_secrets.audit.decision_journal.os.replace',
                side_effect=OSError('disk full'),
            ):
                with pytest.raises(OSError):
                    _run_audit(baseline_filename, journal_filename, 'bob', 'y')

            assert open(baseline_filename).read() == baseline_before
            assert open(journal_filename).read() == journal_before

            # Recovery: the next run reconciles the untouched baseline against the saved
            # journal, so the labels line back up with the history.
            recovered = DecisionJournal.load(journal_filename)
            assert recovered.reconcile(_load_baseline(baseline_filename)).is_clean

    def test_baseline_changed_out_of_band_is_rejected(self, baseline_filename, printer):
        with mock_named_temporary_file() as journal_file:
            journal_filename = journal_file.name
            _run_audit(baseline_filename, journal_filename, 'alice', 'n')

            # Simulate the agreed baseline being replaced by a different one (empty results).
            with open(baseline_filename) as handle:
                payload = json.load(handle)
            payload['results'] = {}
            with open(baseline_filename, 'w') as handle:
                handle.write(json.dumps(payload))

            with pytest.raises(BaselineMismatchError):
                _run_audit(baseline_filename, journal_filename, 'bob', 'y')

    def test_legacy_baseline_only_flow_unchanged(self, baseline_filename, printer):
        # No --journal: nothing decision-related is created, and labels save as before.
        with mock.patch('detect_secrets.audit.io.input') as mocked_input:
            mocked_input.side_effect = ['n', 'q']
            main(['audit', baseline_filename])

        assert _only_secret(_load_baseline(baseline_filename)).is_secret is True

    def test_empty_journal_file_starts_a_new_one(self, baseline_filename, printer):
        with mock_named_temporary_file() as journal_file:
            journal_filename = journal_file.name  # exists but is empty
            _run_audit(baseline_filename, journal_filename, 'alice', 'n')

            journal = DecisionJournal.load(journal_filename)
        assert [entry.reviewer for entry in journal.decisions] == ['alice']
        assert 'Creating new decision journal' in printer.message

    def test_malformed_journal_is_not_silently_replaced(
        self, baseline_filename, printer,
    ):
        with mock_named_temporary_file() as journal_file:
            journal_filename = journal_file.name
            with open(journal_filename, 'w') as handle:
                handle.write('{this is not valid json')

            with pytest.raises(json.JSONDecodeError):
                _run_audit(baseline_filename, journal_filename, 'alice', 'n')

    def test_quitting_without_deciding_writes_nothing(
        self, baseline_filename, printer,
    ):
        with mock_named_temporary_file() as journal_file:
            journal_filename = journal_file.name  # exists but is empty

            with mock.patch('detect_secrets.audit.io.input') as mocked_input:
                mocked_input.side_effect = ['q']
                main([
                    'audit', baseline_filename,
                    '--journal', journal_filename,
                    '--reviewer', 'alice',
                ])

            # No decision was made, so nothing was persisted to the journal.
            assert open(journal_filename).read() == ''
            assert _only_secret(_load_baseline(baseline_filename)).is_secret is None

    def test_reconciles_drifted_labels_without_a_new_decision(
        self, baseline_filename, printer,
    ):
        with mock_named_temporary_file() as journal_file:
            journal_filename = journal_file.name
            _run_audit(baseline_filename, journal_filename, 'alice', 'n')
            assert _only_secret(_load_baseline(baseline_filename)).is_secret is True

            # Tamper with the baseline label out-of-band, without touching the finding inventory.
            drifted = _load_baseline(baseline_filename)
            _only_secret(drifted).is_secret = False
            baseline.save_to_file(drifted, baseline_filename)

            # The journal still anchors to the same inventory, so this is label drift (not a
            # baseline mismatch): opening reconciles the label back, and the reviewer just quits.
            with mock.patch('detect_secrets.audit.io.input') as mocked_input:
                mocked_input.side_effect = ['q']
                main([
                    'audit', baseline_filename,
                    '--journal', journal_filename,
                    '--reviewer', 'bob',
                ])

            realigned = _load_baseline(baseline_filename)
            assert _only_secret(realigned).is_secret is True

            # No new decision was appended: the history still holds only alice's call.
            journal = DecisionJournal.load(journal_filename)
            assert [entry.reviewer for entry in journal.decisions] == ['alice']
            assert journal.reconcile(realigned).is_clean
