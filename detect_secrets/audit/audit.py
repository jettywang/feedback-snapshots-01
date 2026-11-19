"""
The audit module allows analysts to easily scan the baseline, and verify whether
the secrets flagged are actually secrets.
"""
import json
import os
from typing import Callable
from typing import Optional

from . import io
from ..core import baseline
from ..core.potential_secret import PotentialSecret
from ..core.secrets_collection import SecretsCollection
from ..exceptions import NoLineNumberError
from ..exceptions import SecretNotFoundOnSpecifiedLineError
from ..types import SecretContext
from ..util.code_snippet import get_code_snippet
from .common import get_baseline_from_file
from .common import get_raw_secret_from_file
from .common import open_file
from .decision_journal import DecisionJournal
from .iterator import BidirectionalIterator
from .iterator import get_secret_iterator


def audit_baseline(
    filename: str,
    journal_filename: Optional[str] = None,
    reviewer: Optional[str] = None,
) -> None:
    """
    :param journal_filename: when provided, every decision is additionally appended to an
        append-only decision journal anchored to this baseline. When omitted, the audit
        behaves exactly as before: only the latest labels are saved to the baseline.
    :param reviewer: identity recorded on each journal entry. Required when a journal is used.

    :raises: InvalidBaselineError
    :raises: BaselineMismatchError
    """
    secrets = get_baseline_from_file(filename)
    secrets.trim()

    journal = None
    reconciled_labels = False
    if journal_filename:
        journal = _open_journal(journal_filename, secrets)

        # Replay any earlier session's decisions, so the labels the reviewer sees (and the
        # baseline we are about to save) are aligned with the recorded history.
        reconciliation = journal.apply_to(secrets)
        reconciled_labels = bool(reconciliation.applied)

        recorder = _make_recorder(journal, reviewer)
    else:
        recorder = None

    has_changes = _classify_secrets(
        get_secret_iterator(secrets, include_labelled=journal is not None),
        recorder=recorder,
    )

    # Reconciliation may have corrected labels even if the reviewer made no new decision. The
    # journal itself only changes through new decisions, so it is only rewritten for those.
    if has_changes or reconciled_labels:
        io.print_message('Saving progress...')
        if journal is not None and has_changes:
            # Persist the journal first (atomically). The baseline is saved afterwards, so a
            # failure never leaves a labelled baseline whose history wasn't recorded: the next
            # run simply reconciles the still-unchanged baseline against the saved journal.
            journal.save(journal_filename)
        baseline.save_to_file(secrets, filename)


def _open_journal(
    journal_filename: str,
    secrets: SecretsCollection,
) -> DecisionJournal:
    try:
        journal = DecisionJournal.load(journal_filename)
    except FileNotFoundError:
        journal = None
    except json.JSONDecodeError:
        # An empty file simply means no journal has been written yet. A non-empty but malformed
        # journal is a real problem: let it surface rather than silently overwriting history.
        if os.path.getsize(journal_filename) > 0:
            raise
        journal = None

    if journal is None:
        io.print_message(f'Creating new decision journal at {journal_filename}...')
        return DecisionJournal.for_baseline(secrets)

    io.print_message(f'Loaded decision journal from {journal_filename}.')
    return journal


def _make_recorder(
    journal: DecisionJournal,
    reviewer: Optional[str],
) -> Callable[[PotentialSecret, Optional[bool]], None]:
    if not reviewer:
        raise ValueError('A reviewer must be supplied when recording decisions to a journal.')

    def record(secret: PotentialSecret, is_secret: Optional[bool]) -> None:
        journal.record(secret=secret, reviewer=reviewer, is_secret=is_secret)

    return record


def _classify_secrets(
    iterator: BidirectionalIterator,
    recorder: Optional[Callable[[PotentialSecret, Optional[bool]], None]] = None,
) -> bool:
    """
    :param recorder: when provided, each explicit labelling decision is also forwarded to it.

    :returns: True if changes were made.
    """
    # NOTE: Technically, this is a conservative estimate. If an entry was changed to the same
    # value, we would return True as well.
    has_changes = False

    for secret in iterator:
        try:
            secret.secret_value = get_raw_secret_from_file(secret)
            io.clear_screen()
            io.print_context(
                SecretContext(
                    current_index=iterator.index + 1,
                    num_total_secrets=len(iterator.collection),
                    secret=secret,
                    snippet=get_code_snippet(
                        lines=open_file(secret.filename).raw_lines,
                        line_number=secret.line_number,
                    ),
                ),
            )

            decision = io.get_user_decision(can_step_back=iterator.can_step_back())
        except SecretNotFoundOnSpecifiedLineError as e:
            io.clear_screen()
            io.print_secret_not_found(
                SecretContext(
                    current_index=iterator.index + 1,
                    num_total_secrets=len(iterator.collection),
                    secret=secret,
                    error=e,
                ),
            )

            decision = io.get_user_decision(
                prompt_secret_decision=False,
                can_step_back=iterator.can_step_back(),
            )
        except NoLineNumberError as e:
            io.print_error(str(e))
            break

        if decision == io.InputOptions.QUIT:
            io.print_message('Quitting...')
            break

        if decision == io.InputOptions.BACK:
            iterator.step_back_on_next_iteration()

        # The question asked is: "Should this string be committed to the repository?"
        elif decision == io.InputOptions.NO:
            secret.is_secret = True
            has_changes = True
            if recorder:
                recorder(secret, True)
        elif decision == io.InputOptions.YES:
            secret.is_secret = False
            has_changes = True
            if recorder:
                recorder(secret, False)
        elif decision == io.InputOptions.SKIP and secret.is_secret is not None:
            # This handles the case of back-stepping to clear a mistake. In the baseline-only
            # flow it never fires for pre-labelled secrets, since those are excluded from the
            # iterator; a journal session includes them so a reviewer can clear a label instead.
            secret.is_secret = None
            has_changes = True
            if recorder:
                recorder(secret, None)

    return has_changes
