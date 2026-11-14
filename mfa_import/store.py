"""Storage phase.

Planning and persistence are deliberately separate.  The planner has no side
effects; a caller that accepts an :class:`~mfa_import.model.ImportPlan` hands
it to a :class:`CredentialStore`.  Installation is two-phase: every
credential is staged first, and the whole batch is committed only if every
stage succeeds.  A failure rolls back every already-staged credential, so a
rejected plan can never leave a partially installed credential behind.
"""

from typing import List, Protocol, runtime_checkable

from .errors import ImportFailure
from .model import CredentialEntry, ImportPlan


@runtime_checkable
class CredentialStore(Protocol):
    def stage(self, entry: CredentialEntry) -> None: ...
    def commit(self) -> None: ...
    def rollback(self) -> None: ...


class InMemoryCredentialStore:
    """Reference store used by the demo and tests.

    ``installed`` only changes at commit time, so observing it after a failed
    installation proves that nothing was partially persisted.
    """

    def __init__(self):
        self._staged = {}
        self.installed = {}

    def stage(self, entry):
        if entry.key_id in self._staged or entry.key_id in self.installed:
            raise ImportFailure("credential identifier already exists")
        self._staged[entry.key_id] = entry

    def commit(self):
        self.installed.update(self._staged)
        self._staged = {}

    def rollback(self):
        self._staged = {}

    def installed_key_ids(self):
        return tuple(sorted(self.installed))


def install_plan(plan, store):
    """Persist an importable plan all-or-nothing.

    :returns: the number of credentials committed.
    :raises ImportFailure: if the plan is not importable or a stage fails;
        in either case every staged credential is rolled back.
    """
    if not isinstance(plan, ImportPlan):
        raise ImportFailure("expected an ImportPlan")
    if not plan.importable:
        raise ImportFailure("plan is not importable; refusing to install any credential")

    staged: List[CredentialEntry] = []
    try:
        for entry in plan.entries:
            store.stage(entry)
            staged.append(entry)
        store.commit()
    except Exception:
        store.rollback()
        raise
    return len(staged)
