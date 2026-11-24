from __future__ import annotations

import copy
import threading
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Optional

from dynaconf.nodes import recursively_evaluate_lazy_format
from dynaconf.utils import to_dict
from dynaconf.validator import ValidationError

if TYPE_CHECKING:
    from dynaconf.base import Settings

_MEMORY_LOADER_PATH = "dynaconf.loaders.memory_loader"


class TransactionError(RuntimeError):
    """Raised when a transaction is used outside of its lifecycle."""


class TransactionCancelled(TransactionError):
    """Raised when committing or writing into a cancelled transaction."""


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class CandidateRecord:
    """Diagnostic information about a configuration candidate.

    Every candidate - committed, failed or cancelled - is retained so an
    operator can trace back why a generation never became effective.
    """

    generation: int
    status: str  # "committed" | "failed" | "cancelled"
    started_at: str
    finished_at: Optional[str] = None
    error: Optional[str] = None
    changes: dict = field(default_factory=dict)

    def as_dict(self) -> dict:
        return {
            "generation": self.generation,
            "status": self.status,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "error": self.error,
            "changes": copy.deepcopy(self.changes),
        }


class ConfigTransaction:
    """A staged, all-or-nothing configuration update.

    Proposed writes are buffered while the transaction is open and never touch
    the live settings. At :meth:`commit` the manager rebases the buffer onto a
    private copy of the *latest* approved configuration, validates it, and only
    then swaps the whole core into place in a single step. Readers therefore
    always observe a complete, validated generation.
    """

    def __init__(self, manager: "TransactionManager", generation: int):
        self._manager = manager
        self.generation = generation
        self._status = "open"
        self._record = CandidateRecord(
            generation=generation,
            status="open",
            started_at=_now_iso(),
        )
        # Ordered buffer of (key, value, kwargs) staged by the caller.
        self._buffer: list[tuple] = []

    @property
    def status(self) -> str:
        return self._status

    @property
    def record(self) -> CandidateRecord:
        return self._record

    def _ensure_open(self) -> None:
        if self._status == "cancelled":
            raise TransactionCancelled(
                f"Transaction generation {self.generation} was cancelled"
            )
        if self._status != "open":
            raise TransactionError(
                f"Transaction generation {self.generation} is {self._status}"
            )

    def set(self, key, value, **kwargs):
        """Stage a single key/value into the candidate generation."""
        self._ensure_open()
        self._buffer.append((key, value, kwargs))
        self._record.changes[key] = value
        return self

    def update(self, data=None, **kwargs):
        """Stage a mapping of key/value pairs into the candidate generation."""
        merged = dict(data or {})
        merged.update(kwargs)
        for key, value in merged.items():
            self.set(key, value)
        return self

    def commit(self, validate: str | bool = "all") -> int:
        """Validate the staged candidate and, if valid, publish it atomically.

        :param validate: ``"all"`` (default) collects every validator error,
         ``True`` stops at the first failure, or ``False`` skips validation.
        :return: the committed generation number.
        """
        self._ensure_open()
        try:
            with self._manager._lock:
                self._manager._apply_and_publish(self, validate)
                self._status = "committed"
                self._record.status = "committed"
                self._record.finished_at = _now_iso()
                self._manager._archive(self._record)
                return self.generation
        except Exception as exc:  # noqa: BLE001 - diagnosed and re-raised
            self._abort(exc)
            raise

    def _abort(self, exc: Exception) -> None:
        # The live object is never mutated on failure; retain the rejected
        # candidate for post-mortem diagnostics.
        self._status = "failed"
        self._record.status = "failed"
        self._record.finished_at = _now_iso()
        self._record.error = f"{type(exc).__name__}: {exc}"
        self._manager._archive(self._record)

    def cancel(self, reason: Optional[str] = None) -> None:
        """Discard a candidate without touching the live configuration."""
        if self._status != "open":
            return
        self._status = "cancelled"
        self._record.status = "cancelled"
        self._record.finished_at = _now_iso()
        self._record.error = reason
        self._manager._archive(self._record)

    def __enter__(self) -> "ConfigTransaction":
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:
        if exc_type is not None:
            if self._status == "open":
                self.cancel(reason=f"{exc_type.__name__}: {exc}")
            return False
        if self._status == "open":
            self.commit()
        return False


class TransactionManager:
    """Coordinates generation-based, atomic configuration updates.

    A single re-entrant lock serialises the build-validate-swap critical
    section, while reads stay lock-free and always resolve against a complete,
    approved generation because the core is replaced atomically. The manager
    also retains diagnostic history for every candidate.
    """

    def __init__(self, settings: "Settings"):
        self.settings = settings
        self._lock = threading.RLock()
        self._generation = 0
        self._history: list[CandidateRecord] = []
        self._ensure_memory_loader(settings)
        # Deep copy of the currently approved core for instant rollback.
        self._approved = copy.deepcopy(settings.__core__)

    @staticmethod
    def _ensure_memory_loader(settings: "Settings") -> None:
        loaders = settings.LOADERS_FOR_DYNACONF
        if _MEMORY_LOADER_PATH not in list(loaders):
            loaders.append(_MEMORY_LOADER_PATH)
        # Reset the resolved loader cache so the new loader gets imported.
        settings.__core__.config.loaders = []

    @property
    def generation(self) -> int:
        return self._generation

    @property
    def current_generation(self) -> int:
        return self._generation

    @contextmanager
    def consistent_read(self):
        """Pin settings to one approved generation for a block of reads.

        A commit swaps the whole core atomically, but reading several keys one
        by one can otherwise straddle a swap. Holding the core returned here
        guarantees every read inside the ``with`` block resolves against the
        same complete generation.

        Example::

            with manager.consistent_read() as view:
                one = view("ITEM_ONE")
                two = view("ITEM_TWO")  # always from the same generation
        """
        # One attribute read pins the core reference for the whole block.
        core = self.settings.__core__
        obj = core.obj

        def view(key, default=None):
            value = core.store.get(key, default)
            return recursively_evaluate_lazy_format(value, obj)

        view.generation = self._generation
        view.core = core
        try:
            yield view
        finally:
            pass

    def read_generation(self) -> tuple[int, dict]:
        """Return the current generation and a coherent snapshot of its data.

        The returned mapping is materialised from a single pinned core, so all
        keys belong to one validated generation even under concurrent commits.
        """
        core = self.settings.__core__
        return self._generation, to_dict(core.store)

    def history(self, status: Optional[str] = None) -> list[dict]:
        """Return diagnostic records, optionally filtered by status."""
        records = self._history
        if status is not None:
            records = [r for r in records if r.status == status]
        return [r.as_dict() for r in records]

    def candidate(self, generation: int) -> Optional[dict]:
        """Look up the diagnostic record for a specific generation."""
        for record in self._history:
            if record.generation == generation:
                return record.as_dict()
        return None

    def begin(self) -> ConfigTransaction:
        """Start a new candidate generation."""
        with self._lock:
            self._generation += 1
            return ConfigTransaction(self, self._generation)

    @contextmanager
    def transaction(self):
        tx = self.begin()
        try:
            yield tx
        except Exception:
            if tx.status == "open":
                tx.cancel()
            raise
        else:
            if tx.status == "open":
                tx.commit()

    def _apply_and_publish(self, tx: ConfigTransaction, validate) -> None:
        settings = self.settings

        # Build the candidate on a private copy of the LATEST approved core.
        # Rebasing here means transactions that committed while this one was
        # open are preserved instead of being overwritten.
        candidate_core = copy.deepcopy(settings.__core__)
        candidate_core.cache_enabled = False
        candidate_obj = candidate_core.obj
        candidate_obj.__core__ = candidate_core

        # Re-point validators at the candidate so they validate the new record.
        validators = candidate_core.validators
        original_validator_settings = validators.settings
        validators.settings = candidate_obj
        try:
            for key, value, kwargs in tx._buffer:
                candidate_obj.set(key, value, validate=False, **kwargs)

            if validate == "all":
                errors = validators.validate_all(raise_error=False)
                if errors:
                    raise ValidationError("; ".join(str(e) for e in errors))
            elif validate:
                validators.validate()

            # Record raw committed values so a fresh read (which re-runs the
            # loaders) reproduces this approved generation rather than files.
            registry = candidate_core.config.memory_generation_data
            for key, value, _ in tx._buffer:
                registry[key] = value
        finally:
            validators.settings = original_validator_settings

        # Publish in one assignment: readers never observe a partial record.
        candidate_core.obj = settings
        candidate_core.cache_enabled = True
        candidate_core.clear_cache()
        self._approved = copy.deepcopy(settings.__core__)
        settings.__core__ = candidate_core
        self._generation = tx.generation

    def _archive(self, record: CandidateRecord) -> None:
        self._history.append(record)

    def rollback(self) -> int:
        """Restore the configuration to the previous approved generation."""
        with self._lock:
            current = copy.deepcopy(self.settings.__core__)
            restored = copy.deepcopy(self._approved)
            restored.obj = self.settings
            restored.clear_cache()
            self.settings.__core__ = restored
            self._approved = current
            self._generation += 1
            record = CandidateRecord(
                generation=self._generation,
                status="committed",
                started_at=_now_iso(),
                finished_at=_now_iso(),
                changes={"rollback": True},
            )
            self._archive(record)
            return self._generation
