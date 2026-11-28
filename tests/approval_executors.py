"""
Local test helpers that model two business executors racing one approval.

Nothing here talks to a network or a real payment provider.  Two worker
threads share one instrumented fake payment backend so tests can count how
often the irreversible business action really ran, independently of whether
authentication or coexistence of a valid approval succeeded.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from django.db import OperationalError


@dataclass
class PaymentBackend:
    """
    Records actual payment calls.

    ``fail_record`` makes an executor fail while writing its finance record
    *after* the payment call went through, reproducing a "paid but not
    recorded" outcome.
    """

    lock: threading.Lock = field(default_factory=threading.Lock)
    calls: list[dict[str, Any]] = field(default_factory=list)
    record_attempts: int = 0
    fail_record: Callable[[int], bool] = lambda attempt: False

    def charge(self, approval, **_: Any) -> str:
        with self.lock:
            self.calls.append(
                {
                    "approval": approval.token_id,
                    "operation": approval.operation,
                    "amount": str(approval.amount),
                }
            )
            index = len(self.calls)
        return f"payment-{index}"

    def write_finance_record(self, receipt: str) -> str:
        with self.lock:
            self.record_attempts += 1
            attempt = self.record_attempts
            should_fail = self.fail_record(attempt)

        if should_fail:
            raise RuntimeError("finance record write failed")

        return f"record-for-{receipt}"

    @property
    def call_count(self) -> int:
        with self.lock:
            return len(self.calls)


class Executor:
    """
    One business executor holding its own copy of the *same* approval string.
    """

    def __init__(self, name: str, backend: PaymentBackend) -> None:
        self.name = name
        self.backend = backend
        self.outcome: dict[str, Any] = {}

    def operation_runner(self, grant) -> str:
        receipt = self.backend.charge(grant)
        return self.backend.write_finance_record(receipt)

    def start(
        self, commit: Callable[..., Any], approval: str, *, retries: int = 8
    ) -> None:
        """
        Runs one commit attempt.

        SQLite serializes writers and can reject contenders with a transient
        "database is locked" error, which real workers retry.  Retrying never
        re-runs a payment: an already-consumed approval is reported back
        instead of being charged again.
        """
        for attempt in range(1, retries + 1):
            try:
                record = commit(approval, operation_runner=self.operation_runner)
            except OperationalError as e:
                if attempt == retries:
                    self.outcome = {
                        "executor": self.name,
                        "status": "contended",
                        "error": type(e).__name__,
                        "message": str(e),
                    }
                    return
                time.sleep(0.01 * attempt)
                continue
            except Exception as e:  # noqa: BLE001 - outcome is the assertion subject
                self.outcome = {
                    "executor": self.name,
                    "status": "error",
                    "error": type(e).__name__,
                    "message": str(e),
                }
                return

            self.outcome = _outcome_from_record(self.name, record)
            return


def _outcome_from_record(name: str, record: Any) -> dict[str, Any]:
    """
    Normalises either a ``CommitOutcome`` or a commit endpoint's response dict.
    """
    if isinstance(record, dict):
        status = "committed" if record.get("executed") else "replayed"
        return {
            "executor": name,
            "status": status,
            "result": record.get("result"),
            "settled": record.get("settled", False),
            "approval": record.get("approval"),
        }
    return {
        "executor": name,
        "status": "committed" if record.executed else "replayed",
        "result": record.result,
        "settled": record.is_settled,
        "approval": record.token_id,
    }


def race(
    commit: Callable[..., Any],
    approval: str,
    *executors: Executor,
    release: Optional[threading.Barrier] = None,
) -> list[Executor]:
    """
    Releases every executor at the same instant so their commit attempts race.

    A barrier (rather than a plain ``start()``) is used so the test can assert
    both workers really reached the commit boundary together.
    """
    barrier = release or threading.Barrier(len(executors))

    def target(executor: Executor) -> None:
        barrier.wait()
        executor.start(commit, approval)

    threads = [
        threading.Thread(target=target, args=(e,), name=e.name, daemon=True)
        for e in executors
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=10)

    return list(executors)
