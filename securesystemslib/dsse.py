"""Dead Simple Signing Envelope"""

from __future__ import annotations

import logging
import threading
import time
from concurrent.futures import (
    CancelledError,
    Future,
    ThreadPoolExecutor,
    wait,
)
from dataclasses import dataclass
from typing import Any

from securesystemslib import exceptions
from securesystemslib._internal.utils import b64dec, b64enc, make_hashable
from securesystemslib.signer import Key, Signature, Signer

logger = logging.getLogger(__name__)

# How often to wake a blocking wait in order to re-check a caller-supplied
# cancel event when no overall timeout bounds the call.
_CANCEL_POLL_INTERVAL = 0.05


@dataclass(frozen=True)
class _WorkItem:
    """A single, immutable (key, signature) verification task.

    The work plan is computed once from a fixed snapshot of the envelope
    signatures and the trusted keys, before any plugin code is scheduled.
    Workers therefore never observe caller mutations of the envelope or the
    key list.
    """

    keyid: str
    key: Key
    signature: Signature


@dataclass(frozen=True)
class _Outcome:
    """Result of running one ``_WorkItem``."""

    keyid: str
    status: str  # one of "verified", "bad", "fault"
    error: Exception | None = None


@dataclass(frozen=True)
class _Plan:
    """The immutable, pre-scheduled verification inputs."""

    pae: bytes
    trusted: dict[str, Key]
    work: tuple[_WorkItem, ...]
    threshold: int
    max_workers: int
    timeout: float | None
    cancel_event: threading.Event | None


@dataclass(frozen=True)
class _ParallelOptions:
    """Caller-chosen bounds for a parallel verification run."""

    max_workers: int
    timeout: float | None
    cancel_event: threading.Event | None


def _run_verification(item: _WorkItem, pae: bytes) -> _Outcome:
    """Worker callable: run one plugin verification and classify the result.

    A bad signature (``UnverifiedSignatureError``) is distinguished from a
    plugin/process failure (any other exception). The latter is captured as
    an outcome instead of escaping the worker, so one failing plugin cannot
    tear down the executor or the other in-flight verifications.
    """
    try:
        item.key.verify_signature(item.signature, pae)
        return _Outcome(item.keyid, "verified")

    except exceptions.UnverifiedSignatureError as error:
        return _Outcome(item.keyid, "bad", error)

    except Exception as error:  # plugin boundary: classify every other failure
        logger.info("Key %s verification plugin failed: %s", item.keyid, error)
        return _Outcome(item.keyid, "fault", error)


def _run_bounded_plan(plan: _Plan) -> tuple[dict[str, Key], Exception | None]:
    """Execute a fixed plan under a concurrency bound.

    Returns the accepted signers and the first plugin fault (if any). New work
    is only submitted while the threshold remains achievable; once the
    threshold is met, or the call is cancelled/timed out, no further results
    are applied. In-flight plugin calls that cannot be force-terminated are
    drained and their outcomes discarded.
    """
    outstanding: dict[str, int] = {}
    for item in plan.work:
        outstanding[item.keyid] = outstanding.get(item.keyid, 0) + 1

    accepted: dict[str, Key] = {}
    first_fault: Exception | None = None
    in_flight: set[Future[_Outcome]] = set()
    index = 0
    start = time.monotonic()

    def time_left() -> float | None:
        if plan.timeout is None:
            return None
        return max(0.0, plan.timeout - (time.monotonic() - start))

    with ThreadPoolExecutor(
        max_workers=plan.max_workers,
        thread_name_prefix="dsse-verify",
    ) as executor:
        while True:
            left = time_left()
            cancelled = (
                plan.cancel_event is not None and plan.cancel_event.is_set()
            ) or (left is not None and left <= 0.0)

            # Signers that can still contribute: already accepted, or with at
            # least one candidate that has not finished yet.
            achievable = len(accepted) + sum(
                1 for keyid in outstanding if keyid not in accepted
            )

            # Submit up to the concurrency bound while success is still
            # possible. No work is launched after the threshold is met, after
            # cancellation/timeout, or once it becomes impossible.
            if (
                not cancelled
                and len(accepted) < plan.threshold
                and achievable >= plan.threshold
            ):
                while len(in_flight) < plan.max_workers and index < len(plan.work):
                    item = plan.work[index]
                    index += 1
                    if item.keyid in accepted:
                        # Already counted this signer: drop redundant work
                        # instead of scheduling another plugin call.
                        outstanding[item.keyid] -= 1
                        continue
                    in_flight.add(executor.submit(_run_verification, item, plan.pae))

            if not in_flight:
                break

            # With a cancel event but no overall timeout, wake periodically so a
            # caller request is noticed even if nothing completes.
            wait_timeout = left
            if plan.cancel_event is not None:
                wait_timeout = (
                    _CANCEL_POLL_INTERVAL
                    if wait_timeout is None
                    else min(wait_timeout, _CANCEL_POLL_INTERVAL)
                )

            done, in_flight = wait(
                in_flight,
                timeout=wait_timeout,
                return_when="FIRST_COMPLETED",
            )

            if cancelled:
                # No result is applied after cancellation/timeout. The plugin
                # calls already running cannot be force-terminated, so they are
                # drained here and their outcomes discarded. ``done`` may be
                # empty when the wait timed out without any completion.
                pending = in_flight | done
                if pending:
                    wait(pending)
                if plan.cancel_event is not None and plan.cancel_event.is_set():
                    raise CancelledError(
                        "Verification was cancelled before threshold was met"
                    )
                raise TimeoutError("Verification timed out before threshold was met")

            for future in done:
                outcome = future.result()
                outstanding[outcome.keyid] -= 1

                if len(accepted) >= plan.threshold:
                    # Threshold already reached: ignore late completions.
                    continue

                if outcome.status == "verified":
                    # setdefault guarantees one count per signer regardless of
                    # how many of its candidates return successfully.
                    accepted.setdefault(outcome.keyid, plan.trusted[outcome.keyid])
                elif outcome.status == "fault" and first_fault is None:
                    first_fault = outcome.error

            if len(accepted) >= plan.threshold:
                # Threshold reached: submit and apply nothing further. The
                # context manager waits for in-flight plugins to finish and
                # discards their results.
                return accepted, first_fault

    return accepted, first_fault


class Envelope:
    """DSSE Envelope to provide interface for signing arbitrary data.

    Attributes:
        payload: Arbitrary byte sequence of serialized body.
        payload_type: string that identifies how to interpret payload.
        signatures: dict of Signature key id and Signatures.

    """

    def __init__(
        self,
        payload: bytes,
        payload_type: str,
        signatures: dict[str, Signature],
    ):
        self.payload = payload
        self.payload_type = payload_type
        self.signatures = signatures

    def __eq__(self, other: Any) -> bool:
        if not isinstance(other, Envelope):
            return False

        return (
            self.payload == other.payload
            and self.payload_type == other.payload_type
            and self.signatures == other.signatures
        )

    def __hash__(self) -> int:
        return hash(
            (
                self.payload,
                self.payload_type,
                make_hashable(self.signatures),
            )
        )

    @classmethod
    def from_dict(cls, data: dict) -> Envelope:
        """Creates a DSSE Envelope from its JSON/dict representation.

        Arguments:
            data: A dict containing a valid payload, payloadType and signatures

        Raises:
            KeyError: If any of the "payload", "payloadType" and "signatures"
                fields are missing from the "data".

            FormatError: If signature in "signatures" is incorrect.

        Returns:
            A "Envelope" instance.
        """

        payload = b64dec(data["payload"])
        payload_type = data["payloadType"]

        signatures = {}
        for signature in data["signatures"]:
            signature["sig"] = b64dec(signature["sig"]).hex()
            sig = Signature.from_dict(signature)
            if sig.keyid in signatures:
                raise ValueError(f"Multiple signatures found for keyid {sig.keyid}")
            signatures[sig.keyid] = sig
        return cls(payload, payload_type, signatures)

    def to_dict(self) -> dict:
        """Returns the JSON-serializable dictionary representation of self."""

        signatures = []
        for signature in self.signatures.values():
            sig_dict = signature.to_dict()
            sig_dict["sig"] = b64enc(bytes.fromhex(sig_dict["sig"]))
            signatures.append(sig_dict)

        return {
            "payload": b64enc(self.payload),
            "payloadType": self.payload_type,
            "signatures": signatures,
        }

    def pae(self) -> bytes:
        """Pre-Auth-Encoding byte sequence of self."""

        payload_type = self.payload_type.encode("utf-8")
        return b"DSSEv1 %d %b %d %b" % (
            len(payload_type),
            payload_type,
            len(self.payload),
            self.payload,
        )

    def sign(self, signer: Signer) -> Signature:
        """Sign the payload and create the signature.

        Arguments:
            signer: A "Signer" class instance.

        Returns:
            A "Signature" instance.
        """

        signature = signer.sign(self.pae())
        self.signatures[signature.keyid] = signature

        return signature

    def verify(self, keys: list[Key], threshold: int) -> dict[str, Key]:
        """Verify the payload with the provided Keys.

        Arguments:
            keys: A list of public keys to verify the signatures.
            threshold: Number of signatures needed to pass the verification.

        Raises:
            ValueError: If "threshold" is not valid.
            VerificationError: If the enclosed signatures do not pass the
                verification.

        Note:
            Mandating keyid in signatures and matching them with keyid of Key
            in order to consider them for verification, is not DSSE spec
            compliant (Issue #416).

        Returns:
            A dict of the threshold of unique public keys that verified a
            signature.
        """

        accepted_keys = {}
        pae = self.pae()

        # checks for threshold value.
        if threshold <= 0:
            raise ValueError("Threshold must be greater than 0")

        if len(keys) < threshold:
            raise ValueError("Number of keys can't be less than threshold")

        for signature in self.signatures.values():
            for key in keys:
                # If Signature keyid doesn't match with Key, skip.
                if not key.keyid == signature.keyid:
                    continue

                # If a key verifies the signature, we exit and use the result.
                try:
                    key.verify_signature(signature, pae)
                    accepted_keys[key.keyid] = key
                    break
                except exceptions.UnverifiedSignatureError:
                    continue

            # Break, if amount of accepted_keys are more than threshold.
            if len(accepted_keys) >= threshold:
                break

        if threshold > len(accepted_keys):
            raise exceptions.VerificationError(
                "Accepted signatures do not match threshold,"
                f" Found: {len(accepted_keys)}, Expected {threshold}"
            )

        return accepted_keys

    def _build_plan(
        self,
        keys: list[Key],
        threshold: int,
        options: _ParallelOptions,
    ) -> _Plan:
        """Snapshot the envelope and trusted keys into an immutable plan."""
        pae = self.pae()
        trusted = {key.keyid: key for key in keys}
        work = []
        for signature in self.signatures.values():
            key = trusted.get(signature.keyid)
            if key is not None:
                work.append(_WorkItem(signature.keyid, key, signature))

        return _Plan(
            pae=pae,
            trusted=trusted,
            work=tuple(work),
            threshold=threshold,
            max_workers=options.max_workers,
            timeout=options.timeout,
            cancel_event=options.cancel_event,
        )

    def verify_parallel(  # noqa: PLR0913 - public API mirrors verify() plus bounds
        self,
        keys: list[Key],
        threshold: int,
        max_workers: int,
        timeout: float | None = None,
        cancel_event: threading.Event | None = None,
    ) -> dict[str, Key]:
        """Verify the payload with the provided Keys, bounded in parallel.

        This is an optional, parallel entry point with the same threshold
        semantics as :meth:`verify`: it returns the unique public keys that
        verified a signature once their number reaches ``threshold``. The
        number of concurrently running verification plugins never exceeds
        ``max_workers``, and the total amount of plugin work is bounded by the
        number of (key, signature) pairs -- a malicious envelope cannot expand
        into unbounded work. Each signer (keyid) is counted at most once, no
        matter how many candidate signatures verify for it.

        Arguments:
            keys: A list of public keys to verify the signatures.
            threshold: Number of distinct signers needed to pass.
            max_workers: Upper bound on concurrently running verifications;
                must be a positive integer.
            timeout: If given, maximum total seconds to wait for verification.
                Work already running in a plugin cannot be force-terminated:
                on timeout no new work is submitted and in-flight calls are
                allowed to finish, but their results are discarded.
            cancel_event: Caller-set event that cooperatively cancels
                verification. As with ``timeout``, in-flight plugin calls are
                awaited for cleanup but their results are not applied.

        Raises:
            ValueError: If ``threshold`` or ``max_workers`` is invalid.
            TimeoutError: If ``timeout`` elapses before the threshold is met.
            CancelledError: If ``cancel_event`` is set before success.
            exceptions.VerificationError: If the threshold cannot be reached
                (not enough valid signatures), or a verification plugin fails
                in a way that makes the threshold unreachable. The original
                plugin error is attached as ``__cause__`` when applicable.

        Returns:
            A dict of the threshold of unique public keys that verified a
            signature.
        """
        if threshold <= 0:
            raise ValueError("Threshold must be greater than 0")

        if len(keys) < threshold:
            raise ValueError("Number of keys can't be less than threshold")

        if not isinstance(max_workers, int) or max_workers <= 0:
            raise ValueError("max_workers must be a positive integer")

        if timeout is not None and timeout < 0:
            raise ValueError("timeout must not be negative")

        if cancel_event is not None and cancel_event.is_set():
            raise CancelledError("Verification was cancelled before it started")

        # Fix the input and the trusted-key view before scheduling anything.
        options = _ParallelOptions(max_workers, timeout, cancel_event)
        plan = self._build_plan(keys, threshold, options)

        candidate_signers = {item.keyid for item in plan.work}
        if len(candidate_signers) < threshold:
            raise exceptions.VerificationError(
                "Accepted signatures do not match threshold,"
                f" Found: 0, Expected {threshold}"
            )

        accepted, first_fault = _run_bounded_plan(plan)

        if len(accepted) >= threshold:
            return accepted

        if first_fault is not None:
            raise exceptions.VerificationError(
                "Verification plugin failed and threshold could not be met"
            ) from first_fault

        raise exceptions.VerificationError(
            "Accepted signatures do not match threshold,"
            f" Found: {len(accepted)}, Expected {threshold}"
        )
