from __future__ import annotations

import hashlib
import os
from typing import TYPE_CHECKING

from hatch.config.constants import ExecutionEnvVars

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable, Mapping

# The two stages of an automated run. Provisioning an environment (creating it and installing
# its declared dependencies) is one stage; running project-owned code is another and must be
# approved separately.
PREBUILD = "prebuild"
EXECUTE = "execute"

# Environment provisioning performed during the prebuild stage.
PROVISION = "provision"

# Executable actions are split so that approving a project command never implicitly approves
# an executable plugin callback (and vice versa).
PLUGIN_CALLBACK = "plugin-callback"
PROJECT_COMMAND = "project-command"

# Approving every action is also possible with this wildcard.
WILDCARD = "*"

_TRUTHY = frozenset({"1", "true", "yes", "on"})
_FALSY = frozenset({"", "0", "false", "no", "off", "none"})
_EVERYTHING = frozenset({WILDCARD, "all", "full"})
_PHASES = frozenset({PREBUILD, EXECUTE})


def _split_tokens(value: str | None) -> list[str]:
    return [token.strip() for token in (value or "").replace(";", ",").split(",") if token.strip()]


class ExecutionDenied(Exception):
    """Raised when an action needs a stage or approval that has not been granted."""

    def __init__(self, action: ExecutionAction, reason: str) -> None:
        self.action = action
        self.reason = reason
        super().__init__(self.message)

    @property
    def message(self) -> str:
        if self.action.phase == EXECUTE:
            if self.reason.startswith("phase"):
                return (
                    f"Executing `{self.action.label}` ({self.action.category}, environment "
                    f"`{self.action.environment}`) requires the `execute` stage, which "
                    f"{ExecutionEnvVars.POLICY} does not grant. Approve this exact action with "
                    f"{ExecutionEnvVars.APPROVAL}={self.action.fingerprint} and grant the stage, "
                    f"or use {ExecutionEnvVars.APPROVAL}={WILDCARD} to approve execution broadly."
                )

            return (
                f"Execution of `{self.action.label}` was denied ({self.action.category}, "
                f"environment `{self.action.environment}`). Approve this exact action with "
                f"{ExecutionEnvVars.APPROVAL}={self.action.fingerprint} or "
                f"{ExecutionEnvVars.APPROVAL}={WILDCARD} to approve execution broadly."
            )

        return (
            f"`{self.action.label}` was denied by the execution policy "
            f"(environment `{self.action.environment}` is not permitted to prebuild)."
        )


class ExecutionAction:
    """
    A single thing an automated run wants to do.

    The identity of an action deliberately excludes the current working directory so that the
    same action attempted after a directory change (or a retry after an exception) is matched
    against the same decision and, when applicable, the same approval token.
    """

    __slots__ = ("category", "environment", "label", "phase", "source", "working_directory")

    def __init__(
        self,
        phase: str,
        category: str,
        label: str,
        *,
        environment: str = "",
        source: str = "",
        working_directory: str | None = None,
    ) -> None:
        if phase not in _PHASES:
            message = f"Unknown execution phase: {phase}"
            raise ValueError(message)

        self.phase = phase
        self.category = category
        self.label = label
        self.environment = environment
        self.source = source
        # Recorded for diagnostics only; intentionally excluded from the fingerprint.
        self.working_directory = working_directory

    def __eq__(self, other: object) -> bool:
        return isinstance(other, ExecutionAction) and self.identity == other.identity

    def __hash__(self) -> int:
        return hash(self.identity)

    def __repr__(self) -> str:
        return (
            f"ExecutionAction(phase={self.phase!r}, category={self.category!r}, label={self.label!r}, "
            f"environment={self.environment!r})"
        )

    @property
    def identity(self) -> tuple[str, str, str, str]:
        return (self.phase, self.category, self.environment, self.label)

    @property
    def fingerprint(self) -> str:
        digest = hashlib.sha256()
        for part in self.identity:
            digest.update(part.encode("utf-8"))
            digest.update(b"\0")

        return digest.hexdigest()[:16]

    def copy(self, **changes) -> ExecutionAction:
        data = {
            "phase": self.phase,
            "category": self.category,
            "label": self.label,
            "environment": self.environment,
            "source": self.source,
            "working_directory": self.working_directory,
        }
        data.update(changes)
        return ExecutionAction(**data)


class ExecutionDecision:
    __slots__ = ("action", "allowed", "reason")

    def __init__(self, action: ExecutionAction, allowed: bool, reason: str) -> None:
        self.action = action
        self.allowed = allowed
        self.reason = reason

    def __repr__(self) -> str:
        return f"ExecutionDecision(action={self.action!r}, allowed={self.allowed!r}, reason={self.reason!r})"

    @property
    def phase(self) -> str:
        return self.action.phase

    @property
    def category(self) -> str:
        return self.action.category

    @property
    def label(self) -> str:
        return self.action.label

    @property
    def environment(self) -> str:
        return self.action.environment

    @property
    def fingerprint(self) -> str:
        return self.action.fingerprint

    @property
    def message(self) -> str:
        return ExecutionDenied(self.action, self.reason).message


class ExecutionPolicy:
    """
    The optional runtime convention.

    It is disabled unless ``HATCH_EXECUTION_POLICY`` explicitly opts in, so existing behavior is
    untouched. When enabled, the ``prebuild`` stage permits environment provisioning while the
    ``execute`` stage additionally considers project commands and executable plugin callbacks;
    every execute action still requires a matching approval token.
    """

    __slots__ = ("approvals", "enabled", "phases")

    def __init__(
        self,
        *,
        enabled: bool = False,
        phases: Iterable[str] = (),
        approvals: Iterable[str] = (),
    ) -> None:
        self.enabled = enabled
        self.phases = frozenset(phases)
        self.approvals = frozenset(approvals)

    def __repr__(self) -> str:
        return (
            f"ExecutionPolicy(enabled={self.enabled!r}, phases={sorted(self.phases)!r}, "
            f"approvals={sorted(self.approvals)!r})"
        )

    @classmethod
    def from_environ(cls, environ: Mapping[str, str] | None = None) -> ExecutionPolicy:
        environ = os.environ if environ is None else environ

        return cls.from_values(
            environ.get(ExecutionEnvVars.POLICY),
            (environ.get(ExecutionEnvVars.APPROVAL) or "",),
        )

    @classmethod
    def from_values(cls, raw_policy: str | None, approvals: Iterable[str] = ()) -> ExecutionPolicy:
        raw = (raw_policy or "").strip()
        if raw.lower() in _FALSY:
            return cls()

        if raw.lower() in _TRUTHY or raw.lower() in _EVERYTHING:
            phases = set(_PHASES)
        else:
            phases = set()
            for token in _split_tokens(raw):
                token = token.lower()
                if token in _PHASES:
                    phases.add(token)
                elif token in _EVERYTHING:
                    phases.update(_PHASES)
                else:
                    message = f"Unknown execution phase `{token}` in {ExecutionEnvVars.POLICY}: {raw}"
                    raise ValueError(message)

        # Execution is meaningless without provisioning, so granting it implies prebuild.
        if EXECUTE in phases:
            phases.add(PREBUILD)

        tokens: list[str] = []
        for entry in approvals:
            tokens.extend(_split_tokens(entry))

        return cls(enabled=True, phases=phases, approvals=tokens)

    @property
    def prebuild_enabled(self) -> bool:
        return self.enabled and PREBUILD in self.phases

    @property
    def execute_enabled(self) -> bool:
        return self.enabled and EXECUTE in self.phases

    def phase_granted(self, phase: str) -> bool:
        return not self.enabled or phase in self.phases

    def authorizes(self, action: ExecutionAction) -> bool:
        return WILDCARD in self.approvals or action.fingerprint in self.approvals

    def requires_approval(self, action: ExecutionAction) -> bool:
        """Whether a given action would need an approval token once its phase is granted."""
        if not self.enabled or action.phase != EXECUTE:
            return False

        return not self.authorizes(action)


class ExecutionEvent:
    """A single entry in the execution journal, used to show what did and did not run."""

    __slots__ = ("allowed", "category", "fingerprint", "label", "phase", "status", "working_directory")

    def __init__(self, decision: ExecutionDecision, status: str) -> None:
        self.phase = decision.phase
        self.category = decision.category
        self.label = decision.label
        self.fingerprint = decision.fingerprint
        self.allowed = decision.allowed
        self.status = status
        self.working_directory = decision.action.working_directory

    def __repr__(self) -> str:
        return (
            f"ExecutionEvent(status={self.status!r}, phase={self.phase!r}, "
            f"category={self.category!r}, label={self.label!r})"
        )

    @property
    def executed(self) -> bool:
        return self.status == "executed"

    @property
    def blocked(self) -> bool:
        return self.status == "denied"

    def as_dict(self) -> dict[str, str | bool]:
        return {
            "phase": self.phase,
            "category": self.category,
            "label": self.label,
            "fingerprint": self.fingerprint,
            "allowed": self.allowed,
            "status": self.status,
        }


class ExecutionGate:
    """
    Applies an :class:`ExecutionPolicy` to attempted actions.

    Decisions are memoized by fingerprint so the outcome is stable across working directory
    changes and retries after exceptions. A denied action never runs; approving its fingerprint
    clears only that denial, so a retry runs exactly the approved action and nothing else.
    """

    __slots__ = ("_approvals", "_decisions", "_executed", "events", "policy")

    def __init__(self, policy: ExecutionPolicy | None = None) -> None:
        self.policy = policy or ExecutionPolicy()
        self._approvals = set(self.policy.approvals)
        self._decisions: dict[str, ExecutionDecision] = {}
        self._executed: set[str] = set()
        self.events: list[ExecutionEvent] = []

    def approve(self, *tokens: str) -> None:
        """
        Grant approvals for the remainder of this run. Tokens are action fingerprints (as shown
        when an action is denied) or the wildcard ``*``.

        Only denied decisions are invalidated, so previously denied actions stay blocked until
        they are approved explicitly.
        """
        added = {token.strip() for token in tokens if token and token.strip()}
        if not added:
            return

        self._approvals.update(added)
        for fingerprint, decision in list(self._decisions.items()):
            if not decision.allowed:
                self._decisions.pop(fingerprint)

    def authorizes(self, action: ExecutionAction) -> bool:
        return WILDCARD in self._approvals or action.fingerprint in self._approvals

    def evaluate(self, action: ExecutionAction) -> ExecutionDecision:
        if not self.policy.enabled:
            return ExecutionDecision(action, True, "policy disabled")

        if action.phase not in self.policy.phases:
            return ExecutionDecision(action, False, f"phase `{action.phase}` not granted")

        if action.phase == EXECUTE and not self.authorizes(action):
            return ExecutionDecision(action, False, "no matching approval")

        return ExecutionDecision(action, True, "allowed")

    def decide(self, action: ExecutionAction) -> ExecutionDecision:
        key = action.fingerprint
        if key not in self._decisions:
            self._decisions[key] = self.evaluate(action)

        return self._decisions[key]

    def _journal(self, action: ExecutionAction, status: str, allowed: bool) -> None:
        if self.policy.enabled:
            self.events.append(ExecutionEvent(ExecutionDecision(action, allowed, status), status))

    def check(self, action: ExecutionAction) -> bool:
        """Whether the action may run, without journaling the decision."""
        return self.decide(action).allowed

    def request(self, action: ExecutionAction, *, defer: bool = False) -> bool:
        """
        Ask permission for an action and journal the outcome.

        Returns whether the action may run. Denials are recorded as ``denied`` or, when
        ``defer`` is true, as ``deferred``. Deferring is used by the prebuild stage for
        executable steps that must not abort provisioning but must not run yet either.
        """
        decision = self.decide(action)
        if decision.allowed:
            return True

        self._journal(action, "deferred" if defer else "denied", False)
        return False

    def require(self, action: ExecutionAction) -> None:
        if not self.request(action):
            decision = self.decide(action)
            raise ExecutionDenied(action, decision.reason)

    def mark_executed(self, action: ExecutionAction) -> None:
        self._executed.add(action.fingerprint)
        self._journal(action, "executed", True)

    def mark_failed(self, action: ExecutionAction) -> None:
        """Journal an approved action whose execution raised, so a retry can run it again."""
        self._executed.discard(action.fingerprint)
        self._journal(action, "failed", True)

    def attempt(self, action: ExecutionAction, callback: Callable[[], object]) -> tuple[bool, object]:
        """
        Run ``callback`` at most once per action, and only when allowed.

        Returns ``(executed, result)``. A blocked action records a ``denied`` event and leaves
        the callback untouched. A successfully executed action is never run again; an action
        whose callback raised is recorded as ``failed`` so a retry after the exception is still
        governed by the same decision and can run.
        """
        if not self.request(action):
            return False, None

        if action.fingerprint in self._executed:
            return True, None

        try:
            result = callback()
        except BaseException:
            self.mark_failed(action)
            raise

        self.mark_executed(action)
        return True, result

    def run(self, action: ExecutionAction, callback: Callable[[], object]) -> bool:
        """Like :meth:`attempt` but discards the callback result."""
        return self.attempt(action, callback)[0]

    def provision(self, action: ExecutionAction) -> None:
        """
        Record a prebuild provisioning step.

        Provisioning does not execute project code, so once the prebuild stage is granted it is
        always allowed. It is journaled as executed so the prebuild stage is visible in
        comparison records alongside the executable actions.
        """
        decision = self.decide(action)
        if not decision.allowed:
            self._journal(action, "denied", False)
            raise ExecutionDenied(action, decision.reason)

        self._journal(action, "executed", True)

    @property
    def executed(self) -> list[str]:
        return list(self._executed)

    @property
    def pending(self) -> list[ExecutionDecision]:
        """Execute-phase actions that were denied and would run once approved."""
        seen = set()
        pending = []
        for fingerprint, decision in self._decisions.items():
            if (
                not decision.allowed
                and decision.phase == EXECUTE
                and fingerprint not in self._executed
                and fingerprint not in seen
            ):
                seen.add(fingerprint)
                pending.append(decision)

        return pending

    def summary(self) -> list[dict[str, str | bool]]:
        return [event.as_dict() for event in self.events]

    def write_journal(self, path: str | os.PathLike[str] | None = None) -> bool:
        """
        Persist the execution journal as JSON so an automated caller can compare what ran.

        The destination defaults to ``HATCH_EXECUTION_JOURNAL``. Returns whether anything was
        written; a disabled policy produces no journal.
        """
        import json
        from pathlib import Path

        destination = path or os.environ.get(ExecutionEnvVars.JOURNAL)
        if not destination or not self.policy.enabled:
            return False

        events = self.summary()
        data = {
            "version": 1,
            "policy": {
                "enabled": self.policy.enabled,
                "phases": sorted(self.policy.phases),
                "approvals": sorted(self._approvals),
            },
            "totals": {
                "executed": sum(1 for event in events if event["status"] == "executed"),
                "denied": sum(1 for event in events if event["status"] == "denied"),
                "deferred": sum(1 for event in events if event["status"] == "deferred"),
                "failed": sum(1 for event in events if event["status"] == "failed"),
            },
            "events": events,
            "pending": [
                {
                    "phase": decision.phase,
                    "category": decision.category,
                    "label": decision.label,
                    "environment": decision.environment,
                    "fingerprint": decision.fingerprint,
                }
                for decision in self.pending
            ],
        }

        journal_path = Path(destination)
        journal_path.parent.mkdir(parents=True, exist_ok=True)
        journal_path.write_text(json.dumps(data, indent=2))
        return True
