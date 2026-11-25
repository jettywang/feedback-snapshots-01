from __future__ import annotations

import dataclasses
from typing import Any, Literal


@dataclasses.dataclass(frozen=True)
class UnconfirmedMutation:
    """A mutating request whose remote outcome could not be determined.

    Instances are returned instead of the usual response data when the
    ``conservative_mutations`` option is enabled and the connection fails
    after the request may have reached the server. The library cannot know
    whether the change was applied, so it deliberately does not retry and
    leaves the decision to the caller.

    The caller can use :attr:`verb`, :attr:`path`, and :attr:`attempts` to
    reconcile the state with an independent read, a fresh lookup, or the
    server's audit log.
    """

    verb: str
    path: str
    error: str
    attempts: int = 1
    status: Literal["pending_verification"] = "pending_verification"

    @property
    def pending(self) -> bool:
        """Whether the remote outcome still needs to be verified."""
        return True

    @property
    def outcome(self) -> Literal["unknown"]:
        """The remote outcome, which is explicitly unknown."""
        return "unknown"

    def describe(self) -> dict[str, Any]:
        """Return a serializable description suitable for logs or reports."""
        return {
            "status": self.status,
            "outcome": self.outcome,
            "verb": self.verb,
            "path": self.path,
            "error": self.error,
            "attempts": self.attempts,
        }

    def __str__(self) -> str:
        return (
            f"{self.verb.upper()} {self.path} may have been applied "
            f"({self.error}); verify the remote state"
        )


#: Descriptive alias for callers that prefer the "pending" wording.
PendingMutation = UnconfirmedMutation

__all__ = ["PendingMutation", "UnconfirmedMutation"]
