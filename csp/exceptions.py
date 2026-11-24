from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from csp.utils import PolicyBuildResult


class CSPNonceError(Exception):
    pass


class CSPPolicyTooLongError(Exception):
    """Raised when an assembled CSP header exceeds its configured size budget.

    The middleware never writes a truncated policy: delivering an incomplete
    Content-Security-Policy would silently weaken the intended protections.
    """

    def __init__(self, result: PolicyBuildResult, header: str) -> None:
        self.result = result
        self.header = header
        self.limit = result.size_limit
        self.policy = result.policy
        self.policy_size = result.policy_size
        self.offending_directive = result.offending_directive
        self.offending_directive_size = result.offending_directive_size
        super().__init__(
            (
                f"{header} policy is {result.policy_size} bytes, exceeding the configured "
                f"POLICY_SIZE_LIMIT of {result.size_limit} bytes. "
                f"The directive {result.offending_directive!r} ("
                f"{result.offending_directive_size} bytes) caused the overflow. "
                f"Assembled policy: {result.policy!r}"
            )
        )
