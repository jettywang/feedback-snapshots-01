# Copyright: (c) 2026, pyspnego contributors
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

"""Public interface for the replay-safe NTLM challenge state.

The pure Python NTLM acceptor accepts ``challenge_store``, ``challenge_lifetime``,
and ``clock`` keyword arguments.  This module re-exports the types those arguments
use so callers do not need to import a private module.
"""

from spnego._ntlm_challenge import (
    FixedClock,
    FixedNTLMClock,
    InMemoryNTLMChallengeStore,
    MemoryNTLMChallengeStore,
    NTLMChallengeState,
    NTLMChallengeStatus,
    NTLMChallengeStore,
    NTLMChallengeTransition,
    NTLMClock,
    SystemClock,
    SystemNTLMClock,
)

__all__ = [
    "FixedClock",
    "FixedNTLMClock",
    "InMemoryNTLMChallengeStore",
    "MemoryNTLMChallengeStore",
    "NTLMChallengeState",
    "NTLMChallengeStatus",
    "NTLMChallengeStore",
    "NTLMChallengeTransition",
    "NTLMClock",
    "SystemClock",
    "SystemNTLMClock",
]
