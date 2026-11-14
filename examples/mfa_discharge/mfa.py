"""A simulated MFA verifier; no SMS, push, or login integration."""

from __future__ import annotations

import hmac
import secrets
from typing import Dict, Optional, Tuple


class SimulatedMfaVerifier:
    """Models the single question an MFA verifier can answer.

    The verifier sends a fresh proof code to the subject and remembers which
    subject received it.  The challenge identifier is deliberately *not* the
    proof: it is public and travels inside the third-party caveat.

    ``read_code`` is a demo helper that stands in for the user looking at
    their phone.  A real verifier would deliver the code out of band and
    expose no such method.
    """

    def __init__(self) -> None:
        self._pending: Dict[str, Tuple[str, str]] = {}

    def send_challenge(self, challenge_id: str, user_id: str) -> None:
        self._pending[challenge_id] = (user_id, self._new_code())

    def read_code(self, user_id: str, challenge_id: str) -> Optional[str]:
        record = self._pending.get(challenge_id)
        if record is None or record[0] != user_id:
            return None
        return record[1]

    def verify(self, challenge_id: str, user_id: str, proof: str) -> bool:
        record = self._pending.get(challenge_id)
        if record is None or record[0] != user_id:
            return False
        if not hmac.compare_digest(proof, record[1]):
            return False
        # A real TOTP or passkey assertion is single-use too.
        del self._pending[challenge_id]
        return True

    @staticmethod
    def _new_code() -> str:
        return '{:06d}'.format(secrets.randbelow(1_000_000))
