"""A manually advanced clock for deterministic MFA expiry demonstrations."""

from dataclasses import dataclass


@dataclass
class ManualClock:
    """Logical clock whose value only moves when a caller advances it."""

    current: int = 1_700_000_000

    def now(self) -> int:
        return self.current

    def advance(self, seconds: int) -> int:
        if seconds < 0:
            raise ValueError('the demo clock cannot move backwards')
        self.current += seconds
        return self.current
