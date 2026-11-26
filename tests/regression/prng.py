"""Small, dependency-free deterministic PRNG.

Python's ``random.Random`` is seeded deterministically across CPython
versions for the operations we use here, but relying on its internals
ties the fixtures to an implementation detail.  This module keeps a
tiny explicitly-specified generator (SplitMix64) so that "same seed ->
same corpus" is a property of our code and not of the standard library.
"""

_MASK = (1 << 64) - 1


def splitmix64(state):
    """Advance a SplitMix64 state; returns (new_state, 64-bit value)."""
    state = (state + 0x9E3779B97F4A7C15) & _MASK
    z = state
    z = ((z ^ (z >> 30)) * 0xBF58476D1CE4E5B9) & _MASK
    z = ((z ^ (z >> 27)) * 0x94D049BB133111EB) & _MASK
    return state, z ^ (z >> 31)


class SeededRandom(object):
    """Deterministic helpers on top of SplitMix64."""

    def __init__(self, seed):
        if not isinstance(seed, int) or seed < 0:
            raise ValueError("seed must be a non-negative int")
        self._state = seed & _MASK

    def _next(self):
        self._state, value = splitmix64(self._state)
        return value

    def below(self, n):
        """Uniform-ish integer in [0, n)."""
        if n <= 0:
            raise ValueError("n must be positive")
        return self._next() % n

    def between(self, low, high):
        """Inclusive integer in [low, high]."""
        if high < low:
            raise ValueError("empty range")
        return low + self.below(high - low + 1)

    def chance(self, numerator, denominator=100):
        return self.below(denominator) < numerator

    def choice(self, sequence):
        if not sequence:
            raise ValueError("empty sequence")
        return sequence[self.below(len(sequence))]

    def sample(self, sequence, count):
        """Pick `count` distinct items when possible (stable order)."""
        items = list(sequence)
        count = min(count, len(items))
        picked = []
        for _ in range(count):
            index = self.below(len(items))
            picked.append(items.pop(index))
        return picked

    def shuffle(self, sequence):
        items = list(sequence)
        for index in range(len(items) - 1, 0, -1):
            swap = self.below(index + 1)
            items[index], items[swap] = items[swap], items[index]
        return items
