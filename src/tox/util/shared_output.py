"""Redact values that may leave a tox run through its shared output.

Build stages create paths and response files that are meaningful only while the run lasts. They are safe to keep in
the internal record tox writes for diagnostics, but must not reach output shared outside the run. A single policy
carries those values to every outward boundary: the terminal streams, the run journal written for consumers, and log
records.
"""

from __future__ import annotations

__lazy_modules__ = [
    "re",
    "threading",
]

import re
from pathlib import Path
from threading import Lock
from typing import Final

REPLACEMENT: Final[str] = "<restricted>"
"""What a restricted value is replaced with wherever output is shared."""
_REPLACEMENT_BYTES: Final[bytes] = REPLACEMENT.encode()
_PATTERN_LOOKBACK: Final[int] = 1024
"""Bytes a stream holds back when a pattern is restricted, so a match split across chunks is still seen whole."""


class SharedOutput:
    """The values and patterns a run must keep out of its shared output.

    Register values before the stage that produces them starts writing output. The policy is shared by the handler
    that prints to the terminal and by the journal, so all outward boundaries apply the same rule.

    """

    def __init__(self) -> None:
        self._lock = Lock()
        self._values: tuple[str, ...] = ()
        self._patterns: tuple[re.Pattern[str], ...] = ()
        self._bytes_patterns: tuple[re.Pattern[bytes], ...] = ()
        self._bytes_regex: re.Pattern[bytes] | None = None
        self._holdback = 0
        self._version = 0

    @property
    def version(self) -> int:
        """:returns: a number that changes whenever a restricted value is added"""
        return self._version

    def add_relative(self, value: Path, root: Path) -> None:
        """Restrict a path both in full and relative to a root, the form used in some display lines.

        :param value: the path to restrict
        :param root: the directory that display lines are relative to

        """
        self.add(value)
        try:
            self.add(value.relative_to(root))
        except ValueError:  # a path outside the root has no relative form to mask
            pass

    def add(self, *values: str | Path) -> None:
        """Restrict literal values, such as the paths of a temporary build directory.

        :param values: the values to keep out of shared output

        """
        additions = tuple(str(value) for value in values if str(value))
        if not additions:
            return
        with self._lock:
            existing = set(self._values)
            new = tuple(value for value in dict.fromkeys(additions) if value not in existing)
            if not new:
                return
            self._values = (*self._values, *new)
            self._values = tuple(sorted(self._values, key=len, reverse=True))
            self._rebuild_bytes_regex()
            self._version += 1

    def add_pattern(self, pattern: re.Pattern[str]) -> None:
        """Restrict text matching a pattern, such as a per-call temporary response file.

        :param pattern: the pattern to replace in shared text

        """
        with self._lock:
            if pattern in self._patterns:
                return
            self._patterns = (*self._patterns, pattern)
            self._bytes_patterns = (*self._bytes_patterns, re.compile(pattern.pattern.encode()))
            self._rebuild_bytes_regex()
            self._version += 1

    def _rebuild_bytes_regex(self) -> None:
        parts = [re.escape(value.encode()) for value in self._values]
        parts.extend(pattern.pattern for pattern in self._bytes_patterns)
        self._bytes_regex = re.compile(b"|".join(parts)) if parts else None
        self._holdback = max(
            max((len(value) for value in self._values), default=0),
            _PATTERN_LOOKBACK if self._bytes_patterns else 0,
        )

    def scrub_text(self, text: str) -> str:
        """Replace restricted values and pattern matches in text shared outside the run.

        :param text: the text to scrub

        :returns: the text with every restricted value masked

        """
        if not text:
            return text
        with self._lock:
            values, patterns = self._values, self._patterns
        if not values and not patterns:
            return text
        for value in values:
            text = text.replace(value, REPLACEMENT)
        for pattern in patterns:
            text = pattern.sub(REPLACEMENT, text)
        return text

    def scrub_bytes(self, data: bytes) -> bytes:
        """Replace restricted values in a byte blob shared outside the run.

        :param data: the bytes to scrub

        :returns: the bytes with every restricted value masked

        """
        with self._lock:
            regex = self._bytes_regex
        if regex is None or not data:
            return data
        return regex.sub(_REPLACEMENT_BYTES, data)

    def stream_scrubber(self) -> StreamScrubber:
        """:returns: a stateful scrubber for a byte stream, safe across chunk boundaries"""
        return StreamScrubber(self)

    def _stream_snapshot(self) -> tuple[re.Pattern[bytes] | None, int, int]:
        with self._lock:
            return self._bytes_regex, self._holdback, self._version


class StreamScrubber:
    """Scrub a byte stream while preserving values split across chunk boundaries.

    :param policy: the policy holding the values to restrict

    """

    def __init__(self, policy: SharedOutput) -> None:
        self._policy = policy
        self._pending = b""
        self._version = policy.version

    def feed(self, chunk: bytes) -> bytes:
        """Accept the next chunk and return the bytes that are safe to share.

        :param chunk: the next bytes read from the stream

        :returns: the scrubbed bytes that can be shared now

        """
        if not chunk:
            return b""
        self._pending += chunk
        regex, holdback, version = self._policy._stream_snapshot()  # ruff:ignore[private-member-access]
        if version != self._version:
            # A value registered after this stream started can still occur in the text held back for boundary checks.
            self._pending = self._policy.scrub_bytes(self._pending)
            self._version = version
        if regex is None:
            ready, self._pending = self._pending, b""
            return ready
        cut = len(self._pending) - holdback + 1
        if cut <= 0:
            return b""
        result, position = bytearray(), 0
        while position < cut:
            match = regex.search(self._pending, position)
            if match is None or match.start() >= cut:
                break
            result += self._pending[position : match.start()]
            result += _REPLACEMENT_BYTES
            position = match.end()
        emit_until = max(position, cut)
        if position < cut:
            result += self._pending[position:cut]
        self._pending = self._pending[emit_until:]
        return bytes(result)

    def finish(self) -> bytes:
        """Return the remaining scrubbed bytes once the stream has ended.

        :returns: the scrub of the bytes still held back for boundary detection

        """
        pending, self._pending = self._pending, b""
        return self._policy.scrub_bytes(pending)


def scrub_json(value: object, policy: SharedOutput) -> object:
    """Scrub every string in a JSON-like structure without changing its shape or order.

    :param value: the value to copy and scrub
    :param policy: the policy holding the values to restrict

    :returns: a new value with the strings scrubbed

    """
    if isinstance(value, str):
        return policy.scrub_text(value)
    if isinstance(value, dict):
        return {key: scrub_json(item, policy) for key, item in value.items()}
    if isinstance(value, list):
        return [scrub_json(item, policy) for item in value]
    if isinstance(value, tuple):
        return tuple(scrub_json(item, policy) for item in value)
    return value


__all__ = [
    "REPLACEMENT",
    "SharedOutput",
    "StreamScrubber",
    "scrub_json",
]
