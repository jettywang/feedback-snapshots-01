from __future__ import annotations

import re
from pathlib import Path

import pytest

from tox.util.shared_output import REPLACEMENT, SharedOutput, scrub_json

_RESPONSE_FILE = re.compile(r"pep517_[\w-]+-[\w.-]+\.json")


def test_scrub_text_replaces_every_registered_value() -> None:
    policy = SharedOutput()
    policy.add("build-dir", "nested-build-dir")

    assert policy.scrub_text("in build-dir and nested-build-dir and build-dir") == (
        f"in {REPLACEMENT} and {REPLACEMENT} and {REPLACEMENT}"
    )


def test_scrub_text_registers_longer_value_first() -> None:
    # A value that contains another one must be replaced whole, never partially.
    policy = SharedOutput()
    policy.add("build", "build-dir")

    assert policy.scrub_text("build-dir then build") == f"{REPLACEMENT} then {REPLACEMENT}"


def test_scrub_text_applies_late_registrations() -> None:
    policy = SharedOutput()
    assert policy.scrub_text("build-dir") == "build-dir"

    policy.add("build-dir")

    assert policy.scrub_text("build-dir") == REPLACEMENT


def test_add_relative_registers_both_forms(tmp_path: Path) -> None:
    policy = SharedOutput()
    policy.add_relative(tmp_path / ".tox" / ".tmp", tmp_path)

    assert policy.scrub_text(str(tmp_path / ".tox" / ".tmp")) == REPLACEMENT
    assert policy.scrub_text(".tox/.tmp") == REPLACEMENT


def test_add_relative_ignores_path_outside_root(tmp_path: Path) -> None:
    policy = SharedOutput()
    policy.add_relative(tmp_path / "outside", tmp_path / "root")

    assert policy.scrub_text(str(tmp_path / "outside")) == REPLACEMENT
    assert policy.scrub_text("outside") == "outside"


def test_scrub_text_with_no_restrictions_is_identity() -> None:
    policy = SharedOutput()
    assert policy.scrub_text("nothing restricted") == "nothing restricted"


def test_scrub_text_ignores_empty_values() -> None:
    policy = SharedOutput()
    policy.add("")
    assert policy.scrub_text("text") == "text"


@pytest.mark.parametrize(
    "pattern",
    [
        pytest.param("pep517__optional_hooks-abc123.json", id="hyphen"),
        pytest.param("pep517_build_wheel-1a2b3c.json", id="underscore"),
    ],
)
def test_scrub_text_matches_pattern_registrations(pattern: str) -> None:
    policy = SharedOutput()
    policy.add_pattern(_RESPONSE_FILE)

    assert policy.scrub_text(f"left {pattern} right") == f"left {REPLACEMENT} right"


def test_stream_scrubber_emits_scrubbed_text_once_complete() -> None:
    policy = SharedOutput()
    policy.add("build-dir")
    scrubber = policy.stream_scrubber()
    chunks = [b"before build-", b"dir after build-", b"dir end"]

    shared = b"".join(scrubber.feed(chunk) for chunk in chunks) + scrubber.finish()

    assert shared == b"before <restricted> after <restricted> end"


def test_stream_scrubber_keeps_short_tail_for_finish() -> None:
    policy = SharedOutput()
    policy.add("build-dir")
    scrubber = policy.stream_scrubber()

    # The last 9 bytes could start a restricted value, so they wait for more input or the end of the stream.
    assert scrubber.feed(b"tail build-") == b"tai"
    assert scrubber.finish() == b"l build-"


def test_stream_scrubber_masks_a_pattern_split_across_chunks() -> None:
    policy = SharedOutput()
    policy.add_pattern(_RESPONSE_FILE)
    scrubber = policy.stream_scrubber()

    chunks = [b"to /tmp/pep517_build_", b"wheel-abc123.json done"]
    shared = b"".join(scrubber.feed(chunk) for chunk in chunks) + scrubber.finish()

    assert shared == b"to /tmp/<restricted> done"


def test_scrub_bytes_masks_a_pattern() -> None:
    policy = SharedOutput()
    policy.add_pattern(_RESPONSE_FILE)

    assert policy.scrub_bytes(b"at /tmp/pep517__optional_hooks-abc123.json") == b"at /tmp/<restricted>"


def test_stream_scrubber_without_restrictions_passes_through() -> None:
    policy = SharedOutput()
    scrubber = policy.stream_scrubber()

    assert scrubber.feed(b"one") == b"one"
    assert scrubber.finish() == b""


def test_stream_scrubber_scrubs_bytes_held_when_value_registered_late() -> None:
    policy = SharedOutput()
    scrubber = policy.stream_scrubber()
    assert scrubber.feed(b"build-dir") == b"build-dir"

    # Registering a value after the stream started also applies to the bytes the scrubber holds for boundaries.
    policy.add("build-dir")
    held = scrubber.feed(b" and build-dir") + scrubber.finish()
    assert held == b" and <restricted>"


def test_scrub_json_copies_and_preserves_shape() -> None:
    policy = SharedOutput()
    policy.add("build-dir")

    result = scrub_json({"a": "build-dir", "b": ["build-dir", 1, None], "c": {"d": True}}, policy)

    assert result == {"a": REPLACEMENT, "b": [REPLACEMENT, 1, None], "c": {"d": True}}


def test_scrub_json_leaves_non_string_scalars() -> None:
    policy = SharedOutput()
    policy.add("build-dir")

    assert scrub_json(1.5, policy) == 1.5
    assert scrub_json(None, policy) is None
