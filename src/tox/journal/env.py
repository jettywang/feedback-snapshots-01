"""Record information about tox environments."""

from __future__ import annotations

__lazy_modules__ = [
    "tox.util.redact",
    "tox.util.shared_output",
]

from typing import TYPE_CHECKING

from tox.util.redact import redact_argv
from tox.util.shared_output import SharedOutput, scrub_json

if TYPE_CHECKING:
    from tox.execute import Outcome
    from tox.util.json_types import JsonValue


class EnvJournal:
    """Report the status of a tox environment.

    :param enabled: whether the journal records anything
    :param name: the name of the tox environment
    :param shared_output: the policy that keeps restricted values out of the shared document

    """

    def __init__(  # keeps the signature
        self,
        enabled: bool,  # ruff:ignore[boolean-type-hint-positional-argument]  # keeps the signature
        name: str,  # keeps the signature
        shared_output: SharedOutput | None = None,
    ) -> None:
        self._enabled = enabled
        self.name = name
        self._shared_output = shared_output
        self._content: dict[str, JsonValue] = {}
        self._executes: list[tuple[str, Outcome]] = []

    def __setitem__(self, key: str, value: JsonValue) -> None:
        """Add a new entry under key into the event journal.

        :param key: the key under what to add the data
        :param value: the data to add

        """
        self._content[key] = value

    def __bool__(self) -> bool:
        """:returns: a flag indicating if the event journal is on or not"""
        return self._enabled

    @property
    def content(self) -> dict[str, JsonValue]:
        """The env journal content, merging the explicit keys and the execution commands."""
        tests: list[JsonValue] = []
        setup: list[JsonValue] = []
        for run_id, outcome in self._executes:
            one: dict[str, JsonValue] = {
                "command": redact_argv(outcome.cmd),
                "output": outcome.out,
                "err": outcome.err,
                "retcode": outcome.exit_code,
                "elapsed": outcome.elapsed,
                "show_on_standard": outcome.show_on_standard,
                "run_id": run_id,
                "start": outcome.start,
                "end": outcome.end,
            }
            if run_id.startswith(("commands", "build")):
                tests.append(one)
            else:
                setup.append(one)
        if tests:
            self._content["test"] = tests
        if setup:
            self._content["setup"] = setup
        return self._content

    @property
    def shared_content(self) -> dict[str, JsonValue]:
        """The env journal content that may be shared, with restricted values masked."""
        content = self.content
        if self._shared_output is None:
            return content
        scrubbed = scrub_json(content, self._shared_output)
        assert isinstance(scrubbed, dict)  # ruff:ignore[assert]  # the input is a mapping, so is the copy
        return scrubbed

    def add_execute(self, outcome: Outcome, run_id: str) -> None:
        """Add a command execution to the journal.

        :param outcome: the execution outcome
        :param run_id: the execution id

        """
        self._executes.append((run_id, outcome))


__all__ = [
    "EnvJournal",
]
