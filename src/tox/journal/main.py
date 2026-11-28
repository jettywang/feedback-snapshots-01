"""Generate json report of a tox run."""

from __future__ import annotations

__lazy_modules__ = [
    "socket",
    "tox.util.shared_output",
    "tox.version",
    f"{__spec__.parent}.env",  # ty: ignore[missing-union-attribute]  # imported modules have a spec
]

import socket
import sys
from typing import TYPE_CHECKING

from tox.util.shared_output import SharedOutput, scrub_json
from tox.version import version

from .env import EnvJournal

if TYPE_CHECKING:
    from tox.util.json_types import JsonValue


class Journal:
    """The result of a tox session.

    :param enabled: whether the journal records anything
    :param shared_output: the policy that keeps restricted values out of the shared document

    """

    def __init__(  # keeps the signature
        self,
        enabled: bool,  # ruff:ignore[boolean-type-hint-positional-argument]  # keeps the signature
        shared_output: SharedOutput | None = None,
    ) -> None:
        self._enabled = enabled
        self._shared_output = shared_output
        self._content: dict[str, JsonValue] = {}
        self._env: dict[str, EnvJournal] = {}

        if self._enabled:
            self._content.update(
                {
                    "reportversion": "1",
                    "toxversion": version,
                    "platform": sys.platform,
                    "host": socket.getfqdn(),
                },
            )

    def __bool__(self) -> bool:
        return self._enabled

    @property
    def content(self) -> dict[str, JsonValue]:
        """The journal of the run, with the journal of each environment under its name."""
        test_env_journals: dict[str, JsonValue] = {}
        for name, value in self._env.items():
            test_env_journals[name] = value.content
        if test_env_journals:
            self._content["testenvs"] = test_env_journals
        return self._content

    @property
    def shared_content(self) -> dict[str, JsonValue]:
        """The journal that may be shared outside the run, with restricted values masked."""
        content = self.content
        if self._shared_output is None:
            return content
        scrubbed = scrub_json(content, self._shared_output)
        assert isinstance(scrubbed, dict)  # ruff:ignore[assert]  # the input is a mapping, so is the copy
        return scrubbed

    def get_env_journal(self, name: str) -> EnvJournal:
        """Return the env log of an environment (create on first call).

        :param name: the name of the tox environment

        :returns: the journal of the environment

        """
        if name not in self._env:
            self._env[name] = EnvJournal(self._enabled, name, self._shared_output)
        return self._env[name]


__all__ = [
    "Journal",
]
