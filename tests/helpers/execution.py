from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Sequence


class RecordingRunner:
    """
    A command runner that records every attempted invocation instead of executing it.

    It returns an object shaped like the standard library's completed process so it can stand
    in for `EnvironmentInterface.run_shell_command` in tests. Entries are `(command, cwd)`
    tuples and the working directory is captured at call time, which lets a test prove that a
    decision does not depend on where the command would run.
    """

    def __init__(self, *, returncodes: dict[str, int] | None = None) -> None:
        self.calls: list[tuple[str, str | None]] = []
        self.returncodes = returncodes or {}
        self.fail_once: set[str] = set()
        self._raised: set[str] = set()

    @property
    def commands(self) -> list[str]:
        return [command for command, _cwd in self.calls]

    def run(self, command: str, *, cwd: str | None = None, **kwargs) -> RecordingProcess:
        self.calls.append((command, cwd if cwd is not None else _current_directory()))

        if command in self.fail_once and command not in self._raised:
            self._raised.add(command)
            message = f"transient failure: {command}"
            raise RuntimeError(message)

        return RecordingProcess(command, self.returncodes.get(command, 0))


class RecordingProcess:
    def __init__(self, args: Sequence[str] | str, returncode: int = 0) -> None:
        self.args = args
        self.returncode = returncode
        self.stdout = b""
        self.stderr = b""


def _current_directory() -> str:
    import os

    return os.getcwd()
