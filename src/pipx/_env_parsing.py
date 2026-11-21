from __future__ import annotations

__lazy_modules__ = ["typing"]

import re
from typing import Final

from pipx.constants import FetchPythonOptions

_ENV_NAME: Final[re.Pattern[str]] = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


def compute_env_allowlist(raw: str | None) -> tuple[frozenset[str] | None, bool]:
    """Parse a comma-separated allowlist of environment variable names.

    :param raw: the raw value of the allowlist variable.
    :returns: the allowed names, None when the variable is unset so no filtering applies, and whether any
        non-empty entry was not a valid variable name.
    """
    if raw is None:
        return None, False
    entries: Final[list[str]] = [entry.strip() for entry in raw.split(",")]
    names: Final[set[str]] = {entry for entry in entries if _ENV_NAME.fullmatch(entry)}
    invalid: Final[bool] = any(entry and not _ENV_NAME.fullmatch(entry) for entry in entries)
    return frozenset(names), invalid


def compute_fetch_python(missing_raw: str | None, python_raw: str | None) -> tuple[FetchPythonOptions, bool]:
    fetch_missing: Final[bool] = (missing_raw or "").strip().lower() not in {"", "0", "false", "f", "no", "n", "off"}
    raw: Final[str] = python_raw or (
        FetchPythonOptions.MISSING.value if fetch_missing else FetchPythonOptions.NEVER.value
    )
    try:
        return FetchPythonOptions(raw), False
    except ValueError:
        return FetchPythonOptions.NEVER, True


def compute_cooldown(raw: str | None) -> tuple[int | None, bool]:
    if raw is None or not (stripped := raw.strip()):
        return None, False
    try:
        days: Final[int] = int(stripped)
    except ValueError:
        return None, True
    return (days, False) if days >= 0 else (None, True)


def compute_max_logs(raw: str | None) -> tuple[int, bool]:
    if raw is None or not (stripped := raw.strip()):
        return 10, False
    try:
        logs: Final[int] = int(stripped)
    except ValueError:
        return 10, True
    return (logs, False) if logs >= 0 else (10, True)


__all__ = [
    "compute_cooldown",
    "compute_env_allowlist",
    "compute_fetch_python",
    "compute_max_logs",
]
