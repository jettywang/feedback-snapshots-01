"""Read the variables a plan records from the configuration, so a preview creates no environment."""

from __future__ import annotations

__lazy_modules__ = [
    "fnmatch",
    "os",
    "re",
    "tox.config.set_env",
    "tox.tox_env.api",
]

import os
import re
from fnmatch import translate as fnmatch_translate
from typing import TYPE_CHECKING

from tox.config.set_env import SetEnv

if TYPE_CHECKING:
    from tox.tox_env.api import ToxEnv


def plan_variables(env: ToxEnv) -> dict[str, str]:
    """Get the variables a plan records for an environment.

    Building the full environment variables runs the environment's constructor, which the preview must not do. The
    values a run reaches through ``pass_env`` and ``set_env`` are read from the configuration alone, so a preview
    records those without creating the environment the run would.

    :param env: the environment

    :returns: the variables the plan records

    """
    result: dict[str, str] = {}
    patterns = [re.compile(fnmatch_translate(entry), re.IGNORECASE) for entry in env.conf.get("pass_env", list[str])]
    result.update({name: value for name, value in os.environ.items() if any(p.match(name) for p in patterns)})
    disallow_entries = env.conf.get("disallow_pass_env", list[str])
    disallow = [re.compile(fnmatch_translate(entry), re.IGNORECASE) for entry in disallow_entries]
    result = {name: value for name, value in result.items() if not any(p.match(name) for p in disallow)}
    set_env = env.conf.get("set_env", SetEnv)
    for key in set_env:
        result[key] = set_env.load(key)
    result["TOX_ENV_NAME"] = env.name
    result["TOX_WORK_DIR"] = str(env.core["work_dir"])
    result["TOX_ENV_DIR"] = str(env.conf["env_dir"])
    exported = getattr(env, "_exported_set_env", None)  # ruff:ignore[private-member-access]  # internal access
    if exported is not None:
        result.update({name: value() for name, value in exported().items()})
    return result


__all__ = [
    "plan_variables",
]
