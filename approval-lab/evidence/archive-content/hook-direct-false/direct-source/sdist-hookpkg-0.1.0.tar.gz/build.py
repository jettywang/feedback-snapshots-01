from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path


def _record(event: str, **details: object) -> None:
    log_path = os.environ.get("APPROVAL_EVENT_LOG")
    if not log_path:
        return
    record = {
        "event": event,
        "when": datetime.now(timezone.utc).isoformat(),
        "pid": os.getpid(),
        "ppid": os.getppid(),
        "argv": sys.argv,
        "dunder_name": __name__,
        "cwd": os.getcwd(),
        "profile": os.environ.get("APPROVAL_PROFILE", "unset"),
        **details,
    }
    with open(log_path, "a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, sort_keys=True) + "\n")


def _native_extension():
    from setuptools import Extension

    return [
        Extension(
            "hookpkg._native",
            sources=[str(Path("hookpkg") / "native.c")],
        )
    ]


def build(setup_kwargs: dict) -> None:
    _record("build_function_enter", setup_keys=sorted(setup_kwargs))
    if os.environ.get("APPROVAL_NATIVE") == "1":
        setup_kwargs["ext_modules"] = _native_extension()
        _record("native_extension_configured", target="hookpkg._native")
    _record("build_function_exit")


def _build_native_in_place() -> None:
    from setuptools import Distribution
    from setuptools.command.build_ext import build_ext

    distribution = Distribution({
        "name": "hookpkg",
        "ext_modules": _native_extension(),
    })
    command = build_ext(distribution)
    command.inplace = 1
    command.finalize_options()
    command.run()


_record("build_py_module_enter")

if __name__ == "__main__":
    _record("build_py_main_enter")
    if os.environ.get("APPROVAL_NATIVE") == "1":
        _build_native_in_place()
        _record("native_extension_built_inplace")
    _record("build_py_main_exit")
