from __future__ import annotations

import hashlib
import json
import os
import sys
import time

from hatchling.builders.hooks.plugin.interface import BuildHookInterface
from hatchling.plugin import hookimpl

SOURCE_ID = "A"


def _emit(event: str, **fields: object) -> None:
    log_path = os.environ.get("PROBE_LOG")
    if not log_path:
        return
    try:
        with open(__file__, "rb") as source_file:
            source_sha256 = hashlib.sha256(source_file.read()).hexdigest()
    except OSError:
        source_sha256 = None
    record = {
        "record": "plugin-call",
        "source_id": SOURCE_ID,
        "event": event,
        "pid": os.getpid(),
        "ppid": os.getppid(),
        "time_ns": time.time_ns(),
        "python": sys.executable,
        "argv": sys.argv,
        "module_file": __file__,
        "module_sha256": source_sha256,
    }
    record.update(fields)
    with open(log_path, "a", encoding="utf-8") as log_file:
        log_file.write(json.dumps(record, sort_keys=True) + "\n")


_emit("module-import")


class ProbeRecorderBuildHook(BuildHookInterface):
    PLUGIN_NAME = "probe"

    def __init__(self, *args: object, **kwargs: object) -> None:
        root, config, build_config, metadata, directory, target_name = args[:6]
        _emit(
            "instantiated",
            constructor_args={
                "root": root,
                "config": config,
                "directory": directory,
                "target_name": target_name,
            },
        )
        super().__init__(*args, **kwargs)  # type: ignore[arg-type]

    def dependencies(self) -> list[str]:
        _emit("dependencies")
        return []

    def clean(self, versions: list[str]) -> None:
        _emit("clean", callback_args={"versions": list(versions)})

    def initialize(self, version: str, build_data: dict) -> None:
        _emit(
            "initialize",
            callback_args={
                "version": version,
                "build_data_build_hooks": list(build_data.get("build_hooks", ())),
            },
        )

    def finalize(self, version: str, build_data: dict, artifact_path: str) -> None:
        _emit(
            "finalize",
            callback_args={
                "version": version,
                "artifact_path": artifact_path,
                "build_data_build_hooks": list(build_data.get("build_hooks", ())),
            },
        )


@hookimpl
def hatch_register_build_hook() -> type[ProbeRecorderBuildHook]:
    _emit("register-build-hook")
    return ProbeRecorderBuildHook
