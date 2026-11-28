#!/usr/bin/env python3
"""Preview local tox configuration and record where every value came from.

The tool only reads configuration through tox's own parser. It never creates an
environment, installs a package, or runs a configured command.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path
from typing import Any

from tox.config.cli.parse import get_options
from tox.config.loader.native import to_native
from tox.config.main import Config
from tox.config.of_type import ConfigConstantDefinition
from tox.session.state import State

VOLATILE = {"PYTHONHASHSEED"}
DEFAULT_KEYS = [
    "base",
    "env_name",
    "package",
    "package_env",
    "package_tox_env_type",
    "skip_install",
    "use_develop",
    "commands",
    "commands_pre",
    "commands_post",
    "deps",
    "dependency_groups",
    "extras",
    "pass_env",
    "disallow_pass_env",
    "set_env",
    "allowlist_externals",
    "change_dir",
    "install_command",
    "skip_missing_interpreters",
]
CORE_KEYS = [
    "config_file_path",
    "env_list",
    "tox_root",
    "work_dir",
    "package_env",
    "no_package",
    "requires",
    "min_version",
]
# the same semantic layer spelled by each format
LAYER = {
    "tox": "<core>",
    "": "<core>",
    "testenv": "<run-base>",
    "env_run_base": "<run-base>",
    "tool.tox.env_run_base": "<run-base>",
    "pkgenv": "<pkg-base>",
    "env_pkg_base": "<pkg-base>",
    "tool.tox.env_pkg_base": "<pkg-base>",
}
# these keys identify the previewed file, not a setting the user approves
IDENTITY_KEYS = {"config_file_path"}
ENV_TOKEN = re.compile(r"\{env:([^}:]+)(?::([^}]*))?\}")
REF_TOKEN = re.compile(r"\{\[([^\]]+)]([^}]+)}")
POS_TOKEN = re.compile(r"\{posargs(?::([^}]*))?\}")
FORMAT_OF_LOADER = {"IniLoader": "ini", "TomlLoader": "toml"}


def _options(project: Path, config: Path | None, envs: list[str]) -> Any:
    args = ["c", "--format", "json", "-e", ",".join(envs)]
    if config is not None:
        args.extend(("-c", str(config)))
    previous = Path.cwd()
    os.chdir(project)
    try:
        return get_options(*args)
    finally:
        os.chdir(previous)


def _layer(section: str) -> str:
    if section in LAYER:
        return LAYER[section]
    if section.startswith("testenv:"):
        return "<env:" + section.split(":", 1)[1] + ">"
    rest = section.removeprefix("tool.tox.")
    if rest in LAYER:
        return LAYER[rest]
    if rest.startswith("env."):
        return "<env:" + rest.split(".", 1)[1] + ">"
    return rest


def _set_env(conf: Config, env: str) -> dict[str, Any]:
    try:
        values = conf.get_env(env)["set_env"]
    except Exception:  # noqa: BLE001 - a broken fixture must still produce a trace
        return {}
    try:
        return {key: values.load(key) for key in values}
    except Exception:  # noqa: BLE001 - a broken fixture must still produce a trace
        return {}


def _env_origin(
    name: str, default: str | None, conf: Config, env: str | None, set_env: dict[str, Any] | None = None
) -> str:
    if env is not None:
        values = _set_env(conf, env) if set_env is None else set_env
        if name in values:
            return "set_env"
    if name in os.environ:
        return "host"
    return "default" if default is not None else "unset"


def _substitutions(
    value: Any,
    conf: Config,
    env: str | None,
    pos_args: tuple[str, ...] | None,
    set_env: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    found: list[dict[str, Any]] = []

    def walk(node: Any) -> None:
        if isinstance(node, str):
            for match in ENV_TOKEN.finditer(node):
                found.append(
                    {
                        "type": "env",
                        "name": match.group(1),
                        "origin": _env_origin(match.group(1), match.group(2), conf, env, set_env),
                    }
                )
            for match in REF_TOKEN.finditer(node):
                found.append({"type": "section-ref", "section": match.group(1), "key": match.group(2)})
            if POS_TOKEN.search(node):
                found.append({"type": "posargs", "origin": "cli" if pos_args is not None else "default"})
            return
        if isinstance(node, list):
            for item in node:
                walk(item)
            return
        if not isinstance(node, dict):
            return
        replace = node.get("replace")
        if replace == "env" and isinstance(node.get("name"), str):
            found.append(
                {
                    "type": "env",
                    "name": node["name"],
                    "origin": _env_origin(node["name"], node.get("default"), conf, env, set_env),
                }
            )
            return
        if replace == "posargs":
            found.append({"type": "posargs", "origin": "cli" if pos_args is not None else "default"})
            return
        if replace == "ref":
            found.append(
                {
                    "type": "ref",
                    "of": node.get("of"),
                    "env": node.get("env"),
                    "key": node.get("key"),
                    "extend": bool(node.get("extend")),
                }
            )
            return
        if replace == "if":
            walk(node.get("then"))
            walk(node.get("else"))
            return
        if replace == "glob":
            walk(node.get("pattern"))
            walk(node.get("default"))
            return
        for item in node.values():
            walk(item)

    walk(value)
    return found


def _normalize(value: Any, key: str, project: Path) -> Any:
    native = to_native(value)
    if key == "base" and isinstance(native, list):
        native = [LAYER.get(str(item), str(item)) for item in native]
    text = json.dumps(native, sort_keys=True, default=str, ensure_ascii=False)
    for prefix in {
        str(project),
        str(project.resolve()),
        str(project.absolute()),
        os.path.realpath(project),
    }:
        text = text.replace(prefix, "<PROJECT>")
    if key == "set_env":
        try:
            mapping = json.loads(text)
        except json.JSONDecodeError:
            pass
        else:
            for volatile in VOLATILE:
                if volatile in mapping:
                    mapping[volatile] = "<RANDOM>"
            return mapping
    return json.loads(text)


def _source(conf_set: Any, key: str, conf: Config) -> dict[str, Any]:
    definition = conf_set._defined[key]
    if isinstance(definition, ConfigConstantDefinition):
        return {"kind": "constant"}
    aliases = set(definition.keys)
    namespaces = {conf_set.name, conf_set._section.key}
    overrides = [o for ns in namespaces for o in conf.overrides.get(ns, []) if o.key in aliases]
    if overrides:
        return {"kind": "override", "via": str(overrides[-1])}
    for depth, loader in enumerate(conf_set.loaders):
        if any(alias in loader.found_keys() for alias in aliases):
            raw = None
            for alias in (key, *definition.keys):
                try:
                    raw = loader.load_raw(alias, conf, conf_set.env_name)
                    break
                except Exception:  # noqa: BLE001 - keep probing aliases
                    continue
            return {
                "kind": "loader",
                "loader": type(loader).__name__,
                "format": FORMAT_OF_LOADER.get(type(loader).__name__, "unknown"),
                "section": loader.section.key,
                "layer": _layer(loader.section.key),
                "depth": depth,
                "raw": raw,
            }
    default = definition.default
    if callable(default):
        shown = f"<callable {getattr(default, '__name__', type(default).__name__)}>"
    else:
        shown = default if isinstance(default, (str, int, float, bool, type(None))) else repr(default)
    return {"kind": "default", "default": shown}


def _record(conf_set: Any, keys: list[str], conf: Config, project: Path) -> dict[str, Any]:
    result: dict[str, Any] = {}
    pos_args = conf.pos_args(None)
    resolver: dict[str, Any] | None = None
    if conf_set.env_name is not None:
        try:
            resolver = dict(conf_set["set_env"])
        except Exception:  # noqa: BLE001 - a broken fixture must still produce a trace
            resolver = None
    for key in keys:
        if key not in conf_set:
            result[key] = {"present": False}
            continue
        source = _source(conf_set, key, conf)
        raw = source.pop("raw", None)
        try:
            value = conf_set[key]
        except Exception as exc:  # noqa: BLE001 - a load failure is evidence
            result[key] = {"present": True, "error": f"{type(exc).__name__}: {exc}", "source": source}
            continue
        origin_scope = {} if key == "set_env" else resolver
        result[key] = {
            "present": True,
            "value": _normalize(value, key, project),
            "source": source,
            "substitutions": _substitutions(raw, conf, conf_set.env_name, pos_args, origin_scope),
        }
    return result


def trace(
    project: Path, envs: list[str], keys: list[str], core_keys: list[str], config: Path | None = None
) -> dict[str, Any]:
    project = project.resolve()
    root = project
    options = _options(project, config, envs)
    previous = Path.cwd()
    os.chdir(project)
    try:
        state = State(options, ["c", *(["-c", str(config)] if config is not None else []), "-e", ",".join(envs)])
        conf = state.conf
        env_confs = {name: state.envs[name].conf for name in envs}
    finally:
        os.chdir(previous)
    packed = {"<PROJECT>": str(project)}
    core = _record(conf.core, core_keys or CORE_KEYS, conf, project)
    env = {name: _record(env_conf, keys or DEFAULT_KEYS, conf, project) for name, env_conf in env_confs.items()}
    referenced = {
        sub["name"]
        for record in [*env.values(), core]
        for value in record.values()
        for sub in value.get("substitutions", [])
        if sub.get("type") == "env"
    }
    selected = conf.src_path
    try:
        selected_shown = str(selected.relative_to(root))
    except ValueError:
        selected_shown = f"<OUTSIDE PROFILE: {selected.name}>"
    candidates = sorted(
        name
        for name in {src.FILENAME for src in __import__("tox.config.source.discover", fromlist=["_SOURCE_TYPES"])._SOURCE_TYPES}
        if (project / name).exists()
    )
    unused = {name: sorted(record.unused()) for name, record in [(n, state.envs[n].conf) for n in envs]}
    return {
        "selected": {"path": selected_shown, "type": type(options.source).__name__, "candidates": candidates},
        "unused": {"core": sorted(conf.core.unused()), **unused},
        "inputs": {
            "packed": packed,
            "pos_args": list(options.pos_args) if options.pos_args is not None else None,
            "host_env": {name: os.environ.get(name) for name in sorted(referenced)},
            "hash_seed": getattr(options.parsed, "hash_seed", None),
            "overrides": [str(entry) for entry in getattr(options.parsed, "override", [])],
        },
        "core": core,
        "env": env,
    }


def _verdict(old: dict[str, Any], new: dict[str, Any], key: str) -> tuple[str, str]:
    if not old.get("present") or not new.get("present"):
        if old.get("present") != new.get("present"):
            return "REAPPROVE", "presence changed"
        return "CARRY", "absent on both sides"
    if "error" in old or "error" in new:
        return "BLOCKED", "a side fails to load"
    if old.get("value") != new.get("value"):
        return "REAPPROVE", "final value changed"
    old_src, new_src = old.get("source", {}), new.get("source", {})
    if old_src.get("kind") != new_src.get("kind"):
        return "REVIEW", f"same value, source kind {old_src.get('kind')} -> {new_src.get('kind')}"
    if old_src.get("kind") == "loader":
        if old_src.get("layer") != new_src.get("layer"):
            return (
                "REVIEW",
                f"same value, layer {old_src.get('layer')} -> {new_src.get('layer')}",
            )
        if old.get("substitutions") != new.get("substitutions"):
            return "REVIEW", "same value, substitution origin changed"
        if key == "base" and old_src.get("loader") != new_src.get("loader"):
            return "TRANSLATED", "same base chain, format-native names"
        if old_src.get("format") != new_src.get("format"):
            return "TRANSLATED", f"same value, {old_src.get('format')} -> {new_src.get('format')}"
        return "CARRY", "same value, same layer, same substitution origins"
    if old_src.get("kind") == "default":
        if old.get("substitutions") != new.get("substitutions"):
            return "REVIEW", "same value, substitution origin changed"
        return "CARRY", "same default"
    return "CARRY", f"same {old_src.get('kind')}"


def classify(before: dict[str, Any], after: dict[str, Any]) -> dict[str, Any]:
    rows: list[dict[str, Any]] = []

    def compare(scope: str, old: dict[str, Any], new: dict[str, Any]) -> None:
        for key in sorted(set(old) | set(new)):
            verdict, why = _verdict(old.get(key, {"present": False}), new.get(key, {"present": False}), key)
            if key in IDENTITY_KEYS and verdict == "REAPPROVE":
                verdict, why = "IDENTITY", "expected: the previewed file changed"
            rows.append({"scope": scope, "key": key, "verdict": verdict, "why": why})

    compare("core", before.get("core", {}), after.get("core", {}))
    for env in sorted(set(before.get("env", {})) | set(after.get("env", {}))):
        compare(env, before.get("env", {}).get(env, {}), after.get("env", {}).get(env, {}))
    counts: dict[str, int] = {}
    for row in rows:
        counts[row["verdict"]] = counts.get(row["verdict"], 0) + 1
    blocking = [row for row in rows if row["verdict"] in {"REAPPROVE", "BLOCKED"}]
    review = [row for row in rows if row["verdict"] == "REVIEW"]
    translated = [row for row in rows if row["verdict"] in {"TRANSLATED", "IDENTITY"}]
    return {
        "rows": rows,
        "summary": {
            "counts": counts,
            "reapprove_or_blocked": len(blocking),
            "review": len(review),
            "translated_or_identity": len(translated),
            "carry": counts.get("CARRY", 0),
            "approvable": not blocking,
        },
    }


def gate(approvals: dict[str, Any], trace_data: dict[str, Any]) -> dict[str, Any]:
    rows: list[dict[str, Any]] = []
    for env, expected in approvals.get("environments", {}).items():
        actual = trace_data.get("env", {}).get(env)
        if actual is None:
            rows.append({"env": env, "key": "commands", "verdict": "MISSING", "why": "approved environment disappeared"})
            continue
        for key, approved in expected.items():
            got = actual.get(key, {"present": False})
            if not got.get("present"):
                rows.append({"env": env, "key": key, "verdict": "MISSING", "why": "value no longer present"})
            elif got.get("value") != approved:
                rows.append(
                    {
                        "env": env,
                        "key": key,
                        "verdict": "CHANGED",
                        "why": f"approved {approved!r}, preview {got.get('value')!r}",
                    }
                )
            else:
                rows.append({"env": env, "key": key, "verdict": "KEEP", "why": "matches the approval"})
    return {
        "rows": rows,
        "summary": {
            "keep": sum(1 for r in rows if r["verdict"] == "KEEP"),
            "changed": sum(1 for r in rows if r["verdict"] == "CHANGED"),
            "missing": sum(1 for r in rows if r["verdict"] == "MISSING"),
            "approvable": all(r["verdict"] == "KEEP" for r in rows),
        },
    }


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="cmd", required=True)
    t = sub.add_parser("trace", help="record a preview and the provenance of each value")
    t.add_argument("--project", type=Path, required=True, help="project directory to preview")
    t.add_argument("--config", type=Path, help="config file; omit to use tox's own discovery")
    t.add_argument("--env", action="append", default=[])
    t.add_argument("--keys", nargs="*")
    t.add_argument("--core-keys", nargs="*")
    d = sub.add_parser("diff", help="classify a before/after pair of traces")
    d.add_argument("before", type=Path)
    d.add_argument("after", type=Path)
    g = sub.add_parser("gate", help="check that approved environments and commands are preserved")
    g.add_argument("approvals", type=Path)
    g.add_argument("trace", type=Path)
    args = parser.parse_args(argv)
    if args.cmd == "trace":
        config = args.config.resolve() if args.config is not None else None
        result = trace(args.project, args.env or ["py"], args.keys or [], args.core_keys or [], config)
    elif args.cmd == "diff":
        result = classify(json.loads(args.before.read_text()), json.loads(args.after.read_text()))
    else:
        result = gate(json.loads(args.approvals.read_text()), json.loads(args.trace.read_text()))
    json.dump(result, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
