"""Forensic snapshots built from Dynaconf loading records.

This module is read-only with regard to settings loading: it derives evidence
from ``loaded_by_loaders`` (raw values) and the sidecar records written while
loading (effective values and file digests). Runtime merging behaviour is
therefore unchanged.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
from typing import Any
from typing import TYPE_CHECKING

from dynaconf.utils.files import content_digest
from dynaconf.utils.inspect import builtin_dumpers
from dynaconf.utils.inspect import OutputFormatError
from dynaconf.utils.parse_conf import Lazy

if TYPE_CHECKING:  # pragma: no cover
    from dynaconf.base import LazySettings
    from dynaconf.base import Settings


SNAPSHOT_FORMAT = "dynaconf-forensic-snapshot"
SNAPSHOT_VERSION = 1

# Loaders that only describe Dynaconf itself instead of application settings.
# Note: ``undefined`` is intentionally *not* here. It is the identifier used
# when user code calls ``settings.set()`` without a loader, which is direct
# evidence of a runtime write and must remain visible.
INTERNAL_IDENTIFIERS = frozenset(
    {
        "_root_path",
        "default_settings",
        "envvars_first_load",
        "init_kwargs",
        "init_settings_module",
        "settings_module_method",
    }
)

MISSING = object()


def _normalize(value: Any, seen: set[int] | None = None) -> Any:
    """Convert Dynaconf/container values to plain JSON-compatible objects."""
    seen = seen or set()
    if isinstance(value, Lazy):
        return value._dynaconf_encode()

    if isinstance(value, dict):
        marker = id(value)
        if marker in seen:  # pragma: no cover - cycle guard
            return "<recursive>"
        seen.add(marker)
        result = {
            str(key): _normalize(item, seen) for key, item in value.items()
        }
        seen.discard(marker)
        return result

    if isinstance(value, (list, tuple)):
        return [_normalize(item, seen) for item in value]

    if isinstance(value, (set, frozenset)):
        return sorted((_normalize(item, seen) for item in value), key=repr)

    if value is None or isinstance(value, (bool, int, float, str)):
        return value

    return str(value)


def _canonical(value: Any) -> str:
    """Stable text used for equality checks and digests."""
    return json.dumps(
        _normalize(value),
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":"),
        default=str,
    )


def _digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(_canonical(value).encode()).hexdigest()


def _same(left: Any, right: Any) -> bool:
    if left is MISSING or right is MISSING:
        return left is right
    return _canonical(left) == _canonical(right)


def _source_dict(
    source_metadata,
    order: int,
    digest: dict | None = None,
    *,
    keys: dict | None = None,
    changed_keys: list[str] | None = None,
    merged_keys: list[str] | None = None,
) -> dict:
    return {
        "order": order,
        "generation": None,
        "loader": source_metadata.loader,
        "identifier": source_metadata.identifier,
        "env": source_metadata.env,
        "merged": bool(source_metadata.merged),
        "digest": digest,
        "keys": keys or {},
        "changed_keys": changed_keys or [],
        "merged_keys": merged_keys or [],
    }


def _source_identity(source: dict) -> str:
    return "|".join(
        [
            str(source.get("loader")),
            str(source.get("identifier")),
            str(source.get("env")),
            "merged" if source.get("merged") else "direct",
        ]
    )


def _key_source_identity(evidence: dict | None) -> str | None:
    if not evidence:
        return None
    return _source_identity(evidence)


def _resolve_digest(identifier: str, file_digests: dict) -> dict | None:
    """Find the digest for a source identifier.

    Loader identifiers do not always equal a file path: Python loaders use the
    module name and YAML multi-document sources use ``path[N]`` suffixes.
    """
    if identifier in file_digests:
        return file_digests[identifier]

    # YAML multi-doc: "/path/file.yml[0]" -> "/path/file.yml"
    if identifier.endswith("]") and "[" in identifier:
        candidate = identifier.rsplit("[", 1)[0]
        if candidate in file_digests:
            return file_digests[candidate]

    # Python modules: identifier is the module name, digest is keyed by path.
    basename = os.path.basename(identifier)
    for path, digest in file_digests.items():
        stem = os.path.splitext(os.path.basename(path))[0]
        if stem == basename or path == identifier:
            return digest
    return None


def _is_internal_source(source_metadata) -> bool:
    return source_metadata.identifier in INTERNAL_IDENTIFIERS


def _is_internal_key(key: str) -> bool:
    from dynaconf.base import UPPER_DEFAULT_SETTINGS

    return str(key) in UPPER_DEFAULT_SETTINGS


def _file_entry(identifier: str, digest: dict | None) -> dict:
    if digest is None:
        return {
            "identifier": identifier,
            "algorithm": None,
            "value": None,
            "size": None,
            "status": "unavailable",
        }
    return {"identifier": identifier, **digest, "status": "digest"}


def _loader_name(loader: Any) -> str:
    """Normalize a loader identifier to a JSON-friendly name."""
    if isinstance(loader, str):
        return loader
    return getattr(loader, "loader", str(loader))


def _winner(history: list[dict], effective: Any) -> dict | None:
    """Find the history event that produced the final effective value.

    History may contain events merged from another env (``from_env`` merges
    the child's records into the parent). Scanning backwards for an event
    whose effective value equals the current one keeps the reported winning
    source consistent with the current settings object.
    """
    if not history:
        return None
    target = _canonical(effective)
    for event in reversed(history):
        if _canonical(event.get("effective")) == target:
            return event
    return history[-1]


def get_forensic_snapshot(
    settings: Settings | LazySettings,
    *,
    label: str | None = None,
    previous: dict | None = None,
    include_internal: bool = False,
) -> dict:
    """Build a forensic snapshot of the currently effective settings.

    The snapshot separates:

    - **direct source evidence**: the raw value as loaded from a source
      (``loaded_by_loaders``);
    - **merged result evidence**: the effective value immediately after that
      source was applied, including any ``dynaconf_merge`` behaviour;
    - **the winning source** for every key in the final merged settings;
    - **file digests**, so a caller can later prove which bytes were loaded.

    :param settings: A Dynaconf instance.
    :param label: Optional human label for this generation (e.g. "run-1").
    :param previous: A snapshot returned by a previous call. When provided,
        the snapshot includes ``changes`` and evidence ``gaps`` relative to it.
    :param include_internal: Include Dynaconf internal keys and sources.
    :return: A JSON-serializable dict.
    """
    config = settings.__core__.config
    raw_history = dict(settings.loaded_by_loaders)
    effects = dict(config.loaded_effects)
    source_digests = dict(config.loaded_source_digests)
    file_digests = dict(config.loaded_file_digests)

    # Replay effective values in loading order to know the value *before* each
    # source. That is what makes "this source changed this key" provable.
    state: dict[str, Any] = {}
    source_records: list[dict] = []
    key_history: dict[str, list[dict]] = {}

    for order, (source_metadata, raw_data) in enumerate(raw_history.items()):
        effect_data = effects.get(source_metadata, raw_data)
        digest = source_digests.get(source_metadata)
        if digest is None:
            digest = _resolve_digest(
                str(source_metadata.identifier), file_digests
            )

        keys: dict[str, dict] = {}
        changed_keys: list[str] = []
        merged_keys: list[str] = []

        for key, direct_value in raw_data.items():
            key = str(key)
            effective_value = effect_data.get(key, direct_value)
            before = state.get(key, MISSING)
            changed = not _same(before, effective_value)
            state[key] = effective_value

            if not include_internal and _is_internal_key(key):
                continue

            entry = {
                "direct": _normalize(direct_value),
                "before": None if before is MISSING else _normalize(before),
                "effective": _normalize(effective_value),
                "changed": changed,
                "change": (
                    "added"
                    if before is MISSING
                    else ("modified" if changed else "unchanged")
                ),
            }
            if source_metadata.merged:
                entry["merged"] = True
                merged_keys.append(key)
            if changed:
                changed_keys.append(key)

            keys[key] = entry
            key_history.setdefault(key, []).append(
                {
                    "order": order,
                    "generation": None,
                    "loader": source_metadata.loader,
                    "identifier": source_metadata.identifier,
                    "env": source_metadata.env,
                    "merged": bool(source_metadata.merged),
                    "digest": digest,
                    **entry,
                }
            )

        if _is_internal_source(source_metadata) and not include_internal:
            continue

        source_records.append(
            _source_dict(
                source_metadata,
                order,
                digest,
                keys=keys,
                changed_keys=sorted(changed_keys),
                merged_keys=sorted(set(merged_keys)),
            )
        )

    current = _normalize(settings.as_dict(internal=include_internal))
    if not isinstance(current, dict):  # pragma: no cover - defensive
        current = {}

    generation_id = _digest({"current": current, "sources": source_records})
    generation = {
        "id": generation_id,
        "sequence": (
            previous.get("generation", {}).get("sequence", 0) + 1
            if previous
            else 1
        ),
        "label": label,
        "values_digest": _digest(current),
        "current_env": settings.current_env,
        "environments": bool(
            settings.get("ENVIRONMENTS_FOR_DYNACONF", False)
        ),
        "settings_module": _normalize(settings.get("SETTINGS_MODULE", None)),
        "loaded_files": list(config.loaded_files),
    }

    # Stamp every replay event with the generation that was effective then.
    for source in source_records:
        source["generation"] = generation_id
    for history in key_history.values():
        for event in history:
            event["generation"] = generation_id

    # Per-key evidence from the final effective value and its history.
    key_evidence: dict[str, dict] = {}
    for key, value in current.items():
        history = key_history.get(key, [])
        winner = _winner(history, value)
        key_evidence[key] = {
            "effective": value,
            "source": (
                {
                    "generation": generation_id,
                    "order": winner["order"],
                    "loader": winner["loader"],
                    "identifier": winner["identifier"],
                    "env": winner["env"],
                    "merged": winner["merged"],
                    "digest": winner["digest"],
                }
                if winner
                else None
            ),
            "direct": winner["direct"] if winner else None,
            "history": history,
        }

    # Keys seen in records but no longer effective stay visible.
    for key, history in key_history.items():
        if key not in key_evidence:
            key_evidence[key] = {
                "effective": None,
                "source": None,
                "direct": None,
                "history": history,
                "state": "not_effective",
            }

    if not include_internal:
        key_evidence = {
            key: value
            for key, value in key_evidence.items()
            if not _is_internal_key(key)
        }

    files = {}
    for identifier, digest in file_digests.items():
        files[identifier] = _file_entry(identifier, digest)
    for source in source_records:
        identifier = source["identifier"]
        if not source["digest"]:
            continue
        if identifier in files or _looks_like_file(str(identifier)):
            files.setdefault(
                identifier, _file_entry(identifier, source["digest"])
            )
        # Python sources are identified by module name; also expose the path
        # so callers can verify the file bytes directly.
        for path, digest in file_digests.items():
            if digest == source["digest"]:
                files.setdefault(path, _file_entry(path, digest))
                break

    snapshot = {
        "format": SNAPSHOT_FORMAT,
        "version": SNAPSHOT_VERSION,
        "generation": generation,
        "current": current,
        "sources": source_records,
        "keys": key_evidence,
        "files": files,
        "gaps": _collect_load_gaps(config, source_records)
        + _collect_untracked_keys(key_evidence),
    }

    if previous is not None:
        comparison = compare_snapshots(previous, snapshot)
        snapshot["comparison"] = comparison
        snapshot["changes"] = comparison["changes"]
        snapshot["gaps"] = comparison["gaps"]

    return snapshot


def _collect_load_gaps(config, source_records: list[dict]) -> list[dict]:
    gaps: list[dict] = []
    seen: set[tuple] = set()

    for error in config.loaded_source_errors:
        marker = (
            _loader_name(error.get("loader")),
            error.get("identifier"),
            "unavailable",
        )
        if marker in seen:
            continue
        seen.add(marker)
        gaps.append(
            {
                "kind": "source_unavailable",
                "loader": _loader_name(error.get("loader")),
                "identifier": error.get("identifier"),
                "error": error.get("error"),
                "missing": bool(error.get("missing")),
                "detail": (
                    "The source was requested while loading but no content "
                    "was available; keys it would have provided are not "
                    "evidenced in this generation."
                ),
            }
        )

    for source in source_records:
        if source["digest"] is not None:
            continue
        identifier = str(source["identifier"])
        if not _looks_like_file(identifier):
            continue
        marker = (source["loader"], identifier, "digest")
        if marker in seen:
            continue
        seen.add(marker)
        gaps.append(
            {
                "kind": "digest_unavailable",
                "loader": source["loader"],
                "identifier": identifier,
                "env": source["env"],
                "detail": (
                    "The source was loaded but its content digest could not "
                    "be captured (not a regular readable file)."
                ),
            }
        )
    return gaps


def _looks_like_file(identifier: str) -> bool:
    return identifier.endswith(
        (
            ".py",
            ".toml",
            ".tml",
            ".yaml",
            ".yml",
            ".json",
            ".ini",
            ".conf",
            ".properties",
        )
    )


def _collect_untracked_keys(key_evidence: dict) -> list[dict]:
    """Report effective keys that have no loading record at all.

    Normally every effective key has a source. If one does not, the snapshot
    must say so instead of silently attributing it to nothing.
    """
    gaps = []
    for key, evidence in key_evidence.items():
        if evidence.get("source") is not None:
            continue
        if evidence.get("state") == "not_effective":
            continue
        gaps.append(
            {
                "kind": "key_untracked",
                "identifier": None,
                "key": key,
                "detail": (
                    "The key is effective but no loading record explains it; "
                    "its provenance is unknown in this generation."
                ),
            }
        )
    return gaps


def compare_snapshots(previous: dict, current: dict) -> dict:
    """Compare two forensic snapshots.

    Returns key level changes (from ``previous`` to ``current``), source level
    changes and explicit evidence gaps.
    """
    previous_current = previous.get("current", {})
    current_current = current.get("current", {})
    previous_keys = previous.get("keys", {})
    current_keys = current.get("keys", {})

    changes: list[dict] = []
    for key in sorted(set(previous_current) | set(current_current)):
        old = previous_current.get(key, MISSING)
        new = current_current.get(key, MISSING)
        if _same(old, new):
            continue
        if old is MISSING:
            kind = "added"
        elif new is MISSING:
            kind = "removed"
        else:
            kind = "modified"

        old_evidence = previous_keys.get(key, {})
        new_evidence = current_keys.get(key, {})
        changes.append(
            {
                "key": key,
                "change": kind,
                "previous": None if old is MISSING else _normalize(old),
                "current": None if new is MISSING else _normalize(new),
                "previous_source": old_evidence.get("source"),
                "source": new_evidence.get("source"),
                "direct": new_evidence.get("direct"),
                "merged": bool(
                    (new_evidence.get("source") or {}).get("merged")
                ),
            }
        )

    previous_sources = {
        _source_identity(source): source
        for source in previous.get("sources", [])
    }
    current_sources = {
        _source_identity(source): source
        for source in current.get("sources", [])
    }

    source_changes: list[dict] = []
    gaps: list[dict] = list(current.get("gaps", []))

    for identity, source in current_sources.items():
        old_source = previous_sources.get(identity)
        if old_source is None:
            source_changes.append(
                {
                    "source": identity,
                    "change": "source_added",
                    "loader": source["loader"],
                    "identifier": source["identifier"],
                    "env": source["env"],
                    "changed_keys": source.get("changed_keys", []),
                }
            )
            continue

        old_digest = old_source.get("digest")
        new_digest = source.get("digest")
        if old_digest != new_digest:
            source_changes.append(
                {
                    "source": identity,
                    "change": "content_changed",
                    "loader": source["loader"],
                    "identifier": source["identifier"],
                    "env": source["env"],
                    "previous_digest": old_digest,
                    "current_digest": new_digest,
                    "changed_keys": source.get("changed_keys", []),
                }
            )
        elif old_source.get("changed_keys") != source.get("changed_keys"):
            source_changes.append(
                {
                    "source": identity,
                    "change": "effect_changed",
                    "loader": source["loader"],
                    "identifier": source["identifier"],
                    "env": source["env"],
                    "previous_changed_keys": old_source.get(
                        "changed_keys", []
                    ),
                    "current_changed_keys": source.get("changed_keys", []),
                }
            )

    for identity, source in previous_sources.items():
        if identity in current_sources:
            continue
        previously_loaded = set(source.get("keys", {}))
        missing_keys = sorted(
            key
            for key in previously_loaded
            if _key_source_identity(
                (current_keys.get(key) or {}).get("source")
            )
            != identity
        )
        evidence = {
            "source": identity,
            "change": "source_missing",
            "loader": source["loader"],
            "identifier": source["identifier"],
            "env": source["env"],
            "previous_digest": source.get("digest"),
            "keys_previously_loaded": sorted(previously_loaded),
            "keys_no_longer_covered": missing_keys,
        }
        source_changes.append(evidence)
        gaps.append(
            {
                "kind": "source_missing",
                "loader": source["loader"],
                "identifier": source["identifier"],
                "env": source["env"],
                "previous_digest": source.get("digest"),
                "keys_previously_loaded": sorted(previously_loaded),
                "keys_no_longer_covered": missing_keys,
                "detail": (
                    "A source present in the previous generation is absent "
                    "from the current one. Keys listed above are no longer "
                    "evidenced by that source; their current values, if any, "
                    "come from the remaining sources."
                ),
            }
        )

    unique_gaps = []
    seen = set()
    for gap in gaps:
        marker = (
            gap.get("kind"),
            gap.get("identifier"),
            gap.get("loader"),
            gap.get("source"),
        )
        if marker in seen:
            continue
        seen.add(marker)
        unique_gaps.append(gap)

    return {
        "previous_generation": previous.get("generation", {}).get("id"),
        "previous_sequence": previous.get("generation", {}).get("sequence"),
        "current_generation": current.get("generation", {}).get("id"),
        "current_sequence": current.get("generation", {}).get("sequence"),
        "changes": changes,
        "source_changes": source_changes,
        "gaps": unique_gaps,
    }


def verify_file_digest(snapshot: dict, identifier: str) -> dict:
    """Compare current bytes of ``identifier`` with the recorded digest.

    This is the "look the file content up again" operation: it proves whether
    the file still has the bytes that produced this snapshot.
    """
    files = snapshot.get("files", {})
    recorded = files.get(identifier)
    resolved_identifier = identifier
    if recorded is None:
        for path, entry in files.items():
            if os.path.basename(path) == os.path.basename(identifier):
                recorded = entry
                resolved_identifier = path
                break

    if recorded is None:
        return {
            "identifier": identifier,
            "status": "not_recorded",
            "match": False,
            "expected": None,
            "actual": None,
        }

    expected = {
        key: recorded.get(key)
        for key in ("algorithm", "value", "size")
        if recorded.get(key) is not None
    }
    actual = content_digest(resolved_identifier)
    if actual is None:
        return {
            "identifier": resolved_identifier,
            "status": "file_unavailable",
            "match": False,
            "expected": expected,
            "actual": None,
        }

    return {
        "identifier": resolved_identifier,
        "status": "match" if actual == expected else "mismatch",
        "match": actual == expected,
        "expected": expected,
        "actual": actual,
    }


def dump_forensic_snapshot(
    snapshot: dict,
    *,
    to_file: str | os.PathLike | None = None,
    print_report: bool = False,
    dumper: str | Any | None = None,
) -> dict:
    """Optionally serialise a snapshot using the inspect dumpers."""
    if dumper is None:
        _dumper = builtin_dumpers["yaml"]
    elif isinstance(dumper, str):
        _dumper = builtin_dumpers.get(dumper)
        if _dumper is None:
            raise OutputFormatError(
                f"The desired format is not available: {dumper!r}"
            )
    else:
        _dumper = dumper

    if to_file is not None:
        with open(to_file, "w", encoding="utf-8") as file:
            _dumper(snapshot, file)
    if print_report:
        _dumper(snapshot, sys.stdout)
    return snapshot
