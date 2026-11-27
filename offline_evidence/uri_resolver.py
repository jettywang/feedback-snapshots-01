"""Map SPDX external-document URIs onto local offline paths.

Network/URN identifiers cannot be dereferenced in an offline evidence store;
they are reported as non-local instead of being fetched.  Local identifiers are
resolved against the search roots, first as an explicit relative/absolute path
and then, if that does not exist, by basename so that a relocated mirror still
produces digest-checkable candidates.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional
from urllib.parse import unquote, urlparse

from .inventory import Inventory, InventoryFile

_LOCAL_SCHEMES = ("", "file")


@dataclass
class Resolution:
    kind: str  # "local-path" | "basename-fallback" | "non-local"
    candidates: List[InventoryFile]
    referenced_path: Optional[Path]
    note: Optional[str] = None


def _candidate_paths(uri_path: str, root: Path) -> List[Path]:
    clean = unquote(uri_path.lstrip("/"))
    if not clean or clean in (".", ""):
        return []
    return [root / clean, Path(clean)]


def resolve_uri(uri: str, inventory: Inventory) -> Resolution:
    parsed = urlparse(uri)
    if parsed.scheme not in _LOCAL_SCHEMES:
        return Resolution(
            kind="non-local",
            candidates=[],
            referenced_path=None,
            note=f"URI scheme '{parsed.scheme}' cannot be dereferenced offline",
        )

    if parsed.scheme == "file":
        raw_path = unquote(parsed.path)
        explicit = [Path(raw_path)]
        basename = Path(raw_path).name
    else:
        explicit: List[Path] = []
        for root in inventory.roots:
            explicit.extend(_candidate_paths(uri, root))
        basename = Path(unquote(parsed.path)).name

    referenced: Optional[Path] = None
    for path in explicit:
        item = inventory.get(path)
        if item is not None:
            referenced = item.path
            return Resolution("local-path", [item], item.path)

    fallback = inventory.find_by_basename(basename)
    if fallback:
        return Resolution(
            kind="basename-fallback",
            candidates=fallback,
            referenced_path=fallback[0].path,
            note="explicit path absent; matched by basename within offline root",
        )

    return Resolution(
        kind="local-path",
        candidates=[],
        referenced_path=explicit[0] if explicit else None,
        note="no file with this path or basename exists in the offline root",
    )
