"""Offline inventory of the evidence directory.

Every regular file under the configured search roots is indexed once.  Files
that share a basename are deliberately kept separate: an SPDX edge may only be
proved by *its own* checksum, never by a filename match, so a name collision
has to produce independent evidence for each candidate.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from spdx_tools.spdx.model import ChecksumAlgorithm

from .digest import hash_file

_SIDECAR_RE = re.compile(r"^(?P<hex>[0-9a-fA-F]{8,128})(?:\s+\*?\S.*)?$")


@dataclass
class InventoryFile:
    path: Path
    rel_path: str
    basename: str
    size: int
    _digest_cache: Dict[ChecksumAlgorithm, str] = field(default_factory=dict)

    def digest(self, algorithm: ChecksumAlgorithm) -> str:
        if algorithm not in self._digest_cache:
            self._digest_cache[algorithm] = hash_file(self.path, algorithm)
        return self._digest_cache[algorithm]


@dataclass
class Inventory:
    roots: List[Path]
    files: List[InventoryFile]
    _by_basename: Dict[str, List[InventoryFile]]
    _by_digest: Dict[Tuple[ChecksumAlgorithm, str], List[InventoryFile]]

    @classmethod
    def build(cls, search_roots) -> "Inventory":
        roots = [Path(root).resolve() for root in search_roots]
        files: List[InventoryFile] = []
        for root in roots:
            if not root.exists():
                continue
            for current, _dirs, names in os.walk(root):
                for name in sorted(names):
                    path = Path(current) / name
                    if not path.is_file():
                        continue
                    files.append(
                        InventoryFile(
                            path=path,
                            rel_path=str(path.relative_to(root)),
                            basename=name,
                            size=path.stat().st_size,
                        )
                    )
        by_basename: Dict[str, List[InventoryFile]] = {}
        for item in files:
            by_basename.setdefault(item.basename, []).append(item)
        return cls(roots=roots, files=files, _by_basename=by_basename, _by_digest={})

    def find_by_basename(self, basename: str) -> List[InventoryFile]:
        return list(self._by_basename.get(basename, []))

    def find_by_digest(self, algorithm: ChecksumAlgorithm, value: str) -> List[InventoryFile]:
        key = (algorithm, value.strip().lower())
        if key not in self._by_digest:
            matches = [
                item
                for item in self.files
                if item.digest(algorithm).lower() == value.strip().lower()
            ]
            self._by_digest[key] = matches
        return list(self._by_digest[key])

    def get(self, path: Path) -> Optional[InventoryFile]:
        resolved = path.resolve()
        for item in self.files:
            if item.path == resolved:
                return item
        return None


def read_sidecar_digest(path: Path) -> Optional[str]:
    """Read a `<file>.<algo>` sidecar, tolerating `hex` and `hex  file` forms.

    Returns the lowercase hex string, or None when the file is missing or does
    not contain a recognisable digest line.
    """
    sidecar = Path(path)
    if not sidecar.is_file():
        return None
    for line in sidecar.read_text(encoding="utf-8").splitlines():
        match = _SIDECAR_RE.match(line.strip())
        if match:
            return match.group("hex").lower()
    return None


def sidecar_for(path: Path, algorithm_name: str) -> Path:
    suffix = algorithm_name.lower().replace("_", "-")
    return Path(str(path) + f".{suffix}")
