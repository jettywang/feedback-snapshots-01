# Copyright New York University and the in-toto contributors
# SPDX-License-Identifier: Apache-2.0

"""
<Program Name>
  evidence_index.py

<Purpose>
  Provides an optional, untrusted evidence index that locates link metadata
  files and sublayout evidence directories by step name and *full* functionary
  keyid.

  in-toto's traditional link filenames and sublayout directory names only
  contain the first eight characters of a functionary keyid. If two authorized
  functionaries share that prefix, the legacy names cannot unambiguously map
  evidence to a functionary. An evidence index resolves that naming collision
  without changing the trust model:

  * An index is a location hint only. It never authorizes a key and never
    replaces payload, signature or step-binding verification.
  * Every indexed path must resolve inside the evidence package, i.e. the
    directory the index applies to (``link_dir_path``). Absolute paths and
    paths that resolve outside the package are rejected.
  * An entry binds one step and one full keyid to one link file (and,
    optionally, one sublayout directory). Entries naming a step that is not in
    the layout, or a keyid that is not authorized for that step, are rejected.
  * Two index entries must not resolve to the same file or directory. A single
    piece of evidence may not stand in for two steps or two functionaries.

  Canonical format::

      {
        "version": 1,
        "entries": [
          {
            "step": "build",
            "keyid": "<full functionary keyid>",
            "link": "evidence/build.<full-keyid>.link",
            "sublayout": "evidence/build.<full-keyid>"
          }
        ]
      }

  ``link`` is required and names a Link or Layout metadata file. ``sublayout``
  is optional and, for Layout payloads, names the directory holding the
  delegated layout's evidence. If omitted for a sublayout, the legacy
  ``<step>.<keyid-prefix>`` directory naming is used.

  The equivalent compact form is also accepted::

      {
        "version": 1,
        "steps": {
          "build": {
            "<full functionary keyid>": {
              "link": "evidence/build.<full-keyid>.link",
              "sublayout": "evidence/build.<full-keyid>"
            }
          }
        }
      }

  In the compact form an entry may be a plain string, shorthand for
  ``{"link": "<string>"}``.

  Paths inside the index are resolved relative to the evidence package root,
  not relative to the index file's own directory. The index file itself must
  live inside the package it describes.

"""

import json
import os
from typing import Any, Dict, List, Optional

from in_toto.exceptions import EvidenceIndexError
from in_toto.formats import _check_str

EVIDENCE_INDEX_FILENAME = "evidence-index.json"
SCHEMA_VERSION = 1


def _is_within(root: str, candidate: str) -> bool:
    """Return True if candidate is root or a descendant of root."""
    try:
        return os.path.commonpath([root, candidate]) == root
    except ValueError:
        # Different drives on platforms that support them.
        return False


def resolve_evidence_index(
    link_dir_path: str, evidence_index: Optional[Any] = None
) -> Optional["EvidenceIndex"]:
    """Return the EvidenceIndex that applies to link_dir_path, or None.

    ``evidence_index`` may be an EvidenceIndex instance (whose package root
    must match link_dir_path), a path to an index file, or None. If None, an
    ``evidence-index.json`` inside link_dir_path is loaded when present.
    """
    package_root = os.path.realpath(os.path.abspath(link_dir_path))

    if isinstance(evidence_index, EvidenceIndex):
        if evidence_index.package_root != package_root:
            raise EvidenceIndexError(
                "Evidence index package scope binding failed: index is"
                f" rooted at '{evidence_index.package_root}', but the evidence"
                f" package is '{package_root}'."
            )
        return evidence_index

    if evidence_index is None:
        evidence_index = os.path.join(package_root, EVIDENCE_INDEX_FILENAME)
        if not os.path.isfile(evidence_index):
            return None

    # Resolve with the package root so that a symlinked index file cannot
    # smuggle its contents in from outside the evidence package.
    return EvidenceIndex.load(evidence_index, package_root=package_root)


class IndexEntry:
    """A single (step, full keyid) -> evidence location binding."""

    __slots__ = ("step", "keyid", "link", "sublayout", "layout_keyid")

    def __init__(  # noqa: PLR0913
        self,
        step: str,
        keyid: str,
        link: str,
        sublayout: Optional[str] = None,
        layout_keyid: Optional[str] = None,
    ):
        self.step = step
        self.keyid = keyid
        self.link = link
        self.sublayout = sublayout
        # Canonical keyid spelling from the layout, filled in by
        # validate_for_layout so callers can key evidence by exact keyid.
        self.layout_keyid = layout_keyid

    def __repr__(self):
        return (
            f"IndexEntry(step={self.step!r}, keyid={self.keyid!r},"
            f" link={self.link!r}, sublayout={self.sublayout!r})"
        )


class EvidenceIndex:
    """Parsed, validated evidence index.

    NOTE: Instances are location hints only. They must never be used as a
    source of trust or as a replacement for signature verification.
    """

    def __init__(
        self,
        entries: List[IndexEntry],
        package_root: str,
        source: Optional[str] = None,
    ):
        self.entries = entries
        self.package_root = os.path.realpath(os.path.abspath(package_root))
        self.source = source

        self._by_step_key: Dict[tuple, IndexEntry] = {}
        for entry in entries:
            key = (entry.step, entry.keyid.lower())
            if key in self._by_step_key:
                raise EvidenceIndexError(
                    "Evidence index duplicate binding: step"
                    f" '{entry.step}' and keyid '{entry.keyid}' have more than"
                    " one entry."
                )
            self._by_step_key[key] = entry

    @classmethod
    def load(
        cls, path: str, package_root: Optional[str] = None
    ) -> "EvidenceIndex":
        """Load and validate an index from disk."""
        path = os.fspath(path)
        index_path = os.path.realpath(os.path.abspath(path))

        if package_root is None:
            package_root = os.path.dirname(index_path)
        package_root = os.path.realpath(os.path.abspath(package_root))

        if not _is_within(package_root, index_path):
            raise EvidenceIndexError(
                "Evidence index package scope binding failed: index file"
                f" '{index_path}' is outside evidence package"
                f" '{package_root}'."
            )

        try:
            with open(index_path, encoding="utf8") as fp:
                data = json.load(fp)
        except (OSError, ValueError) as e:
            raise EvidenceIndexError(
                f"Could not read evidence index '{index_path}': {e}"
            ) from e

        return cls.from_dict(data, package_root, source=index_path)

    @classmethod
    def from_dict(
        cls,
        data: Dict[str, Any],
        package_root: str,
        source: Optional[str] = None,
    ) -> "EvidenceIndex":
        """Create an index from its JSON/dict representation."""
        if not isinstance(data, dict):
            raise EvidenceIndexError("Evidence index must be a JSON object.")

        version = data.get("version", SCHEMA_VERSION)
        if not isinstance(version, int) or version != SCHEMA_VERSION:
            raise EvidenceIndexError(
                "Unsupported evidence index version"
                f" '{version}', expected '{SCHEMA_VERSION}'."
            )

        has_entries = "entries" in data
        has_steps = "steps" in data
        if has_entries == has_steps:
            raise EvidenceIndexError(
                "Evidence index must contain exactly one of the 'entries' list"
                " or the 'steps' mapping."
            )

        if has_entries:
            raw_entries = data["entries"]
            if not isinstance(raw_entries, list):
                raise EvidenceIndexError(
                    "Evidence index 'entries' must be a list."
                )
            entries = [cls._parse_entry(item) for item in raw_entries]

        else:
            steps = data["steps"]
            if not isinstance(steps, dict):
                raise EvidenceIndexError(
                    "Evidence index 'steps' must be an object."
                )

            entries = []
            for step_name, key_map in steps.items():
                if not isinstance(key_map, dict):
                    raise EvidenceIndexError(
                        "Evidence index 'steps' value for step"
                        f" '{step_name}' must be an object keyed by keyid."
                    )
                for keyid, value in key_map.items():
                    entry = value
                    if isinstance(entry, str):
                        entry = {"link": entry}
                    elif not isinstance(entry, dict):
                        raise EvidenceIndexError(
                            "Evidence index value for step"
                            f" '{step_name}' and keyid '{keyid}' must be a"
                            " string or an object."
                        )
                    entries.append(
                        cls._parse_entry(
                            {"step": step_name, "keyid": keyid, **entry}
                        )
                    )

        return cls(entries, package_root=package_root, source=source)

    @staticmethod
    def _parse_entry(raw_entry: Any) -> IndexEntry:
        """Validate and normalize one entry."""
        if not isinstance(raw_entry, dict):
            raise EvidenceIndexError("Evidence index entries must be objects.")

        step = raw_entry.get("step")
        keyid = raw_entry.get("keyid")
        link = raw_entry.get("link")
        sublayout = raw_entry.get("sublayout")

        _check_str(step)
        if not step:
            raise EvidenceIndexError(
                "Evidence index step binding failed: empty step name."
            )

        _check_str(keyid)
        if not keyid:
            raise EvidenceIndexError(
                f"Evidence index identity binding failed: empty keyid for"
                f" step '{step}'."
            )
        try:
            int(keyid, 16)
        except ValueError as e:
            raise EvidenceIndexError(
                "Evidence index identity binding failed: keyid"
                f" '{keyid}' for step '{step}' is not a hex string."
            ) from e

        _check_str(link)
        if not link:
            raise EvidenceIndexError(
                "Evidence index link path binding failed: empty link path for"
                f" step '{step}' and keyid '{keyid}'."
            )

        if sublayout is not None:
            _check_str(sublayout)
            if not sublayout:
                raise EvidenceIndexError(
                    "Evidence index sublayout path binding failed: empty"
                    f" sublayout path for step '{step}' and keyid '{keyid}'."
                )

        return IndexEntry(step, keyid, link, sublayout)

    def entries_for_step(self, step_name: str) -> List[IndexEntry]:
        """Return all entries bound to step_name, in index order."""
        return [entry for entry in self.entries if entry.step == step_name]

    def entry_for(self, step_name: str, keyid: str) -> Optional[IndexEntry]:
        """Return the entry for step_name and keyid, if any."""
        return self._by_step_key.get((step_name, keyid.lower()))

    def _resolve(self, rel_path: str, binding: str) -> str:
        """Resolve an index path and enforce the evidence package scope."""
        if "\x00" in rel_path:
            raise EvidenceIndexError(
                f"{binding} failed: path contains a NUL byte."
            )

        if os.path.isabs(rel_path):
            raise EvidenceIndexError(
                f"{binding} failed: path '{rel_path}' is absolute; evidence"
                " index paths must be relative to the evidence package"
                f" '{self.package_root}'."
            )

        candidate = os.path.realpath(os.path.join(self.package_root, rel_path))
        if not _is_within(self.package_root, candidate):
            raise EvidenceIndexError(
                f"{binding} failed: path '{rel_path}' resolves to"
                f" '{candidate}', outside evidence package"
                f" '{self.package_root}'."
            )

        return candidate

    def link_path(self, entry: IndexEntry) -> str:
        """Return the safe absolute path of entry's link metadata file."""
        return self._resolve(
            entry.link,
            "Evidence index link path binding for step"
            f" '{entry.step}' and keyid '{entry.keyid}'",
        )

    def sublayout_path(self, entry: IndexEntry) -> Optional[str]:
        """Return the safe absolute path of entry's sublayout directory."""
        if entry.sublayout is None:
            return None
        return self._resolve(
            entry.sublayout,
            "Evidence index sublayout path binding for step"
            f" '{entry.step}' and keyid '{entry.keyid}'",
        )

    def validate_for_layout(self, layout) -> None:
        """Reject entries that cannot match an authorized layout binding.

        This does not grant authority. It only checks that an entry's step
        exists in the layout and that its keyid is authorized for that step.
        """
        allowed: Dict[str, Dict[str, str]] = {}
        for step in layout.steps:
            keyids: Dict[str, str] = {}
            for authorized_keyid in step.pubkeys:
                keyids[authorized_keyid.lower()] = authorized_keyid
                subkeys = layout.keys.get(authorized_keyid, {}).get(
                    "subkeys", {}
                )
                for subkey in subkeys:
                    keyids[subkey.lower()] = subkey
            allowed[step.name] = keyids

        for entry in self.entries:
            if entry.step not in allowed:
                raise EvidenceIndexError(
                    "Evidence index step binding failed: entry for keyid"
                    f" '{entry.keyid}' names step '{entry.step}', which is not"
                    " defined in the layout."
                )

            if entry.keyid.lower() not in allowed[entry.step]:
                raise EvidenceIndexError(
                    "Evidence index identity binding failed: keyid"
                    f" '{entry.keyid}' is not authorized for step"
                    f" '{entry.step}'."
                )

            # Record the canonical spelling used by signature verification.
            entry.layout_keyid = allowed[entry.step][entry.keyid.lower()]
