# SPDX-License-Identifier: MIT OR Apache-2.0
"""Offline structural analysis of TUF root authorization.

Given a trusted current root and a chain of candidate successor roots, this
module answers a single, narrowly-scaled question:

    What is the *minimum* set of distinct signing keys (physical key material,
    not keyid aliases) an attacker who controls those keys needs in order to:

      1. sign a given top-level role (direct signing authority),
      2. re-sign snapshot / timestamp (freeze / re-point metadata),
      3. deliver an *arbitrary new target* end to end, or
      4. complete a malicious root migration (the dual-threshold rule).

It works only from the public key material embedded in the root documents.
It never reads private keys and never touches the network. It uses the real
``tuf`` data model (``Root`` / ``Role`` / ``Key``) to parse the documents, so
the roles, thresholds and key records are interpreted exactly as a client
interprets them.

Why material, not keyid
-----------------------
``securesystemslib`` documents that a keyid "is not verified to be the hash of
a specific representation of the key". The same public key can therefore be
registered under several keyid aliases, and counting keyids over-counts the
number of independent keys. This analyzer groups keys by the tuple
``(keytype, scheme, keyval)`` and treats each distinct tuple as one physical
key that an attacker has to compromise once.

Bounded scope
-------------
This evaluates the *authorization structure* (thresholds and key sharing) only.
It cannot tell whether two logical keys are operated by independent people,
stored in independent HSMs, or share a deployment pipeline. Treat every result
as "number of distinct key materials", never as "number of independent
organizations".
"""

from __future__ import annotations

import argparse
import hashlib
import itertools
import json
from dataclasses import dataclass, field
from itertools import pairwise
from pathlib import Path
from typing import TYPE_CHECKING, Any

from tuf.api.metadata import Metadata, Root

if TYPE_CHECKING:
    from collections.abc import Iterable

TOP_ROLES = ("root", "targets", "snapshot", "timestamp")
# Roles whose signatures an attacker must forge to push an arbitrary target.
DELIVERY_ROLES = ("targets", "snapshot", "timestamp")
# Safety guard for the exhaustive set-cover search.
DEFAULT_MAX_MATERIALS = 30
# Cap on how many minimum coalitions to enumerate (the result set can explode).
MAX_COALITIONS_REPORTED = 20


# --------------------------------------------------------------------------- #
# Parsing and material grouping
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class Material:
    """One distinct physical key, identified by its public material."""

    fingerprint: str
    keytype: str
    scheme: str
    keyval: dict[str, Any]
    aliases: frozenset[str]

    @property
    def short_id(self: Material) -> str:
        return self.fingerprint[:12]


@dataclass
class RootView:
    """A parsed root reduced to material-based role authorization."""

    version: int
    root: Root
    materials: dict[str, Material]
    # role -> list of distinct physical materials that may sign that role.
    role_materials: dict[str, list[str]]
    thresholds: dict[str, int]

    def role_satisfiable(
        self: RootView, role: str, held: frozenset[str]
    ) -> bool:
        """True if ``held`` materials meet the role threshold.

        Mirrors tuf's counting rule: a role's threshold counts distinct
        signing keys. The same material reused twice in one role only counts
        once, so de-duplicating here matches the implementation.
        """
        usable = set(self.role_materials[role]) & set(held)
        return len(usable) >= self.thresholds[role]


def _fingerprint(keytype: str, scheme: str, keyval: dict[str, Any]) -> str:
    """Stable hash of the public key material (the merge identity)."""
    payload = json.dumps(
        [keytype, scheme, keyval], sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def load_root_view(path: str | Path) -> RootView:
    """Parse a root JSON file and merge keyid aliases by public material."""
    metadata = Metadata[Root].from_file(str(path))
    root = metadata.signed

    # fingerprint -> set of keyid aliases and the defining material fields.
    aliases: dict[str, set[str]] = {}
    material_fields: dict[str, tuple[str, str, dict[str, Any]]] = {}

    for keyid, key in root.keys.items():
        fp = _fingerprint(key.keytype, key.scheme, key.keyval)
        aliases.setdefault(fp, set()).add(keyid)
        material_fields.setdefault(
            fp, (key.keytype, key.scheme, dict(key.keyval))
        )

    materials: dict[str, Material] = {}
    for fp, (keytype, scheme, keyval) in material_fields.items():
        materials[fp] = Material(
            fingerprint=fp,
            keytype=keytype,
            scheme=scheme,
            keyval=keyval,
            aliases=frozenset(aliases[fp]),
        )

    role_materials: dict[str, list[str]] = {}
    thresholds: dict[str, int] = {}
    for role in TOP_ROLES:
        tuf_role = root.roles[role]
        seen: set[str] = set()
        ordered: list[str] = []
        for keyid in tuf_role.keyids:
            if keyid not in root.keys:
                # Dangling keyid: tuf logs and skips it; do the same.
                continue
            key = root.keys[keyid]
            fp = _fingerprint(key.keytype, key.scheme, key.keyval)
            if fp not in seen:
                seen.add(fp)
                ordered.append(fp)
        role_materials[role] = ordered
        thresholds[role] = tuf_role.threshold

    return RootView(
        version=root.version,
        root=root,
        materials=materials,
        role_materials=role_materials,
        thresholds=thresholds,
    )


# --------------------------------------------------------------------------- #
# Minimum winning coalitions
# --------------------------------------------------------------------------- #
def minimum_coalitions(
    role_materials: dict[str, list[str]],
    thresholds: dict[str, int],
    roles: Iterable[str],
    max_materials: int = DEFAULT_MAX_MATERIALS,
) -> list[frozenset[str]]:
    """Return every minimum (inclusion-minimal, smallest-size) key set.

    A coalition "wins" if, for every role in ``roles``, the number of held
    materials that are authorized for that role reaches its threshold. The
    search enumerates subsets in increasing size so the first winning size is
    the minimum, and collects all inclusion-minimal winners at that size.
    """
    universe: set[str] = set()
    role_sets: dict[str, set[str]] = {}
    for role in roles:
        members = set(role_materials[role])
        role_sets[role] = members
        universe |= members

    if len(universe) > max_materials:
        raise ValueError(
            f"{len(universe)} distinct materials exceeds max_materials="
            f"{max_materials}; raise the limit explicitly to run the "
            "exhaustive search"
        )

    def wins(held: frozenset[str]) -> bool:
        return all(
            len(role_sets[role] & held) >= thresholds[role] for role in roles
        )

    material_list = sorted(universe)
    for size in range(1, len(material_list) + 1):
        winners = [
            frozenset(combo)
            for combo in itertools.combinations(material_list, size)
            if wins(frozenset(combo))
        ]
        if winners:
            return winners
    return []


# --------------------------------------------------------------------------- #
# Structural findings
# --------------------------------------------------------------------------- #
@dataclass
class Finding:
    severity: str
    code: str
    message: str


@dataclass
class CoalitionResult:
    label: str
    roles: tuple[str, ...]
    size: int
    coalitions: list[frozenset[str]]
    note: str = ""


@dataclass
class AnalysisReport:
    trusted_version: int
    candidate_versions: list[int]
    distinct_materials: int
    total_keyids: int
    role_views: dict[int, dict[str, dict[str, Any]]] = field(
        default_factory=dict
    )
    findings: list[Finding] = field(default_factory=list)
    per_role_authority: list[CoalitionResult] = field(default_factory=list)
    freeze_authority: CoalitionResult | None = None
    arbitrary_delivery: CoalitionResult | None = None
    migration: CoalitionResult | None = None

    def to_dict(self: AnalysisReport) -> dict[str, Any]:
        def coalitions(cr: CoalitionResult | None) -> dict[str, Any] | None:
            if cr is None:
                return None
            return {
                "label": cr.label,
                "roles": list(cr.roles),
                "minimum_size": cr.size,
                "coalitions": [
                    sorted(c) for c in cr.coalitions[:MAX_COALITIONS_REPORTED]
                ],
                "coalitions_truncated": len(cr.coalitions)
                > MAX_COALITIONS_REPORTED,
                "note": cr.note,
            }

        return {
            "trusted_version": self.trusted_version,
            "candidate_versions": self.candidate_versions,
            "distinct_materials": self.distinct_materials,
            "total_keyids": self.total_keyids,
            "role_views": self.role_views,
            "findings": [f.__dict__ for f in self.findings],
            "per_role_authority": [
                coalitions(c) for c in self.per_role_authority
            ],
            "freeze_authority": coalitions(self.freeze_authority),
            "arbitrary_target_delivery": coalitions(self.arbitrary_delivery),
            "root_migration": coalitions(self.migration),
        }


def _shared_key_findings(view: RootView) -> list[Finding]:
    """Flag material reused across roles and material with multiple aliases."""
    findings: list[Finding] = []
    usage: dict[str, list[str]] = {}
    for role in TOP_ROLES:
        for fp in view.role_materials[role]:
            usage.setdefault(fp, []).append(role)
    for fp, roles in sorted(usage.items()):
        if len(set(roles)) <= 1:
            continue
        material = view.materials[fp]
        findings.append(
            Finding(
                "warning",
                "shared-key",
                f"root v{view.version}: material {material.short_id}\u2026 is "
                f"authorized for multiple roles: "
                f"{', '.join(sorted(set(roles)))}"
                f"; one compromise counts toward all of them "
                f"(aliases: {sorted(material.aliases)})",
            )
        )
    for material in view.materials.values():
        if len(material.aliases) > 1:
            findings.append(
                Finding(
                    "info",
                    "keyid-alias",
                    f"root v{view.version}: one physical key carries "
                    f"{len(material.aliases)} keyid aliases "
                    f"{sorted(material.aliases)}; keyid counting would "
                    "over-count independent keys",
                )
            )
    return findings


def _role_health_findings(view: RootView) -> list[Finding]:
    """Flag unsatisfiable thresholds and dangling keyids within one root."""
    findings: list[Finding] = []
    for role in TOP_ROLES:
        distinct = len(view.role_materials[role])
        if view.thresholds[role] > distinct:
            findings.append(
                Finding(
                    "critical",
                    "unsatisfiable-threshold",
                    f"root v{view.version}: {role} threshold "
                    f"{view.thresholds[role]} exceeds {distinct} distinct "
                    "authorized material(s); role cannot be signed",
                )
            )
        for keyid in view.root.roles[role].keyids:
            if keyid not in view.root.keys:
                findings.append(
                    Finding(
                        "warning",
                        "dangling-keyid",
                        f"root v{view.version}: role {role} references "
                        f"unknown keyid {keyid}; tuf ignores it",
                    )
                )
    return findings


def _keyid_conflict_findings(views: list[RootView]) -> list[Finding]:
    """Flag a keyid bound to conflicting material across root versions."""
    findings: list[Finding] = []
    keyid_material: dict[str, tuple[str, str]] = {}
    for view in views:
        for keyid, key in view.root.keys.items():
            fp = _fingerprint(key.keytype, key.scheme, key.keyval)
            if keyid in keyid_material and keyid_material[keyid][0] != fp:
                findings.append(
                    Finding(
                        "warning",
                        "keyid-conflict",
                        f"keyid {keyid[:12]}\u2026 maps to different "
                        f"material in root v{keyid_material[keyid][1]} vs "
                        f"v{view.version}; a signature envelope cannot "
                        "satisfy both at once",
                    )
                )
            keyid_material.setdefault(keyid, (fp, str(view.version)))
    return findings


def _structural_findings(views: list[RootView]) -> list[Finding]:
    findings: list[Finding] = []
    for view in views:
        findings.extend(_shared_key_findings(view))
        findings.extend(_role_health_findings(view))
    findings.extend(_keyid_conflict_findings(views))
    return findings


def _role_view_dict(view: RootView) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for role in TOP_ROLES:
        fps = view.role_materials[role]
        result[role] = {
            "threshold": view.thresholds[role],
            "distinct_materials": len(fps),
            "keyids": [sorted(view.materials[fp].aliases) for fp in fps],
        }
    return result


def _migration_requirements(
    views: list[RootView],
) -> tuple[dict[str, list[str]], dict[str, int]]:
    """Encode each root hop's old+new root threshold as coalition roles.

    For v_i -> v_{i+1}, the same signature set must meet the root threshold
    of BOTH roots (Root.get_root_verification_result). Each side of every hop
    becomes its own requirement over the union of the two material spaces, so
    the coalition solver satisfies them simultaneously.
    """
    hop_role_materials: dict[str, list[str]] = {}
    hop_thresholds: dict[str, int] = {}
    for hop_index, (prev, nxt) in enumerate(pairwise(views)):
        hop_role_materials[f"hop{hop_index}_old"] = prev.role_materials["root"]
        hop_thresholds[f"hop{hop_index}_old"] = prev.thresholds["root"]
        hop_role_materials[f"hop{hop_index}_new"] = nxt.role_materials["root"]
        hop_thresholds[f"hop{hop_index}_new"] = nxt.thresholds["root"]
    return hop_role_materials, hop_thresholds


def analyze(
    trusted_path: str | Path,
    candidate_paths: list[str | Path],
    max_materials: int = DEFAULT_MAX_MATERIALS,
) -> AnalysisReport:
    """Run the full structural analysis over a root and its successor chain."""
    trusted = load_root_view(trusted_path)
    candidates = [load_root_view(p) for p in candidate_paths]
    views = [trusted, *candidates]

    # Sequential-version sanity check (mirrors update_root's requirement).
    for prev, nxt in pairwise(views):
        if nxt.version != prev.version + 1:
            raise ValueError(
                f"Non-sequential root versions: v{prev.version} -> "
                f"v{nxt.version}"
            )

    findings = _structural_findings(views)
    current = candidates[-1] if candidates else trusted

    report = AnalysisReport(
        trusted_version=trusted.version,
        candidate_versions=[v.version for v in candidates],
        distinct_materials=len(current.materials),
        total_keyids=len(current.root.keys),
        role_views={v.version: _role_view_dict(v) for v in views},
        findings=findings,
    )

    # (1) Direct signing authority per role, evaluated on the latest root.
    for role in TOP_ROLES:
        coals = minimum_coalitions(
            current.role_materials,
            current.thresholds,
            [role],
            max_materials,
        )
        report.per_role_authority.append(
            CoalitionResult(
                label=f"sign {role}",
                roles=(role,),
                size=min((len(c) for c in coals), default=0),
                coalitions=coals,
                note=(
                    "signing authority only; does not by itself deliver "
                    "targets"
                ),
            )
        )

    # (2) Freeze / re-point authority: snapshot + timestamp together.
    freeze = minimum_coalitions(
        current.role_materials,
        current.thresholds,
        ("snapshot", "timestamp"),
        max_materials,
    )
    report.freeze_authority = CoalitionResult(
        label="re-sign snapshot + timestamp",
        roles=("snapshot", "timestamp"),
        size=min((len(c) for c in freeze), default=0),
        coalitions=freeze,
        note=(
            "can freeze updates or point metadata at existing targets; "
            "cannot introduce new target content without targets authority"
        ),
    )

    # (3) Arbitrary target delivery: targets AND snapshot AND timestamp.
    delivery = minimum_coalitions(
        current.role_materials,
        current.thresholds,
        DELIVERY_ROLES,
        max_materials,
    )
    report.arbitrary_delivery = CoalitionResult(
        label="deliver arbitrary new target",
        roles=DELIVERY_ROLES,
        size=min((len(c) for c in delivery), default=0),
        coalitions=delivery,
        note=(
            "end-to-end attack: forge targets content, then make snapshot "
            "and timestamp point clients at it"
        ),
    )

    # (4) Malicious root migration across every hop of the candidate chain.
    if candidates:
        hop_materials, hop_thresholds = _migration_requirements(views)
        migration = minimum_coalitions(
            hop_materials,
            hop_thresholds,
            list(hop_materials),
            max_materials,
        )
        report.migration = CoalitionResult(
            label="malicious root migration (dual threshold per hop)",
            roles=tuple(hop_materials),
            size=min((len(c) for c in migration), default=0),
            coalitions=migration,
            note=(
                "one signature set must satisfy BOTH the old and new root "
                "threshold at every hop; shared old/new root keys reduce "
                "the required collusion"
            ),
        )

    return report


# --------------------------------------------------------------------------- #
# Text rendering
# --------------------------------------------------------------------------- #
def _render_material(fp: str, view: RootView) -> str:
    material = view.materials.get(fp)
    if material is None:
        return fp[:12] + "…"
    aliases = ",".join(sorted(a[:10] for a in material.aliases))
    return f"{material.short_id}… [{aliases}]"


def _render_coalitions(
    lines: list[str], cr: CoalitionResult, latest: RootView
) -> None:
    lines.append(f"{cr.label}")
    lines.append(f"  minimum distinct keys to compromise: {cr.size}")
    shown = cr.coalitions[:MAX_COALITIONS_REPORTED]
    for coalition in shown:
        members = ", ".join(
            sorted(_render_material(fp, latest) for fp in coalition)
        )
        lines.append(f"    - {{{members}}}")
    if len(cr.coalitions) > MAX_COALITIONS_REPORTED:
        lines.append(
            f"    ... {len(cr.coalitions) - len(shown)} more "
            "minimum coalitions not shown"
        )
    if cr.note:
        lines.append(f"  note: {cr.note}")
    lines.append("")


def _render_bounded_conclusion(lines: list[str]) -> None:
    lines.append("Bounded conclusion")
    lines.append("-" * 72)
    lines.append("  Results count distinct public key materials, not people,")
    lines.append("  teams or HSMs. Shared operational control of two materials")
    lines.append("  can make real-world collusion smaller than these numbers.")
    lines.append("  Signature authority is necessary but not sufficient to")
    lines.append("  deliver targets: only the (targets, snapshot, timestamp)")
    lines.append("  combination can install arbitrary new content.")
    lines.append("=" * 72)


def render_text(report: AnalysisReport, views: list[RootView]) -> str:
    latest = views[-1]
    lines: list[str] = []
    lines.append("=" * 72)
    lines.append("TUF ROOT AUTHORIZATION ANALYSIS (offline, public keys only)")
    lines.append("=" * 72)
    lines.append(
        f"trusted root: v{report.trusted_version} | candidate chain: "
        f"v{report.trusted_version} -> "
        f"{['v' + str(v) for v in report.candidate_versions]}"
    )
    lines.append(
        f"distinct physical keys in latest root: "
        f"{report.distinct_materials} "
        f"(keyid entries: {report.total_keyids})"
    )
    lines.append("")

    lines.append("Role authorization in latest root")
    lines.append("-" * 72)
    latest_roles = report.role_views[latest.version]
    for role in TOP_ROLES:
        info = latest_roles[role]
        lines.append(
            f"  {role:<10} threshold {info['threshold']} of "
            f"{info['distinct_materials']} distinct material(s)"
        )
    lines.append("")

    if report.findings:
        lines.append("Structural findings")
        lines.append("-" * 72)
        for finding in report.findings:
            lines.append(f"  [{finding.severity.upper():<8}] {finding.message}")
        lines.append("")

    lines.append("(1) Direct signing authority per role")
    lines.append("-" * 72)
    for cr in report.per_role_authority:
        _render_coalitions(lines, cr, latest)

    lines.append("(2) Snapshot / timestamp change (freeze or re-point)")
    lines.append("-" * 72)
    assert report.freeze_authority is not None
    _render_coalitions(lines, report.freeze_authority, latest)

    lines.append("(3) Deliver an arbitrary new target end to end")
    lines.append("-" * 72)
    assert report.arbitrary_delivery is not None
    _render_coalitions(lines, report.arbitrary_delivery, latest)

    if report.migration:
        lines.append("(4) Malicious root migration (dual threshold)")
        lines.append("-" * 72)
        _render_coalitions(lines, report.migration, latest)

    _render_bounded_conclusion(lines)
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Offline TUF root key-sharing / collusion analysis.",
    )
    parser.add_argument(
        "--trusted",
        required=True,
        type=Path,
        help="Path to the trusted current root JSON.",
    )
    parser.add_argument(
        "--candidate",
        required=True,
        type=Path,
        nargs="+",
        help="Ordered candidate successor root JSON file(s).",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit machine-readable JSON instead of the text report.",
    )
    parser.add_argument(
        "--max-materials",
        type=int,
        default=DEFAULT_MAX_MATERIALS,
        help="Exhaustive-search guard (number of distinct materials).",
    )
    args = parser.parse_args()

    report = analyze(args.trusted, args.candidate, args.max_materials)
    if args.json:
        print(json.dumps(report.to_dict(), indent=2))
        return

    views = [load_root_view(args.trusted)]
    views.extend(load_root_view(p) for p in args.candidate)
    print(render_text(report, views))


if __name__ == "__main__":
    main()
