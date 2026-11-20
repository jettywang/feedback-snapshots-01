"""
Reviewable repair plans for `pip-audit`.

A repair plan separates the two halves of an automated fix:

* **Generating a work order** (`create_fix_plan`) audits the current workspace,
  resolves fix versions, and records the exact file edits it *would* make,
  including the before/after digests and the dependency evidence that justified
  each upgrade. Nothing is written.
* **Applying an approved work order** (`apply_fix_plan`) re-checks that every
  recorded target is still byte-for-byte identical to what the plan was made
  against, then applies every edit across every file as a single transaction.
  If any write fails, every file is restored to its pre-application contents.

The serialized form is deliberately plain JSON so that a human reviewer (or a
CI job) can diff and approve it before it is applied.
"""

from __future__ import annotations

import base64
import difflib
import json
import logging
import os
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from packaging.version import Version

from pip_audit._fix import ResolvedFixVersion, SkippedFixVersion
from pip_audit._service import Dependency, ResolvedDependency, VulnerabilityResult
from pip_audit._util import sha256

logger = logging.getLogger(__name__)

PLAN_VERSION = 1


class FixPlanError(Exception):
    """
    Raised when a fix plan cannot be created, parsed, or applied.
    """

    pass


class FixPlanInvalid(FixPlanError):
    """
    Raised when a fix plan is malformed or from an unsupported format version.
    """

    pass


class FixPlanStale(FixPlanError):
    """
    Raised when a fix plan no longer applies to the current workspace.
    """

    pass


@dataclass(frozen=True)
class PlanEvidence:
    """
    The dependency evidence behind a single upgrade.

    `vulnerabilities` records the vulnerability IDs that were found, the fixed
    versions each advisory offered, and any aliases, so an approver can see
    why the upgrade is being requested.
    """

    name: str
    version: str
    vulnerabilities: tuple[dict[str, Any], ...]


@dataclass(frozen=True)
class PlanEdit:
    """
    One file edit in a fix plan, keyed by content digests rather than offsets.
    """

    path: str
    before_sha256: str
    after_sha256: str
    before_content: bytes = field(repr=False)
    after_content: bytes = field(repr=False)

    def diff(self) -> str:
        """
        Render a unified diff of this edit for human review.
        """
        before = self.before_content.decode("utf-8").splitlines(keepends=True)
        after = self.after_content.decode("utf-8").splitlines(keepends=True)
        return "".join(
            difflib.unified_diff(
                before,
                after,
                fromfile=f"a/{self.path}",
                tofile=f"b/{self.path}",
                lineterm="\n",
            )
        )


@dataclass(frozen=True)
class PlanChange:
    """
    One dependency upgrade in a fix plan, with its evidence and file edits.
    """

    fix: ResolvedFixVersion
    evidence: PlanEvidence
    edits: tuple[PlanEdit, ...]

    @property
    def dependency(self) -> str:
        """
        The dependency this change fixes, e.g. `flask==0.5`.
        """
        return f"{self.evidence.name}=={self.evidence.version}"


@dataclass(frozen=True)
class FixPlan:
    """
    A reviewable work order produced from an audit and its resolved fixes.
    """

    changes: tuple[PlanChange, ...]
    skipped: tuple[SkippedFixVersion, ...] = ()
    tool_version: str = ""
    root: str = ""
    content_loaded: bool = True

    def to_json(self) -> str:
        """
        Serialize this plan to the stable, reviewable JSON interchange format.
        """
        document = {
            "plan_version": PLAN_VERSION,
            "tool": "pip-audit",
            "tool_version": self.tool_version,
            "root": self.root,
            "changes": [
                {
                    "dependency": {
                        "name": change.evidence.name,
                        "version": change.evidence.version,
                    },
                    "fix_version": str(change.fix.version),
                    "evidence": list(change.evidence.vulnerabilities),
                    "edits": [
                        {
                            "path": edit.path,
                            "before_sha256": edit.before_sha256,
                            "after_sha256": edit.after_sha256,
                            "before": _encode(edit.before_content),
                            "after": _encode(edit.after_content),
                            "diff": edit.diff(),
                        }
                        for edit in change.edits
                    ],
                }
                for change in self.changes
            ],
            "skipped": [
                {
                    "name": skipped.dep.name,
                    "version": str(skipped.dep.version),
                    "reason": skipped.skip_reason,
                }
                for skipped in self.skipped
            ],
        }
        return json.dumps(document, indent=2, sort_keys=True) + "\n"

    @classmethod
    def from_json(cls, document: str, *, with_content: bool = True) -> FixPlan:
        """
        Parse a plan previously produced by `to_json`.

        `with_content` defaults to true so that an approved plan can be applied
        without re-running the audit. Pass `False` for a review-only view.
        """
        try:
            data = json.loads(document)
        except json.JSONDecodeError as exc:
            raise FixPlanInvalid(f"fix plan is not valid JSON: {exc}") from exc

        if not isinstance(data, dict):
            raise FixPlanInvalid("fix plan must be a JSON object")

        plan_version = data.get("plan_version")
        if plan_version != PLAN_VERSION:
            raise FixPlanInvalid(
                f"unsupported fix plan version {plan_version!r}; expected {PLAN_VERSION}"
            )

        changes = []
        for raw_change in data.get("changes", []):
            dep = raw_change.get("dependency", {})
            evidence = PlanEvidence(
                name=dep.get("name", ""),
                version=dep.get("version", ""),
                vulnerabilities=tuple(raw_change.get("evidence", [])),
            )
            fix = ResolvedFixVersion(
                dep=ResolvedDependency(name=evidence.name, version=Version(evidence.version)),
                version=Version(raw_change["fix_version"]),
            )
            edits = []
            for raw_edit in raw_change.get("edits", []):
                before = _decode(raw_edit.get("before", "")) if with_content else b""
                after = _decode(raw_edit.get("after", "")) if with_content else b""
                if with_content:
                    _check_digest(before, raw_edit["before_sha256"], raw_edit["path"])
                    _check_digest(after, raw_edit["after_sha256"], raw_edit["path"])
                edits.append(
                    PlanEdit(
                        path=raw_edit["path"],
                        before_sha256=raw_edit["before_sha256"],
                        after_sha256=raw_edit["after_sha256"],
                        before_content=before,
                        after_content=after,
                    )
                )
            changes.append(PlanChange(fix=fix, evidence=evidence, edits=tuple(edits)))

        skipped = [
            SkippedFixVersion(
                dep=ResolvedDependency(
                    name=raw_skipped["name"], version=Version(raw_skipped["version"])
                ),
                skip_reason=raw_skipped["reason"],
            )
            for raw_skipped in data.get("skipped", [])
        ]

        return cls(
            changes=tuple(changes),
            skipped=tuple(skipped),
            tool_version=data.get("tool_version", ""),
            root=data.get("root", ""),
            content_loaded=with_content,
        )

    def target_paths(self) -> list[str]:
        """
        The distinct files this plan wants to edit, in application order.
        """
        seen: dict[str, None] = {}
        for change in self.changes:
            for edit in change.edits:
                seen.setdefault(edit.path, None)
        return list(seen)


def _encode(contents: bytes) -> str:
    return base64.b64encode(contents).decode("ascii")


def _decode(encoded: str) -> bytes:
    try:
        return base64.b64decode(encoded.encode("ascii"), validate=True)
    except Exception as exc:
        raise FixPlanInvalid(f"fix plan contains invalid base64 content: {exc}") from exc


def _check_digest(contents: bytes, expected: str, path: str) -> None:
    actual = sha256(contents)
    if actual != expected:
        raise FixPlanInvalid(f"fix plan content for {path} does not match its recorded digest")


def create_fix_plan(
    source: Any,
    result: dict[Dependency, list[VulnerabilityResult]],
    fixes: list[ResolvedFixVersion],
    skipped: list[SkippedFixVersion],
    *,
    tool_version: str = "",
    root: Path | None = None,
) -> FixPlan:
    """
    Turn an audit result and its resolved fixes into a reviewable `FixPlan`.

    `source` must implement `DependencySource.plan_fixes`; the source is never
    written to.
    """
    planned_fixes = source.plan_fixes(fixes)
    changes = []
    for planned in planned_fixes:
        fix_version = planned.fix
        vulns = result.get(fix_version.dep, [])
        evidence = PlanEvidence(
            name=fix_version.dep.name,
            version=str(fix_version.dep.version),
            vulnerabilities=tuple(
                {
                    "id": str(vuln.id),
                    "fix_versions": [str(v) for v in vuln.fix_versions],
                    "aliases": sorted(str(alias) for alias in vuln.aliases),
                }
                for vuln in vulns
            ),
        )
        changes.append(
            PlanChange(
                fix=fix_version,
                evidence=evidence,
                edits=tuple(
                    PlanEdit(
                        # Pin each target to an absolute path at creation time so
                        # that applying the plan cannot drift with the caller's
                        # working directory.
                        path=str(Path(edit.path).resolve()),
                        before_sha256=edit.before_sha256,
                        after_sha256=edit.after_sha256,
                        before_content=edit.before_content,
                        after_content=edit.after_content,
                    )
                    for edit in planned.edits
                ),
            )
        )
    return FixPlan(
        changes=tuple(changes),
        skipped=tuple(skipped),
        tool_version=tool_version,
        root=str(root) if root is not None else "",
    )


def _edits_by_path(plan: FixPlan) -> dict[str, list[PlanEdit]]:
    grouped: dict[str, list[PlanEdit]] = {}
    for change in plan.changes:
        for edit in change.edits:
            grouped.setdefault(edit.path, []).append(edit)
    return grouped


def verify_fix_plan(plan: FixPlan, *, root: Path | None = None) -> None:
    """
    Check that every edit in `plan` still targets the workspace it was made for.

    Raises `FixPlanStale` if a target is missing, if its current contents no
    longer match the digest recorded when the plan was generated, or if the
    plan's own post-fix contents are already in place. Also raises
    `FixPlanInvalid` if the plan's edit chain for a file is internally
    inconsistent.
    """
    root = _plan_root(plan, root)
    for display, edits in _edits_by_path(plan).items():
        for previous, following in zip(edits, edits[1:]):
            if previous.after_sha256 != following.before_sha256:
                raise FixPlanInvalid(f"fix plan edits for {display} do not form a consistent chain")

        path = _resolve_path(display, root)
        if not path.is_file():
            raise FixPlanStale(f"planned target no longer exists: {display}")

        actual = sha256(path.read_bytes())
        if actual == edits[0].before_sha256:
            continue
        if actual == edits[-1].after_sha256:
            raise FixPlanStale(
                f"fix plan was already applied to {display}; its contents already match "
                "the planned result"
            )
        raise FixPlanStale(
            f"planned target changed since the plan was created: {display}; "
            f"expected {edits[0].before_sha256}, found {actual}"
        )


def apply_fix_plan(plan: FixPlan, *, root: Path | None = None) -> None:
    """
    Apply an approved `FixPlan` to the workspace as one transaction.

    All targets are verified before the first byte is written. Each replacement
    is staged next to its target and swapped in with `os.replace`. If any write
    fails, every target is restored to the exact contents it had before the
    call, and the original error is raised.
    """
    root = _plan_root(plan, root)
    if not plan.changes:
        return
    if not plan.content_loaded:
        raise FixPlanError("fix plan was loaded without content and cannot be applied")

    verify_fix_plan(plan, root=root)

    # Collapse to the final desired contents of each file. Edits are recorded
    # in application order, so the last edit for a path wins.
    finals: dict[Path, bytes] = {}
    for display, edits in _edits_by_path(plan).items():
        if edits[-1].after_sha256 == edits[0].before_sha256:
            # Every edit for this file was a no-op; don't touch it at all.
            continue
        finals[_resolve_path(display, root)] = edits[-1].after_content
    if not finals:
        return

    originals = {path: path.read_bytes() for path in finals}
    staged: dict[Path, Path] = {}
    try:
        for path, contents in finals.items():
            staged[path] = _stage_write(path, contents)
        for path in finals:
            os.replace(staged[path], path)
    except BaseException:
        _discard(staged.values())
        _restore(originals)
        raise


def load_fix_plan(path: Path) -> FixPlan:
    """
    Read and parse an approved plan from disk.
    """
    try:
        document = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise FixPlanError(f"could not read fix plan {path}: {exc}") from exc
    return FixPlan.from_json(document)


def write_fix_plan(plan: FixPlan, path: Path) -> None:
    """
    Serialize `plan` to `path` atomically.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(plan.to_json())
        os.replace(tmp_name, path)
    except BaseException:
        try:
            os.unlink(tmp_name)
        except FileNotFoundError:
            pass
        raise


def _stage_write(path: Path, contents: bytes) -> Path:
    # Write the replacement in the target's own directory so that `os.replace`
    # is atomic and cannot cross filesystems.
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".pip-audit", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(contents)
    except BaseException:
        _discard([Path(tmp_name)])
        raise
    return Path(tmp_name)


def _discard(paths: Any) -> None:
    for tmp in paths:
        Path(tmp).unlink(missing_ok=True)


def _restore(originals: dict[Path, bytes]) -> None:
    for path, contents in originals.items():
        try:
            _restore_one(path, contents)
        except BaseException as exc:  # noqa: PERF203
            logger.warning(f"encountered an exception during fix plan recovery: {exc}")


def _restore_one(path: Path, contents: bytes) -> None:
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".pip-audit", dir=path.parent)
    with os.fdopen(fd, "wb") as f:
        f.write(contents)
    os.replace(tmp_name, path)


def _plan_root(plan: FixPlan, root: Path | None) -> Path:
    # An explicit root always wins. Otherwise honor the workspace recorded in
    # the plan, and fall back to the current directory for hand-written plans.
    if root is not None:
        return root
    if plan.root:
        return Path(plan.root)
    return Path.cwd()


def _resolve_path(path: str, root: Path) -> Path:
    candidate = Path(path)
    if not candidate.is_absolute():
        candidate = root / candidate
    return candidate
