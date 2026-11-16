"""Restricted POSIX ACL interpretation for offline XFS evidence.

Given an XFS filesystem image, a path, a UID and a set of GIDs, this module
explains, step by step, whether each directory on the path grants search
permission and whether the requested permission bits would be granted on the
final component.

The model is deliberately restricted:

- Only the classic discretionary check is modelled (owner / named user /
  group class / other, with the ACL mask applied to the group class).
- Privileges such as ``CAP_DAC_OVERRIDE`` / ``CAP_DAC_READ_SEARCH`` (uid 0)
  are *not* modelled; if they could apply, the verdict is ``INDETERMINATE``.
- Symlink resolution is not modelled; a symlink in the path yields
  ``INDETERMINATE``.
- Default ACLs are reported as evidence but never used to determine access
  to an existing object (they only apply to newly created objects).
- No host identity is consulted: the caller must supply the UID and the full
  GID set. Missing identity material yields ``INDETERMINATE``.
"""

from __future__ import annotations

import argparse
import stat
import struct
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING

from dissect.xfs.exceptions import Error

if TYPE_CHECKING:
    from collections.abc import Collection, Iterator

    from dissect.xfs.xfs import XFS

# POSIX ACL entry tags (Linux posix_acl_xattr format)
ACL_USER_OBJ = 0x01
ACL_USER = 0x02
ACL_GROUP_OBJ = 0x04
ACL_GROUP = 0x08
ACL_MASK = 0x10
ACL_OTHER = 0x20

ACL_UNDEFINED_ID = 0xFFFFFFFF
POSIX_ACL_XATTR_VERSION = 0x0002

# Userspace names and raw on-disk XFS attribute names of the ACL xattrs
XATTR_NAME_POSIX_ACL_ACCESS = "system.posix_acl_access"
XATTR_NAME_POSIX_ACL_DEFAULT = "system.posix_acl_default"
XFS_ACL_ACCESS_NAME = "posix_acl_access"
XFS_ACL_DEFAULT_NAME = "posix_acl_default"

PERM_READ = 0b100
PERM_WRITE = 0b010
PERM_EXEC = 0b001

TAG_NAMES = {
    ACL_USER_OBJ: "user_obj",
    ACL_USER: "user",
    ACL_GROUP_OBJ: "group_obj",
    ACL_GROUP: "group",
    ACL_MASK: "mask",
    ACL_OTHER: "other",
}


class ACLFormatError(Error):
    """The ACL xattr value is malformed."""


class Verdict(Enum):
    ALLOW = "allow"
    DENY = "deny"
    INDETERMINATE = "indeterminate"


def render_perm(perm: int) -> str:
    return "".join(
        (
            "r" if perm & PERM_READ else "-",
            "w" if perm & PERM_WRITE else "-",
            "x" if perm & PERM_EXEC else "-",
        )
    )


def render_want(want: int) -> str:
    return render_perm(want & 0b111)


@dataclass(frozen=True)
class ACLEntry:
    tag: int
    perm: int
    id: int | None = None

    def render(self) -> str:
        if self.tag == ACL_USER_OBJ:
            head = "user::"
        elif self.tag == ACL_USER:
            head = f"user:{self.id}:"
        elif self.tag == ACL_GROUP_OBJ:
            head = "group::"
        elif self.tag == ACL_GROUP:
            head = f"group:{self.id}:"
        elif self.tag == ACL_MASK:
            head = "mask::"
        else:
            head = "other::"
        return head + render_perm(self.perm)


@dataclass(frozen=True)
class ACL:
    entries: tuple[ACLEntry, ...]

    @classmethod
    def from_xattr(cls, buf: bytes) -> ACL:
        """Parse a Linux ``posix_acl_xattr`` value (little endian)."""
        if len(buf) < 4:
            raise ACLFormatError(f"ACL xattr too short for header: {len(buf)} bytes")
        (version,) = struct.unpack_from("<I", buf, 0)
        if version != POSIX_ACL_XATTR_VERSION:
            raise ACLFormatError(f"Unsupported ACL xattr version: {version:#x}")

        payload = buf[4:]
        if len(payload) % 8:
            raise ACLFormatError(f"ACL xattr entries not 8-byte aligned: {len(payload)} bytes")

        entries = []
        for offset in range(0, len(payload), 8):
            tag, perm, entry_id = struct.unpack_from("<HHI", payload, offset)
            if tag not in TAG_NAMES:
                raise ACLFormatError(f"Unknown ACL entry tag: {tag:#x}")
            entries.append(ACLEntry(tag, perm, None if entry_id == ACL_UNDEFINED_ID else entry_id))

        acl = cls(tuple(entries))
        acl.validate()
        return acl

    @classmethod
    def from_mode(cls, mode: int) -> ACL:
        """The minimal ACL equivalent to a mode (no mask entry)."""
        return cls(
            (
                ACLEntry(ACL_USER_OBJ, (mode >> 6) & 0b111),
                ACLEntry(ACL_GROUP_OBJ, (mode >> 3) & 0b111),
                ACLEntry(ACL_OTHER, mode & 0b111),
            )
        )

    def validate(self) -> None:
        """Check entry ordering and completeness (mirrors ``posix_acl_valid``)."""
        state = ACL_USER_OBJ
        needs_mask = False
        has_mask = False
        for entry in self.entries:
            if state == -1:
                raise ACLFormatError("entries after other entry")
            if entry.perm & ~0b111:
                raise ACLFormatError(f"Invalid permission bits: {entry.perm:#x}")
            if entry.tag in (ACL_USER, ACL_GROUP) and entry.id is None:
                raise ACLFormatError(f"Named {TAG_NAMES[entry.tag]} entry without id")
            if entry.tag in (ACL_USER_OBJ, ACL_GROUP_OBJ, ACL_MASK, ACL_OTHER) and entry.id is not None:
                raise ACLFormatError(f"{TAG_NAMES[entry.tag]} entry must not carry an id")

            if entry.tag == ACL_USER_OBJ:
                if state != ACL_USER_OBJ:
                    raise ACLFormatError("user_obj entry must come first")
                state = ACL_USER
            elif entry.tag == ACL_USER:
                if state != ACL_USER:
                    raise ACLFormatError("user entry out of order")
                needs_mask = True
            elif entry.tag == ACL_GROUP_OBJ:
                if state != ACL_USER:
                    raise ACLFormatError("group_obj entry out of order")
                state = ACL_GROUP
            elif entry.tag == ACL_GROUP:
                if state != ACL_GROUP:
                    raise ACLFormatError("group entry out of order")
                needs_mask = True
            elif entry.tag == ACL_MASK:
                if state != ACL_GROUP:
                    raise ACLFormatError("mask entry out of order")
                has_mask = True
                state = ACL_OTHER
            elif entry.tag == ACL_OTHER:
                if state not in (ACL_GROUP, ACL_OTHER):
                    raise ACLFormatError("other entry out of order")
                state = -1
        if state != -1:
            raise ACLFormatError("ACL is missing mandatory entries")
        if needs_mask and not has_mask:
            raise ACLFormatError("ACL has named entries but no mask entry")

    @property
    def mask(self) -> int | None:
        for entry in self.entries:
            if entry.tag == ACL_MASK:
                return entry.perm
        return None

    def render(self) -> str:
        return ", ".join(entry.render() for entry in self.entries)


@dataclass
class Evaluation:
    """Outcome of a single POSIX permission check."""

    verdict: Verdict
    want: int
    granted: int | None
    trace: list[str] = field(default_factory=list)


def evaluate(
    *,
    mode: int,
    uid: int,
    gid: int,
    access_acl: ACL | None,
    want: int,
    fsuid: int | None,
    fsgids: Collection[int] | None,
) -> Evaluation:
    """Evaluate ``want`` permission bits for (``fsuid``, ``fsgids``).

    Mirrors the Linux ``posix_acl_permission`` check: owner, then named user,
    then the group class (owning group and named groups considered together,
    any single matching entry that grants all requested bits suffices), then
    other. The mask, when present, restricts named users and the group class.
    """
    if fsuid is None or fsgids is None:
        return Evaluation(
            Verdict.INDETERMINATE,
            want,
            None,
            ["未提供完整的 fsuid/gid 集合（id 映射未知），无法确定类别归属"],
        )
    if fsuid == 0:
        return Evaluation(
            Verdict.INDETERMINATE,
            want,
            None,
            ["fsuid=0：root 的 CAP_DAC_OVERRIDE/CAP_DAC_READ_SEARCH 特权未建模"],
        )

    acl = access_acl if access_acl is not None else ACL.from_mode(mode)
    source = "access ACL" if access_acl is not None else "mode 位（无 access ACL）"
    mask = acl.mask
    entries = {tag: [e for e in acl.entries if e.tag == tag] for tag in TAG_NAMES}

    def finish(verdict: Verdict, granted: int, trace: list[str]) -> Evaluation:
        return Evaluation(verdict, want, granted, trace)

    # Owner class
    if fsuid == uid:
        entry = entries[ACL_USER_OBJ][0]
        trace = [f"fsuid={fsuid} 即文件属主 uid={uid}（{source}）→ user:: {render_perm(entry.perm)}"]
        verdict = Verdict.ALLOW if entry.perm & want == want else Verdict.DENY
        trace.append(f"请求 {render_want(want)}：{'满足' if verdict is Verdict.ALLOW else '不满足'}")
        return finish(verdict, entry.perm, trace)

    # Named user class (mask applies)
    for entry in entries[ACL_USER]:
        if entry.id == fsuid:
            effective = entry.perm & mask if mask is not None else entry.perm
            trace = [
                f"fsuid={fsuid} 匹配 named user:{entry.id} {render_perm(entry.perm)}（{source}）",
                f"mask:: {render_perm(mask) if mask is not None else '无'} → 有效权限 {render_perm(effective)}",
            ]
            verdict = Verdict.ALLOW if effective & want == want else Verdict.DENY
            trace.append(f"请求 {render_want(want)}：{'满足' if verdict is Verdict.ALLOW else '不满足'}")
            return finish(verdict, effective, trace)

    # Group class: owning group and named groups are considered together;
    # any single matching entry granting all requested bits suffices.
    group_matches = []
    if gid in fsgids:
        group_matches.extend(entries[ACL_GROUP_OBJ])
    group_matches.extend(e for e in entries[ACL_GROUP] if e.id in fsgids)
    if group_matches:
        trace = [
            f"fsuid={fsuid} 的 gid 集 {sorted(fsgids)} 命中组类条目 {len(group_matches)} 条（{source}）"
            + (f"，mask:: {render_perm(mask)}" if mask is not None else "，无 mask")
        ]
        granted = 0
        for entry in group_matches:
            effective = entry.perm & mask if mask is not None else entry.perm
            granted |= effective
            trace.append(f"  {entry.render()} → 有效 {render_perm(effective)}")
            if effective & want == want:
                trace.append(f"该条目单独满足请求 {render_want(want)} → 允许")
                return finish(Verdict.ALLOW, effective, trace)
        trace.append(f"组类中无任何单一条目覆盖全部请求位 {render_want(want)} → 拒绝")
        return finish(Verdict.DENY, granted, trace)

    # Other class
    entry = entries[ACL_OTHER][0]
    trace = [
        f"fsuid={fsuid} 与 gid 集均不匹配属主/命名条目/属组（{source}）→ other:: {render_perm(entry.perm)}"
    ]
    verdict = Verdict.ALLOW if entry.perm & want == want else Verdict.DENY
    trace.append(f"请求 {render_want(want)}：{'满足' if verdict is Verdict.ALLOW else '不满足'}")
    return finish(verdict, entry.perm, trace)


@dataclass
class StepReport:
    """Evidence and verdict for one path component."""

    component: str
    inum: int | None = None
    filetype: str | None = None
    mode: int | None = None
    uid: int | None = None
    gid: int | None = None
    access_acl: ACL | None = None
    default_acl: ACL | None = None
    acl_source: str = "mode"
    want: int = 0
    evaluation: Evaluation | None = None
    note: str | None = None
    verdict: Verdict | None = None


@dataclass
class AccessReport:
    path: str
    want: int
    fsuid: int | None
    fsgids: frozenset[int] | None
    steps: list[StepReport] = field(default_factory=list)
    verdict: Verdict = Verdict.INDETERMINATE
    assumptions: list[str] = field(
        default_factory=lambda: [
            "仅建模自主访问检查（owner/named user/group class/other + mask）",
            "未建模 CAP_DAC_OVERRIDE/CAP_DAC_READ_SEARCH 等特权；fsuid=0 一律不确定",
            "符号链接解析未建模",
            "default ACL 仅用于新建对象继承，不参与对现有对象的判定",
            "未读取宿主进程身份；身份材料完全来自调用方提供的 uid/gid 集",
        ]
    )


def _get_acl_xattr(node, names: tuple[str, ...]) -> bytes | None:
    for name in names:
        value = node.get_xattr(name)
        if value is not None:
            return value
    return None


def _collect_evidence(step: StepReport, node) -> str | None:
    """Fill raw permission evidence of ``node`` into ``step``.

    Returns a note if the permission material is incomplete (which makes the
    step indeterminate).
    """
    step.inum = getattr(node, "inum", None)
    step.mode = node.inode.di_mode
    step.uid = node.inode.di_uid
    step.gid = node.inode.di_gid

    try:
        access_raw = _get_acl_xattr(node, (XATTR_NAME_POSIX_ACL_ACCESS, XFS_ACL_ACCESS_NAME))
        default_raw = _get_acl_xattr(node, (XATTR_NAME_POSIX_ACL_DEFAULT, XFS_ACL_DEFAULT_NAME))
    except Error as exc:
        return f"扩展属性不可读（权限材料缺失）: {exc}"

    note = None
    if access_raw is not None:
        try:
            step.access_acl = ACL.from_xattr(access_raw)
            step.acl_source = "xattr"
        except ACLFormatError as exc:
            note = f"access ACL 解析失败（权限材料缺失）: {exc}"
    if default_raw is not None:
        try:
            step.default_acl = ACL.from_xattr(default_raw)
        except ACLFormatError as exc:
            step.note = f"default ACL 解析失败（仅信息性，不影响判定）: {exc}"
    return note


def _filetype_name(filetype: int | None) -> str:
    return {
        stat.S_IFREG: "普通文件",
        stat.S_IFDIR: "目录",
        stat.S_IFLNK: "符号链接",
        stat.S_IFCHR: "字符设备",
        stat.S_IFBLK: "块设备",
        stat.S_IFIFO: "FIFO",
        stat.S_IFSOCK: "套接字",
    }.get(filetype, "未知")


def _evaluate_step(step: StepReport, node, want: int, fsuid: int | None, fsgids: Collection[int] | None) -> None:
    step.want = want
    note = _collect_evidence(step, node)
    if note is not None:
        step.note = f"{step.note}; {note}" if step.note else note
        step.evaluation = Evaluation(Verdict.INDETERMINATE, want, None, [note])
    else:
        step.evaluation = evaluate(
            mode=stat.S_IMODE(step.mode),
            uid=step.uid,
            gid=step.gid,
            access_acl=step.access_acl,
            want=want,
            fsuid=fsuid,
            fsgids=fsgids,
        )
    step.verdict = step.evaluation.verdict


def check_access(
    fs: XFS,
    path: str,
    want: int,
    fsuid: int | None,
    fsgids: Collection[int] | None,
) -> AccessReport:
    """Walk ``path`` component by component and evaluate permissions.

    Every traversed directory (including the root) needs search (``x``)
    permission; the final component is checked against ``want``. The walk
    stops at the first non-allow verdict.
    """
    gids = frozenset(fsgids) if fsgids is not None else None
    report = AccessReport(path=path, want=want, fsuid=fsuid, fsgids=gids)

    components = [part for part in path.split("/") if part not in ("", ".")]
    node = fs.root

    if not components:
        step = StepReport(component="/")
        _evaluate_step(step, node, want, fsuid, gids)
        report.steps.append(step)
        report.verdict = step.verdict
        return report

    # The root directory itself must be searchable to traverse into it
    root_step = StepReport(component="/")
    _evaluate_step(root_step, node, PERM_EXEC, fsuid, gids)
    report.steps.append(root_step)
    if root_step.verdict is not Verdict.ALLOW:
        report.verdict = root_step.verdict
        return report

    for index, component in enumerate(components):
        last = index == len(components) - 1
        child = None
        for entry in node.iterdir():
            if entry.filename == component:
                child = entry
                break

        step = StepReport(component=component)
        report.steps.append(step)

        if child is None:
            step.note = "组件不存在"
            step.verdict = Verdict.DENY
            report.verdict = Verdict.DENY
            return report

        step.inum = getattr(child, "inum", None)
        step.filetype = _filetype_name(child.filetype)

        if child.filetype == stat.S_IFLNK:
            step.note = "符号链接解析未建模"
            step.verdict = Verdict.INDETERMINATE
            report.verdict = Verdict.INDETERMINATE
            return report

        if not last:
            if child.filetype != stat.S_IFDIR:
                step.note = "路径中间组件不是目录"
                step.verdict = Verdict.DENY
                report.verdict = Verdict.DENY
                return report
            _evaluate_step(step, child, PERM_EXEC, fsuid, gids)
            if step.verdict is not Verdict.ALLOW:
                report.verdict = step.verdict
                return report
            node = child
        else:
            _evaluate_step(step, child, want, fsuid, gids)
            report.verdict = step.verdict
            return report

    return report


def render_report(report: AccessReport) -> str:
    """Render a human-readable report preserving raw evidence and reasoning."""
    lines = [
        f"路径: {report.path}",
        f"请求权限: {render_want(report.want)}",
        f"身份: fsuid={report.fsuid}, fsgids={sorted(report.fsgids) if report.fsgids is not None else None}",
        "建模假设:",
    ]
    lines.extend(f"  - {assumption}" for assumption in report.assumptions)

    for index, step in enumerate(report.steps, 1):
        header = f"[{index}] 组件 {step.component!r}"
        if step.inum is not None:
            header += f" (inode {step.inum})"
        lines.append(header)
        if step.filetype:
            lines.append(f"    类型: {step.filetype}")
        if step.mode is not None:
            lines.append(
                f"    原始属性: mode={stat.S_IMODE(step.mode):04o} uid={step.uid} gid={step.gid}"
            )
        if step.acl_source == "xattr" and step.access_acl is not None:
            lines.append(f"    access ACL (xattr): {step.access_acl.render()}")
        else:
            lines.append("    access ACL: 无（退化为 mode 位）")
        if step.default_acl is not None:
            lines.append(f"    default ACL (xattr): {step.default_acl.render()}（仅继承用，不参与本判定）")
        if step.note:
            lines.append(f"    备注: {step.note}")
        if step.evaluation is not None:
            lines.append(f"    判定请求: {render_want(step.want)}")
            lines.extend(f"    依据: {trace}" for trace in step.evaluation.trace)
        if step.verdict is not None:
            lines.append(f"    结论: {step.verdict.value}")

    lines.append(f"最终结论: {report.verdict.value}")
    return "\n".join(lines)


def _parse_want(text: str) -> int:
    want = 0
    for char in text:
        if char == "r":
            want |= PERM_READ
        elif char == "w":
            want |= PERM_WRITE
        elif char == "x":
            want |= PERM_EXEC
        else:
            raise ValueError(f"无效的权限位: {char!r}（仅支持 r/w/x 组合）")
    return want


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="dissect.xfs.acl",
        description="基于 XFS 离线证据的受限 POSIX ACL 解释（不读取宿主身份）",
    )
    parser.add_argument("image", type=argparse.FileType("rb"), help="XFS 镜像")
    parser.add_argument("path", help="待检查的路径")
    parser.add_argument("--uid", type=int, required=True, help="主体 fsuid（必须显式提供）")
    parser.add_argument(
        "--gid",
        type=str,
        default=None,
        help="逗号分隔的完整 gid 集（含主组）；缺省则身份材料不完整，结论为不确定",
    )
    parser.add_argument("--want", type=_parse_want, default=PERM_READ, help="请求的权限位，如 r、rw、rwx、x")
    args = parser.parse_args()

    from dissect.xfs.xfs import XFS

    fsgids = frozenset(int(part) for part in args.gid.split(",") if part.strip()) if args.gid is not None else None
    report = check_access(XFS(args.image), args.path, args.want, args.uid, fsgids)
    print(render_report(report))

    raise SystemExit({Verdict.ALLOW: 0, Verdict.DENY: 1, Verdict.INDETERMINATE: 2}[report.verdict])


if __name__ == "__main__":
    main()
