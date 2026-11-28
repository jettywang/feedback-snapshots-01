#!/usr/bin/env python3
"""通告库可恢复的本地晋升工具。

把"审批后的通告库"在隔离构建机上的 接收 -> 核对 -> 启用 做成一次可恢复的
本地操作。仅使用 Python 标准库。

两个受管本地目录：
  * staging/  待启用副本（带独立身份与时效说明，等待批准）
  * live/     正在使用的副本（current 符号链接指向当前生效版本）

崩溃安全保证：正在使用的 live/current 只在最后一步通过"临时符号链接 + 原子
rename"切换；此前任何阶段中断都不会改动它。所有阶段都持久化到状态文件，
重跑同一命令即可从断点继续。
"""

import argparse
import hashlib
import json
import os
import sqlite3
import sys
from datetime import datetime, timezone

MANIFEST_NAME = "manifest.json"
DB_NAME = "notices.db"
STATE_NAME = "rollout-state.json"
CURRENT_LINK = "current"
PENDING_LINK = "pending"
HISTORY_DIR = "history"
IDENTITY_CARD = "IDENTITY.txt"

PHASES = ["RECEIVE", "VERIFY", "APPROVE", "PROMOTE"]


# --------------------------------------------------------------------------- #
# 通用辅助
# --------------------------------------------------------------------------- #
class RolloutError(Exception):
    """可预期的业务错误，退出码 2。"""


def now_from_args(args):
    """固定时钟：调用方通过 --now 注入确定性时间。"""
    return parse_time(args.now)


def parse_time(value):
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    dt = datetime.fromisoformat(text)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def iso(dt):
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def file_sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def atomic_write(path, text):
    tmp_path = os.path.join(os.path.dirname(path) or ".",
                            ".%s.tmp-%d" % (os.path.basename(path), os.getpid()))
    with open(tmp_path, "w", encoding="utf-8") as handle:
        handle.write(text)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(tmp_path, path)


def atomic_symlink(target, link_path):
    """用临时符号链接 + rename 原子替换符号链接。"""
    tmp_path = "%s.tmp-%d" % (link_path, os.getpid())
    if os.path.lexists(tmp_path):
        os.remove(tmp_path)
    os.symlink(target, tmp_path)
    os.replace(tmp_path, link_path)


def ensure_dir(path):
    os.makedirs(path, exist_ok=True)
    return path


def read_json(path):
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def load_state(live_dir):
    path = os.path.join(live_dir, STATE_NAME)
    if not os.path.exists(path):
        return None
    return read_json(path)


def save_state(live_dir, state):
    atomic_write(os.path.join(live_dir, STATE_NAME),
                 json.dumps(state, indent=2, sort_keys=True, ensure_ascii=False) + "\n")


def stage_paths(staging_dir, token):
    pending_dir = os.path.join(staging_dir, "pending-" + token)
    return pending_dir, os.path.join(pending_dir, DB_NAME)


def version_dir(live_dir, manifest_id):
    return os.path.join(live_dir, "versions", manifest_id)


def current_link_path(live_dir):
    return os.path.join(live_dir, CURRENT_LINK)


def resolve_current_db(live_dir):
    link = current_link_path(live_dir)
    if not os.path.islink(link):
        return None
    return os.path.join(os.path.realpath(link), DB_NAME)


def materialize_identity_card(pending_dir, manifest, now):
    lines = [
        "通告库待启用副本身份卡",
        "独立身份 (manifest id): %s" % manifest["id"],
        "内容版本            : %s" % manifest["version"],
        "数据库 SHA-256      : %s" % manifest["content_sha256"],
        "时效起点 not_before : %s" % manifest["not_before"],
        "时效止点 not_after  : %s" % manifest["not_after"],
        "到达时间            : %s" % iso(now),
        "状态                : 等待批准 (PENDING APPROVAL)",
    ]
    atomic_write(os.path.join(pending_dir, IDENTITY_CARD),
                 "\n".join(lines) + "\n")


def archive_state(live_dir, state, now):
    """新流程开始前，把上一轮终态状态文件归档，避免覆盖审计轨迹。"""
    history = ensure_dir(os.path.join(live_dir, HISTORY_DIR))
    name = "rollout-%s-%s.json" % (state["token"], iso(now).replace(":", ""))
    atomic_write(os.path.join(history, name),
                 json.dumps(state, indent=2, sort_keys=True, ensure_ascii=False) + "\n")


# --------------------------------------------------------------------------- #
# 阶段实现
# --------------------------------------------------------------------------- #
def do_receive(staging_dir, live_dir, bundle_dir, now, force=False):
    manifest_path = os.path.join(bundle_dir, MANIFEST_NAME)
    db_path = os.path.join(bundle_dir, DB_NAME)
    if not os.path.isfile(manifest_path):
        raise RolloutError("交付包缺少 %s: %s" % (MANIFEST_NAME, manifest_path))
    if not os.path.isfile(db_path):
        raise RolloutError("交付包缺少 %s: %s" % (DB_NAME, db_path))

    manifest = read_json(manifest_path)
    token = manifest["id"]
    pending_dir, pending_db = stage_paths(staging_dir, token)

    prior = load_state(live_dir)
    if prior is not None and prior.get("phase") not in ("ACTIVE", "REJECTED"):
        if prior.get("token") != token:
            raise RolloutError(
                "存在另一轮未完成晋升 (token=%s, phase=%s)；"
                "请先让其完成或由值班人员处理，避免覆盖。"
                % (prior.get("token"), prior.get("phase")))
        state = prior
    else:
        if prior is not None:
            archive_state(live_dir, prior, now)
        state = {
            "token": token,
            "manifest_id": manifest["id"],
            "version": manifest["version"],
            "phase": "RECEIVE",
            "bundle_dir": os.path.abspath(bundle_dir),
            "pending_dir": None,
            "pending_db": None,
            "target_version_dir": None,
            "active_before": None,
            "received_at": iso(now),
            "verified_at": None,
            "approved_at": None,
            "promoted_at": None,
            "rejected_at": None,
            "error": None,
        }
        save_state(live_dir, state)

    # 幂等：已经接收过则直接复用。
    if state["phase"] in ("VERIFY", "APPROVE", "PROMOTE", "ACTIVE"):
        return state, "idempotent"

    ensure_dir(pending_dir)
    import shutil
    shutil.copy2(db_path, pending_db)
    shutil.copy2(manifest_path, os.path.join(pending_dir, MANIFEST_NAME))
    materialize_identity_card(pending_dir, manifest, now)

    state["pending_dir"] = os.path.abspath(pending_dir)
    state["pending_db"] = os.path.abspath(pending_db)
    state["phase"] = "VERIFY"
    save_state(live_dir, state)

    # staging/pending 始终指向本轮待启用副本，值班人员一眼可见在审哪份。
    atomic_symlink(pending_dir, os.path.join(staging_dir, PENDING_LINK))
    return state, "received"


def verify_manifest(manifest, pending_db, now):
    problems = []

    actual_hash = file_sha256(pending_db)
    if actual_hash != manifest.get("content_sha256"):
        problems.append("内容哈希不一致：期望 %s，实际 %s"
                        % (manifest.get("content_sha256"), actual_hash))

    try:
        not_before = parse_time(manifest["not_before"])
        not_after = parse_time(manifest["not_after"])
    except Exception as exc:  # noqa: BLE001 - 时效字段格式问题要转成业务错误
        raise RolloutError("manifest 时效字段无法解析: %s" % exc)

    if now < not_before:
        problems.append("尚未到生效起点 not_before=%s（当前 %s）"
                        % (manifest["not_before"], iso(now)))
    if now > not_after:
        problems.append("已超过时效止点 not_after=%s（当前 %s）"
                        % (manifest["not_after"], iso(now)))

    try:
        connection = sqlite3.connect("file:%s?mode=ro" % pending_db, uri=True)
        try:
            tables = {row[0] for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table'")}
            if "notices" not in tables:
                problems.append("数据库缺少 notices 表")
            else:
                count = connection.execute(
                    "SELECT COUNT(*) FROM notices").fetchone()[0]
                if count <= 0:
                    problems.append("notices 表为空")
        finally:
            connection.close()
    except sqlite3.DatabaseError as exc:
        problems.append("数据库无法打开或已损坏: %s" % exc)

    return actual_hash, problems


def do_verify(staging_dir, live_dir, now):
    state = load_state(live_dir)
    if state is None:
        raise RolloutError("没有可核对的流程，请先执行 run/receive。")
    if state["phase"] == "RECEIVE":
        raise RolloutError("接收尚未完成，无法核对。")
    if state["phase"] in ("APPROVE", "PROMOTE", "ACTIVE"):
        return state, "idempotent", []

    pending_db = state["pending_db"]
    manifest = read_json(os.path.join(state["pending_dir"], MANIFEST_NAME))
    actual_hash, problems = verify_manifest(manifest, pending_db, now)
    state["verified_hash"] = actual_hash

    if problems:
        state["error"] = "; ".join(problems)
        state["phase"] = "REJECTED"
        state["rejected_at"] = iso(now)
        save_state(live_dir, state)
        raise RolloutError("核对未通过：%s" % state["error"])

    state["error"] = None
    state["verified_at"] = iso(now)
    state["phase"] = "APPROVE"
    save_state(live_dir, state)
    return state, "verified", []


def do_approve(staging_dir, live_dir, now):
    state = load_state(live_dir)
    if state is None:
        raise RolloutError("没有可批准的流程。")
    if state["phase"] == "ACTIVE":
        return state, "idempotent"
    if state["phase"] != "APPROVE":
        raise RolloutError("当前阶段为 %s，必须先通过核对 (VERIFY) 才能批准。"
                           % state["phase"])
    state["approved_at"] = iso(now)
    state["phase"] = "PROMOTE"
    save_state(live_dir, state)
    return state, "approved"


def do_abort(staging_dir, live_dir, now, reason):
    """清理未进入启用阶段的流程；绝不改动 live/current。"""
    state = load_state(live_dir)
    if state is None:
        raise RolloutError("没有可中止的流程。")
    if state["phase"] == "ACTIVE":
        raise RolloutError("副本已启用，不能中止；如需回退请走新一轮晋升。")
    if state["phase"] == "PROMOTE":
        raise RolloutError("已批准并进入启用阶段，不能中止（current 尚未切换，"
                           "请重跑 promote 完成或人工核查）。")
    if state["phase"] == "REJECTED":
        return state, "idempotent"
    state["phase"] = "REJECTED"
    state["rejected_at"] = iso(now)
    state["error"] = "人工中止: %s" % reason
    save_state(live_dir, state)
    return state, "aborted"


def do_promote(staging_dir, live_dir, now, crash_after=None):
    state = load_state(live_dir)
    if state is None:
        raise RolloutError("没有可启用的流程。")
    if state["phase"] == "ACTIVE":
        return state, "idempotent"
    if state["phase"] != "PROMOTE":
        raise RolloutError("当前阶段为 %s，必须先批准才能启用。" % state["phase"])

    manifest = read_json(os.path.join(state["pending_dir"], MANIFEST_NAME))
    target_dir = version_dir(live_dir, manifest["id"])
    target_db = os.path.join(target_dir, DB_NAME)
    active_before = resolve_current_db(live_dir)

    # 断点对账：上一轮可能已原子切换 current 但在状态收尾前中断。
    # 若 current 已指向本目标且哈希正确，只需补登记为 ACTIVE，绝不二次切换/回退。
    link = current_link_path(live_dir)
    if os.path.islink(link) and os.path.realpath(link) == os.path.realpath(target_dir):
        if os.path.isfile(target_db) and \
                file_sha256(target_db) == manifest["content_sha256"]:
            state["target_version_dir"] = os.path.abspath(target_dir)
            state["active_before"] = active_before
            state["phase"] = "ACTIVE"
            state["promoted_at"] = iso(now)
            save_state(live_dir, state)
            return state, "reconciled"

    # 1) 物化不可变版本目录（幂等：已存在则校验哈希后复用）。
    ensure_dir(os.path.join(live_dir, "versions"))
    if not os.path.isdir(target_dir):
        ensure_dir(target_dir)
        import shutil
        shutil.copy2(state["pending_db"], target_db)
        shutil.copy2(os.path.join(state["pending_dir"], MANIFEST_NAME),
                     os.path.join(target_dir, MANIFEST_NAME))
    elif file_sha256(target_db) != manifest["content_sha256"]:
        raise RolloutError("目标版本目录已存在但内容不一致: %s" % target_dir)

    state["target_version_dir"] = os.path.abspath(target_dir)
    state["active_before"] = active_before
    save_state(live_dir, state)

    if crash_after == "materialize":
        raise RuntimeError("【模拟崩溃】版本目录已物化，但尚未切换 current")

    # 2) 原子切换 current；这是唯一会改变"正在用副本"的动作。
    atomic_symlink(target_dir, current_link_path(live_dir))

    if crash_after == "swap":
        # 真实地模拟"链接已切换、状态尚未收尾"的中断窗口：此时状态仍是 PROMOTE。
        raise RuntimeError("【模拟崩溃】current 已切换，状态收尾前中断")

    # 3) 对账后落盘 ACTIVE。重跑进入这里时若 current 已指向目标，即为断点恢复。
    state["phase"] = "ACTIVE"
    state["promoted_at"] = iso(now)
    save_state(live_dir, state)

    return state, "promoted"


# --------------------------------------------------------------------------- #
# 扫描：演示实际生效的是哪一份
# --------------------------------------------------------------------------- #
def derive_identity(entry_path, rule):
    git_dir = os.path.join(entry_path, ".git")
    if os.path.isdir(git_dir):
        import subprocess
        try:
            head = subprocess.run(
                ["git", "-C", entry_path, "rev-parse", "--short", "HEAD"],
                capture_output=True, text=True, check=True)
            return "git:" + head.stdout.strip(), "git"
        except Exception:  # noqa: BLE001
            pass

    if rule == "hash":
        db_file = os.path.join(entry_path, DB_NAME)
        if os.path.isfile(db_file):
            digest = file_sha256(db_file)
        else:
            digest = hashlib.sha256(os.path.basename(
                entry_path.rstrip(os.sep)).encode("utf-8")).hexdigest()
        return "sha256:" + digest[:16], "non-git/hash"
    if rule.startswith("regex:"):
        import re
        pattern = rule.split(":", 1)[1]
        match = re.search(pattern, os.path.basename(entry_path))
        if not match:
            raise RolloutError("身份规则 %s 无法从目录名 %s 提取身份"
                               % (rule, os.path.basename(entry_path)))
        return "regex:" + (match.group(1) if match.groups() else match.group(0)), \
            "non-git/regex"
    raise RolloutError("未知身份规则: %s" % rule)


def cmd_scan(args):
    root = os.path.abspath(args.root)
    if not os.path.isdir(root):
        raise RolloutError("扫描根目录不存在: %s" % root)
    current_name = None
    if args.live_dir:
        link = current_link_path(args.live_dir)
        if os.path.islink(link):
            current_name = os.path.basename(os.path.realpath(link))

    rows = []
    for name in sorted(os.listdir(root)):
        entry = os.path.join(root, name)
        if not os.path.isdir(entry):
            continue
        identity, kind = derive_identity(entry, args.identity_rule)
        is_git = kind == "git"
        db_file = os.path.join(entry, DB_NAME)
        db_hash = file_sha256(db_file)[:16] if os.path.isfile(db_file) else "-"
        in_use = "YES" if (current_name and name == current_name) else "-"
        rows.append((name, "git" if is_git else "non-git", identity, db_hash, in_use))

    print("扫描根目录: %s" % root)
    print("身份规则  : %s（git 目录优先用 HEAD；历史非 Git 目录按调用方规则）"
          % args.identity_rule)
    print("%-22s %-8s %-24s %-18s %-7s"
          % ("目录", "类型", "身份", "db sha256(前16)", "在用"))
    print("-" * 86)
    for row in rows:
        print("%-22s %-8s %-24s %-18s %-7s" % row)
    if args.live_dir:
        print("-" * 90)
        print("当前 live/current 实际指向: %s"
              % (os.path.realpath(current_link_path(args.live_dir))
                 if os.path.islink(current_link_path(args.live_dir)) else "(无)"))


# --------------------------------------------------------------------------- #
# 状态展示
# --------------------------------------------------------------------------- #
def phase_cn(phase):
    return {
        "RECEIVE": "接收中",
        "VERIFY": "待核对/核对中",
        "APPROVE": "核对通过，等待批准",
        "PROMOTE": "已批准，待启用",
        "ACTIVE": "已启用",
        "REJECTED": "核对未通过，已拒绝",
    }.get(phase, phase)


def cmd_status(args):
    state = load_state(args.live_dir)
    if state is None:
        print("当前没有晋升流程。")
        if os.path.islink(current_link_path(args.live_dir)):
            print("正在使用: %s" % os.path.realpath(current_link_path(args.live_dir)))
        return

    if args.json:
        print(json.dumps(state, indent=2, ensure_ascii=False))
        return

    manifest_path = os.path.join(state["pending_dir"], MANIFEST_NAME)
    manifest = read_json(manifest_path) if os.path.isfile(manifest_path) else {}
    print("== 本轮在审通告库 ==")
    print("阶段        : %s (%s)" % (state["phase"], phase_cn(state["phase"])))
    print("审核令牌    : %s" % state["token"])
    print("独立身份    : %s" % state["manifest_id"])
    print("内容版本    : %s" % state["version"])
    print("待启用副本  : %s" % state["pending_dir"])
    if manifest:
        print("时效说明    : %s 至 %s"
              % (manifest.get("not_before"), manifest.get("not_after")))
        print("内容哈希    : %s" % manifest.get("content_sha256"))
    print("到达/核对/批准: %s | %s | %s"
          % (state["received_at"], state["verified_at"] or "-",
             state["approved_at"] or "-"))
    link = current_link_path(args.live_dir)
    if os.path.islink(link):
        print("正在使用    : %s （切换前: %s）"
              % (os.path.realpath(link), state.get("active_before") or "无"))
    else:
        print("正在使用    : （尚未启用任何副本）")
    if state.get("error"):
        print("错误        : %s" % state["error"])


# --------------------------------------------------------------------------- #
# 交付包构造（测试/演示用）
# --------------------------------------------------------------------------- #
def cmd_make_bundle(args):
    ensure_dir(args.out)
    db_path = os.path.join(args.out, DB_NAME)
    if os.path.exists(db_path):
        os.remove(db_path)
    connection = sqlite3.connect(db_path)
    connection.execute("CREATE TABLE notices (id INTEGER PRIMARY KEY, body TEXT)")
    for index, line in enumerate(args.notice or [], start=1):
        connection.execute("INSERT INTO notices (id, body) VALUES (?, ?)",
                           (index, line))
    connection.commit()
    connection.close()

    digest = file_sha256(db_path)
    manifest = {
        "id": args.id,
        "version": args.version,
        "content_sha256": digest,
        "not_before": args.not_before,
        "not_after": args.not_after,
        "created_at": args.now,
    }
    atomic_write(os.path.join(args.out, MANIFEST_NAME),
                 json.dumps(manifest, indent=2, ensure_ascii=False) + "\n")
    print("已生成交付包: %s" % args.out)
    print("  身份=%s 版本=%s sha256=%s" % (args.id, args.version, digest))


# --------------------------------------------------------------------------- #
# 一次可恢复的 run，以及独立阶段命令
# --------------------------------------------------------------------------- #
def cmd_run(args):
    now = now_from_args(args)
    ensure_dir(args.staging_dir)
    ensure_dir(args.live_dir)

    state, recv_kind = do_receive(args.staging_dir, args.live_dir,
                                  args.bundle_dir, now)
    print("[1/4] 接收     : %s（令牌 %s -> %s）"
          % (recv_kind, state["token"], state["pending_dir"]))

    state, verify_kind, _ = do_verify(args.staging_dir, args.live_dir, now)
    print("[2/4] 核对     : %s（哈希与时效已验证，%s）"
          % (verify_kind, iso(now)))

    print("[3/4] 批准闸门 : 核对完成，副本 %s 现在等待批准。"
          % state["manifest_id"])
    print('           值班人员确认后执行: %s approve --live-dir %s --now "..."'
          % (os.path.basename(sys.argv[0]), args.live_dir))
    print("[4/4] 启用     : 尚未执行（暂停在批准闸门）。")
    print("提示：中断后重跑同一条 run 命令即可从断点继续，正在使用的副本不受影响。")


def cmd_receive(args):
    now = now_from_args(args)
    ensure_dir(args.staging_dir)
    ensure_dir(args.live_dir)
    state, kind = do_receive(args.staging_dir, args.live_dir, args.bundle_dir, now)
    print("接收完成（%s）：%s" % (kind, state["pending_dir"]))


def cmd_verify(args):
    now = now_from_args(args)
    state, kind, _ = do_verify(args.staging_dir, args.live_dir, now)
    print("核对完成（%s）：阶段=%s，等待批准。" % (kind, state["phase"]))


def cmd_approve(args):
    now = now_from_args(args)
    state, kind = do_approve(args.staging_dir, args.live_dir, now)
    print("批准完成（%s）：阶段=%s。" % (kind, state["phase"]))


def cmd_abort(args):
    now = now_from_args(args)
    state, kind = do_abort(args.staging_dir, args.live_dir, now, args.reason)
    print("中止完成（%s）：令牌=%s，正在使用的副本未受影响。"
          % (kind, state["token"]))


def cmd_promote(args):
    now = now_from_args(args)
    state, kind = do_promote(args.staging_dir, args.live_dir, now,
                             crash_after=args.crash_after)
    print("启用完成（%s）：current -> %s"
          % (kind, os.path.realpath(current_link_path(args.live_dir))))


def build_parser():
    parser = argparse.ArgumentParser(
        description="通告库可恢复的本地接收/核对/启用工具")
    parser.add_argument("--now", help="固定时钟（ISO-8601，默认真实 UTC 时间）",
                        default=datetime.now(timezone.utc)
                        .strftime("%Y-%m-%dT%H:%M:%SZ"))
    sub = parser.add_subparsers(dest="command", required=True)

    p_make = sub.add_parser("make-bundle", help="构造一个通告库交付包")
    p_make.add_argument("--out", required=True)
    p_make.add_argument("--id", required=True)
    p_make.add_argument("--version", required=True)
    p_make.add_argument("--not-before", required=True)
    p_make.add_argument("--not-after", required=True)
    p_make.add_argument("--notice", action="append")
    p_make.set_defaults(func=cmd_make_bundle)

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--staging-dir", required=True)
    common.add_argument("--live-dir", required=True)

    p_run = sub.add_parser("run", parents=[common],
                           help="接收+核对，停在批准闸门（可恢复）")
    p_run.add_argument("--bundle-dir", required=True)
    p_run.set_defaults(func=cmd_run)

    p_recv = sub.add_parser("receive", parents=[common], help="仅接收")
    p_recv.add_argument("--bundle-dir", required=True)
    p_recv.set_defaults(func=cmd_receive)

    p_ver = sub.add_parser("verify", parents=[common], help="仅核对")
    p_ver.set_defaults(func=cmd_verify)

    p_app = sub.add_parser("approve", parents=[common], help="批准")
    p_app.set_defaults(func=cmd_approve)

    p_abort = sub.add_parser("abort", parents=[common],
                             help="中止未进入启用阶段的流程（不动 current）")
    p_abort.add_argument("--reason", default="值班人员中止")
    p_abort.set_defaults(func=cmd_abort)

    p_pro = sub.add_parser("promote", parents=[common], help="原子启用")
    p_pro.add_argument("--crash-after", choices=["materialize", "swap"],
                       help="演示用：在指定点模拟崩溃")
    p_pro.set_defaults(func=cmd_promote)

    p_st = sub.add_parser("status", help="查看当前在审哪一份")
    p_st.add_argument("--live-dir", required=True)
    p_st.add_argument("--json", action="store_true")
    p_st.set_defaults(func=cmd_status)

    p_scan = sub.add_parser("scan", help="扫描目录，按调用方规则推导身份")
    p_scan.add_argument("--root", required=True)
    p_scan.add_argument("--live-dir",
                        help="用于标注哪一份是当前生效数据库")
    p_scan.add_argument("--identity-rule", default="hash",
                        help="hash | regex:PATTERN（git 目录始终优先用 HEAD）")
    p_scan.set_defaults(func=cmd_scan)

    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        args.func(args)
    except RolloutError as exc:
        print("错误: %s" % exc, file=sys.stderr)
        return 2
    except RuntimeError as exc:
        print(str(exc), file=sys.stderr)
        return 3
    return 0


if __name__ == "__main__":
    sys.exit(main())
