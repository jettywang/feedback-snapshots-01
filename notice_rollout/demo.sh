#!/usr/bin/env bash
# 固定时钟 + 两个本地目录，演示通告库的成功晋升、中断恢复与身份扫描。
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
TOOL="python3 $HERE/notice_rollout.py"
ROOT="$HERE/demo-work"
STAGING="$ROOT/staging"
LIVE="$ROOT/live"
INCOMING="$ROOT/incoming"
HIST="$ROOT/history-store"

# 固定时钟：整个演示使用确定性时间，不依赖墙上时钟。
T0="2026-11-29T08:00:00Z"
T1="2026-11-29T09:00:00Z"
T2="2026-11-29T10:00:00Z"
T3="2026-11-29T11:00:00Z"
T_EXPIRED="2026-12-02T00:00:00Z"

banner() { printf '\n========== %s ==========\n' "$1"; }
run() { printf '\n$ %s\n' "$*"; "$@"; }

rm -rf "$ROOT"
mkdir -p "$INCOMING" "$HIST"

# 历史非 Git 目录：沿调用方指定的身份规则处理（目录名带编号）。
mkdir -p "$HIST/adv-2026-0001" "$HIST/adv-2026-0002"
echo old1 > "$HIST/adv-2026-0001/notices.db"
echo old2 > "$HIST/adv-2026-0002/notices.db"

banner "0. 构造三份审批后的通告库交付包（v1/v2 有效，v3 已过期）"
run $TOOL --now "$T0" make-bundle --out "$INCOMING/bundle-v1" \
  --id adv-2026-0001 --version 1 \
  --not-before 2026-11-29T00:00:00Z --not-after 2026-11-30T00:00:00Z \
  --notice "v1: 机房巡检通知" --notice "v1: 变更窗口提醒"
run $TOOL --now "$T0" make-bundle --out "$INCOMING/bundle-v2" \
  --id adv-2026-0002 --version 2 \
  --not-before 2026-11-29T00:00:00Z --not-after 2026-11-30T00:00:00Z \
  --notice "v2: 新增安全通告" --notice "v2: 召回旧通知"
run $TOOL --now "$T0" make-bundle --out "$INCOMING/bundle-v3-expired" \
  --id adv-2026-0003 --version 3 \
  --not-before 2026-11-25T00:00:00Z --not-after 2026-11-28T00:00:00Z \
  --notice "v3: 已过期内容"
run $TOOL --now "$T0" make-bundle --out "$INCOMING/bundle-v4" \
  --id adv-2026-0004 --version 4 \
  --not-before 2026-11-29T00:00:00Z --not-after 2026-11-30T00:00:00Z \
  --notice "v4: 交换后崩溃演练"

# ---------------------------------------------------------------------------
banner "1. 一次成功晋升：run 接收+核对，停在批准闸门；批准后原子启用 v1"
run $TOOL --now "$T0" run --staging-dir "$STAGING" --live-dir "$LIVE" \
  --bundle-dir "$INCOMING/bundle-v1"
run $TOOL --now "$T0" status --live-dir "$LIVE"
run cat "$STAGING/pending-adv-2026-0001/IDENTITY.txt"
run $TOOL --now "$T1" approve --staging-dir "$STAGING" --live-dir "$LIVE"
run $TOOL --now "$T1" promote --staging-dir "$STAGING" --live-dir "$LIVE"
run $TOOL --now "$T1" status --live-dir "$LIVE"
run ls -l "$LIVE/current"

# ---------------------------------------------------------------------------
banner "2. 中断恢复 A：v2 在 promote 物化后、切换前崩溃，正在用的 v1 保留"
run $TOOL --now "$T2" run --staging-dir "$STAGING" --live-dir "$LIVE" \
  --bundle-dir "$INCOMING/bundle-v2"
run $TOOL --now "$T2" approve --staging-dir "$STAGING" --live-dir "$LIVE"
run $TOOL --now "$T2" promote --staging-dir "$STAGING" --live-dir "$LIVE" \
  --crash-after materialize || true
printf '\n崩溃后 current 仍指向（应为 v1）: '; readlink "$LIVE/current"
run $TOOL --now "$T2" status --live-dir "$LIVE"
banner "2b. 重跑 promote 从断点恢复，完成 v2 切换"
run $TOOL --now "$T3" promote --staging-dir "$STAGING" --live-dir "$LIVE"
printf '\n恢复后 current 指向（应为 v2）: '; readlink "$LIVE/current"

# ---------------------------------------------------------------------------
banner "2c. 中断恢复 C：v4 在 current 已切换、状态收尾前崩溃，重跑靠对账收敛"
run $TOOL --now "$T3" run --staging-dir "$STAGING" --live-dir "$LIVE" \
  --bundle-dir "$INCOMING/bundle-v4"
run $TOOL --now "$T3" approve --staging-dir "$STAGING" --live-dir "$LIVE"
run $TOOL --now "$T3" promote --staging-dir "$STAGING" --live-dir "$LIVE" \
  --crash-after swap || true
printf '\n崩溃后状态阶段（应为 PROMOTE）: '
python3 -c "import json;print(json.load(open('$LIVE/rollout-state.json'))['phase'])"
printf 'current 已指向（应为 v4）: '; readlink "$LIVE/current"
banner "2d. 重跑 promote：检测到 current 已指向目标，对账补登记为 ACTIVE（不回退）"
run $TOOL --now "$T3" promote --staging-dir "$STAGING" --live-dir "$LIVE"
printf '\n对账后 current 仍指向（应为 v4）: '; readlink "$LIVE/current"
run $TOOL --now "$T3" status --live-dir "$LIVE"

# ---------------------------------------------------------------------------
banner "3. 中断恢复 B：run 在接收后被打断，重跑同一条 run 幂等续跑，再人工中止"
run $TOOL --now "$T3" receive --staging-dir "$STAGING" --live-dir "$LIVE" \
  --bundle-dir "$INCOMING/bundle-v1"
run $TOOL --now "$T3" status --live-dir "$LIVE"
banner "3b. 重跑 run：接收/核对均显示 idempotent，停在同一批准闸门"
run $TOOL --now "$T3" run --staging-dir "$STAGING" --live-dir "$LIVE" \
  --bundle-dir "$INCOMING/bundle-v1"
banner "3c. 值班人员中止这轮重复晋升（current 保持当前生效副本不变）"
run $TOOL --now "$T3" abort --staging-dir "$STAGING" --live-dir "$LIVE" \
  --reason "重复提交，取消本轮"
printf '\n中止后 current 仍指向（应为 v4）: '; readlink "$LIVE/current"

# ---------------------------------------------------------------------------
banner "4. 时效闸门：已过期的 v3 核对被拒绝，正在使用的副本不动"
run $TOOL --now "$T_EXPIRED" run --staging-dir "$STAGING" --live-dir "$LIVE" \
  --bundle-dir "$INCOMING/bundle-v3-expired" || true
run $TOOL --now "$T_EXPIRED" status --live-dir "$LIVE" || true
printf '\n拒绝后 current 仍指向（应为 v4）: '; readlink "$LIVE/current"

# ---------------------------------------------------------------------------
banner "5. 扫描：演示实际指定了哪一份数据库（在用标记 YES）"
# 把生效版本目录并入扫描根，便于对比历史目录与当前在用副本。
mkdir -p "$ROOT/scan-root"
cp -R "$HIST/." "$ROOT/scan-root/"
cp -R "$LIVE/versions/." "$ROOT/scan-root/"
# 再加一个受 Git 管理的历史目录：扫描时它优先用 HEAD 提交，不走调用方规则。
# 手工构造最小 .git（无 hooks 子目录），规避受限环境对 git 模板/钩子文件的写入限制。
GIT_DIR_HIST="$ROOT/scan-root/adv-2026-0009-git"
mkdir -p "$GIT_DIR_HIST/.git/objects" "$GIT_DIR_HIST/.git/refs/heads"
echo git-managed > "$GIT_DIR_HIST/notices.db"
echo "ref: refs/heads/master" > "$GIT_DIR_HIST/.git/HEAD"
G_BLOB=$(git --git-dir="$GIT_DIR_HIST/.git" hash-object -w --stdin \
  --path notices.db < "$GIT_DIR_HIST/notices.db")
G_TREE=$(printf '100644 blob %s\tnotices.db\n' "$G_BLOB" \
  | git --git-dir="$GIT_DIR_HIST/.git" mktree)
G_COMMIT=$(printf 'init\n' \
  | git --git-dir="$GIT_DIR_HIST/.git" commit-tree "$G_TREE")
printf '%s\n' "$G_COMMIT" > "$GIT_DIR_HIST/.git/refs/heads/master"
banner "5a. 调用方身份规则 = hash（非 Git 目录取 notices.db 内容哈希；Git 目录用 HEAD）"
run $TOOL --now "$T3" scan --root "$ROOT/scan-root" --live-dir "$LIVE" \
  --identity-rule hash
banner "5b. 调用方身份规则 = regex 提取通告编号（同一批非 Git 目录，规则不同）"
run $TOOL --now "$T3" scan --root "$ROOT/scan-root" --live-dir "$LIVE" \
  --identity-rule 'regex:adv-([0-9]{4}-[0-9]{4})'

banner "全部演示完成"
