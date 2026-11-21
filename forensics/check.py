#!/usr/bin/env python3
"""只读核对：对照回收的 pipx 环境目录与入口目录，区分三种状态。

对应 src/pipx/commands/health.py 的 _check_health，但只做不执行程序的
部分（目录/文件存在性、链接解析、元数据解析）；health.py 第 84 行会
真正运行解释器 `python --version`，取证核对跳过该步。

用法: check.py --pipx-home <回收的PIPX_HOME> --bin-dir <回收的PIPX_BIN_DIR>
退出码恒为 0：本脚本只出报告，不做判定式失败。
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path


def load_claimed_apps(venv_dir: Path) -> list[str]:
    meta = venv_dir / "pipx_metadata.json"
    if not meta.is_file():
        return []
    try:
        data = json.loads(meta.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    return list(data.get("main_package", {}).get("apps", []))


def interpreter_present(venv_dir: Path) -> bool:
    # 与 get_venv_paths 一致的非 Windows 布局；Windows 回收目录请改用 Scripts/python.exe
    return (venv_dir / "bin" / "python").is_file()


def classify_entry(entry: Path, venvs_dir: Path) -> str:
    resolved = Path(os.path.realpath(entry))
    if entry.is_symlink():
        origin = f"符号链接 -> {os.readlink(entry)}"
    elif entry.is_file():
        first = entry.open("rb").readline().decode("utf-8", "replace").strip()
        origin = f"脚本 shebang {first}" if first.startswith("#!") else "普通文件(非脚本)"
    else:
        return f"{entry.name}: 非常规入口类型，需人工核查"
    if not resolved.exists():
        return f"{entry.name}: 入口悬空 ({origin})；目标 {resolved} 不存在 -> 对应 health: MISSING"
    if resolved.is_relative_to(venvs_dir.resolve()):
        venv_name = resolved.relative_to(venvs_dir.resolve()).parts[0]
        return f"{entry.name}: 入口落在回收环境内 ({origin})，归属 venv [{venv_name}] -> 可互相印证"
    return f"{entry.name}: 状态B 指向其他环境 ({origin})；实际解析到 {resolved}，在回收目录之外"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--pipx-home", type=Path, required=True, help="回收的 PIPX_HOME（含 venvs/）")
    parser.add_argument("--bin-dir", type=Path, required=True, help="回收的 PIPX_BIN_DIR")
    args = parser.parse_args()

    venvs_dir = args.pipx_home / "venvs"
    venvs = {d.name: d for d in sorted(venvs_dir.iterdir()) if d.is_dir()} if venvs_dir.is_dir() else {}
    entries = {e.name: e for e in sorted(args.bin_dir.iterdir())} if args.bin_dir.is_dir() else {}

    print("== 1. venv 目录核对（health 的只读部分）==")
    claimed: dict[str, str] = {}
    for name, venv_dir in venvs.items():
        interp = "解释器文件存在" if interpreter_present(venv_dir) else "解释器缺失 -> 对应 health: BROKEN"
        apps = load_claimed_apps(venv_dir)
        for app in apps:
            claimed[app] = name
        print(f"[venv] {name}: 目录存在, {interp}, 元数据声称 apps={apps or '无'}")
    if not venvs:
        print("(venvs/ 为空或不存在 -> 对应 health: 无受管环境)")

    print("\n== 2. 入口目录核对 ==")
    for entry in entries.values():
        print(f"[bin] {classify_entry(entry, venvs_dir)}")
    if not entries:
        print("(入口目录为空)")

    print("\n== 3. 交叉结论（三种状态）==")
    for app, venv_name in sorted(claimed.items()):
        if app not in entries:
            print(
                f"状态C 只能证明配置声称如此: [{app}] "
                f"仅见于 {venv_name}/pipx_metadata.json，入口目录无对应文件"
            )
    exposed = {os.path.realpath(e) for e in entries.values()}
    for name, venv_dir in venvs.items():
        has_entry = any(str(p).startswith(str(venv_dir.resolve())) for p in exposed)
        if not has_entry and not load_claimed_apps(venv_dir):
            print(f"状态A 命令缺失: [{name}] venv 在，但无入口且元数据无声称，无法证明其命令曾可用")
    print("(状态B 见第 2 节入口解析结果；悬空入口对应 health 的 MISSING)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
