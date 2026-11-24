#!/usr/bin/env python3
"""
Dynaconf inspect 证据实验室（可重跑）

构造 A/B 两条轨迹：相同终值 security.require_mfa=true，唯一受控差异是
B 轨迹的进程环境里存在 DYNACONF_SECURITY__REQUIRE_MFA=true（与文件同值）。
两条轨迹执行完全相同的步骤：本地 JSON 文件 -> 运行时嵌套合并 ->
运行时同值 set -> 同一个 env loader 两次加载（含折叠探针）->
绕过 set 的嵌套属性直改与还原。

用法：
    python evidence_lab.py all                 # 跑两条轨迹+边界探针+生成对照表
    python evidence_lab.py track A             # 单独跑一条轨迹
    python evidence_lab.py probes              # 只跑边界探针

仅依赖 dynaconf 与标准库。行为基于 Dynaconf 3.3.x，已在 3.3.6.dev0 核对。
"""

from __future__ import annotations

import argparse
import copy
import json
import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

KEY = "security.require_mfa"
ENV_VAR = "DYNACONF_SECURITY__REQUIRE_MFA"
PROBE_VAR = "DYNACONF_LAB_PROBE"
LATE_VAR = "DYNACONF_LATE_ONLY"

FIXTURE: dict[str, Any] = {
    "security": {
        "require_mfa": True,
        "session_timeout": 30,
        "policy": {"min_password_length": 12, "issuer": "corp-local"},
    }
}

ROOT = Path(__file__).resolve().parent
LABWORK = ROOT / "labwork"
OUT = ROOT / "out"
FIXTURE_PATH = LABWORK / "security.json"

# ---------------------------------------------------------------------------
# 基础工具
# ---------------------------------------------------------------------------


def to_plain(value: Any) -> Any:
    """把 DataDict/DataList/Path 等转成可 JSON 序列化的普通对象。"""
    return json.loads(json.dumps(value, ensure_ascii=False, default=str))


def compact(value: Any, limit: int | None = None) -> str:
    text = json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)
    if limit and len(text) > limit:
        return text[: limit - 1] + "…"
    return text


def safe_copy(value: Any) -> Any:
    try:
        return copy.deepcopy(value)
    except Exception:
        return repr(value)


def dynaconf_version() -> tuple[str, str]:
    import dynaconf

    try:
        from importlib.metadata import version as pkg_version

        ver = pkg_version("dynaconf")
    except Exception:
        ver = getattr(dynaconf, "__version__", "unknown")
    return ver, str(Path(dynaconf.__file__).resolve())


def scrub_dynaconf_env() -> None:
    for name in list(os.environ):
        if name.startswith("DYNACONF_"):
            del os.environ[name]


def filtered_env() -> dict[str, str]:
    return {k: os.environ[k] for k in sorted(os.environ) if k.startswith("DYNACONF_")}


def write_fixture() -> None:
    LABWORK.mkdir(parents=True, exist_ok=True)
    FIXTURE_PATH.write_text(
        json.dumps(FIXTURE, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    (LABWORK / "cli_settings.py").write_text(
        "from dynaconf import Dynaconf\n"
        f"settings = Dynaconf(settings_files=[{str(FIXTURE_PATH)!r}], "
        "merge_enabled=True)\n",
        encoding="utf-8",
    )


def effective_snapshot(settings: Any) -> dict[str, Any]:
    return {
        "leaf": settings.get(KEY),
        "lab_probe": settings.get("LAB_PROBE"),
        "security": to_plain(settings.get("SECURITY")),
    }


# ---------------------------------------------------------------------------
# set() 边界追踪：记录每个写入“实际收到的输入”（在对象被后续 merge 改写前深拷贝）
# ---------------------------------------------------------------------------

TRACE: dict[str, Any] = {"step": None, "depth": 0, "events": []}


def _describe_identifier(loader_identifier: Any, merge: Any) -> dict[str, Any]:
    from dynaconf.loaders.base import SourceMetadata

    if isinstance(loader_identifier, SourceMetadata):
        return loader_identifier._asdict()
    if loader_identifier is None:
        # 与 dynaconf/base.py Settings.set 的默认解析保持一致
        return {
            "loader": "set_method",
            "identifier": "undefined",
            "env": "global",
            "merged": merge is True,
            "_note": "入参为 None，此处为按源码规则推导",
        }
    if isinstance(loader_identifier, str):
        return {
            "loader": "set_method",
            "identifier": loader_identifier,
            "env": "global",
            "merged": merge is True,
        }
    return {"raw": repr(loader_identifier)}


def _merge_display(kwargs: dict[str, Any]) -> str:
    if "merge" not in kwargs:
        return "<not-passed>"
    value = kwargs["merge"]
    try:
        from dynaconf.utils.functional import empty as empty_sentinel

        if value is empty_sentinel:
            return "empty-sentinel(按配置默认)"
    except Exception:  # noqa: BLE001
        pass
    return repr(value)


def install_set_trace() -> None:
    import dynaconf.base as base

    original_set = base.Settings.set

    def traced_set(self: Any, key: Any, value: Any, *args: Any, **kwargs: Any) -> Any:
        key_upper = str(key).upper()
        interesting = "SECURITY" in key_upper or "PROBE" in key_upper
        if interesting:
            TRACE["events"].append(
                {
                    "step": TRACE["step"],
                    "depth": TRACE["depth"],
                    "key": str(key),
                    "value_at_entry": safe_copy(value),
                    "merge_arg": _merge_display(kwargs),
                    "identifier_at_entry": _describe_identifier(
                        kwargs.get("loader_identifier"), kwargs.get("merge")
                    ),
                }
            )
        TRACE["depth"] += 1
        try:
            return original_set(self, key, value, *args, **kwargs)
        finally:
            TRACE["depth"] -= 1

    base.Settings.set = traced_set  # type: ignore[assignment]


# ---------------------------------------------------------------------------
# 轨迹
# ---------------------------------------------------------------------------


def run_track(name: str) -> dict[str, Any]:
    write_fixture()
    os.chdir(LABWORK)
    scrub_dynaconf_env()
    if name == "B":
        # 唯一受控差异：环境写了与文件相同的值（原始字符串 "true"）
        os.environ[ENV_VAR] = "true"

    install_set_trace()

    from dynaconf import Dynaconf
    from dynaconf.loaders import env_loader
    from dynaconf.utils.inspect import get_history
    from dynaconf.utils.inspect import inspect_settings

    steps: list[dict[str, Any]] = []

    def add_step(
        sid: str,
        title: str,
        input_summary: str,
        input_full: Any,
        settings_obj: Any = None,
    ) -> None:
        steps.append(
            {
                "id": sid,
                "title": title,
                "input_summary": input_summary,
                "input_full": to_plain(input_full),
                "effective": effective_snapshot(settings_obj)
                if settings_obj is not None
                else None,
                "trace_events": [
                    e for e in TRACE["events"] if e["step"] == sid
                ],
            }
        )

    # S0 --------------------------------------------------------------------
    TRACE["step"] = "S0"
    env0 = filtered_env()
    add_step(
        "S0",
        "进程环境快照（Dynaconf 尚未初始化）",
        f"实际收到的 DYNACONF_* 环境变量：{compact(env0)}",
        {"dynaconf_env": env0},
        None,
    )

    # S1 --------------------------------------------------------------------
    TRACE["step"] = "S1"
    settings = Dynaconf(
        settings_files=[str(FIXTURE_PATH)],
        merge_enabled=True,
        ENVVAR_PREFIX_FOR_DYNACONF="DYNACONF",
    )
    add_step(
        "S1",
        "加载本地 JSON 文件 + 初始化期 env loader",
        "Dynaconf(settings_files=['labwork/security.json'], merge_enabled=True)",
        {
            "constructor": {
                "settings_files": [str(FIXTURE_PATH)],
                "merge_enabled": True,
                "ENVVAR_PREFIX_FOR_DYNACONF": "DYNACONF",
            },
            "file_raw_content": FIXTURE,
            "process_env": env0,
        },
        settings,
    )

    # S2 --------------------------------------------------------------------
    TRACE["step"] = "S2"
    merge_input = {"policy": {"mfa_provider": "totp"}}
    settings.set("SECURITY", copy.deepcopy(merge_input), merge=True)
    add_step(
        "S2",
        "运行时嵌套合并（merge=True，新增 policy.mfa_provider，兄弟键保留）",
        f"s.set('SECURITY', {compact(merge_input)}, merge=True)",
        {"call": "settings.set", "key": "SECURITY", "value": merge_input, "merge": True},
        settings,
    )

    # S3 --------------------------------------------------------------------
    TRACE["step"] = "S3"
    settings.set(KEY, True)
    add_step(
        "S3",
        "运行时 set 写入与终值相同的值 true",
        f"s.set('{KEY}', True)",
        {"call": "settings.set", "key": KEY, "value": True},
        settings,
    )

    # S4a -------------------------------------------------------------------
    TRACE["step"] = "S4a"
    os.environ[PROBE_VAR] = "pass-1"
    env_loader.load(settings)
    add_step(
        "S4a",
        "同一个 env loader 再次加载（折叠探针第 1 次）",
        f"os.environ[{PROBE_VAR!r}]='pass-1'; env_loader.load(s)",
        {
            "os.environ_update": {PROBE_VAR: "pass-1"},
            "dynaconf_env_at_pass": filtered_env(),
            "call": "dynaconf.loaders.env_loader.load(settings)",
        },
        settings,
    )

    # S4b -------------------------------------------------------------------
    TRACE["step"] = "S4b"
    os.environ[PROBE_VAR] = "pass-2"
    env_loader.load(settings)
    add_step(
        "S4b",
        "同一个 env loader 再次加载（折叠探针第 2 次，同 SourceMetadata 槽位）",
        f"os.environ[{PROBE_VAR!r}]='pass-2'; env_loader.load(s)",
        {
            "os.environ_update": {PROBE_VAR: "pass-2"},
            "dynaconf_env_at_pass": filtered_env(),
            "call": "dynaconf.loaders.env_loader.load(settings)",
        },
        settings,
    )

    # S5a -------------------------------------------------------------------
    TRACE["step"] = "S5a"
    settings.security.require_mfa = False
    add_step(
        "S5a",
        "绕过 Settings.set 的嵌套属性直改（历史不记录）：先改成 false",
        "s.security.require_mfa = False",
        {"direct_mutation": "settings.security.require_mfa = False"},
        settings,
    )

    # S5b -------------------------------------------------------------------
    TRACE["step"] = "S5b"
    settings.security.require_mfa = True
    add_step(
        "S5b",
        "绕过 Settings.set 的嵌套属性直改：还原为 true（终值与两轨一致）",
        "s.security.require_mfa = True",
        {"direct_mutation": "settings.security.require_mfa = True"},
        settings,
    )

    # -- 最终留在历史中的来源 ------------------------------------------------
    leaf_history = to_plain(get_history(settings, KEY))  # old-first (插入顺序)
    probe_history = to_plain(get_history(settings, "LAB_PROBE"))
    try:
        provider_history = to_plain(
            get_history(settings, "security.policy.mfa_provider")
        )
    except Exception as exc:  # noqa: BLE001
        provider_history = {"error": f"{type(exc).__name__}: {exc}"}

    relevant_slots = []
    all_slots = []
    for metadata, data in settings.loaded_by_loaders.items():
        slot = {"metadata": metadata._asdict(), "data": to_plain(data)}
        all_slots.append(slot)
        if "SECURITY" in data or "LAB_PROBE" in data:
            relevant_slots.append(slot)

    inspect_key = to_plain(inspect_settings(settings, key=KEY, dumper="json"))
    inspect_limit2 = to_plain(
        inspect_settings(settings, key=KEY, history_limit=2, dumper="json")
    )
    inspect_all = to_plain(inspect_settings(settings, dumper="json"))

    OUT.mkdir(parents=True, exist_ok=True)
    inspect_settings(
        settings, key=KEY, dumper="yaml", to_file=str(OUT / f"{name}.inspect.yaml")
    )
    (OUT / f"{name}.inspect.json").write_text(
        json.dumps(inspect_key, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    (OUT / f"{name}.limit2.json").write_text(
        json.dumps(inspect_limit2, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    (OUT / f"{name}.inspect-all.json").write_text(
        json.dumps(inspect_all, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    (OUT / f"{name}.slots.json").write_text(
        json.dumps(relevant_slots, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    (OUT / f"{name}.loaded_by_loaders.full.json").write_text(
        json.dumps(all_slots, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    current_only = {
        "artifact": "模拟只拿到 inspect 的 current（或截图/转述只剩终值）",
        "key": KEY,
        "current": inspect_key["current"],
    }
    (OUT / f"{name}.current-only.json").write_text(
        json.dumps(current_only, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )

    record = {
        "track": name,
        "dynaconf_version": dynaconf_version()[0],
        "dynaconf_file": dynaconf_version()[1],
        "python": sys.version.split()[0],
        "steps": steps,
        "final_effective": effective_snapshot(settings),
        "leaf_history_old_first": leaf_history,
        "probe_history_old_first": probe_history,
        "mfa_provider_history": provider_history,
        "relevant_slots": relevant_slots,
        "inspect_key_new_first": inspect_key,
        "inspect_limit2_new_first": inspect_limit2,
        "current_only": current_only,
    }
    (OUT / f"track_{name}.json").write_text(
        json.dumps(record, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    return record


# ---------------------------------------------------------------------------
# 边界探针
# ---------------------------------------------------------------------------


def run_probes() -> dict[str, Any]:
    write_fixture()
    os.chdir(LABWORK)
    results: list[dict[str, Any]] = []

    # P1: 同一个 SourceMetadata 槽位被再次加载 -> 同顶层键旧值被覆盖 ----------
    scrub_dynaconf_env()
    from dynaconf import Dynaconf
    from dynaconf.loaders import env_loader
    from dynaconf.utils.inspect import get_history

    s = Dynaconf(settings_files=[str(FIXTURE_PATH)], merge_enabled=True)
    os.environ[PROBE_VAR] = "first"
    env_loader.load(s)
    eff_first = s.get("LAB_PROBE")
    os.environ[PROBE_VAR] = "second"
    env_loader.load(s)
    eff_second = s.get("LAB_PROBE")
    slot = None
    for md, data in s.loaded_by_loaders.items():
        if "LAB_PROBE" in data:
            slot = {"metadata": md._asdict(), "data": to_plain(data)}
    results.append(
        {
            "id": "P1",
            "title": "同一 loader、同一 SourceMetadata：历史槽位折叠，较早输入丢失",
            "received_inputs": [
                {"pass": 1, PROBE_VAR: "first", "effective_after": eff_first},
                {"pass": 2, PROBE_VAR: "second", "effective_after": eff_second},
            ],
            "final_key_history": to_plain(get_history(s, "LAB_PROBE")),
            "surviving_slot": slot,
            "boundary": (
                "最终 inspect/loaded_by_loaders 只剩 second；first 无法从最终历史恢复，"
                "只能靠当时的步骤日志或外部环境快照证明。"
            ),
        }
    )

    # P2: 合并槽位记录的是被 object_merge 原地改写后的累积对象 ----------------
    scrub_dynaconf_env()
    s = Dynaconf(settings_files=[str(FIXTURE_PATH)], merge_enabled=True)
    merge_input = {"policy": {"mfa_provider": "totp"}}
    input_before_call = copy.deepcopy(merge_input)
    s.set("SECURITY", merge_input, merge=True)
    merged_slot_blob = None
    for md, data in s.loaded_by_loaders.items():
        if (
            md.loader == "set_method"
            and md.identifier == "undefined"
            and md.merged is True
        ):
            merged_slot_blob = to_plain(data.get("SECURITY"))
    leaf_entries = [
        h
        for h in get_history(s, KEY)
        if h["loader"] == "set_method" and h["merged"] is True
    ]
    results.append(
        {
            "id": "P2",
            "title": "历史里的 value 不是“原始输入”：合并写入会被原地累积改写",
            "input_object_before_set": input_before_call,
            "history_slot_SECURITY_after_set": merged_slot_blob,
            "leaf_history_entries_for_target_from_this_slot": to_plain(leaf_entries),
            "boundary": (
                "object_merge(old, new) 会把 old 合并进 new 并原地改写 new；"
                "因此该槽位最终 blob 含调用时并未显式给出的 require_mfa。"
                "叶子历史出现某来源，不等于该来源显式写过这个叶子。"
                "‘实际收到的输入’必须在 set 入口深拷贝固定。"
            ),
        }
    )

    # P3: 绕过 set 的嵌套直改：当前值可与所有历史值矛盾（可检测），还原后无痕 -
    scrub_dynaconf_env()
    s = Dynaconf(settings_files=[str(FIXTURE_PATH)], merge_enabled=True)
    hist_values_before = [h["value"] for h in get_history(s, KEY)]
    s.security.require_mfa = False
    current_while_false = s.get(KEY)
    hist_values_while_false = [h["value"] for h in get_history(s, KEY)]
    detectable_mismatch = current_while_false not in hist_values_while_false
    s.security.require_mfa = True
    hist_values_after_restore = [h["value"] for h in get_history(s, KEY)]
    results.append(
        {
            "id": "P3",
            "title": "嵌套属性直改不进历史：持续偏离会留下‘当前值≠历史值’矛盾，还原后无痕",
            "history_leaf_values_before": hist_values_before,
            "after_mutation_current": current_while_false,
            "history_leaf_values_during_mutation": hist_values_while_false,
            "current_vs_history_mismatch_detectable": detectable_mismatch,
            "after_restore_current": s.get(KEY),
            "history_leaf_values_after_restore": hist_values_after_restore,
            "restored_is_indistinguishable_in_history": (
                hist_values_before == hist_values_after_restore
            ),
            "boundary": (
                "若当前值与全部历史叶子值都不一致，可证明存在历史未记录的写入，"
                "但不能确定主体/时间；若事后还原成与历史相容的值，最终 inspect 无异常。"
            ),
        }
    )

    # P4: 初始化完成（强制完成首次加载）之后才注入的环境变量，不 reload 无痕迹 --
    scrub_dynaconf_env()
    s = Dynaconf(settings_files=[str(FIXTURE_PATH)], merge_enabled=True)
    s.get(KEY)  # 预热：LazySettings 在此刻才真正执行 execute_loaders
    os.environ[LATE_VAR] = "ghost-after-init"
    current_late = s.get("LATE_ONLY")
    error_name = None
    try:
        get_history(s, "LATE_ONLY")
    except Exception as exc:  # noqa: BLE001
        error_name = f"{type(exc).__name__}: {exc}"
    results.append(
        {
            "id": "P4",
            "title": "真正完成加载后才出现的环境变量：不重新加载就不进 inspect",
            "warmup_key": KEY,
            "env_var_added_after_warmup": {LATE_VAR: "ghost-after-init"},
            "effective_without_reload": current_late,
            "history_query_result": error_name,
            "boundary": (
                "最终 inspect 无法证明该环境变量曾存在；需要进程环境快照、"
                "shell/编排日志或重新加载后的 inspect 才能观察。"
            ),
        }
    )

    # P5: LazySettings 的“加载时点”是首次访问而不是 Dynaconf(...) 这一行 ------
    scrub_dynaconf_env()
    from dynaconf.utils.functional import empty as empty_sentinel

    lazy = Dynaconf(settings_files=[str(FIXTURE_PATH)], merge_enabled=True)
    pending_before_first_get = lazy._wrapped is empty_sentinel
    os.environ[LATE_VAR] = "ghost-before-first-get"
    current_lazy = lazy.get("LATE_ONLY")  # 第一次访问 -> 此刻才真正加载
    lazy_hist = to_plain(get_history(lazy, "LATE_ONLY"))
    results.append(
        {
            "id": "P5",
            "title": "LazySettings 时间零点陷阱：首次 get 前注入的变量会被当作启动环境",
            "setup_pending_before_first_get": pending_before_first_get,
            "env_var_set_between_constructor_and_first_get": {
                LATE_VAR: "ghost-before-first-get"
            },
            "effective_on_first_get": current_lazy,
            "history": lazy_hist,
            "boundary": (
                "证据时间线的零点是首次真正访问/execute_loaders，而非 "
                "Dynaconf(...) 构造语句的位置；判断‘是否启动时已有此 env’"
                "需要知道进程内第一次访问 settings 的时点。"
            ),
        }
    )

    payload = {"probes": results, "dynaconf_version": dynaconf_version()[0]}
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "probes.json").write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    return payload


# ---------------------------------------------------------------------------
# 对照报告生成
# ---------------------------------------------------------------------------


def short_path(text: str) -> str:
    return (
        text.replace(str(LABWORK), "labwork")
        .replace(str(ROOT), ".")
        .replace(str(Path.cwd()), ".")
    )


def md_cell(value: Any) -> str:
    if not isinstance(value, str):
        value = compact(value)
    return value.replace("|", "\\|").replace("\n", " ")


def metadata_key(h: dict[str, Any]) -> tuple[str, str, str, bool]:
    return (h["loader"], h["identifier"], h["env"], bool(h["merged"]))


def find_divergence(a: dict[str, Any], b: dict[str, Any]) -> dict[str, Any]:
    first_input = None
    first_effective = None
    for sa, sb in zip(a["steps"], b["steps"]):
        if first_input is None and compact(sa["input_full"]) != compact(
            sb["input_full"]
        ):
            first_input = {
                "step": sa["id"],
                "title": sa["title"],
                "A": sa["input_full"],
                "B": sb["input_full"],
            }
        if first_effective is None and compact(sa["effective"]) != compact(
            sb["effective"]
        ):
            first_effective = {"step": sa["id"], "A": sa["effective"], "B": sb["effective"]}

    ha = a["leaf_history_old_first"]
    hb = b["leaf_history_old_first"]
    pos_a: dict[tuple[str, str, str, bool], int] = {}
    pos_b: dict[tuple[str, str, str, bool], int] = {}
    for i, h in enumerate(ha):
        pos_a.setdefault(metadata_key(h), i)
    for i, h in enumerate(hb):
        pos_b.setdefault(metadata_key(h), i)
    all_keys = set(pos_a) | set(pos_b)

    def sort_key(k: tuple[str, str, str, bool]) -> tuple[int, int]:
        ia = pos_a.get(k)
        ib = pos_b.get(k)
        present = [i for i in (ia, ib) if i is not None]
        return (min(present), max(present))

    aligned = []
    first_slot_diff = None
    for k in sorted(all_keys, key=sort_key):
        ah = ha[pos_a[k]] if k in pos_a else None
        bh = hb[pos_b[k]] if k in pos_b else None
        row = {
            "A_pos_old_first": pos_a.get(k),
            "B_pos_old_first": pos_b.get(k),
            "metadata": {
                "loader": k[0],
                "identifier": short_path(k[1]),
                "env": k[2],
                "merged": k[3],
            },
            "A_value": ah["value"] if ah else "—",
            "B_value": bh["value"] if bh else "—",
        }
        aligned.append(row)
        if first_slot_diff is None and (ah is None or bh is None or ah["value"] != bh["value"]):
            first_slot_diff = row
    return {
        "first_input_divergence": first_input,
        "first_effective_divergence": first_effective,
        "first_history_slot_divergence": first_slot_diff,
        "aligned_leaf_history": aligned,
    }


def render_comparison() -> Path:
    a = json.loads((OUT / "track_A.json").read_text(encoding="utf-8"))
    b = json.loads((OUT / "track_B.json").read_text(encoding="utf-8"))
    probes = json.loads((OUT / "probes.json").read_text(encoding="utf-8"))["probes"]
    div = find_divergence(a, b)
    (OUT / "divergence.json").write_text(
        json.dumps(div, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )

    lines: list[str] = []
    w = lines.append
    w("# A/B 逐步对照表（由 evidence_lab.py 自动生成）")
    w("")
    w(f"- dynaconf `{a['dynaconf_version']}`（A/B 同版本）；Python `{a['python']}`")
    w(f"- dynaconf 来源：`{short_path(a['dynaconf_file'])}`")
    w(f"- 调查键：`{KEY}`；A/B 最终值：`{a['final_effective']['leaf']}` / `{b['final_effective']['leaf']}`")
    w("- A=`no-env`（环境不提供目标变量）；B=`env-same-value`（环境提供同值 `true`）")
    w("")
    w("## 分歧定位（机器可读另见 `out/divergence.json`）")
    w("")
    fi = div["first_input_divergence"]
    w(f"- 首次**输入证据**分歧：`{fi['step']}` — {fi['title']}")
    w(f"  - A: `{md_cell(fi['A'])}`")
    w(f"  - B: `{md_cell(fi['B'])}`")
    fe = div["first_effective_divergence"]
    w(
        "- 首次**有效值**分歧："
        + ("无（两条轨迹每一步的有效值都相同，包括 S5a 的瞬时 false）" if fe is None else f"`{fe}`")
    )
    fs = div["first_history_slot_divergence"]
    w(
        "- 最终历史中首次**来源槽位**分歧（按 SourceMetadata 对齐，old-first）："
        f"`{fs['metadata']['loader']}/{fs['metadata']['identifier']}`，"
        f"A 值=`{fs['A_value']}`，B 值=`{fs['B_value']}`"
    )
    w("")

    # -- 逐步输入/有效值对照 --------------------------------------------------
    w("## 1. 逐步输入 × 有效值对照表")
    w("")
    w("| 步骤 | A 实际收到的输入 | A: leaf 有效值 | B 实际收到的输入 | B: leaf 有效值 | 输入分歧 |")
    w("|---|---|---|---|---|---|")
    for sa, sb in zip(a["steps"], b["steps"]):
        diff_fields = sorted(
            k
            for k in set(sa["input_full"]) | set(sb["input_full"])
            if compact(sa["input_full"].get(k, "<缺失>"))
            != compact(sb["input_full"].get(k, "<缺失>"))
        )
        diff = "差异字段: " + ", ".join(f"`{k}`" for k in diff_fields) if diff_fields else ""
        w(
            "| {sid} {title} | `{ain}` | `{ae}` | `{bin}` | `{be}` | {diff} |".format(
                sid=sa["id"],
                title=md_cell(sa["title"]),
                ain=md_cell(sa["input_summary"]),
                ae=md_cell(None if sa["effective"] is None else sa["effective"]["leaf"]),
                bin=md_cell(sb["input_summary"]),
                be=md_cell(None if sb["effective"] is None else sb["effective"]["leaf"]),
                diff=diff,
            )
        )
    w("")

    # -- 嵌套状态对照 ----------------------------------------------------------
    w("## 2. 每步完整 `security` 有效值（嵌套合并证据）")
    w("")
    w("| 步骤 | A `security` | B `security` | 相同 |")
    w("|---|---|---|---|")
    for sa, sb in zip(a["steps"], b["steps"]):
        if sa["effective"] is None:
            continue
        same = compact(sa["effective"]["security"]) == compact(sb["effective"]["security"])
        w(
            f"| {sa['id']} | `{md_cell(sa['effective']['security'])}` "
            f"| `{md_cell(sb['effective']['security'])}` | {'✓' if same else '✗'} |"
        )
    w("")

    # -- set 边界 trace --------------------------------------------------------
    w("## 3. `Settings.set` 边界追踪：入口处实际收到的 value（深拷贝固定）")
    w("")
    w("| 轨迹 | 步骤 | depth | key | 入口 value | 解析来源 | merged 参数 |")
    w("|---|---|---:|---|---|---|---|")
    for rec in (a, b):
        for step in rec["steps"]:
            for ev in step["trace_events"]:
                ident = ev["identifier_at_entry"]
                ident_id = short_path(str(ident.get("identifier", "")))
                ident_s = f"{ident.get('loader')} | {ident_id} | m={ident.get('merged')}"
                w(
                    f"| {rec['track']} | {ev['step']} | {ev['depth']} | `{md_cell(ev['key'])}` "
                    f"| `{md_cell(ev['value_at_entry'])}` | `{md_cell(ident_s)}` | `{md_cell(ev['merge_arg'])}` |"
                )
    w("")
    w("> depth=1 通常是 dotted key 经 `_dotted_set` 重建嵌套 dict 后的重入写入；"
      "其 value 是重建后的顶层对象，不一定等于调用方原始输入。")
    w("")

    # -- 最终叶子历史对齐 ------------------------------------------------------
    w("## 4. 最终 `inspect -k security.require_mfa` 历史来源对齐（old-first）")
    w("")
    w("| A# | B# | loader | identifier | env | merged | A value | B value |")
    w("|---:|---:|---|---|---|---|---|---|")
    for row in div["aligned_leaf_history"]:
        m = row["metadata"]
        w(
            f"| {row['A_pos_old_first'] if row['A_pos_old_first'] is not None else '—'} "
            f"| {row['B_pos_old_first'] if row['B_pos_old_first'] is not None else '—'} "
            f"| `{m['loader']}` | `{md_cell(m['identifier'])}` | `{m['env']}` | `{m['merged']}` "
            f"| `{md_cell(row['A_value'])}` | `{md_cell(row['B_value'])}` |"
        )
    w("")
    w("注意：行号不能直接逐行对比——B 多出的 env 槽位会把后续行整体错位；"
      "应按 `(loader, identifier, env, merged)` 这个 SourceMetadata 对齐。")
    w("")

    # -- 折叠探针 ---------------------------------------------------------------
    p1 = next(p for p in probes if p["id"] == "P1")
    w("## 5. 同 loader 再次加载的折叠证据（探针 P1，两轨相同）")
    w("")
    w(f"- 两次实际输入：`{compact(p1['received_inputs'])}`")
    w(f"- 最终 `LAB_PROBE` 叶子历史：`{compact(p1['final_key_history'])}`")
    w(f"- 幸存槽位：`{compact(p1['surviving_slot'])}`")
    w(f"- 边界：{p1['boundary']}")
    w("")

    # -- 其他探针 ---------------------------------------------------------------
    w("## 6. 其余证据边界探针")
    w("")
    for p in probes:
        if p["id"] == "P1":
            continue
        w(f"### {p['id']} {p['title']}")
        w("")
        for key, value in p.items():
            if key in ("id", "title", "boundary"):
                continue
            w(f"- `{key}` = `{md_cell(value)}`")
        w(f"- **边界含义**：{p['boundary']}")
        w("")

    target = OUT / "comparison.md"
    target.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return target


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def cmd_all() -> None:
    if OUT.exists():
        shutil.rmtree(OUT)
    OUT.mkdir(parents=True)
    write_fixture()
    this = str(Path(__file__).resolve())
    for name in ("A", "B"):
        proc = subprocess.run(
            [sys.executable, this, "track", name],
            check=False,
            cwd=str(LABWORK),
            capture_output=True,
            text=True,
        )
        if proc.returncode != 0:
            sys.stderr.write(proc.stdout)
            sys.stderr.write(proc.stderr)
            raise SystemExit(f"track {name} 运行失败")
        last_line = [ln for ln in proc.stderr.splitlines() if ln.strip()]
        print(f"[lab] track {name} done — {last_line[-1] if last_line else 'ok'}")
    proc = subprocess.run(
        [sys.executable, this, "probes"],
        check=False,
        cwd=str(LABWORK),
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        sys.stderr.write(proc.stdout)
        sys.stderr.write(proc.stderr)
        raise SystemExit("probes 运行失败")
    print("[lab] probes done")
    path = render_comparison()
    print(f"[lab] track artifacts : {OUT}")
    print(f"[lab] comparison table: {path}")
    print(f"[lab] narrative report: {ROOT / 'EVIDENCE_REPORT.zh.md'}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Dynaconf inspect evidence lab")
    sub = parser.add_subparsers(dest="cmd", required=True)
    t = sub.add_parser("track")
    t.add_argument("name", choices=["A", "B"])
    sub.add_parser("probes")
    sub.add_parser("all")
    args = parser.parse_args()

    if args.cmd == "all":
        cmd_all()
    elif args.cmd == "track":
        OUT.mkdir(parents=True, exist_ok=True)
        record = run_track(args.name)
        print(json.dumps(record["inspect_key_new_first"], ensure_ascii=False, indent=2))
        print(f"[lab] wrote {OUT / f'track_{args.name}.json'}", file=sys.stderr)
    elif args.cmd == "probes":
        OUT.mkdir(parents=True, exist_ok=True)
        payload = run_probes()
        print(json.dumps(payload, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
