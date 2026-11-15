"""Analyse IFEO / SilentProcessExit evidence in an offline SOFTWARE hive.

Conservative by design:

* registry presence is a candidate configuration, never proof of execution;
* native and Wow6432Node views are never merged;
* every value occurrence is retained, including duplicate names;
* malformed type/size records are reported and excluded from decisions;
* environment variables are retained verbatim; expansion only uses
  caller-supplied, explicitly labelled assumptions.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import ntpath
import re
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

from dissect.regf import RegistryHive, RegistryKeyNotFoundError

REG_SZ = 1
REG_EXPAND_SZ = 2
REG_DWORD = 4

TYPE_NAMES = {
    0: "REG_NONE",
    1: "REG_SZ",
    2: "REG_EXPAND_SZ",
    3: "REG_BINARY",
    4: "REG_DWORD",
    5: "REG_DWORD_BIG_ENDIAN",
    6: "REG_LINK",
    7: "REG_MULTI_SZ",
    8: "REG_RESOURCE_LIST",
    9: "REG_FULL_RESOURCE_DESCRIPTOR",
    10: "REG_RESOURCE_REQUIREMENTS_LIST",
    11: "REG_QWORD",
}

VIEWS = {
    "native": r"Microsoft\Windows NT\CurrentVersion",
    "wow6432": r"Wow6432Node\Microsoft\Windows NT\CurrentVersion",
}

IFEO_KEY = "Image File Execution Options"
SPE_KEY = "SilentProcessExit"

FLG_MONITOR_SILENT_PROCESS_EXIT = 0x200
ENV_VAR_RE = re.compile(r"%([^%]+)%")

@dataclass
class Finding:
    code: str
    severity: str
    message: str
    path: str
    value: str | None = None


@dataclass
class ValueEvidence:
    name: str
    path: str
    raw_type: int
    type_name: str
    size: int
    data: bytes
    decoded: Any
    issues: list[Finding] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "path": self.path,
            "raw_type": self.raw_type,
            "type_name": self.type_name,
            "size": self.size,
            "data_hex": self.data.hex(),
            "decoded": self.decoded,
            "issues": [issue.__dict__ for issue in self.issues],
        }


def _issue(code: str, severity: str, message: str, path: str, value: str | None = None) -> Finding:
    return Finding(code, severity, message, path, value)


def _decode_string(raw: bytes, path: str, value_name: str) -> tuple[str, list[Finding]]:
    issues: list[Finding] = []
    if not raw:
        issues.append(_issue("EMPTY_STRING", "error", "字符串值为空", path, value_name))
        return "", issues
    if len(raw) % 2:
        issues.append(_issue("ODD_STRING_LENGTH", "error", "UTF-16LE 字符串长度为奇数", path, value_name))
    text = raw.decode("utf-16-le", "replace")
    if not text.endswith("\x00"):
        issues.append(_issue("MISSING_NUL_TERMINATOR", "warning", "字符串未以 NUL 结尾", path, value_name))
    text = text.rstrip("\x00")
    if not text:
        issues.append(_issue("EMPTY_STRING", "error", "字符串去掉 NUL 后为空", path, value_name))
    return text, issues


def _string_value(value, path: str) -> tuple[str | None, list[Finding], bool]:
    issues: list[Finding] = []
    if value.type not in (REG_SZ, REG_EXPAND_SZ):
        issues.append(
            _issue(
                "WRONG_TYPE",
                "error",
                f"{value.name} 必须是 REG_SZ 或 REG_EXPAND_SZ，实际为 {TYPE_NAMES.get(value.type, hex(value.type))}",
                path,
                value.name,
            )
        )
        return None, issues, False
    text, string_issues = _decode_string(value.data, path, value.name)
    issues.extend(string_issues)
    return (text if text else None), issues, not any(i.severity == "error" for i in issues)


def _dword_value(value, path: str, *, allowed_values: set[int] | None = None) -> tuple[int | None, list[Finding]]:
    issues: list[Finding] = []
    if value.type != REG_DWORD:
        issues.append(
            _issue(
                "WRONG_TYPE",
                "error",
                f"{value.name} 必须是 REG_DWORD，实际为 {TYPE_NAMES.get(value.type, hex(value.type))}",
                path,
                value.name,
            )
        )
        return None, issues
    if value.size != 4:
        issues.append(
            _issue(
                "WRONG_SIZE",
                "error",
                f"{value.name} 必须是 4 字节 DWORD，实际为 {value.size} 字节",
                path,
                value.name,
            )
        )
        return None, issues
    number = struct.unpack("<I", value.data[:4])[0]
    if allowed_values is not None and number not in allowed_values:
        issues.append(
            _issue(
                "UNEXPECTED_VALUE",
                "warning",
                f"{value.name} 值为 {number}，不在常见取值 {sorted(allowed_values)} 中",
                path,
                value.name,
            )
        )
    return number, issues


def _collect_values(key, path: str) -> list[ValueEvidence]:
    return [
        ValueEvidence(
            name=value.name,
            path=path,
            raw_type=value.type,
            type_name=TYPE_NAMES.get(value.type, f"0x{value.type:x}"),
            size=value.size,
            data=value.data,
            decoded=value.value,
        )
        for value in key.values()
    ]


def _values_named(key, name: str) -> list:
    return [value for value in key.values() if value.name.casefold() == name.casefold()]


def _dup_issues(values: list[ValueEvidence], path: str) -> list[Finding]:
    issues: list[Finding] = []
    counts: dict[str, int] = {}
    for value in values:
        counts[value.name.casefold()] = counts.get(value.name.casefold(), 0) + 1
    for name, count in counts.items():
        if count > 1:
            issues.append(
                _issue(
                    "DUPLICATE_VALUE_NAME",
                    "error",
                    f"同一键内 {name!r} 出现 {count} 次；全部记录保留，但 hive 本身不说明哪个值生效",
                    path,
                    name,
                )
            )
    return issues


def _env_info(raw: str | None, assumptions: dict[str, str]) -> dict[str, Any]:
    if not raw:
        return {
            "has_environment_variables": False,
            "variables": [],
            "unresolved": [],
            "expanded_candidate": None,
            "candidate_only": True,
        }
    variables = ENV_VAR_RE.findall(raw)
    if not variables:
        return {
            "has_environment_variables": False,
            "variables": [],
            "unresolved": [],
            "expanded_candidate": raw,
            "candidate_only": True,
            "note": "路径未做存在性、签名或可执行性验证",
        }
    expanded = raw
    unresolved: list[str] = []
    for variable in variables:
        if variable in assumptions:
            expanded = expanded.replace(f"%{variable}%", assumptions[variable])
        else:
            unresolved.append(variable)
    return {
        "has_environment_variables": True,
        "variables": variables,
        "unresolved": unresolved,
        "expanded_candidate": None if unresolved else expanded,
        "candidate_only": True,
        "assumptions_used": {name: assumptions[name] for name in variables if name in assumptions},
        "note": "展开结果只是候选解释；hive 不携带目标机环境，未验证路径或程序",
    }


def _path_flags(raw: str | None) -> dict[str, Any]:
    if not raw:
        return {"raw": None, "basename": None, "quoted": False, "absolute": False}
    candidate = raw.strip()
    quoted = candidate.startswith('"') and candidate.endswith('"')
    if quoted:
        candidate = candidate[1:-1]
    return {
        "raw": raw,
        "basename": ntpath.basename(candidate),
        "quoted": quoted,
        "absolute": bool(ntpath.splitdrive(candidate)[0]),
    }


def _parse_filter_conditions(key, path: str, assumptions: dict[str, str]) -> tuple[list[dict[str, Any]], list[Finding]]:
    """Return every FilterFullPath condition, without collapsing duplicates."""
    conditions: list[dict[str, Any]] = []
    issues: list[Finding] = []

    # A FilterFullPath directly on the image key is itself a condition candidate.
    for value in _values_named(key, "FilterFullPath"):
        raw: str | None = None
        value_issues: list[Finding] = []
        if value.type in (REG_SZ, REG_EXPAND_SZ):
            raw, value_issues = _decode_string(value.data, path, value.name)
        else:
            value_issues.append(
                _issue(
                    "WRONG_TYPE",
                    "error",
                    f"FilterFullPath 必须是 REG_SZ 或 REG_EXPAND_SZ，实际为 {TYPE_NAMES.get(value.type, hex(value.type))}",
                    path,
                    value.name,
                )
            )
        issues.extend(value_issues)
        conditions.append(
            {
                "source": "image-key-value",
                "subkey": None,
                "path": path,
                "raw": raw,
                "raw_type": value.type,
                "type_name": TYPE_NAMES.get(value.type, f"0x{value.type:x}"),
                "size": value.size,
                "data_hex": value.data.hex(),
                "issues": [issue.__dict__ for issue in value_issues],
                "path_flags": _path_flags(raw),
                "environment": _env_info(raw, assumptions),
            }
        )

    for child in key.subkeys():
        child_path = f"{path}\\{child.name}"
        child_values = _collect_values(child, child_path)
        issues.extend(_dup_issues(child_values, child_path))
        found = False
        for entry in child_values:
            if entry.name.casefold() != "filterfullpath":
                continue
            found = True
            raw: str | None = None
            value_issues: list[Finding] = []
            if entry.raw_type in (REG_SZ, REG_EXPAND_SZ):
                raw, value_issues = _decode_string(entry.data, child_path, entry.name)
            else:
                value_issues.append(
                    _issue(
                        "WRONG_TYPE",
                        "error",
                        f"FilterFullPath 必须是 REG_SZ 或 REG_EXPAND_SZ，实际为 {entry.type_name}",
                        child_path,
                        entry.name,
                    )
                )
            issues.extend(value_issues)
            conditions.append(
                {
                    "source": "filter-subkey",
                    "subkey": child.name,
                    "path": child_path,
                    "raw": raw,
                    "raw_type": entry.raw_type,
                    "type_name": entry.type_name,
                    "size": entry.size,
                    "data_hex": entry.data.hex(),
                    "issues": [issue.__dict__ for issue in value_issues],
                    "path_flags": _path_flags(raw),
                    "environment": _env_info(raw, assumptions),
                }
            )
        if not found:
            issues.append(
                _issue(
                    "FILTER_SUBKEY_WITHOUT_FILTERFULLPATH",
                    "warning",
                    f"子键 {child.name!r} 存在但没有 FilterFullPath；保留为结构线索",
                    child_path,
                )
            )
    return conditions, issues


def _conflict_issue(occurrences: list[dict[str, Any]], name: str, path: str) -> Finding | None:
    valid = [entry for entry in occurrences if entry.get("valid")]
    distinct = {entry.get("value") for entry in valid}
    if len(distinct) > 1:
        return _issue(
            "CONFLICTING_VALID_VALUES",
            "error",
            f"{name} 有多个合法但取值不同的记录 {sorted(distinct)}；不能静默选择其中一个",
            path,
            name,
        )
    return None


def _analyse_view(hive: RegistryHive, view_name: str, base_path: str, assumptions: dict[str, str]) -> dict[str, Any]:
    result: dict[str, Any] = {
        "view": view_name,
        "base_path": base_path,
        "view_root_present": True,
        "ifeo_key_present": False,
        "spe_key_present": False,
        "images": [],
        "issues": [],
    }
    try:
        hive.open(base_path)
    except RegistryKeyNotFoundError:
        result["view_root_present"] = False
        result["issues"].append(
            _issue("VIEW_ROOT_MISSING", "warning", f"该 hive 中不存在视图根键 {base_path!r}", base_path).__dict__
        )

    ifeo = spe = None
    try:
        ifeo = hive.open(f"{base_path}\\{IFEO_KEY}")
        result["ifeo_key_present"] = True
        result["ifeo_path"] = ifeo.path
    except RegistryKeyNotFoundError:
        pass
    try:
        spe = hive.open(f"{base_path}\\{SPE_KEY}")
        result["spe_key_present"] = True
        result["spe_path"] = spe.path
    except RegistryKeyNotFoundError:
        pass

    ifeo_keys: dict[str, list[Any]] = {}
    spe_keys: dict[str, list[Any]] = {}
    if ifeo is not None:
        for key in ifeo.subkeys():
            ifeo_keys.setdefault(key.name.casefold(), []).append(key)
    if spe is not None:
        for key in spe.subkeys():
            spe_keys.setdefault(key.name.casefold(), []).append(key)

    for folded in sorted(set(ifeo_keys) | set(spe_keys)):
        image_keys = ifeo_keys.get(folded, [])
        monitor_keys = spe_keys.get(folded, [])
        ambiguous_pairing = len(image_keys) > 1 or len(monitor_keys) > 1
        if ambiguous_pairing:
            result["issues"].append(
                _issue(
                    "CASE_VARIANT_DUPLICATE_KEY",
                    "error",
                    f"映像 {folded!r} 在同一视图中存在大小写变体重复键；全部逐键保留，禁止自动配对或合并结论",
                    base_path,
                ).__dict__
            )
            # Pairing an IFEO key with a SilentProcessExit key would be a guess.
            # Keep every key as its own record instead of dropping the extras.
            pairs: list[tuple[Any | None, Any | None]] = [(key, None) for key in image_keys]
            pairs.extend((None, key) for key in monitor_keys)
        else:
            pairs = [(image_keys[0] if image_keys else None, monitor_keys[0] if monitor_keys else None)]
        for image_key, monitor_key in pairs:
            display_image = (image_key or monitor_key).name
            record = _analyse_image(display_image, image_key, monitor_key, view_name, base_path, assumptions)
            record["pairing_ambiguous"] = ambiguous_pairing
            result["images"].append(record)
    return result


def _analyse_image(
    image: str,
    image_key,
    monitor_key,
    view_name: str,
    base_path: str,
    assumptions: dict[str, str],
) -> dict[str, Any]:
    issues: list[Finding] = []
    ifeo_path = image_key.path if image_key is not None else None
    spe_path = monitor_key.path if monitor_key is not None else None

    ifeo_values: list[ValueEvidence] = []
    filters: list[dict[str, Any]] = []
    if image_key is not None:
        ifeo_values = _collect_values(image_key, ifeo_path)
        issues.extend(_dup_issues(ifeo_values, ifeo_path))
        filters, filter_issues = _parse_filter_conditions(image_key, ifeo_path, assumptions)
        issues.extend(filter_issues)
        for name in ("MonitorProcess", "ReportingMode"):
            stray = _values_named(image_key, name)
            if stray:
                issues.append(
                    _issue(
                        "MISPLACED_ASSOCIATION_VALUE",
                        "warning",
                        f"{name} 出现在 IFEO 映像键而非 SilentProcessExit 键；不作为关联依据",
                        ifeo_path,
                        name,
                    )
                )
        for child in image_key.subkeys():
            for name in ("MonitorProcess", "ReportingMode"):
                if _values_named(child, name):
                    issues.append(
                        _issue(
                            "MISPLACED_ASSOCIATION_VALUE",
                            "warning",
                            f"{name} 出现在 IFEO 映像键的子键 {child.name!r} 中；不作为关联依据，也未当作过滤条件",
                            f"{ifeo_path}\\{child.name}",
                            name,
                        )
                    )

    spe_values: list[ValueEvidence] = []
    if monitor_key is not None:
        spe_values = _collect_values(monitor_key, spe_path)
        issues.extend(_dup_issues(spe_values, spe_path))
        for name in ("Debugger", "GlobalFlag", "UseFilter"):
            stray = _values_named(monitor_key, name)
            if stray:
                issues.append(
                    _issue(
                        "MISPLACED_ENABLE_VALUE",
                        "warning",
                        f"{name} 出现在 SilentProcessExit 键；不作为 IFEO 启用依据",
                        spe_path,
                        name,
                    )
                )

    def string_occurrences(key, path: str, name: str) -> tuple[list[dict[str, Any]], str | None, bool]:
        occurrences: list[dict[str, Any]] = []
        first_valid: str | None = None
        if key is None:
            return occurrences, first_valid, False
        for value in _values_named(key, name):
            text, value_issues, valid = _string_value(value, path)
            issues.extend(value_issues)
            occurrences.append({"raw": text, "type": value.type, "valid": valid})
            if first_valid is None and valid:
                first_valid = text
        conflict = _conflict_issue(occurrences, name, path)
        if conflict:
            issues.append(conflict)
        return occurrences, first_valid, bool(first_valid)

    def dword_occurrences(
        key, path: str, name: str, *, allowed: set[int] | None = None
    ) -> tuple[list[dict[str, Any]], int | None, bool]:
        occurrences: list[dict[str, Any]] = []
        first_valid: int | None = None
        if key is None:
            return occurrences, first_valid, False
        for value in _values_named(key, name):
            number, value_issues = _dword_value(value, path, allowed_values=allowed)
            issues.extend(value_issues)
            entry = {
                "value": number,
                "type": value.type,
                "size": value.size,
                "valid": number is not None,
            }
            if name == "GlobalFlag" and number is not None:
                entry["silent_process_exit_bit"] = bool(number & FLG_MONITOR_SILENT_PROCESS_EXIT)
                entry["other_bits"] = number & ~FLG_MONITOR_SILENT_PROCESS_EXIT
            occurrences.append(entry)
            if first_valid is None and number is not None:
                first_valid = number
        conflict = _conflict_issue(occurrences, name, path)
        if conflict:
            issues.append(conflict)
        return occurrences, first_valid, first_valid is not None

    debugger_occ, debugger_raw, debugger_valid = string_occurrences(
        image_key, ifeo_path or "", "Debugger"
    )
    gf_occ, global_flag, global_flag_valid = dword_occurrences(
        image_key, ifeo_path or "", "GlobalFlag"
    )
    uf_occ, use_filter, use_filter_valid = dword_occurrences(
        image_key, ifeo_path or "", "UseFilter", allowed={0, 1}
    )
    mon_occ, monitor_raw, monitor_valid = string_occurrences(
        monitor_key, spe_path or "", "MonitorProcess"
    )
    rm_occ, reporting_mode, reporting_mode_valid = dword_occurrences(
        monitor_key, spe_path or "", "ReportingMode"
    )

    def _ambiguous(name: str) -> bool:
        return any(
            issue.code in ("CONFLICTING_VALID_VALUES", "DUPLICATE_VALUE_NAME")
            and (issue.value or "").casefold() == name.casefold()
            for issue in issues
        )

    gf_ambiguous = _ambiguous("GlobalFlag")
    uf_ambiguous = _ambiguous("UseFilter")
    mon_ambiguous = _ambiguous("MonitorProcess")
    flag_active = global_flag_valid and not gf_ambiguous and bool(global_flag & FLG_MONITOR_SILENT_PROCESS_EXIT)
    valid_filter_conditions = [
        condition for condition in filters if condition["raw"] and not any(
            issue["severity"] == "error" for issue in condition["issues"]
        )
    ]
    use_filter_enabled = use_filter_valid and not uf_ambiguous and use_filter == 1
    use_filter_disabled = use_filter_valid and not uf_ambiguous and use_filter == 0
    use_filter_ambiguous = uf_ambiguous
    monitor_association_complete = bool(
        image_key is not None
        and monitor_key is not None
        and flag_active
        and monitor_valid
        and global_flag_valid
        and not gf_ambiguous
        and not mon_ambiguous
    )

    mechanisms: list[str] = []
    if debugger_valid:
        mechanisms.append("IFEO_DEBUGGER_REDIRECT_CANDIDATE")
    if image_key is not None and use_filter_enabled and valid_filter_conditions:
        # Filtering is an IFEO path-condition candidate. The hive does not prove
        # that it also gates SilentProcessExit monitoring, so keep them separate.
        mechanisms.append("IFEO_FILTER_CONDITION_CANDIDATE")
    if monitor_association_complete:
        mechanisms.append("SILENT_PROCESS_EXIT_MONITOR_CANDIDATE")
    if monitor_valid and not flag_active:
        mechanisms.append("MONITOR_WITHOUT_FLAG_ORPHAN")
    if flag_active and not monitor_valid:
        mechanisms.append("FLAG_WITHOUT_MONITOR")
    if use_filter_enabled and not valid_filter_conditions:
        mechanisms.append("USEFILTER_WITHOUT_FILTER_CONDITION")
    if use_filter_disabled and valid_filter_conditions:
        mechanisms.append("FILTER_CONDITION_NOT_ENABLED")

    normalised_filter_paths: dict[str, list[dict[str, Any]]] = {}
    for condition in valid_filter_conditions:
        raw = condition["raw"]
        if raw:
            key = ntpath.normcase(ntpath.normpath(raw.strip().strip('"')))
            normalised_filter_paths.setdefault(key, []).append(condition)
    for key, group in normalised_filter_paths.items():
        if len(group) > 1:
            issues.append(
                _issue(
                    "DUPLICATE_FILTER_CONDITION",
                    "warning",
                    f"同一映像有 {len(group)} 条过滤条件指向同一路径 {key!r}；全部保留，不推断去重或优先级",
                    group[0]["path"],
                    "FilterFullPath",
                )
            )

    for condition in valid_filter_conditions:
        raw = condition["raw"]
        if raw and image:
            basename = ntpath.basename(raw.strip().strip('"'))
            if basename.casefold() != image.casefold():
                issues.append(
                    _issue(
                        "FILTER_PATH_BASENAME_MISMATCH",
                        "warning",
                        f"过滤路径 basename {basename!r} 与映像键名 {image!r} 不同；保留原值，不推断其匹配语义",
                        condition["path"],
                        "FilterFullPath",
                    )
                )

    missing: list[str] = []
    informational_missing: list[str] = []
    if image_key is None:
        missing.append("IFEO 映像键")
    if image_key is not None and not flag_active:
        missing.append("含 0x200 的 4 字节 REG_DWORD GlobalFlag")
    if monitor_key is None:
        missing.append("SilentProcessExit 映像键")
    elif not monitor_valid:
        missing.append("合法 MonitorProcess")
    if image_key is not None and not debugger_valid:
        informational_missing.append("Debugger（独立重定向线索，非监控必需）")
    if monitor_key is not None and not reporting_mode_valid:
        informational_missing.append("ReportingMode（参考信息，非候选必要条件）")

    ifeo_association_relevant = any(
        condition["raw"] is None for condition in valid_filter_conditions
    )
    if ifeo_association_relevant:
        issues.append(
            _issue(
                "EMPTY_FILTER_CONDITION",
                "error",
                "过滤条件路径为空；不作为过滤候选依据",
                ifeo_path or base_path,
            )
        )

    return {
        "image": image,
        "view": view_name,
        "ifeo_path": ifeo_path,
        "spe_path": spe_path,
        "ifeo_present": image_key is not None,
        "spe_present": monitor_key is not None,
        "values": {
            "ifeo": [value.as_dict() for value in ifeo_values],
            "spe": [value.as_dict() for value in spe_values],
        },
        "debugger": {
            "raw": debugger_raw,
            "valid": debugger_valid,
            "occurrences": debugger_occ,
            "path_flags": _path_flags(debugger_raw),
            "environment": _env_info(debugger_raw, assumptions),
        },
        "global_flag": {
            "value": global_flag,
            "valid": global_flag_valid,
            "bit_0x200": flag_active,
            "ambiguous": gf_ambiguous,
            "occurrences": gf_occ,
        },
        "use_filter": {
            "value": use_filter,
            "valid": use_filter_valid,
            "enabled": use_filter_enabled,
            "disabled": use_filter_disabled,
            "ambiguous": use_filter_ambiguous,
            "occurrences": uf_occ,
        },
        "filters": filters,
        "filter_values": [
            {
                "source": condition["source"],
                "subkey": condition["subkey"],
                "path": condition["path"],
                "name": "FilterFullPath",
                "raw_type": condition["raw_type"],
                "type_name": condition["type_name"],
                "size": condition["size"],
                "data_hex": condition["data_hex"],
                "decoded": condition["raw"],
            }
            for condition in filters
        ],
        "valid_filter_count": len(valid_filter_conditions),
        "monitor": {
            "raw": monitor_raw,
            "valid": monitor_valid,
            "occurrences": mon_occ,
            "path_flags": _path_flags(monitor_raw),
            "environment": _env_info(monitor_raw, assumptions),
        },
        "reporting_mode": {"value": reporting_mode, "valid": reporting_mode_valid, "occurrences": rm_occ},
        "monitor_association_complete": monitor_association_complete,
        "mechanisms": mechanisms,
        "missing_associations": missing,
        "informational_missing": informational_missing,
        "issues": [issue.__dict__ for issue in issues],
        "notes": _notes(
            mechanisms=mechanisms,
            debugger_valid=debugger_valid,
            flag_active=flag_active,
            monitor_valid=monitor_valid,
            gf_ambiguous=gf_ambiguous,
            uf_ambiguous=uf_ambiguous,
        ),
    }


def _notes(
    *,
    mechanisms: list[str],
    debugger_valid: bool,
    flag_active: bool,
    monitor_valid: bool,
    gf_ambiguous: bool,
    uf_ambiguous: bool,
) -> list[str]:
    notes: list[str] = []
    if debugger_valid:
        notes.append("Debugger 存在只说明 IFEO 重定向候选，不是执行证据。")
    if gf_ambiguous:
        notes.append("GlobalFlag 存在重复或冲突记录，0x200 位状态不确定，故不判定监控生效。")
    if uf_ambiguous:
        notes.append("UseFilter 存在重复或冲突记录，过滤启用状态不确定；这不改变 GlobalFlag+MonitorProcess 的监控关联判定。")
    if "SILENT_PROCESS_EXIT_MONITOR_CANDIDATE" in mechanisms:
        notes.append("GlobalFlag 的 0x200 位与 MonitorProcess 同时合法成立，支持 SilentProcessExit 监控候选。")
    elif flag_active and not monitor_valid:
        notes.append("GlobalFlag 的 0x200 位存在但 MonitorProcess 不可用，关联不完整。")
    elif monitor_valid and not flag_active:
        notes.append("MonitorProcess 存在但缺少可用的 GlobalFlag 0x200，不能仅凭监控路径认定生效。")
    if not mechanisms:
        notes.append("未形成可描述的候选机制。")
    return notes


def analyse_hive(path: Path, assumptions: dict[str, str]) -> dict[str, Any]:
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    with path.open("rb") as fh:
        hive = RegistryHive(fh)
        views = [_analyse_view(hive, name, base, assumptions) for name, base in VIEWS.items()]
        return {
            "hive": str(path),
            "sha256": digest,
            "size": path.stat().st_size,
            "parser": {"library": "dissect.regf"},
            "hive_header": {
                "version": hive.version,
                "filename": hive.filename,
                # dissect.regf stores the XOR-32 checksum comparison result here.
                "checksum_comparison_true": hive.dirty,
                "in_transaction": hive.in_transaction,
            },
            "views": views,
            "issues": [issue for view in views for issue in view["issues"]],
        }


def _all_images(report: dict[str, Any]) -> Iterable[dict[str, Any]]:
    for view in report["views"]:
        yield from view["images"]


def _md(text: str) -> str:
    return text.replace("|", "\\|")


def report_markdown(reports: list[dict[str, Any]], assumptions: dict[str, str]) -> str:
    lines: list[str] = []
    lines.append("# IFEO / SilentProcessExit 离线 hive 分析报告")
    lines.append("")
    lines.append("> 结论边界：本报告只分析注册表配置证据，不执行、不验证任何真实程序，也不把配置存在等同于劫持生效。")
    lines.append("")
    lines.append("## 1. 方法")
    lines.append("")
    lines.append("- 使用 `dissect.regf.RegistryHive` 直接解析 hive；原生视图与 `Wow6432Node` 视图分别取证，不跨视图合并。")
    lines.append("- 每个值保留原始字节、类型、大小与重复次数；类型/宽度/空值不合法时进入问题列表，并从机制判定中排除。")
    lines.append("- `Debugger` 重定向与 `SilentProcessExit` 监控是独立候选机制；`GlobalFlag`/`UseFilter` 不单独等同于“劫持生效”。")
    lines.append("- 环境变量保留原文；只有显式提供 `--assume-env NAME=VALUE` 时才产生候选展开，且标注为未验证。")
    if assumptions:
        lines.append("")
        lines.append("候选展开假设（仅用于展示，不代表目标机真实环境）：")
        lines.append("")
        for name, value in sorted(assumptions.items()):
            lines.append(f"- `%{name}%` → `{value}`")
    else:
        lines.append("")
        lines.append("未提供环境变量假设，所有 `%VAR%` 路径保持原文。")
    lines.append("")

    lines.append("## 2. 字段语义与联合判定")
    lines.append("")
    lines.append("| 证据 | 位置 | 单独出现时的含义 | 联合关系 |")
    lines.append("| --- | --- | --- | --- |")
    lines.append("| `Debugger` | `...\\Image File Execution Options\\<image>` | IFEO 调试器重定向候选 | 与 SilentProcessExit 无必然关系；类型必须合法 |")
    lines.append("| `GlobalFlag` | 同上 | DWORD 位图；`0x200` 与 SilentProcessExit 监控相关 | 必须与同视图同映像的 `MonitorProcess` 共同成立 |")
    lines.append("| `UseFilter` | 同上 | DWORD 开关；`1` 为启用过滤候选 | 还需合法 `FilterFullPath` 条件；`0` 时条件保留但不启用 |")
    lines.append("| `FilterFullPath` | 映像键值或直接子键 | 一个路径条件候选 | 多个条件全部保留；hive 不证明匹配优先级或 AND/OR 语义 |")
    lines.append("| `MonitorProcess` | `...\\SilentProcessExit\\<image>` | 监控程序路径候选 | 缺 `GlobalFlag` 的 `0x200` 位时不能认定 SilentProcessExit 生效 |")
    lines.append("| `ReportingMode` | 同上 | DWORD 报告模式 | 记录数值；缺失不阻断监控候选，但列入信息缺失 |")
    lines.append("")
    lines.append("候选机制的最低共同证据：")
    lines.append("")
    lines.append("- `IFEO_DEBUGGER_REDIRECT_CANDIDATE`：同视图存在类型合法、非空 `Debugger`。")
    lines.append("- `SILENT_PROCESS_EXIT_MONITOR_CANDIDATE`：同视图 `GlobalFlag` 是 4 字节 `REG_DWORD` 且含 `0x200`，且 `SilentProcessExit\\<image>` 有类型合法、非空 `MonitorProcess`。")
    lines.append("- `IFEO_FILTER_CONDITION_CANDIDATE`：同视图 `UseFilter=1` 且至少一条合法 `FilterFullPath`。它只说明 IFEO 路径过滤候选；hive 不证明该过滤同时门控 SilentProcessExit。")
    lines.append("- `MONITOR_WITHOUT_FLAG_ORPHAN` / `FLAG_WITHOUT_MONITOR` / `USEFILTER_WITHOUT_FILTER_CONDITION` / `FILTER_CONDITION_NOT_ENABLED`：不完整或惰性配置，仅作线索。")
    lines.append("")

    lines.append("## 3. 样本总览")
    lines.append("")
    lines.append("| 样本 | 原生视图映像 | Wow6432Node 映像 | 机制集合 |")
    lines.append("| --- | --- | --- | --- |")
    for report in reports:
        native = [img["image"] for view in report["views"] if view["view"] == "native" for img in view["images"]]
        wow = [img["image"] for view in report["views"] if view["view"] == "wow6432" for img in view["images"]]
        mechs = sorted({m for img in _all_images(report) for m in img["mechanisms"]})
        lines.append(
            f"| `{Path(report['hive']).name}` | {', '.join(native) or '—'} | {', '.join(wow) or '—'} | {', '.join(mechs) or '—'} |"
        )
    lines.append("")
    lines.append("`dissect.regf` 的 `hive.dirty` 在实现上是 `xor32_crc(header[:508]) == CheckSum` 的结果，因此 `True` 表示校验和匹配，与变量名的常见直觉相反；本报告原样记录该布尔值，不据此判定 hive 损坏。")
    lines.append("")

    lines.append("## 4. 对照矩阵")
    lines.append("")
    lines.append("| 样本 / 映像 | 视图 | Debugger | GlobalFlag | UseFilter | 过滤条件 | MonitorProcess | 监控关联完整 | 候选机制 |")
    lines.append("| --- | --- | --- | --- | --- | --- | --- | --- | --- |")
    for report in reports:
        for image in _all_images(report):
            dbg = f"`{image['debugger']['raw']}`" if image["debugger"]["valid"] else "—"
            gf = (
                f"0x{image['global_flag']['value']:x}" + ("（冲突）" if image["global_flag"].get("ambiguous") else "")
                if image["global_flag"]["valid"]
                else "—"
            )
            uf = (
                str(image["use_filter"]["value"]) + ("（冲突）" if image["use_filter"].get("ambiguous") else "")
                if image["use_filter"]["valid"]
                else "—"
            )
            filters = f"{len(image['filters'])} 条（{image['valid_filter_count']} 合法）" if image["filters"] else "—"
            mon = f"`{image['monitor']['raw']}`" if image["monitor"]["valid"] else "—"
            complete = "是" if image["monitor_association_complete"] else "否"
            mechs = "<br>".join(image["mechanisms"]) or "—"
            lines.append(
                f"| `{Path(report['hive']).name}` / `{image['image']}` | {image['view']} | {_md(dbg)} | {gf} | {uf} | {filters} | {_md(mon)} | {complete} | {_md(mechs)} |"
            )
    lines.append("")

    lines.append("### 各样本中“共同支持”的候选机制")
    lines.append("")
    lines.append("| 样本 | 共同出现的证据 | 仍缺少/不能据此断言 | 支持的候选机制 |")
    lines.append("| --- | --- | --- | --- |")
    lines.append("| A 仅监控路径 | `SilentProcessExit\\monitor-only.exe\\MonitorProcess` + `ReportingMode` | 无 IFEO 键、无 `GlobalFlag 0x200` | `MONITOR_WITHOUT_FLAG_ORPHAN`，**不**支持 SilentProcessExit 生效 |")
    lines.append("| B 标志与关联完整 | `Debugger` + `GlobalFlag=0x200` + `MonitorProcess`（同映像同视图） | 本次样本无过滤条件；未验证程序存在性/执行 | `IFEO_DEBUGGER_REDIRECT_CANDIDATE` 与 `SILENT_PROCESS_EXIT_MONITOR_CANDIDATE` |")
    lines.append("| C 32/64 两套不同配置 | 两视图各自都有 `Debugger`、`GlobalFlag=0x200`、`MonitorProcess`、`UseFilter=1`、`FilterFullPath`；但 DBG/MON/过滤路径均不同 | hive 不证明进程位数、优先级或执行结果 | 两视图各自 `IFEO_DEBUGGER_REDIRECT_CANDIDATE` + `SILENT_PROCESS_EXIT_MONITOR_CANDIDATE` + `IFEO_FILTER_CONDITION_CANDIDATE` |")
    lines.append("| D 非法/缺失/多条件 | 每个映像只保留实际出现的子集；重复值、错误类型、错误宽度、误放值全部记录 | 非法记录已从机制判定中排除；重复 `UseFilter` 使启用状态标记为不确定 | 逐映像输出 `MONITOR_WITHOUT_FLAG_ORPHAN`、`FLAG_WITHOUT_MONITOR`、`USEFILTER_WITHOUT_FILTER_CONDITION`、`FILTER_CONDITION_NOT_ENABLED` 等不完整线索 |")
    lines.append("")
    lines.append("关键点：`Debugger` 本身不触发 SilentProcessExit；`GlobalFlag` 或 `MonitorProcess` 任一单独出现也不足以认定生效；只有同一视图、同一映像键下标志与监控路径同时合法成立，才输出 `SILENT_PROCESS_EXIT_MONITOR_CANDIDATE`。")
    lines.append("")

    lines.append("## 5. 逐样本证据")
    lines.append("")
    for report in reports:
        lines.append(f"### `{Path(report['hive']).name}`")
        lines.append("")
        header = report["hive_header"]
        lines.append(
            f"- {report['size']} 字节；hive 版本 {header['version']}；"
            f"`dissect.regf` 校验和比较结果 `{header['checksum_comparison_true']}`"
            f"（`True` 表示校验和匹配；该库变量名为 `dirty`，与直觉相反）；事务中 `{header['in_transaction']}`。"
        )
        for view in report["views"]:
            lines.append("")
            lines.append(f"**视图 `{view['view']}` — `{view['base_path']}`**")
            lines.append("")
            if not view["view_root_present"]:
                lines.append("- 视图根键缺失；本视图无配置证据。")
                continue
            if not view["images"]:
                lines.append("- 未发现 IFEO 或 SilentProcessExit 映像键。")
                continue
            for image in view["images"]:
                lines.append(f"- 映像 `{image['image']}`")
                lines.append(f"  - IFEO：`{image['ifeo_path'] or '缺失'}`；SilentProcessExit：`{image['spe_path'] or '缺失'}`")
                lines.append(
                    f"  - `Debugger`：{('`' + image['debugger']['raw'] + '`（类型合法）') if image['debugger']['valid'] else '缺失/不合法'}"
                )
                if image["debugger"]["valid"]:
                    env = image["debugger"]["environment"]
                    lines.append(
                        f"    - 环境变量：`{env['variables'] or '无'}`；候选展开：`{env['expanded_candidate'] or '未展开'}`"
                    )
                if image["global_flag"]["occurrences"]:
                    gf = image["global_flag"]
                    detail = "；".join(
                        f"值 `{entry['value']}`/类型 {entry['type']}/大小 {entry['size']}/{'合法' if entry['valid'] else '不合法'}"
                        for entry in gf["occurrences"]
                    )
                    lines.append(
                        f"  - `GlobalFlag`：{detail}；有效 `0x200` 位：`{gf['bit_0x200']}`；取值冲突：`{gf.get('ambiguous', False)}`"
                    )
                else:
                    lines.append("  - `GlobalFlag`：缺失")
                if image["use_filter"]["occurrences"]:
                    uf = image["use_filter"]
                    detail = "；".join(
                        f"值 `{entry['value']}`/类型 {entry['type']}/大小 {entry['size']}/{'合法' if entry['valid'] else '不合法'}"
                        for entry in uf["occurrences"]
                    )
                    lines.append(
                        f"  - `UseFilter`：{detail}；启用：`{uf['enabled']}`；取值冲突：`{uf.get('ambiguous', False)}`"
                    )
                else:
                    lines.append("  - `UseFilter`：缺失")
                if image["filters"]:
                    lines.append(f"  - 过滤条件（{len(image['filters'])} 条，全部保留，不合并不去重）：")
                    for condition in image["filters"]:
                        origin = f"子键 `{condition['subkey']}`" if condition["source"] == "filter-subkey" else "映像键值"
                        lines.append(f"    - {origin} / `{condition['raw'] or '空/不可用'}`（{condition['type_name']}）")
                else:
                    lines.append("  - 过滤条件：缺失")
                if image["monitor"]["occurrences"]:
                    mon = image["monitor"]
                    if mon["valid"]:
                        env = mon["environment"]
                        lines.append(
                            f"  - `MonitorProcess`：`{mon['raw']}`（类型合法）；环境变量 `{env['variables'] or '无'}`；"
                            f"候选展开 `{env['expanded_candidate'] or '未展开'}`；**未验证存在性/可执行性**"
                        )
                    else:
                        lines.append("  - `MonitorProcess`：有记录但不合法")
                else:
                    lines.append("  - `MonitorProcess`：缺失")
                rm = image["reporting_mode"]
                lines.append(f"  - `ReportingMode`：`{rm['value']}`（{'合法' if rm['valid'] else '缺失/不合法'}）")
                lines.append(
                    f"  - 监控关联完整：`{image['monitor_association_complete']}`；必要缺失项：{', '.join(image['missing_associations']) or '无'}；"
                    f"参考信息缺失：{', '.join(image['informational_missing']) or '无'}"
                )
                lines.append(f"  - 候选机制：{', '.join(f'`{m}`' for m in image['mechanisms']) or '无'}")
                if image["issues"]:
                    lines.append("  - 问题记录：")
                    for issue in image["issues"]:
                        lines.append(f"    - `{issue['code']}`（{issue['severity']}）：{issue['message']} @ `{issue['path']}`")
                for note in image["notes"]:
                    lines.append(f"  - 说明：{note}")
        lines.append("")

    lines.append("## 6. 原始值保留")
    lines.append("")
    lines.append("以下表格给出所有解析到的 IFEO/SilentProcessExit 值，包括重复项；`data_hex` 为 `dissect.regf` 返回的原始数据。")
    lines.append("")
    lines.append("| 样本 | 视图 | 键路径 | 值名 | 类型 | 大小 | data_hex |")
    lines.append("| --- | --- | --- | --- | --- | --- | --- |")
    for report in reports:
        for view in report["views"]:
            for image in view["images"]:
                for group in ("ifeo", "spe"):
                    for value in image["values"][group]:
                        lines.append(
                            f"| `{Path(report['hive']).name}` | {view['view']} | `{_md(value['path'])}` | "
                            f"`{_md(value['name'])}` | {value['type_name']} | {value['size']} | `{value['data_hex']}` |"
                        )
                for value in image["filter_values"]:
                    lines.append(
                        f"| `{Path(report['hive']).name}` | {view['view']} | `{_md(value['path'])}` | "
                        f"`{_md(value['name'])}` | {value['type_name']} | {value['size']} | `{value['data_hex']}` |"
                    )
    lines.append("")

    lines.append("## 7. 32/64 位视图结论")
    lines.append("")
    for report in reports:
        native = next(view for view in report["views"] if view["view"] == "native")
        wow = next(view for view in report["views"] if view["view"] == "wow6432")
        native_images = {image["image"].casefold(): image for image in native["images"]}
        wow_images = {image["image"].casefold(): image for image in wow["images"]}
        shared = sorted(set(native_images) & set(wow_images))
        if not shared:
            lines.append(f"- `{Path(report['hive']).name}`：没有同名映像同时出现在两视图，未做跨视图外推。")
            continue
        for name in shared:
            n, w = native_images[name], wow_images[name]
            same = (
                n["debugger"]["raw"] == w["debugger"]["raw"]
                and n["monitor"]["raw"] == w["monitor"]["raw"]
                and n["global_flag"]["value"] == w["global_flag"]["value"]
                and n["use_filter"]["value"] == w["use_filter"]["value"]
                and n["valid_filter_count"] == w["valid_filter_count"]
            )
            lines.append(
                f"- `{Path(report['hive']).name}` / `{name}`：原生视图 DBG=`{n['debugger']['raw']}`、MON=`{n['monitor']['raw']}`、过滤 {n['valid_filter_count']} 条；"
                f"Wow6432Node DBG=`{w['debugger']['raw']}`、MON=`{w['monitor']['raw']}`、过滤 {w['valid_filter_count']} 条；"
                f"{'配置相同' if same else '两套配置不同，必须按目标进程位数分别解释'}。"
            )
    lines.append("")
    lines.append("32 位进程通常读取 `Wow6432Node`，64 位进程读取原生视图；仅凭 hive 无法确定未来启动哪个位数的进程，因此不把任一视图的配置外推到另一视图。")
    lines.append("")

    lines.append("## 8. 复现")
    lines.append("")
    lines.append("```sh")
    lines.append(".venv/bin/python ifeo_analysis/build_samples.py")
    lines.append(".venv/bin/python ifeo_analysis/analyze.py \\")
    lines.append("  ifeo_analysis/samples/case_a_monitor_only.hive \\")
    lines.append("  ifeo_analysis/samples/case_b_full_chain.hive \\")
    lines.append("  ifeo_analysis/samples/case_c_two_views.hive \\")
    lines.append("  ifeo_analysis/samples/case_d_ambiguous.hive \\")
    lines.append("  --assume-env 'SystemRoot=C:\\Windows' \\")
    lines.append("  --assume-env 'ProgramFiles=C:\\Program Files' \\")
    lines.append("  --json ifeo_analysis/reports/analysis.json \\")
    lines.append("  --markdown ifeo_analysis/reports/analysis.md")
    lines.append("```")
    lines.append("")
    lines.append("样本是最小合成 REGF 文件，仅用于验证解析与判定逻辑；其中程序路径均为占位符，未执行或验证。")
    return "\n".join(lines) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("hives", nargs="+", type=Path)
    parser.add_argument("--json", type=Path)
    parser.add_argument("--markdown", type=Path)
    parser.add_argument(
        "--assume-env",
        action="append",
        default=[],
        metavar="NAME=VALUE",
        help="候选展开假设；可重复。仅用于展示，不代表目标机真实环境。",
    )
    args = parser.parse_args()
    assumptions: dict[str, str] = {}
    for item in args.assume_env:
        if "=" not in item:
            parser.error(f"--assume-env 需要 NAME=VALUE，收到 {item!r}")
        name, value = item.split("=", 1)
        assumptions[name] = value

    reports = [analyse_hive(path, assumptions) for path in args.hives]
    payload = {"assumptions": assumptions, "reports": reports}
    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(json.dumps(payload, ensure_ascii=False, indent=2, default=str) + "\n")
    if args.markdown:
        args.markdown.parent.mkdir(parents=True, exist_ok=True)
        args.markdown.write_text(report_markdown(reports, assumptions))
    if not args.json and not args.markdown:
        print(json.dumps(payload, ensure_ascii=False, indent=2, default=str))


if __name__ == "__main__":
    main()
