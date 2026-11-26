"""
单次分层追踪：用 Policy Sentry 真实的匹配与渲染入口，把一份 CRUD 模板
从原始 ARN 到最终 Sid 的每一层结果落成 JSON，供离线比对。

用法（务必用仓库 .venv 的解释器，并通过 HOME 指向目标目录快照）：

    HOME=<含 .policy_sentry/iam-definition.json 的目录> \
        .venv/bin/python offline-triage/trace_run.py <模板.yml> <输出.json> <运行名>

分层约定（分歧定位全靠它）：
    layer0_environment      实际加载的 iam-definition.json 路径与哈希（证据锚点）
    layer1_template_input   模板原文与每个 ARN 的 parse_arn 结果
    layer2_resource_match   每个 ARN 经 get_matching_raw_arns 得到的候选资源类型
    layer3_action_condition 每个候选资源类型的动作清单与条件键能力
    layer4_final_sid        SidGroup.process_template 渲染出的最终策略与内部 Sid
"""

from __future__ import annotations

import copy
import hashlib
import json
import sys
from pathlib import Path

import yaml

ACCESS_LEVEL_SECTIONS = {
    "read": "Read",
    "write": "Write",
    "list": "List",
    "tagging": "Tagging",
    "permissions-management": "Permissions management",
}


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    template_path = Path(sys.argv[1])
    output_path = Path(sys.argv[2])
    run_name = sys.argv[3]

    # 必须在导入 policy_sentry 之前不触碰其模块；快照选择发生在导入期。
    from policy_sentry.querying.actions import (
        get_actions_with_arn_type_and_access_level,
    )
    from policy_sentry.querying.arns import (
        get_matching_raw_arns,
        get_resource_type_name_with_raw_arn,
    )
    from policy_sentry.querying.conditions import (
        get_condition_keys_available_to_raw_arn,
        get_condition_keys_for_service,
        get_conditions_for_action_and_raw_arn,
    )
    from policy_sentry.shared.constants import (
        BUNDLED_DATASTORE_FILE_PATH,
        DATASTORE_FILE_PATH,
    )
    from policy_sentry.shared.iam_data import get_iam_definition_schema_version
    from policy_sentry.util.arns import get_service_from_arn, parse_arn
    from policy_sentry.writing.sid_group import SidGroup

    cfg = yaml.safe_load(template_path.read_text(encoding="utf-8"))

    record: dict = {"run_name": run_name, "layers": {}}

    # ---- layer 0: 环境（哪份目录快照参与了本次运行） ----
    record["layers"]["layer0_environment"] = {
        "datastore_file_path": str(DATASTORE_FILE_PATH),
        "datastore_sha256": sha256_file(DATASTORE_FILE_PATH),
        "is_bundled_datastore": DATASTORE_FILE_PATH == BUNDLED_DATASTORE_FILE_PATH,
        "datastore_schema_version": get_iam_definition_schema_version(),
        "template_path": str(template_path),
        "template_sha256": sha256_file(template_path),
    }

    # ---- layer 1: 模板输入（原始 ARN 的解析结果） ----
    requested: list[dict] = []
    for section, access_level in ACCESS_LEVEL_SECTIONS.items():
        for arn in cfg.get(section) or []:
            requested.append(
                {
                    "section": section,
                    "access_level": access_level,
                    "arn": arn,
                    "parsed": parse_arn(arn),
                }
            )
    record["layers"]["layer1_template_input"] = {
        "template": cfg,
        "requested_arns": requested,
    }

    # ---- layer 2: 资源匹配（ARN -> 候选原始 ARN / 资源类型） ----
    layer2 = []
    for item in requested:
        arn = item["arn"]
        candidates = []
        for raw_arn in get_matching_raw_arns(arn):
            candidates.append(
                {
                    "raw_arn": raw_arn,
                    "resource_type_name": get_resource_type_name_with_raw_arn(raw_arn),
                }
            )
        layer2.append(
            {
                "arn": arn,
                "service_prefix": get_service_from_arn(arn),
                "candidates": candidates,
                "match_ok": bool(candidates),
            }
        )
    record["layers"]["layer2_resource_match"] = layer2

    # ---- layer 3: 动作与条件能力（匹配成功的资源类型能拿什么） ----
    layer3 = []
    for item, match in zip(requested, layer2):
        for candidate in match["candidates"]:
            raw_arn = candidate["raw_arn"]
            resource_type = candidate["resource_type_name"]
            service_prefix = match["service_prefix"]
            actions = sorted(
                get_actions_with_arn_type_and_access_level(
                    service_prefix, resource_type, item["access_level"]
                )
            )
            layer3.append(
                {
                    "arn": item["arn"],
                    "access_level": item["access_level"],
                    "raw_arn": raw_arn,
                    "resource_type_name": resource_type,
                    "actions": actions,
                    "condition_keys_available_to_raw_arn": sorted(
                        get_condition_keys_available_to_raw_arn(raw_arn)
                    ),
                    "service_level_condition_keys": sorted(
                        get_condition_keys_for_service(service_prefix)
                    ),
                    "per_action_condition_keys": {
                        action: sorted(
                            get_conditions_for_action_and_raw_arn(action, raw_arn)
                        )
                        for action in actions
                    },
                }
            )
    record["layers"]["layer3_action_condition_capability"] = layer3

    # ---- layer 4: 最终 Sid（真实渲染入口） ----
    sid_group = SidGroup()
    rendered = sid_group.process_template(copy.deepcopy(cfg))
    record["layers"]["layer4_final_sid"] = {
        "rendered_policy": rendered,
        # 内部 Sid 结构里带有 conditions 字段（当前实现恒为空，见 sid_group.py 的 TODO），
        # 记录它是为了说明：Policy Sentry 渲染层不下发 Condition 块，
        # 审批工具展示的“资源条件”只能来自 layer3 的能力查询结果。
        "internal_sid_group": sid_group.get_sid_group(),
    }

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(record, indent=2, ensure_ascii=False, sort_keys=True),
        encoding="utf-8",
    )
    print(f"[trace_run] {run_name}: wrote {output_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
