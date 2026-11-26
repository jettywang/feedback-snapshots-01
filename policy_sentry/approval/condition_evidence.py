"""Condition implementation evidence for generated Policy Sentry policies.

The evaluator deliberately keys its evidence to the statements produced by
:class:`policy_sentry.writing.sid_group.SidGroup`.  A catalog can report that a
condition is supported, explicitly unsupported, or that the catalog record is
too incomplete to verify support.  Only policies where every action/resource
pair is observed carrying the requested condition are marked publishable.
"""

from __future__ import annotations

import contextlib
import copy
import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from policy_sentry.querying import actions as query_actions
from policy_sentry.querying import all as query_all
from policy_sentry.querying import arns as query_arns
from policy_sentry.querying import conditions as query_conditions
from policy_sentry.querying import services as query_services
from policy_sentry.querying.arns import (
    get_matching_raw_arns,
    get_resource_type_name_with_raw_arn,
)
from policy_sentry.querying.conditions import (
    get_condition_keys_available_to_raw_arn,
    get_conditions_for_action_and_raw_arn,
)
from policy_sentry.shared import iam_data
from policy_sentry.util.conditions import is_condition_key_match
from policy_sentry.writing.sid_group import SidGroup
from policy_sentry.writing.validate import validate_condition_block

CONDITION_EVIDENCE_VERSION = "1.0"

_PATCHED_CATALOG_MODULES = (
    iam_data,
    query_actions,
    query_all,
    query_services,
)


def _read_json_file(path: str | Path) -> dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def load_catalog(source: dict[str, Any] | str | Path | None = None) -> dict[str, Any]:
    """Load an IAM definition catalog, defaulting to the bundled catalog."""
    if source is None:
        return iam_data.load_iam_definition()
    if isinstance(source, dict):
        return copy.deepcopy(source)
    return _read_json_file(source)


def deep_merge_catalog(base: dict[str, Any], overlay: dict[str, Any]) -> dict[str, Any]:
    """Deep-merge *overlay* into *base*.

    An overlay value of ``None`` deletes the corresponding catalog key.  This
    lets a tiny fixture simulate an old catalog that omits a newer field.
    """
    for key, value in overlay.items():
        if value is None:
            base.pop(key, None)
        elif isinstance(value, dict) and isinstance(base.get(key), dict):
            deep_merge_catalog(base[key], value)
        else:
            base[key] = copy.deepcopy(value)
    return base


def prepare_catalog(
    catalog: dict[str, Any] | str | Path | None = None,
    overlay: dict[str, Any] | str | Path | None = None,
) -> dict[str, Any]:
    """Load a catalog and optionally apply a small local overlay."""
    prepared = load_catalog(catalog)
    if overlay is not None:
        overlay_data = (
            overlay if isinstance(overlay, dict) else _read_json_file(overlay)
        )
        deep_merge_catalog(prepared, overlay_data)
    return prepared


def _clear_module_caches() -> None:
    for module in (
        iam_data,
        query_actions,
        query_all,
        query_arns,
        query_conditions,
        query_services,
    ):
        for value in vars(module).values():
            cache_clear = getattr(value, "cache_clear", None)
            if callable(cache_clear):
                with contextlib.suppress(Exception):
                    cache_clear()


@contextlib.contextmanager
def iam_definition_context(catalog: dict[str, Any]) -> Iterator[None]:
    """Temporarily point every catalog consumer at *catalog*."""
    original_values: list[tuple[Any, Any]] = []
    try:
        for module in _PATCHED_CATALOG_MODULES:
            original_values.append((module, module.iam_definition))
            module.iam_definition = catalog
        _clear_module_caches()
        yield
    finally:
        for module, value in reversed(original_values):
            module.iam_definition = value
        _clear_module_caches()


def condition_map_from_block(
    condition_block: dict[str, Any],
) -> dict[str, dict[str, str]]:
    """Convert the Policy Sentry condition-block shape to IAM Condition JSON."""
    return {
        condition_block["condition_type_string"]: {
            condition_block["condition_key_string"]: condition_block["condition_value"]
        }
    }


def _condition_is_enforced(
    actual_condition: Any,
    expected_condition: dict[str, dict[str, str]],
) -> bool:
    if not isinstance(actual_condition, dict):
        return False
    for operator, expected_entries in expected_condition.items():
        actual_entries = actual_condition.get(operator)
        if not isinstance(actual_entries, dict):
            return False
        for key, expected_value in expected_entries.items():
            if actual_entries.get(key) != expected_value:
                return False
    return True


def _raw_arn_candidates(resource: str) -> list[str]:
    if resource == "*":
        return ["*"]
    if get_resource_type_name_with_raw_arn(resource):
        return [resource]
    return get_matching_raw_arns(resource)


def _assess_action_raw_arn(
    action: str,
    resource: str,
    raw_arn: str,
    requested_condition_key: str,
) -> dict[str, Any]:
    service_prefix, action_name = action.split(":", 1)
    service_data = iam_data.get_service_prefix_data(service_prefix)

    assessment: dict[str, Any] = {
        "action": action,
        "resource": resource,
        "raw_arn": raw_arn if raw_arn != "*" else None,
        "resource_type": None,
        "documented_condition_keys": [],
        "resource_condition_keys": [],
        "raw_arn_condition_keys": [],
        "matching_condition_keys": [],
        "support_status": "unverifiable",
        "reason_code": "catalog_entry_missing",
        "reason": "",
    }

    if not service_data:
        assessment["reason_code"] = "service_missing"
        assessment["reason"] = f"The catalog has no service prefix {service_prefix!r}."
        return assessment

    canonical_action = service_data.get("privileges_lower_name", {}).get(
        action_name.lower()
    )
    privilege = (
        service_data.get("privileges", {}).get(canonical_action)
        if canonical_action
        else None
    )
    if not isinstance(privilege, dict):
        assessment["reason_code"] = "action_missing"
        assessment["reason"] = f"The catalog has no action {action!r}."
        return assessment

    resource_type: str | None = None
    resource_data: dict[str, Any] | None = None
    action_resource_entry: dict[str, Any] | None = None
    missing_records: list[str] = []

    if raw_arn == "*":
        wildcard_entry = privilege.get("resource_types", {}).get("")
        if wildcard_entry is None:
            missing_records.append("action.wildcard_resource_type")
    else:
        resource_type = get_resource_type_name_with_raw_arn(raw_arn)
        assessment["resource_type"] = resource_type
        if resource_type is None:
            missing_records.append("raw_arn_resource_name")
        else:
            resource_data = service_data.get("resources", {}).get(resource_type)
            if not isinstance(resource_data, dict):
                missing_records.append(f"resources.{resource_type}")
            else:
                assessment["resource_condition_keys"] = list(
                    resource_data.get("condition_keys", [])
                )
                if "condition_keys" not in resource_data:
                    missing_records.append(f"resources.{resource_type}.condition_keys")
            action_resource_entry = privilege.get("resource_types", {}).get(
                resource_type
            )
            if action_resource_entry is None:
                missing_records.append(
                    f"privileges.{action_name}.resource_types.{resource_type}"
                )

    action_condition_keys = get_conditions_for_action_and_raw_arn(action, raw_arn)
    assessment["documented_condition_keys"] = action_condition_keys
    raw_arn_keys_error: str | None = None
    if raw_arn != "*":
        try:
            assessment["raw_arn_condition_keys"] = (
                get_condition_keys_available_to_raw_arn(raw_arn)
            )
        except (KeyError, TypeError) as exc:
            raw_arn_keys_error = f"{type(exc).__name__}: {exc}"
            assessment["raw_arn_condition_keys_error"] = raw_arn_keys_error
    matching_keys = [
        documented_key
        for documented_key in action_condition_keys
        if is_condition_key_match(documented_key, requested_condition_key)
    ]
    raw_arn_matching_keys = [
        documented_key
        for documented_key in assessment["raw_arn_condition_keys"]
        if is_condition_key_match(documented_key, requested_condition_key)
    ]
    for documented_key in raw_arn_matching_keys:
        if documented_key not in matching_keys:
            matching_keys.append(documented_key)
    assessment["matching_condition_keys"] = matching_keys

    if matching_keys:
        assessment["support_status"] = "supported"
        assessment["reason_code"] = "condition_supported"
        assessment["reason"] = (
            "The action/resource catalog record lists a matching condition key."
        )
    elif missing_records or raw_arn_keys_error:
        if not missing_records and raw_arn_keys_error:
            missing_records.append("raw_arn_condition_keys")
            assessment["missing_records"] = missing_records
        field_only_missing = missing_records == [
            f"resources.{resource_type}.condition_keys"
        ]
        assessment["reason_code"] = (
            "catalog_condition_field_missing"
            if field_only_missing
            else "catalog_record_missing"
        )
        assessment["missing_records"] = missing_records
        assessment["reason"] = (
            "The old catalog is incomplete ("
            + ", ".join(missing_records)
            + "); support cannot be verified from the catalog."
        )
    else:
        assessment["support_status"] = "known_unsupported"
        assessment["reason_code"] = "catalog_reports_unsupported"
        assessment["reason"] = (
            "The catalog record is complete but does not list the requested condition key."
        )

    return assessment


def _statement_pair_assessments(
    policy: dict[str, Any],
    requested_condition_key: str,
) -> list[dict[str, Any]]:
    assessments: list[dict[str, Any]] = []
    for statement_index, statement in enumerate(policy.get("Statement", [])):
        action_value = statement.get("Action", [])
        actions = [action_value] if isinstance(action_value, str) else list(action_value)
        resource_value = statement.get("Resource", [])
        resources = (
            [resource_value] if isinstance(resource_value, str) else list(resource_value)
        )
        for single_action in actions:
            for resource in resources:
                raw_arns = _raw_arn_candidates(resource)
                if not raw_arns:
                    raw_arns = [resource]
                for raw_arn in raw_arns:
                    assessment = _assess_action_raw_arn(
                        single_action,
                        resource,
                        raw_arn,
                        requested_condition_key,
                    )
                    assessment.update(
                        {
                            "statement_index": statement_index,
                            "sid": statement.get("Sid"),
                            "effect": statement.get("Effect"),
                        }
                    )
                    assessments.append(assessment)
    return assessments


def _add_conditions_to_supported_statements(
    policy: dict[str, Any],
    assessments: list[dict[str, Any]],
    expected_condition: dict[str, dict[str, str]],
) -> dict[str, Any]:
    governed_policy = copy.deepcopy(policy)
    statements_with_assessments = {
        assessment["statement_index"] for assessment in assessments
    }

    for statement_index, statement in enumerate(governed_policy.get("Statement", [])):
        if statement_index not in statements_with_assessments:
            continue
        statement_assessments = [
            a for a in assessments if a["statement_index"] == statement_index
        ]
        all_supported = all(
            a["support_status"] == "supported" for a in statement_assessments
        )
        if all_supported and statement.get("Effect", "Allow") == "Allow":
            condition = statement.setdefault("Condition", {})
            for operator, entries in expected_condition.items():
                condition.setdefault(operator, {})
                condition[operator].update(entries)
    return governed_policy


def _required_evidence_instruction(item: dict[str, Any]) -> str:
    resource_label = (
        item.get("resource_type") or item.get("raw_arn") or item.get("resource")
    )
    if item["support_status"] == "known_unsupported":
        return (
            f"审批人必须为 {item['action']} 在资源 {resource_label} 上的使用提供补偿控制证据或明确风险接受；"
            f"目录已表明该资源不支持条件键 {item.get('condition_key_string', 'the requested condition key')}。"
        )
    return (
        f"审批人必须补充 {item['action']} 在资源 {resource_label} 上的目录缺项/资源证据，"
        f"确认条件键 {item.get('condition_key_string', 'the requested condition key')} 是否可落实；"
        "当前旧目录资料不足，无法验证支持状态。"
    )


def _render_governed_policy(
    base_policy: dict[str, Any],
    assessments: list[dict[str, Any]],
    expected_condition: dict[str, dict[str, str]],
    sid_group: SidGroup | None,
    minimize: int | None,
) -> tuple[dict[str, Any], str]:
    eligible_indexes = {
        statement_index
        for statement_index in {a["statement_index"] for a in assessments}
        if all(
            a["support_status"] == "supported"
            for a in assessments
            if a["statement_index"] == statement_index
        )
        and base_policy["Statement"][statement_index].get("Effect", "Allow") == "Allow"
    }

    if sid_group is not None and minimize is None:
        for statement_index in eligible_indexes:
            sid = base_policy["Statement"][statement_index].get("Sid")
            if sid and sid in sid_group.sids:
                sid_group.sids[sid]["condition"] = expected_condition
        effect = "Allow"
        if base_policy.get("Statement"):
            effect = base_policy["Statement"][0].get("Effect", "Allow")
        native_policy = sid_group.get_rendered_policy(None, effect=effect)
        native_sids = [
            statement.get("Sid") for statement in native_policy.get("Statement", [])
        ]
        base_sids = [
            statement.get("Sid") for statement in base_policy.get("Statement", [])
        ]
        if native_sids == base_sids:
            return native_policy, "SidGroup.get_rendered_policy"

    return (
        _add_conditions_to_supported_statements(
            base_policy, assessments, expected_condition
        ),
        "evidence_postprocessor",
    )


def _build_report_within_context(
    base_policy: dict[str, Any],
    condition_block: dict[str, Any],
    *,
    catalog_source: str,
    overlay_source: str | None,
    template: dict[str, Any] | None,
    sid_group: SidGroup | None = None,
    minimize: int | None = None,
) -> dict[str, Any]:
    if not validate_condition_block(condition_block):
        raise ValueError(
            "condition_block does not match Policy Sentry's condition-block schema"
        )

    expected_condition = condition_map_from_block(condition_block)
    requested_key = condition_block["condition_key_string"]
    pre_assessments = _statement_pair_assessments(base_policy, requested_key)
    rendered_policy, condition_compiler = _render_governed_policy(
        base_policy,
        pre_assessments,
        expected_condition,
        sid_group,
        minimize,
    )

    items: list[dict[str, Any]] = []
    for assessment in pre_assessments:
        statement = rendered_policy["Statement"][assessment["statement_index"]]
        enforced = _condition_is_enforced(
            statement.get("Condition"), expected_condition
        )
        item = copy.deepcopy(assessment)
        item["condition_key_string"] = requested_key
        item["expected_condition"] = expected_condition
        item["actual_statement_condition"] = statement.get("Condition")
        item["condition_enforced"] = enforced

        if assessment["support_status"] == "supported" and enforced:
            item["status"] = "covered"
            item["publishable"] = True
        elif assessment["support_status"] == "supported":
            item["status"] = "supported_not_enforced"
            item["publishable"] = False
        elif assessment["support_status"] == "known_unsupported":
            item["status"] = "catalog_unsupported_uncovered"
            item["publishable"] = False
        else:
            item["status"] = "unverifiable_uncovered"
            item["publishable"] = False

        if not item["publishable"]:
            item["required_evidence"] = _required_evidence_instruction(item)
        else:
            item["required_evidence"] = None
        items.append(item)

    publishable = bool(items) and all(item["publishable"] for item in items)
    required_evidence = [
        {
            "statement_index": item["statement_index"],
            "sid": item["sid"],
            "action": item["action"],
            "resource": item["resource"],
            "raw_arn": item["raw_arn"],
            "resource_type": item["resource_type"],
            "support_status": item["support_status"],
            "status": item["status"],
            "reason_code": item["reason_code"],
            "required_evidence": item["required_evidence"],
        }
        for item in items
        if not item["publishable"]
    ]

    summary = {
        "statements": len(base_policy.get("Statement", [])),
        "resource_checks": len(items),
        "covered": sum(item["status"] == "covered" for item in items),
        "known_unsupported": sum(
            item["support_status"] == "known_unsupported" for item in items
        ),
        "unverifiable": sum(item["support_status"] == "unverifiable" for item in items),
        "not_enforced": sum(
            item["status"] == "supported_not_enforced" for item in items
        ),
        "blocked": sum(not item["publishable"] for item in items),
    }

    return {
        "schema_version": CONDITION_EVIDENCE_VERSION,
        "condition_compiler": condition_compiler,
        "request": {
            "template": template,
            "condition_block": condition_block,
            "condition": expected_condition,
        },
        "catalog": {
            "source": catalog_source,
            "overlay": overlay_source,
        },
        "summary": summary,
        "publishable": publishable,
        "release_status": "publishable" if publishable else "blocked_needs_evidence",
        "gate": {
            "passed": publishable,
            "unresolved_checks": summary["blocked"],
            "required_evidence_count": len(required_evidence),
        },
        "required_evidence": required_evidence,
        "items": items,
        "base_policy": base_policy,
        "rendered_policy": rendered_policy,
        "publishable_policy": rendered_policy if publishable else None,
    }


def build_condition_evidence_report(
    policy: dict[str, Any],
    condition_block: dict[str, Any],
    *,
    catalog: dict[str, Any] | str | Path | None = None,
    overlay: dict[str, Any] | str | Path | None = None,
    template: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Attach condition evidence to an already rendered Policy Sentry policy."""
    catalog_source = (
        str(catalog)
        if catalog is not None
        else "bundled:policy_sentry/shared/data/iam-definition.json"
    )
    overlay_source = str(overlay) if isinstance(overlay, (str, Path)) else None
    prepared_catalog = prepare_catalog(catalog, overlay)
    with iam_definition_context(prepared_catalog):
        return _build_report_within_context(
            policy,
            condition_block,
            catalog_source=catalog_source,
            overlay_source=overlay_source,
            template=template,
        )


def generate_condition_evidence(
    template: dict[str, Any],
    condition_block: dict[str, Any],
    *,
    catalog: dict[str, Any] | str | Path | None = None,
    overlay: dict[str, Any] | str | Path | None = None,
    minimize: int | None = None,
) -> dict[str, Any]:
    """Generate a policy and its condition evidence in one catalog context."""
    catalog_source = (
        str(catalog)
        if catalog is not None
        else "bundled:policy_sentry/shared/data/iam-definition.json"
    )
    overlay_source = str(overlay) if isinstance(overlay, (str, Path)) else None
    prepared_catalog = prepare_catalog(catalog, overlay)
    if not validate_condition_block(condition_block):
        raise ValueError(
            "condition_block does not match Policy Sentry's condition-block schema"
        )

    with iam_definition_context(prepared_catalog):
        sid_group = SidGroup()
        base_policy = sid_group.process_template(template, minimize)
        return _build_report_within_context(
            base_policy,
            condition_block,
            catalog_source=catalog_source,
            overlay_source=overlay_source,
            template=template,
            sid_group=sid_group,
            minimize=minimize,
        )


def render_condition_evidence_markdown(report: dict[str, Any]) -> str:
    """Render an approver-facing checklist that points at exact statements."""
    status_labels = {
        "covered": "已受控",
        "catalog_unsupported_uncovered": "目录表明不支持",
        "unverifiable_uncovered": "目录缺项，无法验证",
        "supported_not_enforced": "目录支持但语句未落实条件",
    }
    release_label = "可发布" if report["publishable"] else "阻断：需审批人补证"
    lines = [
        "# 条件落实证据",
        "",
        f"- 发布状态：`{report['release_status']}`（{release_label}）",
        f"- 语句数：{report['summary']['statements']}",
        f"- 资源核对项：{report['summary']['resource_checks']}",
        f"- 已覆盖：{report['summary']['covered']}",
        f"- 目录已知不支持：{report['summary']['known_unsupported']}",
        f"- 无法验证：{report['summary']['unverifiable']}",
        f"- 待补证：{report['summary']['blocked']}",
        f"- 条件：`{report['request']['condition_block']['condition_type_string']}` "
        f"`{report['request']['condition_block']['condition_key_string']}` = "
        f"`{report['request']['condition_block']['condition_value']}`",
        "",
        "## 逐项对照",
        "",
        "| 语句# | Sid | 动作 | 资源类型 / ARN | 目录结论 | 实际 Condition | 状态 |",
        "|---:|---|---|---|---|---|---|",
    ]
    for item in report["items"]:
        resource_label = item.get("resource_type") or "（无资源类型）"
        if item.get("raw_arn"):
            resource_label += f"<br>`{item['raw_arn']}`"
        actual_condition = "无"
        if item.get("actual_statement_condition"):
            actual_condition = (
                "`"
                + json.dumps(item["actual_statement_condition"], ensure_ascii=False)
                + "`"
            )
        catalog_label = {
            "supported": "支持",
            "known_unsupported": "已知不支持",
            "unverifiable": "缺项/无法验证",
        }[item["support_status"]]
        lines.append(
            f"| {item['statement_index']} | `{item['sid']}` | `{item['action']}` | {resource_label} | "
            f"{catalog_label}<br>`{item['reason_code']}` | {actual_condition} | "
            f"{status_labels.get(item['status'], item['status'])} |"
        )

    lines.extend(["", "## 必须补证的资源", ""])
    if not report["required_evidence"]:
        lines.append(
            "无；所有实际输出语句均已落实请求条件，`publishable_policy` 可发布。"
        )
    else:
        for evidence in report["required_evidence"]:
            lines.append(
                f"- 语句 #{evidence['statement_index']} `{evidence['sid']}` / "
                f"`{evidence['resource_type'] or evidence['raw_arn'] or evidence['resource']}`："
                f"{evidence['required_evidence']}"
            )

    lines.extend(["", "## 真实输出语句", ""])
    for index, statement in enumerate(report["rendered_policy"]["Statement"]):
        lines.extend(
            [
                f"### Statement {index}: `{statement.get('Sid')}`",
                "",
                "```json",
                json.dumps(statement, indent=2, ensure_ascii=False),
                "```",
                "",
            ]
        )
    return "\n".join(lines)
