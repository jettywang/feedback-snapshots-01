# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

import json
from logging import getLogger
from os import environ
from typing import Any

_logger = getLogger(__name__)


def parse_boolean_environment_variable(environment_variable: str, default: bool = False) -> bool:
    value = environ.get(environment_variable)
    if value is None:
        return default

    match value.strip().lower():
        case "true":
            return True
        case "false":
            return False
        case _:
            _logger.warning(
                "Invalid value for %s: %r. Expected 'true' or 'false'.",
                environment_variable,
                value,
            )
            return default


def parse_fair_quotas_environment_variable(environment_variable: str) -> dict[str, int] | None:
    """Parses a JSON object of ``{source: queue slots}`` from an environment variable."""
    value = environ.get(environment_variable)
    if value is None:
        return None
    try:
        parsed: Any = json.loads(value)
    except (json.JSONDecodeError, TypeError):
        _logger.warning(
            "Invalid value for %s: %r. Expected a JSON object of non-negative integer quotas.",
            environment_variable,
            value,
        )
        return None
    if not isinstance(parsed, dict) or any(
        not isinstance(quota, int) or isinstance(quota, bool) or quota < 0
        for quota in parsed.values()
    ):
        _logger.warning(
            "Invalid value for %s: %r. Expected a JSON object of non-negative integer quotas.",
            environment_variable,
            value,
        )
        return None
    return {str(source): quota for source, quota in parsed.items()}
