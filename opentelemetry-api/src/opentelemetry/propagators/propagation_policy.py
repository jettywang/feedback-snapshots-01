# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

"""Compatibility module for propagation policy imports."""

from opentelemetry.propagators.policy import *  # noqa: F403
from opentelemetry.propagators.policy import __all__ as _policy_all

__all__ = _policy_all
