# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

"""Compatibility module for destination policy imports."""

from opentelemetry.propagators.destination import *  # noqa: F403
from opentelemetry.propagators.destination import __all__ as _destination_all

__all__ = _destination_all
