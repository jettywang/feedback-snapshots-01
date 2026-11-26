# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

# pylint: disable=protected-access

import pytest
from unittest.mock import Mock

from opentelemetry.sdk._logs.export import BatchLogRecordProcessor
from opentelemetry.sdk.environment_variables import (
    OTEL_BLRP_FAIR_QUOTAS,
    OTEL_BSP_FAIR_QUOTAS,
)
from opentelemetry.sdk.environment_variables._internal import (
    parse_fair_quotas_environment_variable,
)
from opentelemetry.sdk.trace.export import BatchSpanProcessor


@pytest.mark.parametrize(
    "env_var",
    [OTEL_BSP_FAIR_QUOTAS, OTEL_BLRP_FAIR_QUOTAS],
)
class TestFairQuotaEnvParsing:
    def test_unset_returns_none(self, env_var, monkeypatch):
        monkeypatch.delenv(env_var, raising=False)
        assert parse_fair_quotas_environment_variable(env_var) is None

    def test_valid_json_object(self, env_var, monkeypatch):
        monkeypatch.setenv(env_var, '{"auth": 256, "checkout": 128}')
        assert parse_fair_quotas_environment_variable(env_var) == {"auth": 256, "checkout": 128}

    @pytest.mark.parametrize(
        "raw_value",
        ["not-json", "[]", '{"auth": -1}', '{"auth": 1.5}', '{"auth": true}', '{"auth": "4"}'],
    )
    def test_invalid_values_are_ignored(self, env_var, monkeypatch, raw_value):
        monkeypatch.setenv(env_var, raw_value)
        assert parse_fair_quotas_environment_variable(env_var) is None


@pytest.mark.parametrize(
    "processor_class,env_var",
    [
        (BatchSpanProcessor, OTEL_BSP_FAIR_QUOTAS),
        (BatchLogRecordProcessor, OTEL_BLRP_FAIR_QUOTAS),
    ],
)
class TestFairQuotaProcessorConfiguration:
    def test_quotas_are_read_from_the_environment(self, processor_class, env_var, monkeypatch):
        monkeypatch.setenv(env_var, '{"auth": 4}')
        processor = processor_class(Mock(), max_queue_size=12, max_export_batch_size=4)

        gate = processor._batch_processor._fair_quota_gate
        assert gate is not None
        assert gate.fair_quotas == {"auth": 4}
        processor.shutdown()

    def test_quotas_larger_than_the_queue_are_rejected(self, processor_class, env_var, monkeypatch):
        monkeypatch.delenv(env_var, raising=False)
        with pytest.raises(ValueError, match="must not exceed max_queue_size"):
            processor_class(Mock(), max_queue_size=12, max_export_batch_size=4, fair_quotas={"auth": 13})

    def test_no_quotas_keeps_the_legacy_queue_path(self, processor_class, env_var, monkeypatch):
        monkeypatch.delenv(env_var, raising=False)
        processor = processor_class(Mock(), max_queue_size=12, max_export_batch_size=4)

        assert processor._batch_processor._fair_quota_gate is None
        assert processor.source_occupancy() == {}
        assert processor.dropped_summary() == {}
        assert processor.drop_records() == ()
        processor.shutdown()

    def test_custom_source_key_extractor_enables_the_gate(self, processor_class, env_var, monkeypatch):
        monkeypatch.delenv(env_var, raising=False)
        processor = processor_class(
            Mock(),
            max_queue_size=12,
            max_export_batch_size=4,
            source_key_extractor=lambda item: "custom",
        )

        gate = processor._batch_processor._fair_quota_gate
        assert gate is not None
        assert gate.fair_quotas == {}
        processor.shutdown()
