"""Tests for the executable extension-governance sample."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

from compat import admit_new, ingest_attributes  # noqa: E402
from matrix import CATALOGUE, assert_contract, build_rows  # noqa: E402
from policy import ExtensionStatus, Mode  # noqa: E402


def test_matrix_contract_is_stable() -> None:
    assert_contract(build_rows(Mode.ENFORCE))


def test_uppercase_is_invalid_syntax_but_hyphen_is_legacy() -> None:
    upper = CATALOGUE.evaluate(
        "LegacyTraceId", "v", "1.0", binding="HTTP structured", stage="produce"
    )
    hyphen = CATALOGUE.evaluate(
        "legacy-trace-id", "v", "1.0", binding="HTTP structured", stage="produce"
    )
    assert upper.status is ExtensionStatus.INVALID_SYNTAX
    assert upper.record_kind == "invalid-syntax"
    assert hyphen.status is ExtensionStatus.LEGACY_QUARANTINED
    assert hyphen.record_kind == "legacy-extension"
    assert hyphen.canonical_name == "legacytraceid"


def test_version_owned_attribute_is_not_a_custom_extension() -> None:
    decision = CATALOGUE.evaluate(
        "schemaurl",
        "https://schema.example",
        "1.0",
        binding="HTTP structured",
        stage="produce",
    )
    assert decision.status is ExtensionStatus.VERSION_MISMATCH
    assert decision.record_kind == "version"
    assert decision.canonical_name == "dataschema"


def test_unknown_extension_has_separate_record() -> None:
    decision = CATALOGUE.evaluate(
        "futuretraceid", "v", "1.0", binding="HTTP structured", stage="produce"
    )
    assert decision.status is ExtensionStatus.UNKNOWN
    assert decision.record_kind == "unknown-extension"


def test_shadow_mode_observes_without_rejecting() -> None:
    shadow = CATALOGUE.evaluate(
        "LegacyTraceId",
        "v",
        "1.0",
        binding="HTTP structured",
        stage="produce",
        mode=Mode.SHADOW,
    )
    enforce = CATALOGUE.evaluate(
        "LegacyTraceId",
        "v",
        "1.0",
        binding="HTTP structured",
        stage="produce",
        mode=Mode.ENFORCE,
    )
    assert shadow.accepted is True
    assert shadow.would_accept is False
    assert enforce.accepted is False


def test_observe_mode_keeps_would_accept_for_comparison() -> None:
    observe = CATALOGUE.evaluate(
        "futuretraceid",
        "v",
        "1.0",
        binding="HTTP structured",
        stage="produce",
        mode=Mode.OBSERVE,
    )
    assert observe.accepted is True
    assert observe.would_accept is False


def test_int_extension_drifts_on_binary_bindings() -> None:
    decision = CATALOGUE.evaluate(
        "attemptcount",
        "3",  # binary/header form
        "1.0",
        binding="HTTP binary",
        stage="produce",
    )
    assert decision.status is ExtensionStatus.TYPE_DRIFT
    assert decision.record_kind == "type-drift"


def test_ingest_rewrites_legacy_name_and_keeps_sidecar() -> None:
    result = ingest_attributes(
        {
            "id": "1",
            "source": "/p",
            "type": "t",
            "specversion": "1.0",
            "time": "2020-01-01T00:00:00Z",
            "legacy-trace-id": "trace-abc",
        },
        "1.0",
        binding="HTTP structured",
        catalogue=CATALOGUE,
    )
    assert result.attributes["legacytraceid"] == "trace-abc"
    assert result.records_by_kind()["legacy-extension"][0].canonical_name == "legacytraceid"


def test_admit_new_drops_unknown_when_enforced() -> None:
    accepted, decisions = admit_new(
        {"id": "1", "source": "/p", "type": "t", "specversion": "1.0", "futurex": "v"},
        "1.0",
        binding="HTTP structured",
        catalogue=CATALOGUE,
        mode=Mode.ENFORCE,
    )
    assert "futurex" not in accepted
    assert decisions[0].record_kind == "unknown-extension"
    assert decisions[0].accepted is False
