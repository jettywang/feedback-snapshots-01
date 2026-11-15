from __future__ import annotations

import gzip
import json
from io import BytesIO
from pathlib import Path
from typing import Any

from dissect.regf.regf import KeyNode, KeyValue, RegistryHive
from dissect.regf.services import analyze_hive, main
from tests.hive_builder import make_system_hive

CS1_SERVICES: list[dict[str, Any]] = [
    {
        "name": "EvilSvc",
        "start": 2,
        "type": 0x10,
        "image_path": "C:\\Program Files\\Evil Corp\\evil.exe /silent",
    },
    {
        "name": "SharedSvc",
        "start": 2,
        "type": 0x20,
        "image_path": "%SystemRoot%\\System32\\svchost.exe -k netsvcs",
        "service_dll": "%SystemRoot%\\System32\\sharedsvc.dll",
    },
    {
        "name": "QuotedSvc",
        "start": 3,
        "type": 0x10,
        "image_path": '"C:\\Tools\\Quoted Svc\\tool.exe" -x',
    },
]

CS2_SERVICES: list[dict[str, Any]] = [
    {
        "name": "OtherSvc",
        "start": 4,
        "type": 0x10,
        "image_path": "C:\\Windows\\System32\\other.exe",
    },
]


def build_hive(**kwargs: Any) -> bytes:
    kwargs.setdefault("control_sets", {1: CS1_SERVICES, 2: CS2_SERVICES})
    return make_system_hive(**kwargs)


def services_by_name(report: Any) -> dict[str, Any]:
    return {service.name: service for service in report.services}


def test_select_current_determines_control_set() -> None:
    report = analyze_hive(BytesIO(build_hive(current=1, default=1, last_known_good=2)))

    selection = report.control_set_selection
    assert selection.selected == "ControlSet001"
    assert "Current" in selection.reason
    assert selection.selected_key_cell_offset is not None

    names = services_by_name(report)
    assert set(names) == {"EvilSvc", "SharedSvc", "QuotedSvc"}
    assert names["EvilSvc"].start_meaning == "automatic"


def test_select_switch_changes_results() -> None:
    report = analyze_hive(BytesIO(build_hive(current=2, default=1, last_known_good=1)))

    selection = report.control_set_selection
    assert selection.selected == "ControlSet002"

    names = services_by_name(report)
    assert set(names) == {"OtherSvc"}
    assert names["OtherSvc"].start_meaning == "disabled"


def test_conflicting_select_pointers_are_preserved() -> None:
    report = analyze_hive(BytesIO(build_hive(current=2, default=1, last_known_good=1)))

    selection = report.control_set_selection
    assert selection.selected == "ControlSet002"
    assert {pointer.source for pointer in selection.pointers} == {"Current", "Default", "LastKnownGood"}
    assert all(pointer.exists_in_hive for pointer in selection.pointers)
    assert any("disagree" in uncertainty for uncertainty in report.uncertainties)


def test_pointer_to_missing_control_set_keeps_uncertainty() -> None:
    report = analyze_hive(BytesIO(build_hive(current=3, default=1, last_known_good=1)))

    selection = report.control_set_selection
    assert selection.selected == "ControlSet001"
    assert "Default" in selection.reason
    assert any("ControlSet003" in uncertainty for uncertainty in report.uncertainties)

    current_pointer = next(pointer for pointer in selection.pointers if pointer.source == "Current")
    assert current_pointer.control_set == "ControlSet003"
    assert not current_pointer.exists_in_hive


def test_unresolvable_select_never_assumes_control_set_001() -> None:
    report = analyze_hive(BytesIO(build_hive(current=3, default=None, last_known_good=None)))

    assert report.control_set_selection.selected is None
    assert report.services == []
    assert any("not assuming ControlSet001" in uncertainty for uncertainty in report.uncertainties)


def test_missing_select_key_keeps_uncertainty() -> None:
    report = analyze_hive(BytesIO(build_hive(include_select=False)))

    assert report.control_set_selection.selected is None
    assert report.services == []
    assert report.control_set_selection.available_control_sets.keys() == {"ControlSet001", "ControlSet002"}
    assert any("Select key not found" in uncertainty for uncertainty in report.uncertainties)


def test_image_path_environment_variables_preserved() -> None:
    report = analyze_hive(BytesIO(build_hive()))
    image_path = services_by_name(report)["SharedSvc"].image_path

    assert image_path.raw == "%SystemRoot%\\System32\\svchost.exe -k netsvcs"
    assert image_path.env_vars == ["SystemRoot"]
    assert image_path.shared_process_host
    assert image_path.executable == "%SystemRoot%\\System32\\svchost.exe"
    assert image_path.arguments == "-k netsvcs"
    assert not image_path.unquoted_with_spaces
    assert any("unexpanded" in note for note in image_path.notes)


def test_image_path_unquoted_with_spaces_lists_candidates() -> None:
    report = analyze_hive(BytesIO(build_hive()))
    image_path = services_by_name(report)["EvilSvc"].image_path

    assert image_path.raw == "C:\\Program Files\\Evil Corp\\evil.exe /silent"
    assert image_path.unquoted_with_spaces
    assert not image_path.quoted
    assert {
        "executable": "C:\\Program Files\\Evil Corp\\evil.exe",
        "arguments": "/silent",
    } in image_path.candidate_interpretations
    assert {
        "executable": "C:\\Program",
        "arguments": "Files\\Evil Corp\\evil.exe /silent",
    } in image_path.candidate_interpretations


def test_image_path_quoted_is_parsed() -> None:
    report = analyze_hive(BytesIO(build_hive()))
    image_path = services_by_name(report)["QuotedSvc"].image_path

    assert image_path.quoted
    assert image_path.executable == "C:\\Tools\\Quoted Svc\\tool.exe"
    assert image_path.arguments == "-x"
    assert not image_path.unquoted_with_spaces


def test_shared_process_service_dll_is_correlated() -> None:
    report = analyze_hive(BytesIO(build_hive()))
    service = services_by_name(report)["SharedSvc"]

    assert service.image_path.shared_process_host
    assert "share-process" in service.service_type_flags
    assert service.service_dll is not None
    assert service.service_dll.value == "%SystemRoot%\\System32\\sharedsvc.dll"
    assert service.service_dll.reg_type == "REG_EXPAND_SZ"
    assert service.parameters_key_cell_offset is not None
    assert any("ServiceDll" in note for note in service.notes)


def test_report_offsets_resolve_to_source_cells() -> None:
    hive_bytes = build_hive()
    report = analyze_hive(BytesIO(hive_bytes))
    hive = RegistryHive(BytesIO(hive_bytes))

    walked_offsets = {offset - 0x1000 for offset, allocated, _ in hive.walk() if allocated}

    key_offsets = [report.control_set_selection.select_key_cell_offset]
    key_offsets += [report.control_set_selection.selected_key_cell_offset]
    key_offsets += list(report.control_set_selection.available_control_sets.values())
    value_offsets = [pointer.value_cell_offset for pointer in report.control_set_selection.pointers]

    for service in report.services:
        key_offsets.append(service.key_cell_offset)
        if service.parameters_key_cell_offset is not None:
            key_offsets.append(service.parameters_key_cell_offset)
        for evidence in (service.start, service.service_type, service.service_dll):
            if evidence is not None:
                value_offsets.append(evidence.cell_offset)
        if service.image_path is not None:
            value_offsets.append(service.image_path.value_cell_offset)

    for offset in key_offsets + value_offsets:
        assert offset is not None
        assert offset in walked_offsets

    for service in report.services:
        node = hive.cell(service.key_cell_offset)
        assert isinstance(node, KeyNode)
        assert node.name == service.name

        if service.service_dll is not None:
            dll_cell = hive.cell(service.service_dll.cell_offset)
            assert isinstance(dll_cell, KeyValue)
            assert dll_cell.name == "ServiceDll"
            parameters = hive.cell(service.parameters_key_cell_offset)
            assert isinstance(parameters, KeyNode)
            assert parameters.name == "Parameters"

    for pointer in report.control_set_selection.pointers:
        pointer_cell = hive.cell(pointer.value_cell_offset)
        assert isinstance(pointer_cell, KeyValue)
        assert pointer_cell.name == pointer.source
        assert pointer_cell.value == pointer.value


def test_report_does_not_claim_execution() -> None:
    report = analyze_hive(BytesIO(build_hive()))

    assert any("not evidence that the service ever executed" in limitation for limitation in report.limitations)
    assert any("filesystem" in limitation for limitation in report.limitations)
    for service in report.services:
        for note in service.notes:
            assert "executed" not in note or "not evidence" in note


def test_real_system_hive(system_hive: Any) -> None:
    report = analyze_hive(system_hive)

    selection = report.control_set_selection
    assert selection.selected == "ControlSet001"
    assert selection.reason.startswith("Select\\Current is 1")
    assert report.uncertainties == []
    assert len(report.services) == 701

    tcpip = services_by_name(report)["Tcpip"]
    assert tcpip.parameters_key_cell_offset is not None
    assert tcpip.start is not None


def test_real_system_hive_offsets_verify(system_hive: Any) -> None:
    report = analyze_hive(system_hive)

    with gzip.GzipFile(Path(__file__).parent / "_data" / "SYSTEM.gz", "rb") as fh:
        hive = RegistryHive(fh)
        service = next(service for service in report.services if service.start is not None)
        node = hive.cell(service.key_cell_offset)
        assert isinstance(node, KeyNode)
        assert node.name == service.name
        start_cell = hive.cell(service.start.cell_offset)
        assert isinstance(start_cell, KeyValue)
        assert start_cell.name == "Start"


def test_cli_outputs_json(tmp_path: Path, capsys: Any) -> None:
    hive_path = tmp_path / "SYSTEM"
    hive_path.write_bytes(build_hive(current=2, default=1, last_known_good=1))

    assert main([str(hive_path)]) == 0
    output = json.loads(capsys.readouterr().out)

    assert output["control_set_selection"]["selected"] == "ControlSet002"
    assert [service["name"] for service in output["services"]] == ["OtherSvc"]
    assert output["services"][0]["key_cell_offset"] is not None
