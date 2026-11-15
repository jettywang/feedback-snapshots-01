"""Structured analysis of service persistence configuration in an offline Windows SYSTEM hive.

The analysis is evidence based: the control set used for service enumeration is
selected from the actual content of the ``Select`` key, never assumed, and
conflicting or dangling ``Select`` pointers are reported as uncertainty instead
of being silently resolved. Every reported key and value is accompanied by its
cell offset (HCELL_INDEX) so each persistence candidate can be traced back to
its source cell in the hive.

Presence of a service configuration is not evidence that the service ever
executed, and no path is ever checked against the local filesystem: all
findings are derived exclusively from the bytes of the analysed hive.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, BinaryIO

from dissect.regf.exceptions import RegistryKeyNotFoundError, RegistryValueNotFoundError
from dissect.regf.regf import RegistryHive

if TYPE_CHECKING:
    from dissect.regf.regf import KeyNode, KeyValue

CONTROL_SET_RE = re.compile(r"^ControlSet(\d{3})$")
ENV_VAR_RE = re.compile(r"%([^%]+)%")
SVCHOST_RE = re.compile(r"\bsvchost\.exe\b", re.IGNORECASE)
SVCHOST_GROUP_RE = re.compile(r"-k\s+(?P<group>\S+)", re.IGNORECASE)
EXECUTABLE_SUFFIX_RE = re.compile(r"\.(exe|sys|dll|com|scr|bat|cmd)$", re.IGNORECASE)

SELECT_POINTERS = ("Current", "Default", "LastKnownGood")

START_MEANINGS = {
    0: "boot",
    1: "system",
    2: "automatic",
    3: "manual",
    4: "disabled",
}

SERVICE_TYPE_FLAGS = (
    (0x0001, "kernel-driver"),
    (0x0002, "file-system-driver"),
    (0x0004, "adapter"),
    (0x0008, "recognizer-driver"),
    (0x0010, "own-process"),
    (0x0020, "share-process"),
    (0x0100, "interactive"),
    (0x0200, "user-mode"),
)

REG_TYPE_NAMES = {
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

LIMITATIONS = [
    "Presence of a service configuration is not evidence that the service ever executed; "
    "this report describes configuration only.",
    "No path was checked against any filesystem; all findings come solely from the analysed hive.",
    "Environment variable references are reported unexpanded, because expansion depends on the "
    "source machine's environment, which an offline hive does not provide.",
    "Cell offsets are HCELL_INDEX values relative to the first hbin; the absolute file offset "
    "of a cell is 0x1000 + offset.",
]


@dataclass
class ValueEvidence:
    """A single registry value and the cell it was read from."""

    key_path: str
    name: str
    reg_type: str
    value: Any
    cell_offset: int | None


@dataclass
class SelectPointer:
    """One Select pointer (Current/Default/LastKnownGood) and whether its target exists."""

    source: str
    value: int
    control_set: str
    exists_in_hive: bool
    value_cell_offset: int | None


@dataclass
class ControlSetSelection:
    """Evidence and reasoning behind the control set used for service enumeration."""

    selected: str | None
    selected_key_cell_offset: int | None
    reason: str
    select_key_cell_offset: int | None
    failed: int | None
    pointers: list[SelectPointer]
    available_control_sets: dict[str, int]
    uncertainties: list[str]


@dataclass
class ImagePathAnalysis:
    """Structured reading of an ImagePath value, preserving the raw value."""

    raw: str
    value_cell_offset: int | None
    env_vars: list[str]
    quoted: bool
    executable: str | None
    arguments: str
    unquoted_with_spaces: bool
    candidate_interpretations: list[dict[str, str]]
    shared_process_host: bool
    notes: list[str]


@dataclass
class ServiceRecord:
    """One service key with its persistence-relevant configuration."""

    name: str
    key_path: str
    key_cell_offset: int | None
    last_write_time: str
    start: ValueEvidence | None
    start_meaning: str
    service_type: ValueEvidence | None
    service_type_flags: list[str]
    image_path: ImagePathAnalysis | None
    parameters_key_cell_offset: int | None
    service_dll: ValueEvidence | None
    notes: list[str]


@dataclass
class ServicesReport:
    """Full structured result of the service persistence analysis."""

    hive_file_name: str
    control_set_selection: ControlSetSelection
    services: list[ServiceRecord]
    uncertainties: list[str]
    limitations: list[str] = field(default_factory=lambda: list(LIMITATIONS))

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serialisable representation of this report."""
        return asdict(self)


def _jsonable(data: Any) -> Any:
    if isinstance(data, bytes):
        return {"hex": data.hex()}
    if isinstance(data, list):
        return [_jsonable(item) for item in data]
    return data


def _value_evidence(key: KeyNode, value: KeyValue) -> ValueEvidence:
    return ValueEvidence(
        key_path=key.path,
        name=value.name,
        reg_type=REG_TYPE_NAMES.get(value.type, f"REG_UNKNOWN_{value.type}"),
        value=_jsonable(value.value),
        cell_offset=value.offset,
    )


def select_control_set(hive: RegistryHive) -> ControlSetSelection:
    """Select a control set based on the actual content of the Select key.

    Never assumes ControlSet001: only pointers that reference a control set
    actually present in the hive are used, and every skipped or conflicting
    pointer is preserved as an uncertainty.
    """
    uncertainties: list[str] = []
    pointers: list[SelectPointer] = []
    failed: int | None = None
    select_offset: int | None = None

    available: dict[str, int] = {}
    for subkey in hive.root().subkeys():
        if CONTROL_SET_RE.match(subkey.name):
            available[subkey.name] = subkey.offset

    try:
        select_key = hive.open("Select")
    except RegistryKeyNotFoundError:
        uncertainties.append("Select key not found in the hive; no control set selection evidence available")
    else:
        select_offset = select_key.offset
        for value in select_key.values():
            if not isinstance(value.value, int):
                uncertainties.append(f"Select\\{value.name} has a non-integer value {value.value!r}; ignored")
                continue
            if value.name == "Failed":
                failed = value.value
            elif value.name in SELECT_POINTERS:
                control_set = f"ControlSet{value.value:03d}"
                pointers.append(
                    SelectPointer(
                        source=value.name,
                        value=value.value,
                        control_set=control_set,
                        exists_in_hive=control_set in available,
                        value_cell_offset=value.offset,
                    )
                )

    selected: str | None = None
    selected_offset: int | None = None
    reason = "no control set selected"
    for pointer in sorted(pointers, key=lambda p: SELECT_POINTERS.index(p.source)):
        if pointer.exists_in_hive:
            selected = pointer.control_set
            selected_offset = available[pointer.control_set]
            reason = f"Select\\{pointer.source} is {pointer.value} and {pointer.control_set} exists in the hive"
            break
        uncertainties.append(
            f"Select\\{pointer.source} points to {pointer.control_set}, but that key is not present in the hive"
        )

    if not pointers:
        uncertainties.append("Select key provides no Current/Default/LastKnownGood evidence")

    if len({pointer.control_set for pointer in pointers}) > 1:
        detail = ", ".join(
            f"{pointer.source} -> {pointer.control_set}{'' if pointer.exists_in_hive else ' (missing)'}"
            for pointer in pointers
        )
        uncertainties.append(f"Select pointers disagree: {detail}")

    if failed:
        uncertainties.append(f"Select\\Failed is {failed}: a control set was marked as failed")

    if selected is None:
        reason = "no Select pointer resolves to a control set present in the hive; not assuming ControlSet001"
        uncertainties.append(reason)

    return ControlSetSelection(
        selected=selected,
        selected_key_cell_offset=selected_offset,
        reason=reason,
        select_key_cell_offset=select_offset,
        failed=failed,
        pointers=pointers,
        available_control_sets=available,
        uncertainties=uncertainties,
    )


def analyze_image_path(raw: str, cell_offset: int | None) -> ImagePathAnalysis:
    """Analyse an ImagePath string without touching any filesystem.

    The raw value is always preserved; environment variables are reported
    unexpanded, and unquoted paths containing spaces yield every candidate
    executable/arguments split instead of a single guessed interpretation.
    """
    notes: list[str] = []
    candidates: list[dict[str, str]] = []

    env_vars = sorted(set(ENV_VAR_RE.findall(raw)))
    if env_vars:
        notes.append(
            f"contains environment variable reference(s) {', '.join(env_vars)}; kept unexpanded because "
            "expansion depends on the source machine's environment"
        )

    stripped = raw.strip()
    quoted = stripped.startswith('"')
    executable: str | None = None
    arguments = ""
    unquoted_with_spaces = False

    if quoted:
        end = stripped.find('"', 1)
        if end == -1:
            notes.append("opening quote without a closing quote; the executable boundary cannot be determined")
        else:
            executable = stripped[1:end]
            arguments = stripped[end + 1 :].strip()
    else:
        tokens = stripped.split(" ")
        if len(tokens) == 1:
            executable = tokens[0]
        elif not stripped:
            notes.append("empty ImagePath value")
        elif EXECUTABLE_SUFFIX_RE.search(tokens[0]):
            # The first token already ends in an executable extension, so the
            # executable/arguments boundary is unambiguous despite the spaces.
            executable = tokens[0]
            arguments = " ".join(tokens[1:])
        else:
            unquoted_with_spaces = True
            for split in range(1, len(tokens)):
                candidates.append(
                    {
                        "executable": " ".join(tokens[:split]),
                        "arguments": " ".join(tokens[split:]),
                    }
                )
            notes.append(
                "unquoted path containing spaces: the executable boundary is ambiguous; all candidate "
                "interpretations are listed, and CreateProcess would also try each candidate with '.exe' "
                "appended, which is a classic persistence/hijack vector"
            )

    shared_process_host = False
    if SVCHOST_RE.search(executable or raw):
        shared_process_host = True
        group_match = SVCHOST_GROUP_RE.search(raw)
        group = f" (group {group_match.group('group')})" if group_match else ""
        notes.append(
            f"shared-process host svchost.exe{group}: the service implementation is the DLL configured "
            "in Parameters\\ServiceDll, not the ImagePath executable"
        )

    return ImagePathAnalysis(
        raw=raw,
        value_cell_offset=cell_offset,
        env_vars=env_vars,
        quoted=quoted,
        executable=executable,
        arguments=arguments,
        unquoted_with_spaces=unquoted_with_spaces,
        candidate_interpretations=candidates,
        shared_process_host=shared_process_host,
        notes=notes,
    )


def analyze_service(key: KeyNode) -> ServiceRecord:
    """Collect the persistence-relevant configuration of one service key."""
    notes: list[str] = []
    start: ValueEvidence | None = None
    start_meaning = "unknown (no Start value)"
    service_type: ValueEvidence | None = None
    service_type_flags: list[str] = []
    image_path: ImagePathAnalysis | None = None

    for value in key.values():
        name = value.name.lower()
        if name == "start":
            start = _value_evidence(key, value)
        elif name == "type":
            service_type = _value_evidence(key, value)
        elif name == "imagepath":
            raw = value.value if isinstance(value.value, str) else repr(value.value)
            image_path = analyze_image_path(raw, value.offset)

    if start is not None:
        if isinstance(start.value, int) and start.value in START_MEANINGS:
            start_meaning = START_MEANINGS[start.value]
            if start.value in (0, 1, 2):
                notes.append(
                    f"Start={start.value} ({start_meaning}): configured to start automatically; "
                    "configuration is not evidence of execution"
                )
        else:
            start_meaning = f"unrecognized Start value {start.value!r}"
            notes.append(f"unrecognized Start value {start.value!r}; no standard start meaning applies")

    if service_type is not None and isinstance(service_type.value, int):
        service_type_flags = [label for bit, label in SERVICE_TYPE_FLAGS if service_type.value & bit]

    parameters_offset: int | None = None
    service_dll: ValueEvidence | None = None
    try:
        parameters = key.subkey("Parameters")
    except RegistryKeyNotFoundError:
        pass
    else:
        parameters_offset = parameters.offset
        try:
            service_dll = _value_evidence(parameters, parameters.value("ServiceDll"))
        except RegistryValueNotFoundError:
            pass

    shared_host = image_path.shared_process_host if image_path else False
    if service_dll is not None:
        if isinstance(service_dll.value, str) and (dll_env_vars := sorted(set(ENV_VAR_RE.findall(service_dll.value)))):
            notes.append(
                f"ServiceDll contains environment variable reference(s) {', '.join(dll_env_vars)}; kept unexpanded"
            )
        if shared_host:
            notes.append("shared-process service: Parameters\\ServiceDll configures the hosted payload DLL")
        else:
            notes.append("Parameters\\ServiceDll is configured for this service")
    elif shared_host:
        notes.append("shared-process service but no Parameters\\ServiceDll value found in this control set")

    return ServiceRecord(
        name=key.name,
        key_path=key.path,
        key_cell_offset=key.offset,
        last_write_time=key.timestamp.isoformat(),
        start=start,
        start_meaning=start_meaning,
        service_type=service_type,
        service_type_flags=service_type_flags,
        image_path=image_path,
        parameters_key_cell_offset=parameters_offset,
        service_dll=service_dll,
        notes=notes,
    )


def analyze_hive(fh: BinaryIO) -> ServicesReport:
    """Analyse an offline SYSTEM hive and return a structured persistence report."""
    hive = RegistryHive(fh)

    selection = select_control_set(hive)
    uncertainties = list(selection.uncertainties)

    services: list[ServiceRecord] = []
    if selection.selected is None:
        uncertainties.append("no services enumerated because no control set could be selected from the evidence")
    else:
        try:
            services_key = hive.open(f"{selection.selected}\\Services")
        except RegistryKeyNotFoundError:
            uncertainties.append(f"{selection.selected}\\Services is not present in the hive")
        else:
            services = [analyze_service(service_key) for service_key in services_key.subkeys()]

    return ServicesReport(
        hive_file_name=hive.filename,
        control_set_selection=selection,
        services=services,
        uncertainties=uncertainties,
    )


def main(argv: list[str] | None = None) -> int:
    """CLI entry point: print the structured service persistence report as JSON."""
    parser = argparse.ArgumentParser(
        description="List service persistence configuration from an offline SYSTEM hive",
    )
    parser.add_argument("hive", type=Path, help="path to the offline SYSTEM hive to analyse")
    args = parser.parse_args(argv)

    with args.hive.open("rb") as fh:
        report = analyze_hive(fh)

    json.dump(report.to_dict(), sys.stdout, indent=2)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
