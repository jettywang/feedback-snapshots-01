"""Minimal regf hive writer used to build targeted test fixtures."""

from __future__ import annotations

import struct
from typing import Any

from dissect.regf.c_regf import REG_DWORD, REG_EXPAND_SZ
from dissect.regf.regf import xor32_crc

HBIN_HEADER_SIZE = 0x20
NO_CELL = 0xFFFFFFFF

KEY_COMP_NAME = 0x20
KEY_HIVE_ENTRY = 0x04
VALUE_COMP_NAME = 0x01

NK_STRUCT = struct.Struct("<2sHQ" + "I" * 15 + "HH")
VK_STRUCT = struct.Struct("<2sHIIIHH")
LF_ENTRY_STRUCT = struct.Struct("<I4s")

# 2024-01-01T00:00:00Z as a Windows FILETIME
FIXTURE_FILETIME = 133485408000000000


def _align8(length: int) -> int:
    return (length + 7) & ~7


def _name_hint(name: str) -> bytes:
    return name[:4].upper().ljust(4, "\x00").encode("ascii")


def _sz(text: str) -> bytes:
    return text.encode("utf-16-le") + b"\x00\x00"


class HiveBuilder:
    """Accumulates cells and serialises them into a valid single-hbin hive."""

    def __init__(self) -> None:
        self._data = bytearray(b"\x00" * HBIN_HEADER_SIZE)

    def _alloc(self, payload: bytes) -> int:
        offset = len(self._data)
        size = _align8(4 + len(payload))
        self._data += struct.pack("<i", -size) + payload
        self._data += b"\x00" * (size - 4 - len(payload))
        return offset

    def add_value(self, name: str, value_type: int, data: bytes | int) -> int:
        """Add a vk cell (DWORDs stored inline) and return its cell offset."""
        if isinstance(data, int):
            data_length = 0x80000000 | 4
            data_field = data
        else:
            data_length = len(data)
            data_field = self._alloc(data) if data else 0
        encoded = name.encode("ascii")
        payload = VK_STRUCT.pack(b"vk", len(encoded), data_length, data_field, value_type, VALUE_COMP_NAME, 0)
        return self._alloc(payload + encoded)

    def add_key(
        self,
        name: str,
        subkeys: list[tuple[str, int]] | None = None,
        values: list[int] | None = None,
        flags: int = KEY_COMP_NAME,
        timestamp: int = FIXTURE_FILETIME,
    ) -> int:
        """Add an nk cell referencing already-created subkeys/values; parent is patched later."""
        subkeys = subkeys or []
        values = values or []

        if subkeys:
            entries = b"".join(LF_ENTRY_STRUCT.pack(offset, _name_hint(subkey_name)) for subkey_name, offset in subkeys)
            subkey_list = self._alloc(struct.pack("<2sH", b"lf", len(subkeys)) + entries)
        else:
            subkey_list = NO_CELL

        value_list = self._alloc(struct.pack(f"<{len(values)}I", *values)) if values else NO_CELL

        encoded = name.encode("ascii")
        payload = NK_STRUCT.pack(
            b"nk",
            flags,
            timestamp,
            0,
            NO_CELL,
            len(subkeys),
            0,
            subkey_list,
            NO_CELL,
            len(values),
            value_list,
            NO_CELL,
            NO_CELL,
            0,
            0,
            0,
            0,
            0,
            len(encoded),
            0,
        )
        return self._alloc(payload + encoded)

    def set_parent(self, child: int, parent: int) -> None:
        """Patch the Parent field of a previously created nk cell."""
        struct.pack_into("<I", self._data, child + 4 + 16, parent)

    def build(self, root: int) -> bytes:
        """Serialise to a complete hive image with a valid header checksum."""
        hbin_size = (len(self._data) + 4095) & ~4095
        hbin = bytearray(self._data) + bytearray(hbin_size - len(self._data))
        struct.pack_into("<III", hbin, 0, 0x6E696268, 0, hbin_size)

        header = bytearray(4096)
        struct.pack_into("<IIIQIIIIIII", header, 0, 0x66676572, 1, 1, 0, 1, 5, 0, 1, root, hbin_size, 1)
        header[48 : 48 + 12] = "SYSTEM".encode("utf-16-le")
        struct.pack_into("<I", header, 508, xor32_crc(bytes(header[:508])))

        return bytes(header) + bytes(hbin)


def make_system_hive(
    *,
    current: int | None = 1,
    default: int | None = 1,
    last_known_good: int | None = 1,
    failed: int | None = 0,
    control_sets: dict[int, list[dict[str, Any]]],
    include_select: bool = True,
) -> bytes:
    """Build a small SYSTEM hive with a Select key and the given control sets.

    Each control set maps a number to a list of service specs with the keys
    ``name``, ``start``, ``type``, ``image_path`` and ``service_dll``.
    """
    builder = HiveBuilder()
    root_subkeys: list[tuple[str, int]] = []

    if include_select:
        select_values = []
        for value_name, number in (
            ("Current", current),
            ("Default", default),
            ("Failed", failed),
            ("LastKnownGood", last_known_good),
        ):
            if number is not None:
                select_values.append(builder.add_value(value_name, REG_DWORD, number))
        select_key = builder.add_key("Select", values=select_values)
        root_subkeys.append(("Select", select_key))

    for number, services in sorted(control_sets.items()):
        service_entries = []
        for spec in services:
            values = []
            if spec.get("start") is not None:
                values.append(builder.add_value("Start", REG_DWORD, spec["start"]))
            if spec.get("type") is not None:
                values.append(builder.add_value("Type", REG_DWORD, spec["type"]))
            if spec.get("image_path") is not None:
                values.append(builder.add_value("ImagePath", REG_EXPAND_SZ, _sz(spec["image_path"])))

            subkeys = []
            parameters = None
            if spec.get("service_dll") is not None:
                service_dll = builder.add_value("ServiceDll", REG_EXPAND_SZ, _sz(spec["service_dll"]))
                parameters = builder.add_key("Parameters", values=[service_dll])
                subkeys.append(("Parameters", parameters))

            service_key = builder.add_key(spec["name"], subkeys=subkeys, values=values)
            if parameters is not None:
                builder.set_parent(parameters, service_key)
            service_entries.append((spec["name"], service_key))

        services_key = builder.add_key("Services", subkeys=service_entries)
        for _, service_key in service_entries:
            builder.set_parent(service_key, services_key)

        control_set_name = f"ControlSet{number:03d}"
        control_set_key = builder.add_key(control_set_name, subkeys=[("Services", services_key)])
        builder.set_parent(services_key, control_set_key)
        root_subkeys.append((control_set_name, control_set_key))

    root = builder.add_key("ROOT", subkeys=root_subkeys, flags=KEY_HIVE_ENTRY | KEY_COMP_NAME)
    for _, subkey in root_subkeys:
        builder.set_parent(subkey, root)

    return builder.build(root)
