"""Generate minimal synthetic SOFTWARE hives for IFEO / SilentProcessExit analysis.

Only synthetic registry structures are written. No executable is launched,
resolved, or validated by this module.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from pathlib import Path

from dissect.regf.c_regf import c_regf

REG_SZ = 1
REG_EXPAND_SZ = 2
REG_DWORD = 4

KEY_COMP_NAME = 0x20
KEY_HIVE_ENTRY = 0x04
NO_INDEX = 0xFFFFFFFF
BASE_SIZE = 0x1000


@dataclass
class ValueSpec:
    name: str
    type: int
    data: bytes


@dataclass
class KeySpec:
    name: str
    values: list[ValueSpec] = field(default_factory=list)
    children: list[KeySpec] = field(default_factory=list)


def dword(value: int) -> bytes:
    return struct.pack("<I", value)


def sz(value: str) -> bytes:
    return value.encode("utf-16-le") + b"\x00\x00"


def xor32_crc(data: bytes) -> int:
    crc = 0
    for (part,) in struct.iter_unpack("<I", data):
        crc ^= part
    return crc


def _encode_name(name: str) -> tuple[bytes, int]:
    if name.isascii():
        return name.encode("ascii"), KEY_COMP_NAME
    return name.encode("utf-16-le"), 0


def _pack_key_node(
    *,
    flags: int,
    parent: int,
    subkey_count: int,
    subkey_list: int,
    value_count: int,
    value_list: int,
    name_length: int,
) -> bytes:
    # Field order follows _CM_KEY_NODE exactly: 15 ULONGs between the
    # LARGE_INTEGER and the two USHORTs (Spare, Parent, 2x SubKeyCounts,
    # 2x SubKeyLists, ValueList.Count, ValueList.List, Security, Class,
    # MaxNameLen, MaxClassLen, MaxValueNameLen, MaxValueDataLen, WorkVar).
    values = [
        0,  # Spare
        parent,
        subkey_count,
        0,  # volatile subkey count
        subkey_list,
        0,  # volatile subkey list
        value_count,
        value_list,
        NO_INDEX,  # Security
        NO_INDEX,  # Class
        name_length,  # MaxNameLen (informational)
        0,
        0,
        0,
        0,  # WorkVar
    ]
    assert len(values) == 15
    header = struct.pack("<2sHQ15IHH", b"nk", flags, 0x01D0000000000000, *values, name_length, 0)
    assert len(header) == c_regf._CM_KEY_NODE.size, len(header)
    return header


class HiveBuilder:
    """Compact single-hbin REGF writer using specification-compliant cells."""

    def __init__(self) -> None:
        self._cells: list[tuple[int, bytes]] = []
        self._next = 0x20
        self._root_offset = NO_INDEX

    def _alloc(self, payload_size: int) -> int:
        offset = self._next
        self._next += (payload_size + 8 + 7) & ~7
        return offset

    def _put(self, offset: int, payload: bytes) -> None:
        alloc = (len(payload) + 8 + 7) & ~7
        self._cells.append((offset, payload.ljust(alloc - 4, b"\x00")))

    def build_key(self, key: KeySpec, parent: int = NO_INDEX) -> int:
        name_bytes, flags = _encode_name(key.name)
        if parent == NO_INDEX:
            flags |= KEY_HIVE_ENTRY
        node_offset = self._alloc(c_regf._CM_KEY_NODE.size + len(name_bytes))
        if parent == NO_INDEX:
            self._root_offset = node_offset

        child_info: list[tuple[int, bytes]] = []
        for child in key.children:
            child_offset = self.build_key(child, node_offset)
            child_name, _ = _encode_name(child.name)
            child_info.append((child_offset, child_name))

        value_offsets = [self.build_value(value) for value in key.values]

        subkey_list = NO_INDEX
        if child_info:
            subkey_list = self.build_fast_leaf(child_info)
        value_list = NO_INDEX
        if value_offsets:
            value_list = self._alloc(len(value_offsets) * 4)
            self._put(value_list, struct.pack(f"<{len(value_offsets)}I", *value_offsets))

        header = _pack_key_node(
            flags=flags,
            parent=parent,
            subkey_count=len(child_info),
            subkey_list=subkey_list,
            value_count=len(value_offsets),
            value_list=value_list,
            name_length=len(name_bytes),
        )
        self._put(node_offset, header + name_bytes)
        return node_offset

    def build_value(self, value: ValueSpec) -> int:
        name_bytes, _ = _encode_name(value.name)
        if len(value.data) <= 4:
            data_field = int.from_bytes(value.data.ljust(4, b"\x00"), "little")
            data_length = len(value.data) | 0x80000000
        else:
            data_field = self._alloc(len(value.data))
            self._put(data_field, value.data)
            data_length = len(value.data)

        header = struct.pack(
            "<2sHIIIHH",
            b"vk",
            len(name_bytes),
            data_length,
            data_field,
            value.type,
            1 if name_bytes else 0,
            0,
        )
        assert len(header) == c_regf._CM_KEY_VALUE.size, len(header)
        offset = self._alloc(len(header) + len(name_bytes))
        self._put(offset, header + name_bytes)
        return offset

    def build_fast_leaf(self, children: list[tuple[int, bytes]]) -> int:
        payload = struct.pack("<2sH", b"lf", len(children))
        for child_offset, name in children:
            hint = name[:4].ljust(4, b"\x00") if name.isascii() else b"\x00\x00\x00\x00"
            payload += struct.pack("<I4s", child_offset, hint)
        offset = self._alloc(len(payload))
        self._put(offset, payload)
        return offset

    def write(self) -> bytes:
        hbin_size = 0x20 + ((self._next - 0x20 + 0x1F) & ~0x1F)
        total = BASE_SIZE + hbin_size
        buf = bytearray(total)
        buf[0:4] = b"regf"
        struct.pack_into("<IIQIIIIIII", buf, 4, 1, 1, 0, 1, 5, 0, 1, self._root_offset, hbin_size, 1)
        file_name = "SOFTWARE".encode("utf-16-le")
        buf[0x30:0x30 + len(file_name)] = file_name
        struct.pack_into("<I", buf, 0x1FC, xor32_crc(bytes(buf[:0x1FC])))
        struct.pack_into("<4sIIIIIQI", buf, BASE_SIZE, b"hbin", 0, hbin_size, 0, 0, 0, 0, 0)
        for offset, payload in self._cells:
            alloc = (len(payload) + 8 + 7) & ~7
            struct.pack_into("<i", buf, BASE_SIZE + offset, -alloc)
            start = BASE_SIZE + offset + 4
            buf[start:start + len(payload)] = payload
        return bytes(buf)


def make_hive(root: KeySpec) -> bytes:
    builder = HiveBuilder()
    builder.build_key(root)
    return builder.write()


def _key(name: str, values: list[ValueSpec] | None = None, children: list[KeySpec] | None = None) -> KeySpec:
    return KeySpec(name, values or [], children or [])


def _software_prefix(children: list[KeySpec], *, wow: bool = False) -> list[KeySpec]:
    branch = [
        _key(
            "Microsoft",
            children=[
                _key(
                    "Windows NT",
                    children=[_key("CurrentVersion", children=children)],
                )
            ],
        )
    ]
    if wow:
        return [_key("Wow6432Node", children=branch)]
    return branch


def _full_chain(
    *,
    image: str,
    debugger: str,
    monitor: str,
    reporting_mode: int,
    filters: list[tuple[str, str, int]] | None = None,
    use_filter: int | None = 1,
) -> tuple[KeySpec, KeySpec]:
    ifeo_values = [
        ValueSpec("Debugger", REG_SZ, sz(debugger)),
        ValueSpec("GlobalFlag", REG_DWORD, dword(0x200)),
    ]
    if use_filter is not None:
        ifeo_values.append(ValueSpec("UseFilter", REG_DWORD, dword(use_filter)))
    ifeo_children = [
        _key(name, values=[ValueSpec("FilterFullPath", value_type, sz(path))]) for name, path, value_type in (filters or [])
    ]
    ifeo = _key("Image File Execution Options", children=[_key(image, values=ifeo_values, children=ifeo_children)])
    spe = _key(
        "SilentProcessExit",
        children=[
            _key(
                image,
                values=[
                    ValueSpec("MonitorProcess", REG_EXPAND_SZ if "%" in monitor else REG_SZ, sz(monitor)),
                    ValueSpec("ReportingMode", REG_DWORD, dword(reporting_mode)),
                ],
            )
        ],
    )
    return ifeo, spe


def write_samples(out_dir: Path) -> dict[str, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    samples: dict[str, Path] = {}

    # A: monitor path only. No IFEO key, GlobalFlag, UseFilter or Debugger.
    sample_a = _key(
        "ROOT",
        children=_software_prefix(
            [
                _key(
                    "SilentProcessExit",
                    children=[
                        _key(
                            "monitor-only.exe",
                            values=[
                                ValueSpec("MonitorProcess", REG_SZ, sz(r"C:\Tools\monitor-only.exe")),
                                ValueSpec("ReportingMode", REG_DWORD, dword(1)),
                            ],
                        )
                    ],
                )
            ]
        ),
    )
    samples["A_monitor_only"] = out_dir / "case_a_monitor_only.hive"
    samples["A_monitor_only"].write_bytes(make_hive(sample_a))

    # B: full association, no filter condition. Debugger, GlobalFlag=0x200,
    # MonitorProcess and ReportingMode are all present and type-valid.
    ifeo_b, spe_b = _full_chain(
        image="full-chain.exe",
        debugger=r"C:\Tools\dbg64.exe",
        monitor=r"%SystemRoot%\Tools\monitor64.exe",
        reporting_mode=1,
        use_filter=None,
    )
    sample_b = _key("ROOT", children=_software_prefix([ifeo_b, spe_b]))
    samples["B_full_chain"] = out_dir / "case_b_full_chain.hive"
    samples["B_full_chain"].write_bytes(make_hive(sample_b))

    # C: the same image name in the native and Wow6432Node views. Both chains
    # are complete, but every path/flag-bearing value differs. The native view
    # has two filter conditions; the Wow6432Node view has one.
    native_ifeo, native_spe = _full_chain(
        image="dual-view.exe",
        debugger=r"C:\Tools\dbg64.exe",
        monitor=r"%SystemRoot%\Tools\monitor64.exe",
        reporting_mode=1,
        filters=[
            ("filter-x64-a", r"C:\Apps64\dual-view.exe", REG_SZ),
            ("filter-x64-b", r"%ProgramFiles%\Dual View\dual-view.exe", REG_EXPAND_SZ),
        ],
    )
    wow_ifeo, wow_spe = _full_chain(
        image="dual-view.exe",
        debugger=r"C:\Tools\dbg32.exe",
        monitor=r"C:\Tools\monitor32.exe",
        reporting_mode=2,
        filters=[("filter-x86", r"C:\Apps32\dual-view.exe", REG_SZ)],
    )
    sample_c = _key(
        "ROOT",
        children=_software_prefix([native_ifeo, native_spe])
        + _software_prefix([wow_ifeo, wow_spe], wow=True),
    )
    samples["C_two_views"] = out_dir / "case_c_two_views.hive"
    samples["C_two_views"].write_bytes(make_hive(sample_c))

    # D: malformed, incomplete and ambiguous cases. All are retained verbatim.
    sample_d = _key(
        "ROOT",
        children=_software_prefix(
            [
                _key(
                    "Image File Execution Options",
                    children=[
                        _key(
                            "bad-flag-type.exe",
                            values=[
                                ValueSpec("GlobalFlag", REG_SZ, sz("512")),
                                ValueSpec("UseFilter", REG_DWORD, dword(1)),
                            ],
                        ),
                        _key(
                            "bad-filter-type.exe",
                            values=[
                                ValueSpec("GlobalFlag", REG_DWORD, dword(0x200)),
                                ValueSpec("UseFilter", REG_SZ, sz("1")),
                            ],
                        ),
                        _key(
                            "bad-flag-width.exe",
                            values=[
                                ValueSpec("GlobalFlag", REG_DWORD, dword(0x200) + b"\x00" * 4),
                                ValueSpec("UseFilter", REG_DWORD, dword(1)),
                            ],
                        ),
                        _key(
                            "duplicate.exe",
                            values=[
                                ValueSpec("GlobalFlag", REG_DWORD, dword(0x200)),
                                ValueSpec("UseFilter", REG_DWORD, dword(1)),
                                ValueSpec("UseFilter", REG_SZ, sz("1")),
                            ],
                        ),
                        _key(
                            "debugger-only.exe",
                            values=[ValueSpec("Debugger", REG_SZ, sz(r"C:\Tools\debug-only.exe"))],
                        ),
                        _key(
                            "no-flag.exe",
                            values=[ValueSpec("Debugger", REG_SZ, sz(r"C:\Tools\dbg-no-flag.exe"))],
                        ),
                        _key(
                            "missing-monitor.exe",
                            values=[
                                ValueSpec("GlobalFlag", REG_DWORD, dword(0x200)),
                                ValueSpec("UseFilter", REG_DWORD, dword(1)),
                            ],
                        ),
                        _key(
                            "bad-monitor-type.exe",
                            values=[
                                ValueSpec("GlobalFlag", REG_DWORD, dword(0x200)),
                                ValueSpec("UseFilter", REG_DWORD, dword(1)),
                            ],
                        ),
                        _key(
                            "filter-without-usefilter.exe",
                            values=[
                                ValueSpec("GlobalFlag", REG_DWORD, dword(0x200)),
                                ValueSpec("UseFilter", REG_DWORD, dword(0)),
                            ],
                            children=[
                                _key(
                                    "inert-filter",
                                    values=[
                                        ValueSpec(
                                            "FilterFullPath",
                                            REG_SZ,
                                            sz(r"C:\Apps\Inert\filter-without-usefilter.exe"),
                                        )
                                    ],
                                )
                            ],
                        ),
                        _key(
                            "usefilter-without-filter.exe",
                            values=[
                                ValueSpec("GlobalFlag", REG_DWORD, dword(0x200)),
                                ValueSpec("UseFilter", REG_DWORD, dword(1)),
                            ],
                        ),
                        _key(
                            "subkey-conflict.exe",
                            values=[
                                ValueSpec("GlobalFlag", REG_DWORD, dword(0x200)),
                                ValueSpec("UseFilter", REG_DWORD, dword(1)),
                            ],
                            children=[
                                _key(
                                    "subkey-conflict.exe",
                                    values=[ValueSpec("MonitorProcess", REG_SZ, sz(r"C:\Tools\shadow.exe"))],
                                )
                            ],
                        ),
                        _key(
                            "multi-filter.exe",
                            values=[
                                ValueSpec("GlobalFlag", REG_DWORD, dword(0x200)),
                                ValueSpec("UseFilter", REG_DWORD, dword(1)),
                            ],
                            children=[
                                _key(
                                    "filter-1",
                                    values=[
                                        ValueSpec(
                                            "FilterFullPath",
                                            REG_SZ,
                                            sz(r"C:\Apps\Multi\multi-filter.exe"),
                                        )
                                    ],
                                ),
                                _key(
                                    "filter-2",
                                    values=[
                                        ValueSpec(
                                            "FilterFullPath",
                                            REG_EXPAND_SZ,
                                            sz(r"%ProgramFiles%\Multi\multi-filter.exe"),
                                        )
                                    ],
                                ),
                            ],
                        ),
                    ],
                ),
                _key(
                    "SilentProcessExit",
                    children=[
                        _key(
                            "bad-flag-type.exe",
                            values=[ValueSpec("MonitorProcess", REG_SZ, sz(r"C:\Tools\m1.exe"))],
                        ),
                        _key(
                            "bad-filter-type.exe",
                            values=[ValueSpec("MonitorProcess", REG_SZ, sz(r"C:\Tools\m2.exe"))],
                        ),
                        _key(
                            "bad-monitor-type.exe",
                            values=[ValueSpec("MonitorProcess", REG_DWORD, dword(1))],
                        ),
                        _key(
                            "duplicate.exe",
                            values=[ValueSpec("MonitorProcess", REG_SZ, sz(r"C:\Tools\m3.exe"))],
                        ),
                        _key(
                            "no-flag.exe",
                            values=[ValueSpec("MonitorProcess", REG_SZ, sz(r"C:\Tools\m4.exe"))],
                        ),
                        _key(
                            "missing-monitor.exe",
                            values=[ValueSpec("ReportingMode", REG_DWORD, dword(1))],
                        ),
                        _key(
                            "monitor-only-orphan.exe",
                            values=[ValueSpec("MonitorProcess", REG_SZ, sz(r"C:\Tools\m5.exe"))],
                        ),
                        _key(
                            "env-missing.exe",
                            values=[
                                ValueSpec(
                                    "MonitorProcess",
                                    REG_EXPAND_SZ,
                                    sz(r"%MISSING_VAR%\m6.exe"),
                                ),
                                ValueSpec("ReportingMode", REG_DWORD, dword(1)),
                            ],
                        ),
                    ],
                ),
            ]
        ),
    )
    samples["D_ambiguous"] = out_dir / "case_d_ambiguous.hive"
    samples["D_ambiguous"].write_bytes(make_hive(sample_d))
    return samples


if __name__ == "__main__":
    paths = write_samples(Path(__file__).parent / "samples")
    for name, path in paths.items():
        print(f"{name}: {path} ({path.stat().st_size} bytes)")
