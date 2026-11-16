#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
pte_diagnostic.py

针对 Windows x64 (Intel32e / IA-32e 长模式) 软 PTE 状态的可运行定位诊断。

不依赖真实进程转储，合成：
  1. 一个物理内存层 (RAMLayer)，放数据页和 prototype PTE(PPTE) 页；
  2. 两个分页文件层 (FileLayer)，并故意不注册第 2、15 号分页文件；
  3. 一张叶子 PTE 表（上层 PML4/PDPT/PD 预置为 present，只保留叶子判定，
     因为状态分支只发生在叶子 PTE 上）。

判定逻辑逐行对齐 Volatility 3 源码：
  - volatility3/framework/layers/intel.py:494  WindowsMixin._page_is_valid
        valid := (entry & 1) or ((entry & 1<<11) and not (entry & 1<<10))
  - volatility3/framework/layers/intel.py:506  WindowsMixin._translate_swap
        软分页文件条目: V=0,T=0,P=0 且 bit7=1；n=(entry>>1)&0xF；
        Intel32e 的 bit_offset=32，swap_offset=(entry>>32)<<12
  - volatility3/framework/layers/intel.py:555  WindowsIntel32e._maxphyaddr=45
  - volatility3/framework/exceptions.py:58    PagedInvalidAddressException(.entry)
  - volatility3/framework/exceptions.py:82    SwappedInvalidAddressException(.swap_offset)

prototype PTE 的二级解析（读 subsection 的 PPTE 再解释）在当前裁剪版 vol3
中没有对应插件，本脚本按 intel.py:500 引用的 Windows Internals (6th, Part2,
pp.268-269) 文档流程建模，并在输出中明确标注为“教学建模”。
"""

from __future__ import annotations

import sys
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# 一、x64 PTE 位常量（与 vol3 intel.py 使用的位定义一致）
# ---------------------------------------------------------------------------
PAGE_SHIFT = 12
PAGE_SIZE = 1 << PAGE_SHIFT
MAXPHYADDR_BITS = 45              # WindowsIntel32e._maxphyaddr
PFN_MASK = (1 << MAXPHYADDR_BITS) - 1

BIT_VALID = 1 << 0                # V / Present
BIT_PROTO = 1 << 10               # P / Prototype
BIT_TRANS = 1 << 11               # T / Transition
BIT_SOFT_U = 1 << 7               # vol3 软(分页文件)条目的 unknown/software 位
INTEL32E_SWAP_BIT_OFFSET = 32     # WindowsIntel32e: bits_per_register // 2


# ---------------------------------------------------------------------------
# 二、异常类型：字段与 volatility3/framework/exceptions.py 保持同名
# ---------------------------------------------------------------------------
class LayerException(Exception):
    def __init__(self, layer_name: str, *args) -> None:
        super().__init__(*args)
        self.layer_name = layer_name


class InvalidAddressException(LayerException):
    def __init__(self, layer_name: str, invalid_address: int, *args) -> None:
        super().__init__(layer_name, *args)
        self.invalid_address = invalid_address


class PagedInvalidAddressException(InvalidAddressException):
    def __init__(self, layer_name, invalid_address, invalid_bits, entry, message=""):
        super().__init__(layer_name, invalid_address, message)
        self.invalid_bits = invalid_bits
        self.entry = entry


class SwappedInvalidAddressException(PagedInvalidAddressException):
    def __init__(self, layer_name, invalid_address, invalid_bits, entry, swap_offset):
        super().__init__(layer_name, invalid_address, invalid_bits, entry)
        self.swap_offset = swap_offset


class PrototypeNotResolvableException(InvalidAddressException):
    """prototype PTE 指向的 PPTE 物理页在转储中缺失（subsection 无法定位）。"""

    def __init__(self, layer_name, invalid_address, proto_pa, entry):
        super().__init__(
            layer_name, invalid_address,
            f"PPTE physical page {proto_pa:#x} not present in dump")
        self.proto_pa = proto_pa
        self.entry = entry


# ---------------------------------------------------------------------------
# 三、底层介质层：物理内存 / 分页文件，全部带读取审计日志
# ---------------------------------------------------------------------------
@dataclass
class AuditEntry:
    layer: str
    offset: int
    length: int
    note: str


class RAMLayer:
    """合成物理内存层，key 为物理页帧号 PFN。"""

    name = "physical_layer (0_layer 风格)"

    def __init__(self, audit: List[AuditEntry]):
        self._pages: Dict[int, bytes] = {}
        self._audit = audit

    def install_page(self, pfn: int, content: bytes) -> None:
        self._pages[pfn] = content.ljust(PAGE_SIZE, b"\x00")

    def install_qword(self, pfn: int, off: int, qword: int) -> None:
        buf = bytearray(self._pages.get(pfn, b"\x00" * PAGE_SIZE))
        buf[off:off + 8] = qword.to_bytes(8, "little")
        self._pages[pfn] = bytes(buf)

    def read(self, offset: int, length: int) -> bytes:
        pfn, _inside = divmod(offset, PAGE_SIZE)
        self._audit.append(AuditEntry(
            self.name, offset, length, f"物理读取 PFN={pfn:#x}"))
        if pfn not in self._pages:
            raise InvalidAddressException(
                self.name, offset, f"physical page PFN={pfn:#x} absent")
        return self._pages[pfn][offset - pfn * PAGE_SIZE:
                                offset - pfn * PAGE_SIZE + length]


class FileLayer:
    """合成分页文件层（vol3 中即 swap_layersN 指向的 FileLayer）。"""

    def __init__(self, file_name: str, swap_index: int, audit: List[AuditEntry]):
        self.name = f"{file_name} (swap_layers{swap_index})"
        self._swap_index = swap_index
        self._data = bytearray(b"\x00" * (16 * PAGE_SIZE))
        self._audit = audit

    def install_marker(self, file_offset: int, content: bytes) -> None:
        self._data[file_offset:file_offset + len(content)] = content

    def read(self, offset: int, length: int) -> bytes:
        self._audit.append(AuditEntry(
            self.name, offset, length,
            f"分页文件#{self._swap_index} 内偏移读取"))
        if offset < 0 or offset + length > len(self._data):
            raise InvalidAddressException(self.name, offset, "offset beyond file")
        return bytes(self._data[offset:offset + length])


# ---------------------------------------------------------------------------
# 四、Windows 风格分页层：状态机严格复刻 vol3 WindowsMixin / WindowsIntel32e
# ---------------------------------------------------------------------------
class WindowsPagedLayer:
    name = "va_layer (WindowsIntel32e 风格, 模拟可疑进程)"

    def __init__(self, ram: RAMLayer, audit: List[AuditEntry],
                 swap_layers: Optional[Dict[int, FileLayer]] = None,
                 swap_enabled: bool = True):
        self._ram = ram
        self._audit = audit
        # 关键：dict key 是分页文件编号 n，vol3 只用精确编号 n 查找，
        # 缺失即抛 SwappedInvalidAddressException，绝不向相邻编号回退。
        self._swap_layers: Dict[int, FileLayer] = swap_layers or {}
        self._swap_enabled = swap_enabled
        self.leaf_pte: Dict[int, int] = {}         # VPN -> 叶子 PTE
        self.proto_registry: Dict[int, int] = {}   # PPTE 物理地址 -> PPTE 值

    # 逐字对应 intel.py:494-504
    @staticmethod
    def _page_is_valid(entry: int) -> bool:
        return bool((entry & 1) or
                    ((entry & (1 << 11)) and not (entry & (1 << 10))))

    # 对应 intel.py:180-182（_maxphyaddr=45）
    @staticmethod
    def _pte_pfn(entry: int) -> int:
        return (entry & PFN_MASK) >> PAGE_SHIFT

    @staticmethod
    def decode(entry: int) -> Dict[str, object]:
        return {
            "V(bit0)": bool(entry & BIT_VALID),
            "P(bit10)": bool(entry & BIT_PROTO),
            "T(bit11)": bool(entry & BIT_TRANS),
            "U(bit7)": bool(entry & BIT_SOFT_U),
            "n=(entry>>1)&0xF": (entry >> 1) & 0xF,
            "high/PFN字段": WindowsPagedLayer._pte_pfn(entry),
            "swap数据(entry>>32)": entry >> INTEL32E_SWAP_BIT_OFFSET,
        }

    # -- prototype PTE 二级解析（教学建模，见模块 docstring） ----------------
    def _resolve_prototype(self, entry: int, offset: int) -> Tuple[int, int, str]:
        # 合成约定：prototype PTE 高位保存 PPTE 的页对齐物理地址
        proto_pa = entry & ~0xFFF
        self._audit.append(AuditEntry(
            self.name, proto_pa, 8,
            f"prototype: 解析 subsection，物理读取 PPTE @ {proto_pa:#x}"))
        try:
            raw = self._ram.read(proto_pa, 8)
        except InvalidAddressException:
            raise PrototypeNotResolvableException(
                self.name, offset, proto_pa, entry)
        ppte = int.from_bytes(raw, "little")
        self._audit.append(AuditEntry(
            self.name, proto_pa, 8,
            f"prototype: 取到 PPTE={ppte:#018x}，重新进入状态机"))
        return self._interpret_leaf(ppte, offset, via_prototype=True)

    # -- 核心状态机 ----------------------------------------------------------
    def _interpret_leaf(self, entry: int, offset: int,
                        via_prototype: bool = False) -> Tuple[int, int, str]:
        tag = "PPTE" if via_prototype else "PTE"

        # 1) prototype：V=0 且 P=1，基础翻译层不把它当有效页（见 _page_is_valid）
        if not (entry & BIT_VALID) and (entry & BIT_PROTO):
            return self._resolve_prototype(entry, offset)

        # 2) present / transition：走物理层
        if self._page_is_valid(entry):
            pfn = self._pte_pfn(entry)
            phys = (pfn << PAGE_SHIFT) | (offset & 0xFFF)
            kind = "present(V=1)" if entry & BIT_VALID else "transition(T=1,P=0)"
            self._audit.append(AuditEntry(
                self.name, offset, 0,
                f"{tag}={entry:#018x} 判定 {kind} -> 物理层 PFN={pfn:#x}"))
            return phys, PAGE_SIZE, self._ram.name

        # 3) 无效条目：复刻 intel.py:512-539 的软分页文件判定
        tbit = bool(entry & BIT_TRANS)
        pbit = bool(entry & BIT_PROTO)
        unknown_bit = bool(entry & BIT_SOFT_U)
        n = (entry >> 1) & 0xF
        vbit = bool(entry & BIT_VALID)

        if (not tbit and not pbit and not vbit and unknown_bit) and \
                ((entry >> INTEL32E_SWAP_BIT_OFFSET) != 0):
            swap_offset = (entry >> INTEL32E_SWAP_BIT_OFFSET) << PAGE_SHIFT
            if self._swap_enabled:
                # 精确编号查找；没有 .get(相邻编号) 这种回退
                swap_layer = self._swap_layers.get(n)
                if swap_layer is not None:
                    self._audit.append(AuditEntry(
                        self.name, offset, 0,
                        f"{tag}={entry:#018x} 软分页条目 n={n} -> "
                        f"{swap_layer.name} 偏移={swap_offset:#x}"))
                    return swap_offset, PAGE_SIZE, swap_layer.name
            raise SwappedInvalidAddressException(
                layer_name=self.name, invalid_address=offset,
                invalid_bits=PAGE_SHIFT, entry=entry, swap_offset=swap_offset)

        # 4) 其余全部是普通无效页（demand-zero / 垃圾值 / 格式不符）
        raise PagedInvalidAddressException(
            layer_name=self.name, invalid_address=offset,
            invalid_bits=PAGE_SHIFT, entry=entry,
            message=f"{tag} {entry:#x} 不符合任何可定位格式")

    def _translate(self, offset: int) -> Tuple[int, int, str]:
        vpn = offset >> PAGE_SHIFT
        if vpn not in self.leaf_pte:
            raise PagedInvalidAddressException(
                self.name, offset, PAGE_SHIFT, 0, "leaf PTE not populated")
        return self._interpret_leaf(self.leaf_pte[vpn], offset)

    # -- 对外公开读取 API（对应 vol3 layer.read） ----------------------------
    def read(self, offset: int, length: int) -> bytes:
        self._audit.append(AuditEntry(
            self.name, offset, length, f"公开 read(va={offset:#x}, len={length})"))
        mapped, _page_size, layer_name = self._translate(offset)
        if layer_name == self._ram.name:
            return self._ram.read(mapped, length)
        for swap_layer in self._swap_layers.values():
            if swap_layer.name == layer_name:
                return swap_layer.read(mapped, length)
        raise InvalidAddressException(
            self.name, offset, f"内部错误：未知目标层 {layer_name}")


# ---------------------------------------------------------------------------
# 五、合成场景
# ---------------------------------------------------------------------------
@dataclass
class Case:
    cid: str
    title: str
    va: int
    pte: int
    expect: str
    note: str = ""


def build_world() -> Tuple[WindowsPagedLayer, RAMLayer, List[AuditEntry],
                           Dict[int, FileLayer], List[Case]]:
    audit: List[AuditEntry] = []
    ram = RAMLayer(audit)

    # 物理数据页
    ram.install_page(0x100, b"VALID-PRESENT-PAGE!!")
    ram.install_page(0x200, b"TRANSITION-PAGE!!!")
    ram.install_page(0x400, b"PROTO-TARGET-PAGE!!")

    # PPTE 页（prototype PTE 指向的 subsection 原型 PTE 数组）
    for ppfn in (0x300, 0x301, 0x302):
        ram.install_page(ppfn, b"\x00" * PAGE_SIZE)
    ppte_present = (0x400 << PAGE_SHIFT) | BIT_VALID       # -> PFN 0x400
    ppte_swap_n1 = (0x6 << 32) | (1 << 1) | BIT_SOFT_U     # -> 分页文件#1
    ppte_zero = 0                                          # demand-zero
    ram.install_qword(0x300, 0, ppte_present)
    ram.install_qword(0x301, 0, ppte_swap_n1)
    ram.install_qword(0x302, 0, ppte_zero)

    # 分页文件：只注册 #0、#1；#2、#15 故意缺失
    swap_layers = {
        0: FileLayer("pagefile0.sys", 0, audit),
        1: FileLayer("pagefile1.sys", 1, audit),
    }
    swap_layers[0].install_marker(0x5000, b"SWAP-FILE0-PAGE!!")
    swap_layers[1].install_marker(0x6000, b"SWAP-FILE1-PAGE!!")

    va = WindowsPagedLayer(ram, audit, swap_layers=swap_layers)

    def pte(va_index: int, value: int) -> None:
        va.leaf_pte[(va_index * PAGE_SIZE) >> PAGE_SHIFT] = value

    pte(0x10, (0x100 << PAGE_SHIFT) | BIT_VALID)                       # C1
    pte(0x20, (0x200 << PAGE_SHIFT) | BIT_TRANS)                       # C2
    pte(0x40, (0x200 << PAGE_SHIFT) | BIT_TRANS)                       # C3a
    pte(0x41, (0x200 << PAGE_SHIFT))                                   # C3b
    pte(0x30, 0x00000000DEADB000)                                      # C4
    pte(0x50, (0x300 << PAGE_SHIFT) | BIT_PROTO)                       # C5
    pte(0x60, (0x301 << PAGE_SHIFT) | BIT_PROTO)                       # C6
    pte(0x70, (0x302 << PAGE_SHIFT) | BIT_PROTO)                       # C7
    pte(0x80, (0x999 << PAGE_SHIFT) | BIT_PROTO)                       # C8
    pte(0x90, (0x5 << 32) | (0 << 1) | BIT_SOFT_U)                     # C9 n=0
    pte(0xA0, (0x7 << 32) | (2 << 1) | BIT_SOFT_U)                     # C10 n=2
    pte(0xB0, (0x9 << 32) | (15 << 1) | BIT_SOFT_U)                    # C11 n=15
    pte(0xC0, 0)                                                       # C12

    cases = [
        Case("C1", "present 有效页", 0x00010000, va.leaf_pte[0x10], "物理层"),
        Case("C2", "transition 页", 0x00020000, va.leaf_pte[0x20], "物理层"),
        Case("C3a", "单比特对：T=1（transition）", 0x00040000,
             va.leaf_pte[0x40], "物理层"),
        Case("C3b", "单比特对：清 bit11（同高位）", 0x00041000,
             va.leaf_pte[0x41], "PagedInvalid 异常"),
        Case("C4", "垃圾无效条目", 0x00030000, va.leaf_pte[0x30],
             "PagedInvalid 异常"),
        Case("C5", "prototype -> present PPTE", 0x00050000,
             va.leaf_pte[0x50], "物理层(二级解析)"),
        Case("C6", "prototype -> 分页文件#1 PPTE", 0x00060000,
             va.leaf_pte[0x60], "分页文件层"),
        Case("C7", "prototype -> demand-zero PPTE", 0x00070000,
             va.leaf_pte[0x70], "PagedInvalid 异常"),
        Case("C8", "prototype -> PPTE 物理页缺失", 0x00080000,
             va.leaf_pte[0x80], "Prototype 无法定位"),
        Case("C9", "分页文件条目 n=0", 0x00090000,
             va.leaf_pte[0x90], "分页文件层 #0"),
        Case("C10", "分页文件条目 n=2（文件缺失）", 0x000A0000,
             va.leaf_pte[0xA0], "SwappedInvalid 异常"),
        Case("C11", "分页文件条目 n=15（文件缺失）", 0x000B0000,
             va.leaf_pte[0xB0], "SwappedInvalid 异常"),
        Case("C12", "全零 PTE demand-zero", 0x000C0000,
             va.leaf_pte[0xC0], "PagedInvalid 异常"),
    ]
    return va, ram, audit, swap_layers, cases


def hx(value: int) -> str:
    return f"0x{value:016x}"


def run() -> int:
    va, ram, audit, swap_layers, cases = build_world()
    failures: List[str] = []
    case_windows: Dict[str, List[AuditEntry]] = {}

    print("=" * 78)
    print("Windows x64 PTE 状态 -> Volatility 3 读取路径 定位诊断")
    print("=" * 78)
    print(f"页大小={PAGE_SIZE:#x}  PFN 掩码位宽={MAXPHYADDR_BITS}  "
          f"swap bit_offset={INTEL32E_SWAP_BIT_OFFSET}")
    print("状态位: V=bit0 present, P=bit10 prototype, T=bit11 transition, "
          "U=bit7 软分页")
    print("已注册分页文件: "
          + ", ".join(f"#{n}={l.name}" for n, l in sorted(swap_layers.items()))
          + "；#2、#15 故意缺失")
    print("-" * 78)

    results = []
    for case in cases:
        start = len(audit)
        print(f"\n【{case.cid}】{case.title}")
        print(f"  VA={case.va:#010x}  叶子 PTE={hx(case.pte)}")
        decoded = va.decode(case.pte)
        print("  解码: " + "  ".join(f"{k}={v}" for k, v in decoded.items()))
        try:
            data = va.read(case.va, 16)
            decision = next((a for a in reversed(audit[start:])
                             if a.layer != va.name), audit[start])
            print(f"  公开读取结果: {data!r}")
            print(f"  所用层: {decision.layer}")
            print(f"  实际偏移: {decision.offset:#x}")
            results.append((case.cid, "OK", case.pte,
                            decision.layer, decision.offset, ""))
        except (PagedInvalidAddressException, PrototypeNotResolvableException) as exc:
            evidence = (
                f"异常={type(exc).__name__}; layer={exc.layer_name}; "
                f"invalid_address={exc.invalid_address:#x}; "
                f"entry={hx(getattr(exc, 'entry', 0))}"
            )
            if isinstance(exc, SwappedInvalidAddressException):
                evidence += (f"; swap_offset={exc.swap_offset:#x}; "
                             f"目标分页文件编号 n={(exc.entry >> 1) & 0xF}")
            if isinstance(exc, PrototypeNotResolvableException):
                evidence += f"; 缺失 PPTE 物理地址={exc.proto_pa:#x}"
            print("  公开读取结果: 抛出异常，无法定位")
            print("  异常中的地址证据: " + evidence)
            reason = {
                "C3b": "T 位被清，V=0/P=0/U=0，高位 0x200 不能当 PFN",
                "C4": "无任何有效状态位，禁止把高位 DEADB 直接解释成物理页号",
                "C7": "PPTE=0 为 demand-zero，内容按零页处理，转储中无实体页",
                "C8": "subsection 的 PPTE 物理页不在转储内，原型链断裂",
                "C10": "分页文件 #2 未提供，精确编号查找失败，禁止改读 #0/#1",
                "C11": "分页文件 #15 未提供，精确编号查找失败，禁止改读邻近文件",
                "C12": "全零 PTE 即 demand-zero，无物理/分页文件落点",
            }.get(case.cid, "状态位不匹配任何可定位格式")
            print("  无法定位原因: " + reason)
            results.append((case.cid, type(exc).__name__, case.pte,
                            "-", "-", reason))
        case_windows[case.cid] = audit[start:]

        print("  审计轨迹:")
        for item in case_windows[case.cid]:
            print(f"    - [{item.layer}] off={item.offset:#x} "
                  f"len={item.length} :: {item.note}")

    # -- 汇总表 -------------------------------------------------------------
    print("\n" + "=" * 78)
    print("汇总")
    print("=" * 78)
    print(f"{'编号':<6}{'结果':<36}{'PTE':<20}所用层/原因")
    for cid, status, pte, layer, off, reason in results:
        target = reason if reason else (
            layer if off == "-" else f"{layer} @ {off:#x}")
        print(f"{cid:<6}{status:<36}{hx(pte):<20}{target}")

    # -- 硬性断言 -----------------------------------------------------------
    print("\n" + "=" * 78)
    print("安全断言")
    print("=" * 78)

    def check(name: str, cond: bool) -> None:
        print(f"  [{'PASS' if cond else 'FAIL'}] {name}")
        if not cond:
            failures.append(name)

    c3a, c3b = cases[2].pte, cases[3].pte
    check("C3a/C3b 仅相差 bit11 一个状态位",
          (c3a ^ c3b) == BIT_TRANS and bool(c3a & BIT_TRANS)
          and not (c3b & BIT_TRANS))
    check("C3b 未把高位 0x200 当物理页号（无 0x200000 物理读取）",
          all(not (a.layer == ram.name and a.offset == 0x200000)
              for a in case_windows["C3b"]))
    check("C4 垃圾条目没有触发任何物理/文件层读取",
          all(a.layer == va.name for a in case_windows["C4"]))
    for cid, n in (("C10", 2), ("C11", 15)):
        leaked = [a for a in case_windows[cid] if "swap_layers" in a.layer]
        check(f"{cid} 缺失分页文件 #{n} 时未回退读取任何邻近分页文件",
              not leaked)

    try:
        va.read(0x000A0000, 16)
        check("C10 确实抛出 SwappedInvalidAddressException", False)
    except SwappedInvalidAddressException as exc:
        check("C10 异常携带 swap_offset=0x7000 与原始 entry",
              exc.swap_offset == 0x7000 and exc.entry == cases[10].pte)

    # -- 与本机 vol3 源码对位（可选） ---------------------------------------
    print("\n" + "-" * 78)
    try:
        from volatility3.framework.layers.intel import WindowsIntel32e
        parity = all(
            WindowsIntel32e._page_is_valid(c.pte) == va._page_is_valid(c.pte)
            for c in cases)
        check("与本机 volatility3 WindowsIntel32e._page_is_valid 逐条目一致",
              parity)
        print("  对位源码: volatility3/framework/layers/intel.py:494-504")
    except Exception as exc:  # pragma: no cover
        print(f"  [SKIP] 未导入 volatility3（{type(exc).__name__}: {exc}）")

    print("\n" + ("全部断言通过 ✅" if not failures else
                  f"存在 {len(failures)} 个失败断言 ❌: {failures}"))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(run())
