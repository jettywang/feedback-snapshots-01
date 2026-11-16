# Windows PTE 状态 → Volatility 3 读取路径 定位诊断

## 运行方式

```bash
# 仅标准库即可运行
python3 pte_diagnostic.py

# 若本机带 volatility3 源码（本仓库即如此），把缓存目录指到可写位置，
# 报告末尾会额外做一次与 WindowsIntel32e._page_is_valid 的逐条目对位
XDG_CACHE_HOME="$TMPDIR/cache" PYTHONPYCACHEPREFIX="$TMPDIR/pycache" \
    python3 pte_diagnostic.py | tee diagnostic_report.txt
```

退出码为 0 表示全部安全断言通过；不需要任何真实进程转储，物理内存和
分页文件均由脚本合成。

## 两条路径由叶子 PTE 的状态位决定

Volatility 3 的 Windows 判定在 `volatility3/framework/layers/intel.py`：

- `WindowsMixin._page_is_valid`（intel.py:494）：
  `(entry & 1) or ((entry & 1<<11) and not (entry & 1<<10))`
- `WindowsMixin._translate_swap`（intel.py:506）在基类翻译抛
  `PagedInvalidAddressException` 后，再判断软分页文件格式。

| PTE 状态 | 位特征 | Volatility 3 走向 | 落点 |
| --- | --- | --- | --- |
| present 有效页 | V=1 | 基类翻译成功，返回 `_base_layer` | 物理层 `PFN<<12 + 页内偏移` |
| transition 页 | V=0, T=1, P=0 | `_page_is_valid` 仍为真，按 PFN 读物理 | 物理层（内容还在 RAM，只是 PFN 数据库标记过渡） |
| prototype 页 | V=0, P=1 | 基础层判为无效，需经 VAD subsection 找到 PPTE 再解释 | 取决于 PPTE：物理页 / 分页文件 / demand-zero / 无法定位 |
| 分页文件条目 | V=0,T=0,P=0,U(bit7)=1 | `_translate_swap`：`n=(entry>>1)&0xF`，`swap_offset=(entry>>32)<<12`（Intel32e） | 精确编号 `swap_layers{n}`；该层未注册则抛 `SwappedInvalidAddressException` |
| demand-zero / 垃圾值 | 上述格式均不满足 | 抛 `PagedInvalidAddressException` | 无落点 |

## 本诊断合成的 13 个条目

- 物理路径：C1 present、C2 transition、C5 prototype→present PPTE。
- 分页文件路径：C9（n=0）、C6（prototype 链最终到 n=1）。
- 异常路径：C3b/C4/C7/C12 普通无效、C8 PPTE 物理页缺失、
  C10（n=2）/C11（n=15）分页文件未注册。

### 单状态位翻转对照（满足“只改一个状态位便走向不同路径”）

C3a `0x0000000000200800`（T=1）→ 物理层 `0x200000` 读出
`TRANSITION-PAGE!`；C3b `0x0000000000200000` 仅清掉 bit11，高位 PFN 字段
完全相同 → 直接 `PagedInvalidAddressException`，审计轨迹证明没有任何
`0x200000` 物理读取。这同时证明：无效条目的高位不能直接当物理页号。

## 两条禁止事项如何被强制验证

1. **缺少分页文件不得改读编号相近文件**：脚本只注册 `swap_layers0/1`。
   C10 的 n=2、C11 的 n=15 都抛 `SwappedInvalidAddressException`（携带
   `swap_offset` 与原始 entry），断言检查对应审计窗口内不存在任何
   `swap_layers` 读取——代码里只有按精确编号的 `dict.get(n)`，没有
   相邻编号回退。
2. **无效条目高位不得当物理页号**：PFN 只在 `_page_is_valid` 为真时才
   通过 `_pte_pfn` 提取。C3b/C4 在状态机阶段就抛异常，物理层读取从未
   发生；断言用审计日志硬性保证。

## 异常中的地址证据

自定义异常类字段与 `volatility3/framework/exceptions.py` 同名：
`layer_name`、`invalid_address`、`entry`、`invalid_bits`，换出异常额外
带 `swap_offset`，prototype 断裂额外带 `proto_pa`。报告中每条失败用例
都打印这些字段，而不是只给一句“读不到”。

## 关于 prototype 二级解析的说明

当前仓库是裁剪版 Volatility 3（`volatility3/plugins/windows` 下没有
VAD/memmap 类插件），基础翻译层只识别 bit10 并把 prototype 视为无效。
脚本中的 subsection→PPTE→重新进入状态机流程，是按 intel.py:500 引用的
Windows Internals (6th Ed, Part 2, pp.268-269) 做的教学建模，合成约定
为“prototype PTE 高位保存 PPTE 的页对齐物理地址”，报告输出中已标注。
