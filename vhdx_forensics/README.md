# VHDX 日志取证工具包（只读）

针对“带非空日志的 VHDX 被直接读取并误称为崩溃前最后状态”的核查工具。所有脚本对
证据文件只读；重放仅在内存中进行，绝不回写。

## 文件

| 文件 | 作用 |
|---|---|
| `vhdx_audit.py` | 只读审计：双 header / 双 region / BAT / 变更日志、CRC-32C、GUID 链接、序列号、三分类 |
| `crc32c.py` | 纯 Python CRC-32C（Castagnoli） |
| `safe_replay.py` | 内存重放引擎，含四项可重放性闸门，不安全即拒绝 |
| `make_synthetic.py` | 生成 5 个合成变体（clean/active/orphan/bat_pending/corrupt） |
| `run_comparison.py` | 直接读取 vs 审计分类 vs 安全恢复视图 三向对照 |
| `audit_cli.py` | 对任意 VHDX 输出完整审计文本 |
| `test_forensics.py` | 自测（6 项） |
| `REPORT.md` | 完整核查报告与接收建议 |

## 快速开始

```sh
.venv/bin/python vhdx_forensics/make_synthetic.py vhdx_forensics/synthetic
.venv/bin/python vhdx_forensics/run_comparison.py
.venv/bin/python vhdx_forensics/audit_cli.py <your.vhdx>
.venv/bin/python -m pytest -q vhdx_forensics/test_forensics.py
```

## 三分类

- `APPLIED / clean`：无待重放日志，直接读取即最后提交状态。
- `CONFIRMED-BUT-NOT-APPLIED`：日志有效且 GUID 链接、CRC、序列均成立，需先在副本重放。
- `INSUFFICIENT-MATERIAL`：日志可扫描但不可链接/校验/连续，禁止重放，不得称崩溃前最后状态。
