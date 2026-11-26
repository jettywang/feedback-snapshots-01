# wheel_evidence — 离线 Wheel 证据清册

值班场景：只拿到一枚 wheel，需要判断某个命令名究竟是

- 控制台入口（`entry_points.txt` 的 `[console_scripts]` / `[gui_scripts]`），
- 插件声明（任意其他 entry-point 组），还是
- 实际归档脚本（`*.data/scripts/*` 或带 shebang 的归档成员）。

工具只用 Python 标准库，不联网、不安装、不执行 wheel 内代码，也不解压到磁盘
（全部在 zip 内读取），因此不会在报告里留下分析机/构建机的绝对路径。

## 调用

在仓库根目录（或把仓库根加入 `PYTHONPATH`）：

```sh
python3 -m wheel_evidence inventory     包.whl [--json]          # 完整清册
python3 -m wheel_evidence entry-points  包.whl [--section console_scripts] [--json]
python3 -m wheel_evidence scripts       包.whl [--json]          # 脚本路径
python3 -m wheel_evidence command       包.whl 命令名 [--json]    # 规范化同名关联
python3 -m wheel_evidence verify        包.whl [--json]          # 全成员 RECORD 校验
```

系统自带 Python 3.9 即可运行；开发验证使用仓库 `.venv`（Python 3.12）。

## 规范化

命令名按 PEP 503 风格规范化：小写并把连续的 `-`/`_`/`.` 折叠为单个 `-`。
例如 `EVIDENCE_PROBE` 与 `evidence-probe` 视为同一查询键，但报告始终同时保留
原始声明名。不同区段、不同证据种类里的同名项不会互相覆盖，而是作为
`claims` 数组同时列出（`same_name_coexists=true`）。

## 判定等级（逐项落到成员与 RECORD 行）

| 判定 `verdict` | 含义 | 可信程度 |
| --- | --- | --- |
| `verified` | 成员在归档中，sha256（及大小）与 RECORD 行一致 | `high` |
| `digest_mismatch` | 成员在归档中，但摘要/大小与 RECORD 冲突 | `conflict` |
| `missing_from_archive` | RECORD 有行，归档里却没有该成员 | `conflict` |
| `unverified` | 成员在归档中，但没有可用摘要证据：未登记 RECORD、RECORD 摘要为空（RECORD 自身按 PEP 427 必须为空）或算法不支持 | `indeterminate` |
| `source_required` | 声明与目标模块字节可以核实，但 dotted object 是否存在、是否可调用、行为如何，需要源码或导入才能确认 | `source-required` |
| `not_packaged` | 入口点目标模块不在本 wheel（可能由依赖提供），同样导向源码/依赖核查 | `indeterminate` |

每条结论的 `evidence_refs` 给出 `成员路径:L行号 [区段]` 与 `RECORD:L行号`
两类锚点；JSON 中还保留 `digest_record` / `digest_actual` / `record_line`。

## 路径卫生

报告的 `wheel.filename` 只保留 basename；所有来源都是 wheel 内部 arcname。
即使以绝对路径传入 wheel，JSON/文本/错误输出都不会回显该绝对路径，也没有
临时解压目录路径。`wheel_evidence/test_inventory.py` 对此有专门断言。

## 测试

```sh
.venv/bin/python -m pytest wheel_evidence/test_inventory.py -q -o addopts=''
```

测试用内存/临时 wheel 覆盖：已核实、摘要冲突、未登记成员、RECORD 自身空摘要、
RECORD 有/归档无、三名共存、规范化变体、`.py` stem 匹配、可执行位与路径不泄漏。
