# 证据实验：构建、对照与逐项核查

本目录是“值班只拿到 wheel”场景的离线实验。报告工具 `wheel_evidence/` 只读取
成品 wheel；样例工程源码仅用于复现构建，核查过程不读取源码。

## 一键复现

```sh
# 1) 用工作区内本地 poetry-core 2.5.0（editable）离线构建两枚 wheel，
#    并生成摘要不一致的对照轮
.venv/bin/python evidence_lab/build_fixtures.py

# 2) 只把 dist/ 里的成品 wheel 交给报告工具，生成 JSON + 文本清册
bash evidence_lab/generate_reports.sh

# 3) 逐项核查来源、冲突、可信度与路径泄漏（40 项断言）
.venv/bin/python evidence_lab/verify_reports.py

# 工具自测（11 项）
.venv/bin/python -m pytest wheel_evidence/test_inventory.py -q -o addopts=''
```

`generate_reports.sh` 会先调用 `make_edge_wheel.py` 生成边缘样本 C，再生成全部报告。

构建使用 `python -m build --wheel --no-isolation`，不访问网络；启动时会打印
`poetry.core.__file__`，确认后端来自本工作区 `src/poetry/core`。

## 成品清单

| 成品 | 角色 | wheel sha256（本次产物） |
| --- | --- | --- |
| `evidence_lab/dist/evidence_samename-1.0.0-py3-none-any.whl` | 同名三合一正例 A | `4916901c42b8db9d6572ef801b3cf55e413ff8d1890191536f4a856149bfd4f5` |
| `evidence_lab/dist/control/evidence_tampered-0.1.0-py3-none-any.whl` | 普通成员摘要不一致对照 B | `bc0dc39fb156e9d2da689386b34fd4731c68485435b562cd38ae72748eac883e` |
| `evidence_lab/dist/evidence_tampered-0.1.0-py3-none-any.whl` | B 篡改前原件 T（额外对照） | `aec9a2c7c086f5bc7ba65796a6f375af8be1922b7c4aba404a07929fd62fe991` |
| `evidence_lab/dist/edge/evidence_edge-0.1.0-py3-none-any.whl` | 边缘样本 C：归档脚本被漏登 RECORD（stdlib 造） | 以 `reports/C_edge_command.json` 现值为准 |

重新构建后 wheel sha256 可能变化，以 `reports/*.json` 中的现值为准。

## A：同一个 `evidence-probe` 的三种身份（同名共存）

构造方式（见 `evidence_lab/projects/evidence_samename/pyproject.toml`）：

- `[project.scripts] evidence-probe = "evidence_samename.cli:main"` →
  `entry_points.txt` 的 `[console_scripts]`；
- `[project.entry-points."evidence.probes"] evidence-probe = ...` →
  自定义插件组 `[evidence.probes]`；
- `[tool.poetry.scripts] evidence-probe = { type="file", reference="bin/evidence-probe" }`
  → poetry-core 原样归档为 `evidence_samename-1.0.0.data/scripts/evidence-probe`（0755）。

`python -m wheel_evidence command <A> EVIDENCE_PROBE` 会把规范化键
`evidence-probe`（大写与 `_` 均可归一）下的三项声明同时列出，
`same_name_coexists=true`，互不覆盖。

| 核查项 | 工具结论 | 实际成员来源 | RECORD 锚点 | 判定 / 可信度 |
| --- | --- | --- | --- | --- |
| 控制台入口 | `[console_scripts] evidence-probe → evidence_samename.cli:main`，定义 L2 | `evidence_samename-1.0.0.dist-info/entry_points.txt`（区段头 L1） | `RECORD:L7` | 声明 `verified` / `high` |
| 入口目标模块 | 成员存在，摘要一致 | `evidence_samename/cli.py` | `RECORD:L2` | `verified` / `high` |
| 入口可调用对象 `main` | dotted object 是否为预期可调用对象无法由 RECORD 证明 | — | — | `source_required` / `source-required` |
| 插件声明 | `[evidence.probes] evidence-probe → ...probe:build_probe`，定义 L5 | 同一个 `entry_points.txt`（区段头 L4） | `RECORD:L7` | 声明 `verified` / `high` |
| 插件目标模块 | 成员存在，摘要一致 | `evidence_samename/probe.py` | `RECORD:L3` | `verified` / `high`；可调用对象仍 `source_required` |
| 实际归档脚本 | `data_script`，权限 `0755`，可执行位真，shebang `#!/usr/bin/env python3` | `evidence_samename-1.0.0.data/scripts/evidence-probe` | `RECORD:L4` | `verified` / `high` |
| RECORD 自身 | PEP 427 规定自行摘要为空 | `evidence_samename-1.0.0.dist-info/RECORD` | `RECORD:L8`（`,,`） | `unverified`（`record_self_hash_absent`，属规范内的“无可用证据”） |

A 的 RECORD 审计：8 个文件成员，7 `verified`，1 `unverified`（RECORD 自身），
0 冲突；wheel 级信任 `record_consistent/high`。

## 三种要求区分的状态，分别落在哪里

1. **归档确实存在且摘要对得上**：A 的脚本、`cli.py`、`probe.py`、
   `entry_points.txt` 等，逐项给出 `digest_record == digest_actual` 与
   `RECORD:L行号`，判定 `verified/high`。
2. **归档里有但没有可用证据**：两枚 wheel 的 `*.dist-info/RECORD` 自身行都是
   `path,,`（无算法/摘要），判定 `unverified/indeterminate`，原因码
   `record_self_hash_absent`。更贴近命令核查的实物证据是边缘轮 C：
   `evidence_edge-0.1.0.data/scripts/ghost-cmd`（0755、带 shebang）确实在归档中，
   但被故意漏登 RECORD，`command ghost-cmd` 给出
   `verdict=unverified`、`confidence=indeterminate`、`record_line=null`、
   证据链末端为 `RECORD:no-row-for-member`；wheel 级信任码 `unlisted_members`。
   工具对“RECORD 摘要字段为空（非自身行）”另有 `record_hash_absent` 状态。
3. **还需要源码才能确认**：入口点/插件的“声明”和“目标模块字节”可以核实，
   但 `module:attr` 指向的属性是否存在、是否可调用、行为是否如命令名所示，
   判定 `source_required/source-required`；工具不导入、不执行 wheel 代码。

此外，安全核查必须有第四种**冲突**态：`digest_mismatch/conflict` 与
`missing_from_archive/conflict`。

## B：一条普通成员摘要不一致的对照

构建后对普通代码成员 `evidence_tampered/__init__.py` 做等长替换
（`pristine-control-value-0001` → `tampered-control-value-0001`，同为 27 字节，
文件大小保持 106），重写 zip 但**不改 RECORD**。

`verify` 结果（见 `reports/B_verify.txt`）：

```
[DIGEST-MISMATCH] evidence_tampered/__init__.py RECORD:L1
    expected sha256=6QBdnsb2WaRUd3_mrrW1UqXMvh9atINWjW68pyp10AU (106 bytes)
    actual   sha256=N6LmlUNO0El5Y3ajs2KyJHhtU6iQICOvGwwv9uhynlk (106 bytes)
trust=conflict (record_conflict)
```

- 恰好 1 条冲突，且是普通成员；大小相同，因此纯粹是摘要证据冲突。
- 同轮 `METADATA`、`WHEEL` 仍 `verified`，RECORD 自身仍为规范内 `unverified`。
- 篡改前原件 T 为 `record_consistent`，构成前后对照。

## 路径卫生

所有 `reports/*.json`、`reports/*.txt` 均只含 wheel basename 与归档内 arcname。
`verify_reports.py` 扫描每份报告，断言不含工作区绝对路径、`/Users/`、
`/private/var`、`/var/folders`；自测还覆盖“以绝对路径传入 wheel 且从其他
目录运行”时 stdout/错误 JSON 均不回显该路径。工具全程内存读 zip，无解压目录。

## 核查结论

`verify_reports.py`：**40/40 PASS**；`pytest wheel_evidence/`：**11 passed**。
报告工具对每个命令名分别给出来源成员、RECORD 行锚点、冲突值与可信程度，
同名身份可共存，三态 + 冲突态边界清晰，报告无生成机器全路径。
