# IFEO / SilentProcessExit 离线 hive 分析

本目录提供：

- `build_samples.py`：生成四个最小、合法的 REGF 合成样本（单 hbin、`nk`/`vk`/`lf` 结构）。
- `analyze.py`：仅基于 `dissect.regf` 解析，按视图逐映像关联证据并生成 JSON/Markdown。
- `test_samples.py`：8 项回归测试，覆盖“仅监控路径”“完整链路”“32/64 双视图”“非法/重复/缺失”。
- `samples/`：生成的 hive；`reports/`：最近一次分析结果。

## 复现

```sh
.venv/bin/python ifeo_analysis/build_samples.py
.venv/bin/python ifeo_analysis/analyze.py \
  ifeo_analysis/samples/case_a_monitor_only.hive \
  ifeo_analysis/samples/case_b_full_chain.hive \
  ifeo_analysis/samples/case_c_two_views.hive \
  ifeo_analysis/samples/case_d_ambiguous.hive \
  --assume-env 'SystemRoot=C:\Windows' \
  --assume-env 'ProgramFiles=C:\Program Files' \
  --json ifeo_analysis/reports/analysis.json \
  --markdown ifeo_analysis/reports/analysis.md
.venv/bin/python -m pytest -q ifeo_analysis/test_samples.py
```

## 判定边界

- 配置存在只是候选机制，不是执行证据；不运行、不验证样本中的任何程序。
- 原生视图和 `Wow6432Node` 分开分析，不互相外推。
- `Debugger` 与 SilentProcessExit 是两条独立线索；`GlobalFlag=0x200` 必须与同视图、同映像的合法 `MonitorProcess` 联合成立。
- `UseFilter=1` + 合法 `FilterFullPath` 只支持 `IFEO_FILTER_CONDITION_CANDIDATE`；hive 不证明该过滤同时门控 SilentProcessExit。
- 每个值保留类型、大小、原始字节和重复出现次数；类型/宽度/空值非法时报告并从判定中排除。
- `%VAR%` 保持原文；只有传入 `--assume-env` 时才给出候选展开，且明确标注未验证。

## 样本说明

| 样本 | 目的 |
| --- | --- |
| `case_a_monitor_only.hive` | 只有监控路径；验证不会仅凭 `MonitorProcess` 认定生效 |
| `case_b_full_chain.hive` | `Debugger` + `GlobalFlag=0x200` + `MonitorProcess`；验证完整关联 |
| `case_c_two_views.hive` | 原生与 Wow6432Node 同名映像、不同 DBG/MON/过滤配置 |
| `case_d_ambiguous.hive` | 非法类型/宽度、重复值、缺失关联、多个过滤条件、错误位置值 |

报告中的程序路径均为占位符。真实案件请把实际 SOFTWARE hive 传给 `analyze.py`，并注意快照/事务状态与 hive 校验和语义。
