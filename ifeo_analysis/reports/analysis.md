# IFEO / SilentProcessExit 离线 hive 分析报告

> 结论边界：本报告只分析注册表配置证据，不执行、不验证任何真实程序，也不把配置存在等同于劫持生效。

## 1. 方法

- 使用 `dissect.regf.RegistryHive` 直接解析 hive；原生视图与 `Wow6432Node` 视图分别取证，不跨视图合并。
- 每个值保留原始字节、类型、大小与重复次数；类型/宽度/空值不合法时进入问题列表，并从机制判定中排除。
- `Debugger` 重定向与 `SilentProcessExit` 监控是独立候选机制；`GlobalFlag`/`UseFilter` 不单独等同于“劫持生效”。
- 环境变量保留原文；只有显式提供 `--assume-env NAME=VALUE` 时才产生候选展开，且标注为未验证。

候选展开假设（仅用于展示，不代表目标机真实环境）：

- `%ProgramFiles%` → `C:\Program Files`
- `%SystemRoot%` → `C:\Windows`

## 2. 字段语义与联合判定

| 证据 | 位置 | 单独出现时的含义 | 联合关系 |
| --- | --- | --- | --- |
| `Debugger` | `...\Image File Execution Options\<image>` | IFEO 调试器重定向候选 | 与 SilentProcessExit 无必然关系；类型必须合法 |
| `GlobalFlag` | 同上 | DWORD 位图；`0x200` 与 SilentProcessExit 监控相关 | 必须与同视图同映像的 `MonitorProcess` 共同成立 |
| `UseFilter` | 同上 | DWORD 开关；`1` 为启用过滤候选 | 还需合法 `FilterFullPath` 条件；`0` 时条件保留但不启用 |
| `FilterFullPath` | 映像键值或直接子键 | 一个路径条件候选 | 多个条件全部保留；hive 不证明匹配优先级或 AND/OR 语义 |
| `MonitorProcess` | `...\SilentProcessExit\<image>` | 监控程序路径候选 | 缺 `GlobalFlag` 的 `0x200` 位时不能认定 SilentProcessExit 生效 |
| `ReportingMode` | 同上 | DWORD 报告模式 | 记录数值；缺失不阻断监控候选，但列入信息缺失 |

候选机制的最低共同证据：

- `IFEO_DEBUGGER_REDIRECT_CANDIDATE`：同视图存在类型合法、非空 `Debugger`。
- `SILENT_PROCESS_EXIT_MONITOR_CANDIDATE`：同视图 `GlobalFlag` 是 4 字节 `REG_DWORD` 且含 `0x200`，且 `SilentProcessExit\<image>` 有类型合法、非空 `MonitorProcess`。
- `IFEO_FILTER_CONDITION_CANDIDATE`：同视图 `UseFilter=1` 且至少一条合法 `FilterFullPath`。它只说明 IFEO 路径过滤候选；hive 不证明该过滤同时门控 SilentProcessExit。
- `MONITOR_WITHOUT_FLAG_ORPHAN` / `FLAG_WITHOUT_MONITOR` / `USEFILTER_WITHOUT_FILTER_CONDITION` / `FILTER_CONDITION_NOT_ENABLED`：不完整或惰性配置，仅作线索。

## 3. 样本总览

| 样本 | 原生视图映像 | Wow6432Node 映像 | 机制集合 |
| --- | --- | --- | --- |
| `case_a_monitor_only.hive` | monitor-only.exe | — | MONITOR_WITHOUT_FLAG_ORPHAN |
| `case_b_full_chain.hive` | full-chain.exe | — | IFEO_DEBUGGER_REDIRECT_CANDIDATE, SILENT_PROCESS_EXIT_MONITOR_CANDIDATE |
| `case_c_two_views.hive` | dual-view.exe | dual-view.exe | IFEO_DEBUGGER_REDIRECT_CANDIDATE, IFEO_FILTER_CONDITION_CANDIDATE, SILENT_PROCESS_EXIT_MONITOR_CANDIDATE |
| `case_d_ambiguous.hive` | bad-filter-type.exe, bad-flag-type.exe, bad-flag-width.exe, bad-monitor-type.exe, debugger-only.exe, duplicate.exe, env-missing.exe, filter-without-usefilter.exe, missing-monitor.exe, monitor-only-orphan.exe, multi-filter.exe, no-flag.exe, subkey-conflict.exe, usefilter-without-filter.exe | — | FILTER_CONDITION_NOT_ENABLED, FLAG_WITHOUT_MONITOR, IFEO_DEBUGGER_REDIRECT_CANDIDATE, IFEO_FILTER_CONDITION_CANDIDATE, MONITOR_WITHOUT_FLAG_ORPHAN, SILENT_PROCESS_EXIT_MONITOR_CANDIDATE, USEFILTER_WITHOUT_FILTER_CONDITION |

`dissect.regf` 的 `hive.dirty` 在实现上是 `xor32_crc(header[:508]) == CheckSum` 的结果，因此 `True` 表示校验和匹配，与变量名的常见直觉相反；本报告原样记录该布尔值，不据此判定 hive 损坏。

## 4. 对照矩阵

| 样本 / 映像 | 视图 | Debugger | GlobalFlag | UseFilter | 过滤条件 | MonitorProcess | 监控关联完整 | 候选机制 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `case_a_monitor_only.hive` / `monitor-only.exe` | native | — | — | — | — | `C:\Tools\monitor-only.exe` | 否 | MONITOR_WITHOUT_FLAG_ORPHAN |
| `case_b_full_chain.hive` / `full-chain.exe` | native | `C:\Tools\dbg64.exe` | 0x200 | — | — | `%SystemRoot%\Tools\monitor64.exe` | 是 | IFEO_DEBUGGER_REDIRECT_CANDIDATE<br>SILENT_PROCESS_EXIT_MONITOR_CANDIDATE |
| `case_c_two_views.hive` / `dual-view.exe` | native | `C:\Tools\dbg64.exe` | 0x200 | 1 | 2 条（2 合法） | `%SystemRoot%\Tools\monitor64.exe` | 是 | IFEO_DEBUGGER_REDIRECT_CANDIDATE<br>IFEO_FILTER_CONDITION_CANDIDATE<br>SILENT_PROCESS_EXIT_MONITOR_CANDIDATE |
| `case_c_two_views.hive` / `dual-view.exe` | wow6432 | `C:\Tools\dbg32.exe` | 0x200 | 1 | 1 条（1 合法） | `C:\Tools\monitor32.exe` | 是 | IFEO_DEBUGGER_REDIRECT_CANDIDATE<br>IFEO_FILTER_CONDITION_CANDIDATE<br>SILENT_PROCESS_EXIT_MONITOR_CANDIDATE |
| `case_d_ambiguous.hive` / `bad-filter-type.exe` | native | — | 0x200 | — | — | `C:\Tools\m2.exe` | 是 | SILENT_PROCESS_EXIT_MONITOR_CANDIDATE |
| `case_d_ambiguous.hive` / `bad-flag-type.exe` | native | — | — | 1 | — | `C:\Tools\m1.exe` | 否 | MONITOR_WITHOUT_FLAG_ORPHAN<br>USEFILTER_WITHOUT_FILTER_CONDITION |
| `case_d_ambiguous.hive` / `bad-flag-width.exe` | native | — | — | 1 | — | — | 否 | USEFILTER_WITHOUT_FILTER_CONDITION |
| `case_d_ambiguous.hive` / `bad-monitor-type.exe` | native | — | 0x200 | 1 | — | — | 否 | FLAG_WITHOUT_MONITOR<br>USEFILTER_WITHOUT_FILTER_CONDITION |
| `case_d_ambiguous.hive` / `debugger-only.exe` | native | `C:\Tools\debug-only.exe` | — | — | — | — | 否 | IFEO_DEBUGGER_REDIRECT_CANDIDATE |
| `case_d_ambiguous.hive` / `duplicate.exe` | native | — | 0x200 | 1（冲突） | — | `C:\Tools\m3.exe` | 是 | SILENT_PROCESS_EXIT_MONITOR_CANDIDATE |
| `case_d_ambiguous.hive` / `env-missing.exe` | native | — | — | — | — | `%MISSING_VAR%\m6.exe` | 否 | MONITOR_WITHOUT_FLAG_ORPHAN |
| `case_d_ambiguous.hive` / `filter-without-usefilter.exe` | native | — | 0x200 | 0 | 1 条（1 合法） | — | 否 | FLAG_WITHOUT_MONITOR<br>FILTER_CONDITION_NOT_ENABLED |
| `case_d_ambiguous.hive` / `missing-monitor.exe` | native | — | 0x200 | 1 | — | — | 否 | FLAG_WITHOUT_MONITOR<br>USEFILTER_WITHOUT_FILTER_CONDITION |
| `case_d_ambiguous.hive` / `monitor-only-orphan.exe` | native | — | — | — | — | `C:\Tools\m5.exe` | 否 | MONITOR_WITHOUT_FLAG_ORPHAN |
| `case_d_ambiguous.hive` / `multi-filter.exe` | native | — | 0x200 | 1 | 2 条（2 合法） | — | 否 | IFEO_FILTER_CONDITION_CANDIDATE<br>FLAG_WITHOUT_MONITOR |
| `case_d_ambiguous.hive` / `no-flag.exe` | native | `C:\Tools\dbg-no-flag.exe` | — | — | — | `C:\Tools\m4.exe` | 否 | IFEO_DEBUGGER_REDIRECT_CANDIDATE<br>MONITOR_WITHOUT_FLAG_ORPHAN |
| `case_d_ambiguous.hive` / `subkey-conflict.exe` | native | — | 0x200 | 1 | — | — | 否 | FLAG_WITHOUT_MONITOR<br>USEFILTER_WITHOUT_FILTER_CONDITION |
| `case_d_ambiguous.hive` / `usefilter-without-filter.exe` | native | — | 0x200 | 1 | — | — | 否 | FLAG_WITHOUT_MONITOR<br>USEFILTER_WITHOUT_FILTER_CONDITION |

### 各样本中“共同支持”的候选机制

| 样本 | 共同出现的证据 | 仍缺少/不能据此断言 | 支持的候选机制 |
| --- | --- | --- | --- |
| A 仅监控路径 | `SilentProcessExit\monitor-only.exe\MonitorProcess` + `ReportingMode` | 无 IFEO 键、无 `GlobalFlag 0x200` | `MONITOR_WITHOUT_FLAG_ORPHAN`，**不**支持 SilentProcessExit 生效 |
| B 标志与关联完整 | `Debugger` + `GlobalFlag=0x200` + `MonitorProcess`（同映像同视图） | 本次样本无过滤条件；未验证程序存在性/执行 | `IFEO_DEBUGGER_REDIRECT_CANDIDATE` 与 `SILENT_PROCESS_EXIT_MONITOR_CANDIDATE` |
| C 32/64 两套不同配置 | 两视图各自都有 `Debugger`、`GlobalFlag=0x200`、`MonitorProcess`、`UseFilter=1`、`FilterFullPath`；但 DBG/MON/过滤路径均不同 | hive 不证明进程位数、优先级或执行结果 | 两视图各自 `IFEO_DEBUGGER_REDIRECT_CANDIDATE` + `SILENT_PROCESS_EXIT_MONITOR_CANDIDATE` + `IFEO_FILTER_CONDITION_CANDIDATE` |
| D 非法/缺失/多条件 | 每个映像只保留实际出现的子集；重复值、错误类型、错误宽度、误放值全部记录 | 非法记录已从机制判定中排除；重复 `UseFilter` 使启用状态标记为不确定 | 逐映像输出 `MONITOR_WITHOUT_FLAG_ORPHAN`、`FLAG_WITHOUT_MONITOR`、`USEFILTER_WITHOUT_FILTER_CONDITION`、`FILTER_CONDITION_NOT_ENABLED` 等不完整线索 |

关键点：`Debugger` 本身不触发 SilentProcessExit；`GlobalFlag` 或 `MonitorProcess` 任一单独出现也不足以认定生效；只有同一视图、同一映像键下标志与监控路径同时合法成立，才输出 `SILENT_PROCESS_EXIT_MONITOR_CANDIDATE`。

## 5. 逐样本证据

### `case_a_monitor_only.hive`

- 5024 字节；hive 版本 5；`dissect.regf` 校验和比较结果 `True`（`True` 表示校验和匹配；该库变量名为 `dirty`，与直觉相反）；事务中 `False`。

**视图 `native` — `Microsoft\Windows NT\CurrentVersion`**

- 映像 `monitor-only.exe`
  - IFEO：`缺失`；SilentProcessExit：`Microsoft\Windows NT\CurrentVersion\SilentProcessExit\monitor-only.exe`
  - `Debugger`：缺失/不合法
  - `GlobalFlag`：缺失
  - `UseFilter`：缺失
  - 过滤条件：缺失
  - `MonitorProcess`：`C:\Tools\monitor-only.exe`（类型合法）；环境变量 `无`；候选展开 `C:\Tools\monitor-only.exe`；**未验证存在性/可执行性**
  - `ReportingMode`：`1`（合法）
  - 监控关联完整：`False`；必要缺失项：IFEO 映像键；参考信息缺失：无
  - 候选机制：`MONITOR_WITHOUT_FLAG_ORPHAN`
  - 说明：MonitorProcess 存在但缺少可用的 GlobalFlag 0x200，不能仅凭监控路径认定生效。

**视图 `wow6432` — `Wow6432Node\Microsoft\Windows NT\CurrentVersion`**

- 视图根键缺失；本视图无配置证据。

### `case_b_full_chain.hive`

- 5440 字节；hive 版本 5；`dissect.regf` 校验和比较结果 `True`（`True` 表示校验和匹配；该库变量名为 `dirty`，与直觉相反）；事务中 `False`。

**视图 `native` — `Microsoft\Windows NT\CurrentVersion`**

- 映像 `full-chain.exe`
  - IFEO：`Microsoft\Windows NT\CurrentVersion\Image File Execution Options\full-chain.exe`；SilentProcessExit：`Microsoft\Windows NT\CurrentVersion\SilentProcessExit\full-chain.exe`
  - `Debugger`：`C:\Tools\dbg64.exe`（类型合法）
    - 环境变量：`无`；候选展开：`C:\Tools\dbg64.exe`
  - `GlobalFlag`：值 `512`/类型 4/大小 4/合法；有效 `0x200` 位：`True`；取值冲突：`False`
  - `UseFilter`：缺失
  - 过滤条件：缺失
  - `MonitorProcess`：`%SystemRoot%\Tools\monitor64.exe`（类型合法）；环境变量 `['SystemRoot']`；候选展开 `C:\Windows\Tools\monitor64.exe`；**未验证存在性/可执行性**
  - `ReportingMode`：`1`（合法）
  - 监控关联完整：`True`；必要缺失项：无；参考信息缺失：无
  - 候选机制：`IFEO_DEBUGGER_REDIRECT_CANDIDATE`, `SILENT_PROCESS_EXIT_MONITOR_CANDIDATE`
  - 说明：Debugger 存在只说明 IFEO 重定向候选，不是执行证据。
  - 说明：GlobalFlag 的 0x200 位与 MonitorProcess 同时合法成立，支持 SilentProcessExit 监控候选。

**视图 `wow6432` — `Wow6432Node\Microsoft\Windows NT\CurrentVersion`**

- 视图根键缺失；本视图无配置证据。

### `case_c_two_views.hive`

- 7552 字节；hive 版本 5；`dissect.regf` 校验和比较结果 `True`（`True` 表示校验和匹配；该库变量名为 `dirty`，与直觉相反）；事务中 `False`。

**视图 `native` — `Microsoft\Windows NT\CurrentVersion`**

- 映像 `dual-view.exe`
  - IFEO：`Microsoft\Windows NT\CurrentVersion\Image File Execution Options\dual-view.exe`；SilentProcessExit：`Microsoft\Windows NT\CurrentVersion\SilentProcessExit\dual-view.exe`
  - `Debugger`：`C:\Tools\dbg64.exe`（类型合法）
    - 环境变量：`无`；候选展开：`C:\Tools\dbg64.exe`
  - `GlobalFlag`：值 `512`/类型 4/大小 4/合法；有效 `0x200` 位：`True`；取值冲突：`False`
  - `UseFilter`：值 `1`/类型 4/大小 4/合法；启用：`True`；取值冲突：`False`
  - 过滤条件（2 条，全部保留，不合并不去重）：
    - 子键 `filter-x64-a` / `C:\Apps64\dual-view.exe`（REG_SZ）
    - 子键 `filter-x64-b` / `%ProgramFiles%\Dual View\dual-view.exe`（REG_EXPAND_SZ）
  - `MonitorProcess`：`%SystemRoot%\Tools\monitor64.exe`（类型合法）；环境变量 `['SystemRoot']`；候选展开 `C:\Windows\Tools\monitor64.exe`；**未验证存在性/可执行性**
  - `ReportingMode`：`1`（合法）
  - 监控关联完整：`True`；必要缺失项：无；参考信息缺失：无
  - 候选机制：`IFEO_DEBUGGER_REDIRECT_CANDIDATE`, `IFEO_FILTER_CONDITION_CANDIDATE`, `SILENT_PROCESS_EXIT_MONITOR_CANDIDATE`
  - 说明：Debugger 存在只说明 IFEO 重定向候选，不是执行证据。
  - 说明：GlobalFlag 的 0x200 位与 MonitorProcess 同时合法成立，支持 SilentProcessExit 监控候选。

**视图 `wow6432` — `Wow6432Node\Microsoft\Windows NT\CurrentVersion`**

- 映像 `dual-view.exe`
  - IFEO：`Wow6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\dual-view.exe`；SilentProcessExit：`Wow6432Node\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\dual-view.exe`
  - `Debugger`：`C:\Tools\dbg32.exe`（类型合法）
    - 环境变量：`无`；候选展开：`C:\Tools\dbg32.exe`
  - `GlobalFlag`：值 `512`/类型 4/大小 4/合法；有效 `0x200` 位：`True`；取值冲突：`False`
  - `UseFilter`：值 `1`/类型 4/大小 4/合法；启用：`True`；取值冲突：`False`
  - 过滤条件（1 条，全部保留，不合并不去重）：
    - 子键 `filter-x86` / `C:\Apps32\dual-view.exe`（REG_SZ）
  - `MonitorProcess`：`C:\Tools\monitor32.exe`（类型合法）；环境变量 `无`；候选展开 `C:\Tools\monitor32.exe`；**未验证存在性/可执行性**
  - `ReportingMode`：`2`（合法）
  - 监控关联完整：`True`；必要缺失项：无；参考信息缺失：无
  - 候选机制：`IFEO_DEBUGGER_REDIRECT_CANDIDATE`, `IFEO_FILTER_CONDITION_CANDIDATE`, `SILENT_PROCESS_EXIT_MONITOR_CANDIDATE`
  - 说明：Debugger 存在只说明 IFEO 重定向候选，不是执行证据。
  - 说明：GlobalFlag 的 0x200 位与 MonitorProcess 同时合法成立，支持 SilentProcessExit 监控候选。

### `case_d_ambiguous.hive`

- 10240 字节；hive 版本 5；`dissect.regf` 校验和比较结果 `True`（`True` 表示校验和匹配；该库变量名为 `dirty`，与直觉相反）；事务中 `False`。

**视图 `native` — `Microsoft\Windows NT\CurrentVersion`**

- 映像 `bad-filter-type.exe`
  - IFEO：`Microsoft\Windows NT\CurrentVersion\Image File Execution Options\bad-filter-type.exe`；SilentProcessExit：`Microsoft\Windows NT\CurrentVersion\SilentProcessExit\bad-filter-type.exe`
  - `Debugger`：缺失/不合法
  - `GlobalFlag`：值 `512`/类型 4/大小 4/合法；有效 `0x200` 位：`True`；取值冲突：`False`
  - `UseFilter`：值 `None`/类型 1/大小 4/不合法；启用：`False`；取值冲突：`False`
  - 过滤条件：缺失
  - `MonitorProcess`：`C:\Tools\m2.exe`（类型合法）；环境变量 `无`；候选展开 `C:\Tools\m2.exe`；**未验证存在性/可执行性**
  - `ReportingMode`：`None`（缺失/不合法）
  - 监控关联完整：`True`；必要缺失项：无；参考信息缺失：Debugger（独立重定向线索，非监控必需）, ReportingMode（参考信息，非候选必要条件）
  - 候选机制：`SILENT_PROCESS_EXIT_MONITOR_CANDIDATE`
  - 问题记录：
    - `WRONG_TYPE`（error）：UseFilter 必须是 REG_DWORD，实际为 REG_SZ @ `Microsoft\Windows NT\CurrentVersion\Image File Execution Options\bad-filter-type.exe`
  - 说明：GlobalFlag 的 0x200 位与 MonitorProcess 同时合法成立，支持 SilentProcessExit 监控候选。
- 映像 `bad-flag-type.exe`
  - IFEO：`Microsoft\Windows NT\CurrentVersion\Image File Execution Options\bad-flag-type.exe`；SilentProcessExit：`Microsoft\Windows NT\CurrentVersion\SilentProcessExit\bad-flag-type.exe`
  - `Debugger`：缺失/不合法
  - `GlobalFlag`：值 `None`/类型 1/大小 8/不合法；有效 `0x200` 位：`False`；取值冲突：`False`
  - `UseFilter`：值 `1`/类型 4/大小 4/合法；启用：`True`；取值冲突：`False`
  - 过滤条件：缺失
  - `MonitorProcess`：`C:\Tools\m1.exe`（类型合法）；环境变量 `无`；候选展开 `C:\Tools\m1.exe`；**未验证存在性/可执行性**
  - `ReportingMode`：`None`（缺失/不合法）
  - 监控关联完整：`False`；必要缺失项：含 0x200 的 4 字节 REG_DWORD GlobalFlag；参考信息缺失：Debugger（独立重定向线索，非监控必需）, ReportingMode（参考信息，非候选必要条件）
  - 候选机制：`MONITOR_WITHOUT_FLAG_ORPHAN`, `USEFILTER_WITHOUT_FILTER_CONDITION`
  - 问题记录：
    - `WRONG_TYPE`（error）：GlobalFlag 必须是 REG_DWORD，实际为 REG_SZ @ `Microsoft\Windows NT\CurrentVersion\Image File Execution Options\bad-flag-type.exe`
  - 说明：MonitorProcess 存在但缺少可用的 GlobalFlag 0x200，不能仅凭监控路径认定生效。
- 映像 `bad-flag-width.exe`
  - IFEO：`Microsoft\Windows NT\CurrentVersion\Image File Execution Options\bad-flag-width.exe`；SilentProcessExit：`缺失`
  - `Debugger`：缺失/不合法
  - `GlobalFlag`：值 `None`/类型 4/大小 8/不合法；有效 `0x200` 位：`False`；取值冲突：`False`
  - `UseFilter`：值 `1`/类型 4/大小 4/合法；启用：`True`；取值冲突：`False`
  - 过滤条件：缺失
  - `MonitorProcess`：缺失
  - `ReportingMode`：`None`（缺失/不合法）
  - 监控关联完整：`False`；必要缺失项：含 0x200 的 4 字节 REG_DWORD GlobalFlag, SilentProcessExit 映像键；参考信息缺失：Debugger（独立重定向线索，非监控必需）
  - 候选机制：`USEFILTER_WITHOUT_FILTER_CONDITION`
  - 问题记录：
    - `WRONG_SIZE`（error）：GlobalFlag 必须是 4 字节 DWORD，实际为 8 字节 @ `Microsoft\Windows NT\CurrentVersion\Image File Execution Options\bad-flag-width.exe`
- 映像 `bad-monitor-type.exe`
  - IFEO：`Microsoft\Windows NT\CurrentVersion\Image File Execution Options\bad-monitor-type.exe`；SilentProcessExit：`Microsoft\Windows NT\CurrentVersion\SilentProcessExit\bad-monitor-type.exe`
  - `Debugger`：缺失/不合法
  - `GlobalFlag`：值 `512`/类型 4/大小 4/合法；有效 `0x200` 位：`True`；取值冲突：`False`
  - `UseFilter`：值 `1`/类型 4/大小 4/合法；启用：`True`；取值冲突：`False`
  - 过滤条件：缺失
  - `MonitorProcess`：有记录但不合法
  - `ReportingMode`：`None`（缺失/不合法）
  - 监控关联完整：`False`；必要缺失项：合法 MonitorProcess；参考信息缺失：Debugger（独立重定向线索，非监控必需）, ReportingMode（参考信息，非候选必要条件）
  - 候选机制：`FLAG_WITHOUT_MONITOR`, `USEFILTER_WITHOUT_FILTER_CONDITION`
  - 问题记录：
    - `WRONG_TYPE`（error）：MonitorProcess 必须是 REG_SZ 或 REG_EXPAND_SZ，实际为 REG_DWORD @ `Microsoft\Windows NT\CurrentVersion\SilentProcessExit\bad-monitor-type.exe`
  - 说明：GlobalFlag 的 0x200 位存在但 MonitorProcess 不可用，关联不完整。
- 映像 `debugger-only.exe`
  - IFEO：`Microsoft\Windows NT\CurrentVersion\Image File Execution Options\debugger-only.exe`；SilentProcessExit：`缺失`
  - `Debugger`：`C:\Tools\debug-only.exe`（类型合法）
    - 环境变量：`无`；候选展开：`C:\Tools\debug-only.exe`
  - `GlobalFlag`：缺失
  - `UseFilter`：缺失
  - 过滤条件：缺失
  - `MonitorProcess`：缺失
  - `ReportingMode`：`None`（缺失/不合法）
  - 监控关联完整：`False`；必要缺失项：含 0x200 的 4 字节 REG_DWORD GlobalFlag, SilentProcessExit 映像键；参考信息缺失：无
  - 候选机制：`IFEO_DEBUGGER_REDIRECT_CANDIDATE`
  - 说明：Debugger 存在只说明 IFEO 重定向候选，不是执行证据。
- 映像 `duplicate.exe`
  - IFEO：`Microsoft\Windows NT\CurrentVersion\Image File Execution Options\duplicate.exe`；SilentProcessExit：`Microsoft\Windows NT\CurrentVersion\SilentProcessExit\duplicate.exe`
  - `Debugger`：缺失/不合法
  - `GlobalFlag`：值 `512`/类型 4/大小 4/合法；有效 `0x200` 位：`True`；取值冲突：`False`
  - `UseFilter`：值 `1`/类型 4/大小 4/合法；值 `None`/类型 1/大小 4/不合法；启用：`False`；取值冲突：`True`
  - 过滤条件：缺失
  - `MonitorProcess`：`C:\Tools\m3.exe`（类型合法）；环境变量 `无`；候选展开 `C:\Tools\m3.exe`；**未验证存在性/可执行性**
  - `ReportingMode`：`None`（缺失/不合法）
  - 监控关联完整：`True`；必要缺失项：无；参考信息缺失：Debugger（独立重定向线索，非监控必需）, ReportingMode（参考信息，非候选必要条件）
  - 候选机制：`SILENT_PROCESS_EXIT_MONITOR_CANDIDATE`
  - 问题记录：
    - `DUPLICATE_VALUE_NAME`（error）：同一键内 'usefilter' 出现 2 次；全部记录保留，但 hive 本身不说明哪个值生效 @ `Microsoft\Windows NT\CurrentVersion\Image File Execution Options\duplicate.exe`
    - `WRONG_TYPE`（error）：UseFilter 必须是 REG_DWORD，实际为 REG_SZ @ `Microsoft\Windows NT\CurrentVersion\Image File Execution Options\duplicate.exe`
  - 说明：UseFilter 存在重复或冲突记录，过滤启用状态不确定；这不改变 GlobalFlag+MonitorProcess 的监控关联判定。
  - 说明：GlobalFlag 的 0x200 位与 MonitorProcess 同时合法成立，支持 SilentProcessExit 监控候选。
- 映像 `env-missing.exe`
  - IFEO：`缺失`；SilentProcessExit：`Microsoft\Windows NT\CurrentVersion\SilentProcessExit\env-missing.exe`
  - `Debugger`：缺失/不合法
  - `GlobalFlag`：缺失
  - `UseFilter`：缺失
  - 过滤条件：缺失
  - `MonitorProcess`：`%MISSING_VAR%\m6.exe`（类型合法）；环境变量 `['MISSING_VAR']`；候选展开 `未展开`；**未验证存在性/可执行性**
  - `ReportingMode`：`1`（合法）
  - 监控关联完整：`False`；必要缺失项：IFEO 映像键；参考信息缺失：无
  - 候选机制：`MONITOR_WITHOUT_FLAG_ORPHAN`
  - 说明：MonitorProcess 存在但缺少可用的 GlobalFlag 0x200，不能仅凭监控路径认定生效。
- 映像 `filter-without-usefilter.exe`
  - IFEO：`Microsoft\Windows NT\CurrentVersion\Image File Execution Options\filter-without-usefilter.exe`；SilentProcessExit：`缺失`
  - `Debugger`：缺失/不合法
  - `GlobalFlag`：值 `512`/类型 4/大小 4/合法；有效 `0x200` 位：`True`；取值冲突：`False`
  - `UseFilter`：值 `0`/类型 4/大小 4/合法；启用：`False`；取值冲突：`False`
  - 过滤条件（1 条，全部保留，不合并不去重）：
    - 子键 `inert-filter` / `C:\Apps\Inert\filter-without-usefilter.exe`（REG_SZ）
  - `MonitorProcess`：缺失
  - `ReportingMode`：`None`（缺失/不合法）
  - 监控关联完整：`False`；必要缺失项：SilentProcessExit 映像键；参考信息缺失：Debugger（独立重定向线索，非监控必需）
  - 候选机制：`FLAG_WITHOUT_MONITOR`, `FILTER_CONDITION_NOT_ENABLED`
  - 说明：GlobalFlag 的 0x200 位存在但 MonitorProcess 不可用，关联不完整。
- 映像 `missing-monitor.exe`
  - IFEO：`Microsoft\Windows NT\CurrentVersion\Image File Execution Options\missing-monitor.exe`；SilentProcessExit：`Microsoft\Windows NT\CurrentVersion\SilentProcessExit\missing-monitor.exe`
  - `Debugger`：缺失/不合法
  - `GlobalFlag`：值 `512`/类型 4/大小 4/合法；有效 `0x200` 位：`True`；取值冲突：`False`
  - `UseFilter`：值 `1`/类型 4/大小 4/合法；启用：`True`；取值冲突：`False`
  - 过滤条件：缺失
  - `MonitorProcess`：缺失
  - `ReportingMode`：`1`（合法）
  - 监控关联完整：`False`；必要缺失项：合法 MonitorProcess；参考信息缺失：Debugger（独立重定向线索，非监控必需）
  - 候选机制：`FLAG_WITHOUT_MONITOR`, `USEFILTER_WITHOUT_FILTER_CONDITION`
  - 说明：GlobalFlag 的 0x200 位存在但 MonitorProcess 不可用，关联不完整。
- 映像 `monitor-only-orphan.exe`
  - IFEO：`缺失`；SilentProcessExit：`Microsoft\Windows NT\CurrentVersion\SilentProcessExit\monitor-only-orphan.exe`
  - `Debugger`：缺失/不合法
  - `GlobalFlag`：缺失
  - `UseFilter`：缺失
  - 过滤条件：缺失
  - `MonitorProcess`：`C:\Tools\m5.exe`（类型合法）；环境变量 `无`；候选展开 `C:\Tools\m5.exe`；**未验证存在性/可执行性**
  - `ReportingMode`：`None`（缺失/不合法）
  - 监控关联完整：`False`；必要缺失项：IFEO 映像键；参考信息缺失：ReportingMode（参考信息，非候选必要条件）
  - 候选机制：`MONITOR_WITHOUT_FLAG_ORPHAN`
  - 说明：MonitorProcess 存在但缺少可用的 GlobalFlag 0x200，不能仅凭监控路径认定生效。
- 映像 `multi-filter.exe`
  - IFEO：`Microsoft\Windows NT\CurrentVersion\Image File Execution Options\multi-filter.exe`；SilentProcessExit：`缺失`
  - `Debugger`：缺失/不合法
  - `GlobalFlag`：值 `512`/类型 4/大小 4/合法；有效 `0x200` 位：`True`；取值冲突：`False`
  - `UseFilter`：值 `1`/类型 4/大小 4/合法；启用：`True`；取值冲突：`False`
  - 过滤条件（2 条，全部保留，不合并不去重）：
    - 子键 `filter-1` / `C:\Apps\Multi\multi-filter.exe`（REG_SZ）
    - 子键 `filter-2` / `%ProgramFiles%\Multi\multi-filter.exe`（REG_EXPAND_SZ）
  - `MonitorProcess`：缺失
  - `ReportingMode`：`None`（缺失/不合法）
  - 监控关联完整：`False`；必要缺失项：SilentProcessExit 映像键；参考信息缺失：Debugger（独立重定向线索，非监控必需）
  - 候选机制：`IFEO_FILTER_CONDITION_CANDIDATE`, `FLAG_WITHOUT_MONITOR`
  - 说明：GlobalFlag 的 0x200 位存在但 MonitorProcess 不可用，关联不完整。
- 映像 `no-flag.exe`
  - IFEO：`Microsoft\Windows NT\CurrentVersion\Image File Execution Options\no-flag.exe`；SilentProcessExit：`Microsoft\Windows NT\CurrentVersion\SilentProcessExit\no-flag.exe`
  - `Debugger`：`C:\Tools\dbg-no-flag.exe`（类型合法）
    - 环境变量：`无`；候选展开：`C:\Tools\dbg-no-flag.exe`
  - `GlobalFlag`：缺失
  - `UseFilter`：缺失
  - 过滤条件：缺失
  - `MonitorProcess`：`C:\Tools\m4.exe`（类型合法）；环境变量 `无`；候选展开 `C:\Tools\m4.exe`；**未验证存在性/可执行性**
  - `ReportingMode`：`None`（缺失/不合法）
  - 监控关联完整：`False`；必要缺失项：含 0x200 的 4 字节 REG_DWORD GlobalFlag；参考信息缺失：ReportingMode（参考信息，非候选必要条件）
  - 候选机制：`IFEO_DEBUGGER_REDIRECT_CANDIDATE`, `MONITOR_WITHOUT_FLAG_ORPHAN`
  - 说明：Debugger 存在只说明 IFEO 重定向候选，不是执行证据。
  - 说明：MonitorProcess 存在但缺少可用的 GlobalFlag 0x200，不能仅凭监控路径认定生效。
- 映像 `subkey-conflict.exe`
  - IFEO：`Microsoft\Windows NT\CurrentVersion\Image File Execution Options\subkey-conflict.exe`；SilentProcessExit：`缺失`
  - `Debugger`：缺失/不合法
  - `GlobalFlag`：值 `512`/类型 4/大小 4/合法；有效 `0x200` 位：`True`；取值冲突：`False`
  - `UseFilter`：值 `1`/类型 4/大小 4/合法；启用：`True`；取值冲突：`False`
  - 过滤条件：缺失
  - `MonitorProcess`：缺失
  - `ReportingMode`：`None`（缺失/不合法）
  - 监控关联完整：`False`；必要缺失项：SilentProcessExit 映像键；参考信息缺失：Debugger（独立重定向线索，非监控必需）
  - 候选机制：`FLAG_WITHOUT_MONITOR`, `USEFILTER_WITHOUT_FILTER_CONDITION`
  - 问题记录：
    - `FILTER_SUBKEY_WITHOUT_FILTERFULLPATH`（warning）：子键 'subkey-conflict.exe' 存在但没有 FilterFullPath；保留为结构线索 @ `Microsoft\Windows NT\CurrentVersion\Image File Execution Options\subkey-conflict.exe\subkey-conflict.exe`
    - `MISPLACED_ASSOCIATION_VALUE`（warning）：MonitorProcess 出现在 IFEO 映像键的子键 'subkey-conflict.exe' 中；不作为关联依据，也未当作过滤条件 @ `Microsoft\Windows NT\CurrentVersion\Image File Execution Options\subkey-conflict.exe\subkey-conflict.exe`
  - 说明：GlobalFlag 的 0x200 位存在但 MonitorProcess 不可用，关联不完整。
- 映像 `usefilter-without-filter.exe`
  - IFEO：`Microsoft\Windows NT\CurrentVersion\Image File Execution Options\usefilter-without-filter.exe`；SilentProcessExit：`缺失`
  - `Debugger`：缺失/不合法
  - `GlobalFlag`：值 `512`/类型 4/大小 4/合法；有效 `0x200` 位：`True`；取值冲突：`False`
  - `UseFilter`：值 `1`/类型 4/大小 4/合法；启用：`True`；取值冲突：`False`
  - 过滤条件：缺失
  - `MonitorProcess`：缺失
  - `ReportingMode`：`None`（缺失/不合法）
  - 监控关联完整：`False`；必要缺失项：SilentProcessExit 映像键；参考信息缺失：Debugger（独立重定向线索，非监控必需）
  - 候选机制：`FLAG_WITHOUT_MONITOR`, `USEFILTER_WITHOUT_FILTER_CONDITION`
  - 说明：GlobalFlag 的 0x200 位存在但 MonitorProcess 不可用，关联不完整。

**视图 `wow6432` — `Wow6432Node\Microsoft\Windows NT\CurrentVersion`**

- 视图根键缺失；本视图无配置证据。

## 6. 原始值保留

以下表格给出所有解析到的 IFEO/SilentProcessExit 值，包括重复项；`data_hex` 为 `dissect.regf` 返回的原始数据。

| 样本 | 视图 | 键路径 | 值名 | 类型 | 大小 | data_hex |
| --- | --- | --- | --- | --- | --- | --- |
| `case_a_monitor_only.hive` | native | `Microsoft\Windows NT\CurrentVersion\SilentProcessExit\monitor-only.exe` | `MonitorProcess` | REG_SZ | 52 | `43003a005c0054006f006f006c0073005c006d006f006e00690074006f0072002d006f006e006c0079002e006500780065000000` |
| `case_a_monitor_only.hive` | native | `Microsoft\Windows NT\CurrentVersion\SilentProcessExit\monitor-only.exe` | `ReportingMode` | REG_DWORD | 4 | `01000000` |
| `case_b_full_chain.hive` | native | `Microsoft\Windows NT\CurrentVersion\Image File Execution Options\full-chain.exe` | `Debugger` | REG_SZ | 38 | `43003a005c0054006f006f006c0073005c00640062006700360034002e006500780065000000` |
| `case_b_full_chain.hive` | native | `Microsoft\Windows NT\CurrentVersion\Image File Execution Options\full-chain.exe` | `GlobalFlag` | REG_DWORD | 4 | `00020000` |
| `case_b_full_chain.hive` | native | `Microsoft\Windows NT\CurrentVersion\SilentProcessExit\full-chain.exe` | `MonitorProcess` | REG_EXPAND_SZ | 66 | `2500530079007300740065006d0052006f006f00740025005c0054006f006f006c0073005c006d006f006e00690074006f007200360034002e006500780065000000` |
| `case_b_full_chain.hive` | native | `Microsoft\Windows NT\CurrentVersion\SilentProcessExit\full-chain.exe` | `ReportingMode` | REG_DWORD | 4 | `01000000` |
| `case_c_two_views.hive` | native | `Microsoft\Windows NT\CurrentVersion\Image File Execution Options\dual-view.exe` | `Debugger` | REG_SZ | 38 | `43003a005c0054006f006f006c0073005c00640062006700360034002e006500780065000000` |
| `case_c_two_views.hive` | native | `Microsoft\Windows NT\CurrentVersion\Image File Execution Options\dual-view.exe` | `GlobalFlag` | REG_DWORD | 4 | `00020000` |
| `case_c_two_views.hive` | native | `Microsoft\Windows NT\CurrentVersion\Image File Execution Options\dual-view.exe` | `UseFilter` | REG_DWORD | 4 | `01000000` |
| `case_c_two_views.hive` | native | `Microsoft\Windows NT\CurrentVersion\SilentProcessExit\dual-view.exe` | `MonitorProcess` | REG_EXPAND_SZ | 66 | `2500530079007300740065006d0052006f006f00740025005c0054006f006f006c0073005c006d006f006e00690074006f007200360034002e006500780065000000` |
| `case_c_two_views.hive` | native | `Microsoft\Windows NT\CurrentVersion\SilentProcessExit\dual-view.exe` | `ReportingMode` | REG_DWORD | 4 | `01000000` |
| `case_c_two_views.hive` | native | `Microsoft\Windows NT\CurrentVersion\Image File Execution Options\dual-view.exe\filter-x64-a` | `FilterFullPath` | REG_SZ | 48 | `43003a005c004100700070007300360034005c006400750061006c002d0076006900650077002e006500780065000000` |
| `case_c_two_views.hive` | native | `Microsoft\Windows NT\CurrentVersion\Image File Execution Options\dual-view.exe\filter-x64-b` | `FilterFullPath` | REG_EXPAND_SZ | 78 | `2500500072006f006700720061006d00460069006c006500730025005c004400750061006c00200056006900650077005c006400750061006c002d0076006900650077002e006500780065000000` |
| `case_c_two_views.hive` | wow6432 | `Wow6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\dual-view.exe` | `Debugger` | REG_SZ | 38 | `43003a005c0054006f006f006c0073005c00640062006700330032002e006500780065000000` |
| `case_c_two_views.hive` | wow6432 | `Wow6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\dual-view.exe` | `GlobalFlag` | REG_DWORD | 4 | `00020000` |
| `case_c_two_views.hive` | wow6432 | `Wow6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\dual-view.exe` | `UseFilter` | REG_DWORD | 4 | `01000000` |
| `case_c_two_views.hive` | wow6432 | `Wow6432Node\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\dual-view.exe` | `MonitorProcess` | REG_SZ | 46 | `43003a005c0054006f006f006c0073005c006d006f006e00690074006f007200330032002e006500780065000000` |
| `case_c_two_views.hive` | wow6432 | `Wow6432Node\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\dual-view.exe` | `ReportingMode` | REG_DWORD | 4 | `02000000` |
| `case_c_two_views.hive` | wow6432 | `Wow6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\dual-view.exe\filter-x86` | `FilterFullPath` | REG_SZ | 48 | `43003a005c004100700070007300330032005c006400750061006c002d0076006900650077002e006500780065000000` |
| `case_d_ambiguous.hive` | native | `Microsoft\Windows NT\CurrentVersion\Image File Execution Options\bad-filter-type.exe` | `GlobalFlag` | REG_DWORD | 4 | `00020000` |
| `case_d_ambiguous.hive` | native | `Microsoft\Windows NT\CurrentVersion\Image File Execution Options\bad-filter-type.exe` | `UseFilter` | REG_SZ | 4 | `31000000` |
| `case_d_ambiguous.hive` | native | `Microsoft\Windows NT\CurrentVersion\SilentProcessExit\bad-filter-type.exe` | `MonitorProcess` | REG_SZ | 32 | `43003a005c0054006f006f006c0073005c006d0032002e006500780065000000` |
| `case_d_ambiguous.hive` | native | `Microsoft\Windows NT\CurrentVersion\Image File Execution Options\bad-flag-type.exe` | `GlobalFlag` | REG_SZ | 8 | `3500310032000000` |
| `case_d_ambiguous.hive` | native | `Microsoft\Windows NT\CurrentVersion\Image File Execution Options\bad-flag-type.exe` | `UseFilter` | REG_DWORD | 4 | `01000000` |
| `case_d_ambiguous.hive` | native | `Microsoft\Windows NT\CurrentVersion\SilentProcessExit\bad-flag-type.exe` | `MonitorProcess` | REG_SZ | 32 | `43003a005c0054006f006f006c0073005c006d0031002e006500780065000000` |
| `case_d_ambiguous.hive` | native | `Microsoft\Windows NT\CurrentVersion\Image File Execution Options\bad-flag-width.exe` | `GlobalFlag` | REG_DWORD | 8 | `0002000000000000` |
| `case_d_ambiguous.hive` | native | `Microsoft\Windows NT\CurrentVersion\Image File Execution Options\bad-flag-width.exe` | `UseFilter` | REG_DWORD | 4 | `01000000` |
| `case_d_ambiguous.hive` | native | `Microsoft\Windows NT\CurrentVersion\Image File Execution Options\bad-monitor-type.exe` | `GlobalFlag` | REG_DWORD | 4 | `00020000` |
| `case_d_ambiguous.hive` | native | `Microsoft\Windows NT\CurrentVersion\Image File Execution Options\bad-monitor-type.exe` | `UseFilter` | REG_DWORD | 4 | `01000000` |
| `case_d_ambiguous.hive` | native | `Microsoft\Windows NT\CurrentVersion\SilentProcessExit\bad-monitor-type.exe` | `MonitorProcess` | REG_DWORD | 4 | `01000000` |
| `case_d_ambiguous.hive` | native | `Microsoft\Windows NT\CurrentVersion\Image File Execution Options\debugger-only.exe` | `Debugger` | REG_SZ | 48 | `43003a005c0054006f006f006c0073005c00640065006200750067002d006f006e006c0079002e006500780065000000` |
| `case_d_ambiguous.hive` | native | `Microsoft\Windows NT\CurrentVersion\Image File Execution Options\duplicate.exe` | `GlobalFlag` | REG_DWORD | 4 | `00020000` |
| `case_d_ambiguous.hive` | native | `Microsoft\Windows NT\CurrentVersion\Image File Execution Options\duplicate.exe` | `UseFilter` | REG_DWORD | 4 | `01000000` |
| `case_d_ambiguous.hive` | native | `Microsoft\Windows NT\CurrentVersion\Image File Execution Options\duplicate.exe` | `UseFilter` | REG_SZ | 4 | `31000000` |
| `case_d_ambiguous.hive` | native | `Microsoft\Windows NT\CurrentVersion\SilentProcessExit\duplicate.exe` | `MonitorProcess` | REG_SZ | 32 | `43003a005c0054006f006f006c0073005c006d0033002e006500780065000000` |
| `case_d_ambiguous.hive` | native | `Microsoft\Windows NT\CurrentVersion\SilentProcessExit\env-missing.exe` | `MonitorProcess` | REG_EXPAND_SZ | 42 | `25004d0049005300530049004e0047005f0056004100520025005c006d0036002e006500780065000000` |
| `case_d_ambiguous.hive` | native | `Microsoft\Windows NT\CurrentVersion\SilentProcessExit\env-missing.exe` | `ReportingMode` | REG_DWORD | 4 | `01000000` |
| `case_d_ambiguous.hive` | native | `Microsoft\Windows NT\CurrentVersion\Image File Execution Options\filter-without-usefilter.exe` | `GlobalFlag` | REG_DWORD | 4 | `00020000` |
| `case_d_ambiguous.hive` | native | `Microsoft\Windows NT\CurrentVersion\Image File Execution Options\filter-without-usefilter.exe` | `UseFilter` | REG_DWORD | 4 | `00000000` |
| `case_d_ambiguous.hive` | native | `Microsoft\Windows NT\CurrentVersion\Image File Execution Options\filter-without-usefilter.exe\inert-filter` | `FilterFullPath` | REG_SZ | 86 | `43003a005c0041007000700073005c0049006e006500720074005c00660069006c007400650072002d0077006900740068006f00750074002d00750073006500660069006c007400650072002e006500780065000000` |
| `case_d_ambiguous.hive` | native | `Microsoft\Windows NT\CurrentVersion\Image File Execution Options\missing-monitor.exe` | `GlobalFlag` | REG_DWORD | 4 | `00020000` |
| `case_d_ambiguous.hive` | native | `Microsoft\Windows NT\CurrentVersion\Image File Execution Options\missing-monitor.exe` | `UseFilter` | REG_DWORD | 4 | `01000000` |
| `case_d_ambiguous.hive` | native | `Microsoft\Windows NT\CurrentVersion\SilentProcessExit\missing-monitor.exe` | `ReportingMode` | REG_DWORD | 4 | `01000000` |
| `case_d_ambiguous.hive` | native | `Microsoft\Windows NT\CurrentVersion\SilentProcessExit\monitor-only-orphan.exe` | `MonitorProcess` | REG_SZ | 32 | `43003a005c0054006f006f006c0073005c006d0035002e006500780065000000` |
| `case_d_ambiguous.hive` | native | `Microsoft\Windows NT\CurrentVersion\Image File Execution Options\multi-filter.exe` | `GlobalFlag` | REG_DWORD | 4 | `00020000` |
| `case_d_ambiguous.hive` | native | `Microsoft\Windows NT\CurrentVersion\Image File Execution Options\multi-filter.exe` | `UseFilter` | REG_DWORD | 4 | `01000000` |
| `case_d_ambiguous.hive` | native | `Microsoft\Windows NT\CurrentVersion\Image File Execution Options\multi-filter.exe\filter-1` | `FilterFullPath` | REG_SZ | 62 | `43003a005c0041007000700073005c004d0075006c00740069005c006d0075006c00740069002d00660069006c007400650072002e006500780065000000` |
| `case_d_ambiguous.hive` | native | `Microsoft\Windows NT\CurrentVersion\Image File Execution Options\multi-filter.exe\filter-2` | `FilterFullPath` | REG_EXPAND_SZ | 76 | `2500500072006f006700720061006d00460069006c006500730025005c004d0075006c00740069005c006d0075006c00740069002d00660069006c007400650072002e006500780065000000` |
| `case_d_ambiguous.hive` | native | `Microsoft\Windows NT\CurrentVersion\Image File Execution Options\no-flag.exe` | `Debugger` | REG_SZ | 50 | `43003a005c0054006f006f006c0073005c006400620067002d006e006f002d0066006c00610067002e006500780065000000` |
| `case_d_ambiguous.hive` | native | `Microsoft\Windows NT\CurrentVersion\SilentProcessExit\no-flag.exe` | `MonitorProcess` | REG_SZ | 32 | `43003a005c0054006f006f006c0073005c006d0034002e006500780065000000` |
| `case_d_ambiguous.hive` | native | `Microsoft\Windows NT\CurrentVersion\Image File Execution Options\subkey-conflict.exe` | `GlobalFlag` | REG_DWORD | 4 | `00020000` |
| `case_d_ambiguous.hive` | native | `Microsoft\Windows NT\CurrentVersion\Image File Execution Options\subkey-conflict.exe` | `UseFilter` | REG_DWORD | 4 | `01000000` |
| `case_d_ambiguous.hive` | native | `Microsoft\Windows NT\CurrentVersion\Image File Execution Options\usefilter-without-filter.exe` | `GlobalFlag` | REG_DWORD | 4 | `00020000` |
| `case_d_ambiguous.hive` | native | `Microsoft\Windows NT\CurrentVersion\Image File Execution Options\usefilter-without-filter.exe` | `UseFilter` | REG_DWORD | 4 | `01000000` |

## 7. 32/64 位视图结论

- `case_a_monitor_only.hive`：没有同名映像同时出现在两视图，未做跨视图外推。
- `case_b_full_chain.hive`：没有同名映像同时出现在两视图，未做跨视图外推。
- `case_c_two_views.hive` / `dual-view.exe`：原生视图 DBG=`C:\Tools\dbg64.exe`、MON=`%SystemRoot%\Tools\monitor64.exe`、过滤 2 条；Wow6432Node DBG=`C:\Tools\dbg32.exe`、MON=`C:\Tools\monitor32.exe`、过滤 1 条；两套配置不同，必须按目标进程位数分别解释。
- `case_d_ambiguous.hive`：没有同名映像同时出现在两视图，未做跨视图外推。

32 位进程通常读取 `Wow6432Node`，64 位进程读取原生视图；仅凭 hive 无法确定未来启动哪个位数的进程，因此不把任一视图的配置外推到另一视图。

## 8. 复现

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
```

样本是最小合成 REGF 文件，仅用于验证解析与判定逻辑；其中程序路径均为占位符，未执行或验证。
