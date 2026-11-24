# Dynaconf inspect 证据边界：同终值下判断“环境是否写过安全设置”

适用问题：合规同事拿到一份 Dynaconf `inspect` 输出，两次运行的
`security.require_mfa` 最终值都是 `true`，但怀疑其中一次的环境变量曾写入
（且写的是同一个 `true`）。本实验用**本地文件 + 环境变量 + 运行时设置**搭出
A/B 两条轨迹，加入**嵌套合并**和**同一个 env loader 的两次再次加载**，先固定
每一步“实际收到的输入 + 有效值”，再核对最终历史里剩下的来源，并给出历史缺失
时的证明边界。

- 核对版本：Dynaconf `3.3.6.dev0`（仓库本地源码），Python `3.12.11`。
  所用 API（`inspect_settings` / `get_history` / `loaded_by_loaders` /
  `env_loader.load`）属于 3.3.x；具体槽位细节可能随版本变化，正式出证前应在
  目标版本重跑本实验。
- 调查键：`security.require_mfa`（布尔叶子，路径写法
  `security.require_mfa` 或环境变量 `DYNACONF_SECURITY__REQUIRE_MFA`）。

---

## 1. 结论先行

1. **相同终值本身不提供任何来源信息。** `current=true` 至少与五种过程相容：
   文件给 `true`；环境用同值 `true` 覆盖；运行时 `set(true)`；先直改成
   `false` 再改回；历史槽位被折叠或截断。
2. **若拿到的是完整、未截断、针对叶子键的 inspect `history`**：在本实验的
   B 轨迹中可以证明 env loader 曾处理并写入该键——历史里存在
   `loader=env_global, identifier=DYNACONF, env=global` 的
   `SourceMetadata` 槽位，叶子值为 `true`。Dynaconf **不做“值是否变化”的判断，
   同值写入一样留来源记录**。A 的目标叶子历史中没有 env 条目（A 也有同名
   `env_global/DYNACONF` 槽位，但里面只有折叠探针 `LAB_PROBE`，不含本键）。
3. **首次证据分歧**：输入侧是步骤 `S0` 的进程环境（B 有
   `DYNACONF_SECURITY__REQUIRE_MFA="true"`，A 没有）；最终历史侧，按
   `(loader, identifier, env, merged)` 四元组对齐（old-first），`json`
   槽位相同，紧随其后的就是 **B 独有的 `env_global/DYNACONF` 槽位**。
   机器判定见 `out/divergence.json`。
4. **“曾被环境写入”不等于“值被环境改变”，也不等于“终值最后由环境决定”。**
   - 同值写入没有造成可观察的值变化；
   - 本实验在 env 之后还有运行时 `set` 和嵌套直改，按时间序最后一个**有历史
     记录**的写入来自 `set_method/undefined`，最后一次无历史写入是 S5b 的
     嵌套属性还原。要回答“终值由谁决定”，必须按 old-first 顺序重放，不能只看
     `current`。
5. **历史不是完整录像。** 同一 `SourceMetadata` 槽位重复写同一顶层键会覆盖
   旧 raw 值（探针 P1）；合并槽位的 `value` 是被原地改写后的累积对象，不是
   当时收到的原始输入（P2）；嵌套属性直改不进历史，持续偏离只会留下
   “`current` 与全部历史值矛盾”这一间接信号，还原后则完全无痕（P3）；加载后
   才注入且不 reload 的环境变量在 inspect 中不存在（P4）；`LazySettings`
   的证据零点是首次访问而非 `Dynaconf(...)` 语句（P5）。
6. **只有一份最终 inspect 时能下哪些结论，见第 6 节的判定表**；多数“是否曾
   被环境覆盖”的肯定/否定结论都需要补充观察。

---

## 2. 怎么重跑

```bash
cd inspect_evidence_lab
./run_evidence_lab.sh                 # 自动选择 ../.venv/bin/python
# 或指定解释器（需要能 import dynaconf）：
PYTHON=/path/to/python ./run_evidence_lab.sh
# 也可以直接：
python3 evidence_lab.py all
```

一键命令会：生成 `labwork/security.json` 与 `labwork/cli_settings.py`；
以独立子进程跑 A、B 两条轨迹和 P1–P5 探针；写出下列产物并重建
`out/comparison.md`（完整逐步对照表）。

产物清单（`inspect_evidence_lab/out/`）：

- `comparison.md`：自动生成的完整对照表（逐步输入/有效值、set 边界 trace、
  历史槽位对齐、折叠与全部探针）。
- `divergence.json`：首次输入分歧、首次有效值分歧（为 `null`）、首次历史槽位
  分歧的机器判定。
- `track_A.json` / `track_B.json`：每一步的完整输入、有效值、入口 trace、
  叶子历史、相关槽位。
- `A.inspect.json` / `B.inspect.json`：等价于
  `inspect_settings(key="security.require_mfa")` 的报告（new-first）。
- `A.inspect.yaml` / `B.inspect.yaml`：YAML 版 inspect 报告。
- `B.limit2.json`：`history_limit=2` 的报告，演示截断如何藏掉 env 来源。
- `*.inspect-all.json`：不带 key 的全量 inspect。
- `*.slots.json`：与 `SECURITY`/`LAB_PROBE` 相关的
  `loaded_by_loaders` 槽位；`*.loaded_by_loaders.full.json` 是全部槽位。
- `*.current-only.json`：模拟“只剩一个终值”的最小证据。
- `probes.json`：P1–P5 边界探针的结构化结果。

用官方 CLI 做最小复现（只含文件 + 启动环境，不含后续步骤）：

```bash
cd inspect_evidence_lab/labwork
DYNACONF_SECURITY__REQUIRE_MFA=true \
  ../../.venv/bin/dynaconf -i cli_settings.settings \
  inspect -k security.require_mfa -f json
```

---

## 3. 两条轨迹与逐步对照表（本次运行快照）

两条轨迹执行**完全相同的脚本步骤**，唯一受控差异是进程初始环境：

- A（`no-env`）：没有 `DYNACONF_SECURITY__REQUIRE_MFA`。
- B（`env-same-value`）：有 `DYNACONF_SECURITY__REQUIRE_MFA="true"`
  （原始字符串，经 env loader 的 tomlfy 解析为布尔 `true`，与文件同值）。

本地文件 `labwork/security.json`（两轨相同）：

```json
{
  "security": {
    "require_mfa": true,
    "session_timeout": 30,
    "policy": {"min_password_length": 12, "issuer": "corp-local"}
  }
}
```

逐步“实际输入 × 有效值”对照（完整字段见 `out/comparison.md` 第 1 节）：

| 步骤 | A 实际收到的输入 | A leaf | B 实际收到的输入 | B leaf | 输入分歧字段 |
|---|---|---|---|---|---|
| S0 进程环境快照 | `DYNACONF_* = {}` | `null` | `{"DYNACONF_SECURITY__REQUIRE_MFA":"true"}` | `null` | `dynaconf_env` |
| S1 文件 + 初始化期 env loader | `Dynaconf(settings_files=['labwork/security.json'], merge_enabled=True)` | `true` | 同左（但进程 env 不同） | `true` | `process_env` |
| S2 运行时嵌套合并 | `s.set('SECURITY', {"policy":{"mfa_provider":"totp"}}, merge=True)` | `true` | 同左 | `true` | — |
| S3 运行时同值 set | `s.set('security.require_mfa', True)` | `true` | 同左 | `true` | — |
| S4a env loader 再加载第 1 次 | `DYNACONF_LAB_PROBE='pass-1'; env_loader.load(s)` | `true` | 同左（env 中仍含目标变量） | `true` | `dynaconf_env_at_pass` |
| S4b env loader 再加载第 2 次 | `DYNACONF_LAB_PROBE='pass-2'; env_loader.load(s)` | `true` | 同左 | `true` | `dynaconf_env_at_pass` |
| S5a 绕过 `set` 的嵌套直改 | `s.security.require_mfa = False` | `false` | 同左 | `false` | — |
| S5b 嵌套直改还原 | `s.security.require_mfa = True` | `true` | 同左 | `true` | — |

要点：

- **两条轨迹每一步的有效值都相同**（`out/divergence.json` 中
  `first_effective_divergence = null`），包括 S5a 的瞬时 `false`——终值相同，
  全过程值序列也相同。差异只在“输入/来源”侧。
- **嵌套合并可见**：S1 后 `security` 含
  `require_mfa/session_timeout/policy{min_password_length,issuer}`；B 的 env
  只给一个叶子，兄弟键全部保留。S2 用 `merge=True` 只补
  `policy.mfa_provider`，其余键保留（完整映射见 `out/comparison.md` 第 2 节）。
- **“实际收到的输入”要在边界固定**：env loader 在调用 `set` 前已用
  `parse_conf_data(..., tomlfy=True)` 把 `"true"` 解析成布尔 `true`，所以
  `Settings.set` 入口 trace 看到的已经是 `true`；**原始字符串只能来自 S0/S4
  的 `os.environ` 快照**，文件原始内容只能来自文件本身。脚本在 `set` 入口对
  `value` 做了深拷贝，避免被后续 `object_merge` 原地改写污染。

---

## 4. 最终留在历史中的来源（核对）

`get_history(s, "security.require_mfa")` 按 `loaded_by_loaders` 的插入顺序
返回（old-first）。按 `SourceMetadata` 四元组对齐后（本次运行结果）：

| A# | B# | loader | identifier | env | merged | A value | B value |
|---:|---:|---|---|---|---|---|---|
| 0 | 0 | `json` | `labwork/security.json` | `default` | false | true | true |
| — | 1 | `env_global` | `DYNACONF` | `global` | false | — | true |
| 1 | 2 | `set_method` | `undefined` | `global` | true | true | true |
| 2 | 3 | `set_method` | `undefined` | `global` | false | true | true |

怎么读这张表：

- `json`：本地文件来源，两轨一致。
- `env_global/DYNACONF`：**首次证据分歧**。对目标叶子而言仅 B 有值（表中 A#
  为 `—`）；A 的同名槽位只装了 `LAB_PROBE`，所以按叶子查询时该来源被跳过。它证明 B 进程里 env
  loader 把前缀 `DYNACONF` 下解析出的该叶子写进了 settings。注意
  `identifier` 是**变量前缀**而不是完整变量名，也不是当时的环境全集。
- `set_method/undefined, merged=true`：S2 的运行时嵌套合并槽位。它的最终
  blob 是**累积合并后的整个 `SECURITY`**（探针 P2），因此叶子历史里也会列出
  它且 `require_mfa=true`——但 S2 的入参
  `{"policy":{"mfa_provider":"totp"}}` **根本没有显式写 `require_mfa`**。
  即：“某来源出现在叶子历史里”不等于“该来源显式提供了这个叶子”。
- `set_method/undefined, merged=false`：S3 的 dotted `set`。dotted 键会经
  `_dotted_set` 重建整个顶层 `SECURITY` 再重入 `set`，所以该槽位保存的也是
  重建后的完整对象（trace 中 depth=1 的行）。
- S4 的两次 env loader 再加载都复用同一个
  `env_global/DYNACONF/global/false` 槽位（B 的目标变量保持 `true`，未触发
  merged 翻转），因此**不会新增行**；它们对目标键的写入覆盖同一槽位。
- S5a/S5b 的嵌套属性直改**不调用 `Settings.set`，历史零新增**。

顺序与“终值归属”：new-first 的 `B.inspect.json` 顺序是
`set_method(false 槽位) → set_method(true 槽位) → env_global → json`。
`current` 不标注 winner；要判断“最后一次有记录的写入”，取 old-first 末尾
槽位并结合步骤日志（本案为 S3 的 `set_method`，其后的 S5b 直改无记录）。

### 截断陷阱（只看最终 inspect 时尤其重要）

`B.limit2.json` 用 `history_limit=2` 且默认 new-first，只保留最新两条：

```text
[set_method/undefined/merged=False, set_method/undefined/merged=True]
```

**env 与 json 两条来源都被切掉**。报告 `header.history_limit` 会写明 `"2"`。
因此看到有限条数的 inspect 时，先读 `header`：带 `history_limit` 或导出者只
贴了“相关几行”，“列表里没有 env”不能作为 env 不存在的证据。

---

## 5. 同一个 loader 再次加载：折叠与变形（P1、P2）

- **P1 同槽位折叠（确定性）**：对同一个 settings 连续两次调用
  `env_loader.load(s)`，只改变 `DYNACONF_LAB_PROBE`：
  - 实际输入序列：`pass-1` → `pass-2`，有效值序列：`first` → `second`；
  - 最终 `LAB_PROBE` 叶子历史只有一条
    `env_global/DYNACONF ... value='second'`，槽位
    `loaded_by_loaders[SourceMetadata(env_global,DYNACONF,global,False)]`
    也只有 `{"LAB_PROBE":"second"}`。
  - 原因在 `dynaconf/base.py` 的 `set`：相同 `SourceMetadata` 已存在时执行
    `loaded_by_loaders[md][key] = value`，按顶层键覆盖。**较早的 `pass-1`
    无法从最终 inspect 恢复**，只有当时的步骤日志/环境快照能证明。
- **P2 “raw value” 不是原始输入**：`object_merge(old, new)` 会把 old 合并进
  new 并**原地改写 new**（见 `dynaconf/utils/__init__.py` 文档串 “new is
  mutated in-place”）。S2 入口深拷贝固定的输入只有
  `{"policy":{"mfa_provider":"totp"}}`，而最终
  `set_method/undefined/merged=True` 槽位的 `SECURITY` blob 是含文件全部键
  的累积对象。出证时不能把该 blob 当作“该步骤实际收到的原始报文”。
- **merged 标志会制造新槽位**：当重加载的值与现值不同且真正发生 dict 合并时，
  `_merge_before_set` 会把 metadata `_replace(merged=True)`，四元组变化，
  于是历史里可能多出一个 `merged=True` 的 env 槽位（实验中改变嵌套值重加载
  时观察到）。这能让两次加载都留下痕迹，但它是实现路径的副产品，**不能当成
  “每次 reload 必留一条独立记录”的审计保证**。
- **`load_file()` 的来源名带调用点**：其 `loader` 字段形如
  `load_file@<调用文件>:<行号>`，通常与初始化期的 `json` 槽位不同；但在
  `3.3.6.dev0` 上，`@invalidates_cache` 包装器会让该调用点可能落到
  `dynaconf/base.py:279`（包装器内 `return func(...)`），不能仅凭这一行号
  断言业务调用位置。相同路径多次 `load_file` 是否同槽位，取决于该调用点字符串
  与四元组是否完全一致，应在目标版本实测。

---

## 6. 只给一份最终 inspect：结论判定表与需要补充的观察

证据力从弱到强：**L0 只有 current → L1 完整未截断 key history →
L2 完整 `loaded_by_loaders` + 入口/步骤 trace → L3 进程外观察**。

| 想下的结论 | 只给 `current=true` | 给完整 key `history`（无 limit） | 仍需补充的观察 |
|---|---|---|---|
| 导出报告时该键有效值为 `true` | 可证明 | 可证明 | 报告导出时点之后的变化不在内 |
| B 运行中 env loader 曾写入该键（即使同值） | 不可判定 | **可证明**：存在 `env_global/<前缀>` 槽位且含该叶子 | 若 history 被截断/折叠则需重导完整报告或 `loaded_by_loaders`；要原始变量值/变量名需启动 env 快照 |
| A 运行中 env 没碰过该键 | 不可判定 | 在“完整、未截断、无折叠疑点”前提下可作否定判断 | 仍建议用启动 `os.environ`/编排 env 核对，排除未加载、前缀不符或 LazySettings 时点问题 |
| env 覆盖“改变了值”（false→true） | 不可判定 | **不能证明**：历史不记前值/差异，同值也留痕 | 每步前后值日志（本实验 S 表）、文件原值与 env 值比对、应用审计日志 |
| 终值“最后由 env 决定” | 不可判定 | 需按 old-first 末尾槽位重放；本案末尾有 runtime/直改，故不能这么说 | 加载/赋值调用顺序与代码路径 |
| 没有任何其他来源/主体碰过该键 | 不可判定 | 不能：折叠、截断、嵌套直改都会缺席 | `loaded_by_loaders` 全量、代码中所有写入口、运行时审计 |
| 曾发生过瞬时 `false`（后还原） | 不可判定 | 不可判定：还原后 current 与历史相容，无异常（P3） | 当时的 trace/APM/审计日志；最终 inspect 对此无证明力 |
| current 与所有历史叶子值矛盾（如 current=false，历史全 true） | 看不到历史 | **可证明存在“历史未记录的写入”**，但不知主体/时间/入口 | 代码内嵌套直改、共享 dict 别名、外部改写；需运行时 trace 定位 |
| 加载后才注入的某 env 变量曾存在 | 不可判定 | 不可判定：未 reload 时查询直接 `KeyNotFoundError`（P4） | 进程 env 快照、shell/CI/编排日志、secret 注入审计 |
| 在 `Dynaconf(...)` 与首次访问之间注入 env 是否算“启动环境” | 不可判定 | 取决于首次 `get` 时点：LazySettings 会把首次访问前注入的变量正常加载（P5） | 代码中第一次访问 settings 的位置/时点 |
| 原始环境字符串是 `"true"` 还是 `"1"`/`"yes"` | 不可判定 | 不能：history 给的是 tomlfy 解析后的布尔 `true` | `os.environ` 快照（注意脱敏）、`/proc/<pid>/environ`、容器/CI env 记录 |
| 哪台机器、哪个进程、谁、何时操作 | 不可判定 | 不含这些字段；槽位无时间戳/PID | 部署记录、镜像摘要、ConfigMap/secret 版本、平台审计、进程日志 |
| 另一次没有导出 inspect 的运行 | 不可判定 | 该报告对它无证明力（历史是进程内内存态，进程结束即失） | 那次运行自己的导出物或外部日志 |

建议的补充取证动作：

1. 要**完整报告**：无 `history_limit` 的 key JSON + 不带 key 的全量 JSON +
   `loaded_by_loaders` 全量 dump（本脚本产物可直接当模板）。
2. 固定**启动环境**：启动时落一份脱敏的
   `env | grep '^DYNACONF_' > dynaconf-env.snapshot`；Linux 事后可取
   `/proc/<pid>/environ`（需权限且进程仍存活）；K8s/CI 取编排与 secret 审计。
3. 固定**文件来源**：`security.json` 原件、哈希、mtime、镜像/ConfigMap 版本。
4. 需要强时序证据时，在应用启动期包一层 `Settings.set` 审计日志（参考
   `evidence_lab.py` 的 `install_set_trace`：在入口深拷贝 value 并记录
   `SourceMetadata`），或直接使用本脚本的步骤记录模式。
5. 先确认报告 `header`：`key_filter` 是不是叶子路径、`history_limit`、
   `new_first`、`include_internal`。

---

## 7. 接手者指南：从相同终值找到首次证据分歧

1. 拿到两边**未截断**的 key inspect（建议统一转 old-first；本实验直接用
   `track_*.json` 的 `leaf_history_old_first`）。
2. 用 `(loader, identifier, env, merged)` 四元组对齐槽位，**不要按显示行号**：
   B 多出的 env 行会让后续行整体错位。
3. 找第一个“仅一侧存在，或同槽位叶子值不同”的位置——本案是
   `env_global/DYNACONF/global/false`（B 独有，值 `true`）。
4. 回到 `S0`/环境快照找该槽位对应的**原始输入**（`"true"` 字符串），再到
   `out/comparison.md` 第 3 节看 `set` 边界事件确认解析与写入路径。
5. 如果对不齐（条数因 `limit` 缺失、同槽位折叠、current 与历史矛盾），停止
   下“env 没碰过”的否定结论，按第 6 节清单补证。
6. 自动化判定：`python3 evidence_lab.py all` 后查看
   `out/divergence.json`：
   - `first_effective_divergence: null` 表示全程有效值无分歧；
   - `first_input_divergence.step = "S0"`；
   - `first_history_slot_divergence.metadata.loader = "env_global"`。

### 证据边界一句话总括

- **完整 history 能证明“本进程的某个 loader 槽位记录过这个叶子”**，并足以在
  同终值的两个导出物之间定位首个来源分歧；
- **它不能证明原始报文、值是否变化、精确时间/主体，也不能覆盖被同槽位覆盖的
  旧值、绕过 `set` 的嵌套直改、截断掉的条目、未 reload 的晚到 env，以及没有
  导出 inspect 的其他运行**；
- 这些“历史看不到”的部分，只能推进到“可证明存在未记录写入/证据被截断”或
  “完全不可由 inspect 证明”，必须借助当时的环境快照、文件原件和时序日志。
