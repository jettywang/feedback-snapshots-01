# 运行配置迁移审批包

这是一组**本地配对夹具 + 预览证据**，用于把老 `tox.ini` 迁到 `pyproject.toml` 时，判断“哪些配置可以沿用批准、哪些必须重新批准”。所有证据都由 `tox config` 的预览路径生成；**没有运行任何真实项目，没有创建环境、安装依赖或执行配置里的命令**。

## 1. 结论先行

审批依据不是“最终文本是否相同”，而是四层绑定是否同时保持：

1. **文件选择**：实际选中的配置文件及其候选文件集合。
2. **继承层级**：值从 `[testenv]` / `env_run_base` / section 链的哪一层解析出来。
3. **替换来源**：`{env:...}`、`{posargs}`、`{replace = "env"}`、`{replace = "ref"}` 最终从 `set_env`、宿主环境变量、默认值还是命令行取值。
4. **最终值**：配置物化后的值（命令参数、依赖列表、环境变量表等）。

判定规则：

| 判定 | 含义 | 是否可沿用原批准 |
| --- | --- | --- |
| `CARRY` | 最终值、层级、替换来源都不变 | 可以 |
| `TRANSLATED` | 仅格式翻译，语义层级和值一致 | 可以 |
| `IDENTITY` | 只有 `config_file_path` 变化 | 可以（记录即可） |
| `REVIEW` | 最终值相同，但来源、层级或替换绑定变了 | **不可以**，需要人工复核 |
| `REAPPROVE` | 最终值或存在性变了 | **必须重新批准** |
| `BLOCKED` | 任一侧加载失败 | **必须修复后重新批准** |

## 2. 选择、继承、替换之间的关系

三者不是三个独立步骤，而是依次收窄同一批候选值：

- **选择**决定“从哪个文件读”。`discover_source` 按 `_SOURCE_TYPES` 的顺序在同一目录挑第一个可加载的源。当前代码顺序是 `ToxIni, SetupCfg, TomlPyProject, LegacyToml, TomlTox`，即**同目录下 `tox.ini` 优先于 `tox.toml`**；而 `tools/generate_manpage.py` 第 118–129 行写的是 `tox.toml` 在前、`tox.ini` 在后、且“first file found is used”。这份文档与实现不一致，迁移时必须把实际选中的文件写进审批记录，不能按文档推断。
- **继承**决定“同一文件里从哪个 section 读”。INI 下是 `[testenv:NAME]` → `[testenv]`，TOML 下是 `env.NAME` → `env_base.NAME` → `env_run_base`；`base` 列表的顺序决定同名键谁先命中（`ConfigDynamicDefinition.__call__` 按 loader 顺序取第一个提供该键的 loader）。
- **替换**发生在值被物化的时候，会把“来源”改写成 `set_env`、宿主变量或默认值。关键点：同一段文本在 INI 和 TOML 里可能产出完全相同的最终值，但替换绑定不同；反过来，同一份配置在宿主变量变化时也可能分叉。

因此审批要绑定到“值 + 来源”，而不是只绑定到物化后的字符串。

## 3. 复现方法

以下命令都在仓库根目录执行，使用本地 `.venv`，不会联网，也不会跑配置里的命令。

```bash
# 1) 生成一份预览轨迹（文件选择、每个值的来源、替换绑定）
.venv/bin/python .feedback/migration-audit/audit.py trace \
  --project .feedback/migration-audit/work/a-lossless/after \
  --env integration --env unit --env lint \
  > "$TMPDIR/a-after.json"

# 2) 对比迁移前后的轨迹，得到逐键判定
.venv/bin/python .feedback/migration-audit/audit.py diff \
  .feedback/migration-audit/preview/a-lossless.before.json \
  .feedback/migration-audit/preview/a-lossless.after.json

# 3) 用已批准的命令清单做门禁
.venv/bin/python .feedback/migration-audit/audit.py gate \
  .feedback/migration-audit/gate.a-lossless.json \
  .feedback/migration-audit/preview/a-lossless.after.json
```

`trace` 只调用 `tox config` 的解析与物化路径；`diff` / `gate` 只读 JSON，不接触项目。`preview/` 里已保存本次的全部输出，可直接复核。需要一次重建所有证据时运行：

```bash
.feedback/migration-audit/run.sh
```

## 4. 配对证据一览

夹具位于 `fixtures/<case>/{before,after}/`，可直接 `tox config` 预览；`work/` 是同一份内容的可写副本，`preview/` 是实际输出。

| 案例 | 迁移动作 | 结论 | 关键证据 |
| --- | --- | --- | --- |
| `a-lossless` | `tox.ini` 等价翻译为 `pyproject.toml` 的 `[tool.tox]` | `approvable: true`（55 CARRY / 12 TRANSLATED / 1 IDENTITY） | `preview/a-lossless.diff.json`，门禁 `gate.a-lossless.json` 全部 KEEP |
| `b-origin` | 原 `set_env = DEPLOY_TARGET = {env:DEPLOY_TARGET:staging}` 被翻成字面量 `"staging"` | `REVIEW`：值相同但来源由 `env` 默认值变为字面量 | `preview/b-origin.diff.json`；宿主设为 `DEPLOY_TARGET=canary` 时旧配置得到 `canary`、迁移后仍是 `staging`（`preview/b-origin.before.host.json` / `.after.host.json`） |
| `c-shadow` | 删掉 `[tool.tox].legacy_tox_ini` 里被遮蔽的配置 | 迁移前后 28 项全部 `CARRY`；删除前 `unused: legacy_tox_ini`，删除后为空 | `preview/c-shadow.{before,after}.json` |
| `d-select` | 删除同目录 `tox.ini`，让 `tox.toml` 生效；两者内容等价 | 25 CARRY / 2 TRANSLATED / 1 IDENTITY，`approvable: true` | `preview/d-select.diff.json` |
| `d-select2` | 删除同目录 `tox.ini`，但 `tox.toml` 的 `commands` 与已批准内容不同 | `REAPPROVE`：`commands` 从 `pytest -q tests` 变为 `ruff check .` | `preview/d-select2.diff.json`，门禁 `gate.d-select2.json` 为 CHANGED |
| `e-provenance` | `commands` 中 `{env:TEST_SCOPE:...}` 改为固定文本；`set_env` 设为相同值 | `REVIEW`：最终命令相同，但替换绑定由 `TEST_SCOPE` 变为字面量 | `preview/e-provenance.diff.json`；把两边的 `TEST_SCOPE` 同时改为 `unit`，旧配置命令变成 `pytest -q -m unit tests`，新配置仍是 `pytest -q -m full tests` |
| `f-pkg` | 纯脚本项目（仅 `tox.ini`）改为在 `pyproject.toml` 中配置 | `REAPPROVE`：`package` 由 `skip` 变为 `sdist`，并新增 `package_env` / `package_tox_env_type` | `preview/f-pkg.diff.json`，门禁 `gate.f-pkg.json` 为 CHANGED |
| `g-order` | 同目录同时存在 `tox.ini` 与 `tox.toml` | 实际选中 `tox.ini`（`candidates: ['tox.ini', 'tox.toml']`），与 manpage 所述顺序相反 | `preview/g-order.json` |
| `h-badextend` | `{posargs}` 翻译成 `{ replace = "posargs", ... }` 时漏写 `extend = true` | `BLOCKED`：`commands` 加载失败 | `preview/h-badextend.diff.json` |

## 5. 至少一条“为什么必须重新批准”

以 `d-select2` 为例。迁移前项目同时有 `tox.ini` 和 `tox.toml`，开发者的直觉（以及 manpage 的排序）会认为 `tox.toml` 是主配置；实际 `discover_source` 选中了 `tox.ini`，因此已批准的是 `pytest -q tests`。删掉 `tox.ini` 后，同目录的 `tox.toml` 才第一次生效，其 `commands = [["ruff", "check", "."]]` 变成新值。

这不是格式翻译，而是**选中的文件变了、最终命令也变了**，所以必须重新批准 `d-select2` 里的 `py.commands`；门禁输出 `preview/gate.d-select2.json` 直接给出 `CHANGED`。

另一个“最终相同但来源不同”的例子是 `b-origin`：迁移前 `DEPLOY_TARGET` 来自宿主默认值 `staging`，迁移后是字面量 `staging`。在宿主变量变化时两者会分叉，所以按规则只能给 `REVIEW`，不能直接沿用批准。

## 6. 逐个迁移时的判定流程

对每个待迁移项目，按以下顺序做，不跳步：

1. **记录候选与选中文件**：在项目目录运行 `trace`，把 `selected.candidates` 和 `selected.path` 存档。若存在多个候选，先确认真正生效的是哪一个；不要按文档顺序推断。
2. **先冻结已批准集合**：从现有 `tox.ini`（或生产备份）生成 `before.json`，并写出 `gate.<case>.json`，只包含已经批准的环境与命令。
3. **做最小翻译**：优先直接改写为同语义的 TOML，不要顺手调整 `package`、`pass_env`、`set_env`。
4. **重复预览**：对迁移后的目录运行 `trace`，与 `before.json` 做 `diff`。
5. **按判定处理**：
   - `CARRY` / `TRANSLATED` / `IDENTITY`：记录后继续。
   - `REVIEW`：核对替换来源与宿主变量；如果能证明来源变化不影响任何环境，再补一条书面说明；否则按 `REAPPROVE` 处理。
   - `REAPPROVE` / `BLOCKED`：回到配置修正，或提交重新审批；在重新批准前不得合并。
6. **跑门禁**：`gate` 必须全部 `KEEP` 才能进入下一项。
7. **最后才删除旧文件**：确认 `unused` 为空、且 `selected.path` 已指向新文件后，再删除 `tox.ini`；删除本身也要重新跑一次 `trace`，因为删除会改变文件选择。

## 7. 需要特别留意的边界

- **同目录多配置文件**：当前实现 `tox.ini` 在 `tox.toml` 之前（`src/tox/config/source/discover.py` 第 28–34 行）；manpage（`tools/generate_manpage.py` 第 118–129 行）写的是相反顺序。迁移时必须以实际 `selected.path` 为准。
- **`pyproject.toml` 会改变打包默认值**：`VirtualEnvRunner.default_pkg_type` 只要看到 `pyproject.toml` / `setup.py` / `setup.cfg` 就默认 `sdist`，否则 `skip`（`src/tox/tox_env/python/virtual_env/runner.py` 第 44–49 行）。把 `tox.ini` 换成 `pyproject.toml` 本身就可能翻转 `package`。
- **`legacy_tox_ini` 被遮蔽**：native `[tool.tox]` 与 `legacy_tox_ini` 并存时前者优先，但后者仍会出现在 `tox config` 的 `unused` 里；迁移后应删除，否则“看起来迁移了、实际旧配置还在”。
- **`set_env` 的自引用**：`{env:NAME}` 先查 `set_env`，再查宿主，最后才用默认值（`src/tox/config/loader/replacer.py` 第 692–711 行）。把 `{env:...}` 翻成固定文本会永久切断这条绑定。
- **`extend` 语义**：TOML 的 `{ replace = "posargs" }` 默认返回列表，放进 `commands` 的列表里必须配 `extend = true`；漏写会得到 `value of type 'list' is not of type 'str'`，这是 `h-badextend` 记录的实际错误。
- **宿主与 CLI 的隐含输入**：`PYTHONHASHSEED` 未设置时每次运行随机生成（`src/tox/config/cli/parser.py` 第 366–371 行），`TOX_HASH_SEED` / `--hashseed` 可覆盖；`TOX_CONFIG_FILE`、`TOX_USER_CONFIG_FILE` 也能改变预览输入。审批记录里应写清这些输入的实际值。
