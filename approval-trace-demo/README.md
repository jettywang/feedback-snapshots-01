# Hatch build-hook approval trace

这个目录提供零 PyPI 依赖的本地复现：一个临时 Hatch 项目、两个同名本地插件来源（A/B）、一个导入前来源校验门，以及实际运行产生的 JSONL/控制台记录。

## 一键复跑

```sh
.venv/bin/python approval-trace-demo/run_demo.py
```

脚本会：

1. 在 `approval-trace-demo/.work/project` 生成临时项目；`build-system.requires = []`，不下载依赖。
2. 通过 `PYTHONPATH` 和手写 `.dist-info/entry_points.txt` 发现本地插件，不安装插件。
3. 用当前 `.venv/bin/hatch` 跑普通 wheel 构建、`--hooks-only`、`hatch clean`。
4. 准备 A 来源审批清单 `records/approval-manifest.a.json`。
5. 把 `.work/active` 符号链接从 `plugins/source_a` 切到 `plugins/source_b` 一次。
6. 分别记录“观察模式下 B 仍执行”和“强制模式下导入前阻断”。

当前记录在 `records/`；每次复跑会重建 JSONL，因此 pid、时间戳和临时目录会变化，事件顺序不变。

## 触发记录

| 场景 | 插件记录 | 关键结果 |
| --- | --- | --- |
| 普通构建 | `records/baseline-normal-build.jsonl` | 预检 `dependencies()` → 动态版本代码 → 实例化 → `initialize` → 构建 wheel → `finalize` |
| 只运行 hooks | `records/baseline-hooks-only.jsonl` | 同上，但只有 `initialize`，没有 artifact 和 `finalize` |
| 只清理 | `records/baseline-clean-only.jsonl` | 同上，但进入 `clean` 后返回，没有 `initialize`/`finalize` |
| 审批门安全执行 A | `records/gate-safe-allowed-hooks-only.jsonl` | 来源匹配；gate 读取并哈希字节后执行同一份已校验字节 |
| 切换 B，仅观察 | `records/switch-b-observed-hooks-only.jsonl` | gate 记录来源不匹配但放行；B 的回调参数与 A 相同 |
| 切换 B，强制审批 | `records/switch-b-blocked-hooks-only.gate.jsonl`、`.console.txt` | 在 `EntryPoint.load()` 内抛错；没有对应的 `switch-b-blocked-hooks-only.jsonl`，即插件模块未写调用记录 |

机器可读结论见 `records/run-summary.json` 和 `records/callback-comparison.json`。

## 总调用时序

```text
平台静态读取 pyproject.toml / hatch.toml
  ├─ 选择 target/mode
  ├─ 列出 tool.hatch.build.hooks.* 与 target-specific hooks
  ├─ 找 dynamic version / metadata hook / custom hatch_build.py
  └─ 在最终构建环境解析 hatch entry point、dist-info、文件摘要
          │
          ▼
平台审批或命中内容寻址缓存
          │
          ▼
hatch build / hatch clean
  └─ Project.prepare_build_environment(targets)
       ├─ 静态读取 build-backend
       └─ HatchBuildFrontend.get_required_build_deps(targets)
            └─ get_build_deps_wheel.py
                 └─ BuilderConfig.dynamic_dependencies
                      └─ plugin_manager.build_hook.get(name)
                           └─ load_setuptools_entrypoints("hatch")
                                └─ EntryPoint.load()       ← 最早可拦截点
                                     ├─ import 模块（顶层代码已执行）
                                     └─ 实例化并调用 dependencies()
          │
          ▼
python -u -m hatchling build --target <target> [--hooks-only] [--clean-only]
  ├─ ProjectMetadata.validate_fields()
  │    └─ 动态 version/metadata 可能先执行项目代码
  ├─ Builder.get_build_hooks(directory)
  │    └─ EntryPoint.load()/import/实例化                  ← 第二个解析点
  ├─ clean_only?
  │    ├─ Builder.clean()（非 hooks-only）
  │    ├─ BuildHook.clean(versions)
  │    └─ return
  ├─ BuildHook.initialize(version, build_data)
  ├─ hooks_only? -> continue（不构建、不 finalize）
  ├─ version_api[version](...) 构建 artifact
  └─ BuildHook.finalize(version, build_data, artifact)
```

## 三种模式的差异

- 普通构建，示例命令 `hatch build --target wheel`：Hatch CLI 在 `src/hatch/cli/build/__init__.py:156` 准备构建环境，在 `src/hatch/cli/build/__init__.py:183` 构造 `python -m hatchling build`。后端在 `backend/src/hatchling/builders/plugin/interface.py:157` 调 `initialize`，在 `backend/src/hatchling/builders/plugin/interface.py:166` 构建 artifact，然后在 `backend/src/hatchling/builders/plugin/interface.py:170` 调 `finalize`。未传 `--target` 时默认是 sdist+wheel，见 `src/hatch/cli/build/__init__.py:76`；每个 target 会分别构造 builder 和 hook 实例。
- 只运行 hooks，示例命令 `hatch build --target wheel --hooks-only`：CLI 追加 `--hooks-only`，见 `src/hatch/cli/build/__init__.py:190`。后端完成 `initialize` 后在 `backend/src/hatchling/builders/plugin/interface.py:160` 直接 `continue`，因此不构建 artifact，也不执行 `finalize`。若同时带 `--clean`，仍会先执行 `clean`。
- 只清理，示例命令 `hatch clean --target wheel`：clean 命令以 `clean_only=True` 调用 build，见 `src/hatch/cli/clean/__init__.py:39`；CLI 追加 `--clean-only`，见 `src/hatch/cli/build/__init__.py:202`。后端在 `backend/src/hatchling/builders/plugin/interface.py:130` 强制 `clean=True`，在 `:136` 调 target builder 的 `clean`，在 `:139` 调每个 hook 的 `clean`，随后在 `:141` 返回，不进入 `initialize`/`finalize`。`hatch clean --hooks-only` 会跳过 builder 自身清理，但仍调用 hook 的 `clean`。

## 容易漏掉的两个早期执行点

1. **依赖预检会导入并实例化 hook。** `Project.prepare_build_environment` 调 `get_required_build_deps`（`src/hatch/project/core.py:287`、`src/hatch/project/frontend/core.py:182`）。只要存在非内置 hook 名，Hatch 会运行 `get_build_deps_wheel.py`；其中 `BuilderConfig.dynamic_dependencies` 会 `plugin_manager.build_hook.get(...)`、实例化 hook，并调用 `dependencies()`，见 `backend/src/hatchling/builders/config.py:585` 至 `backend/src/hatchling/builders/config.py:601`。记录中该进程的 `directory` 为空字符串，argv 是 `get_build_deps_wheel.py`。
2. **动态元数据可能先于 hook 解析执行项目代码。** 后端构建一开始就执行 `metadata.validate_fields()`，见 `backend/src/hatchling/builders/plugin/interface.py:100` 和 `backend/src/hatchling/metadata/core.py:281`。本 demo 使用 `tool.hatch.version.source = "code"`，CodeSource 在 `backend/src/hatchling/version/source/code.py:53` 执行 `spec.loader.exec_module`，并在 `:58` eval 版本表达式。因此主构建记录里 `version-code-import` 早于插件 `module-import`。metadata hook 的实例化/更新入口在 `backend/src/hatchling/metadata/core.py:203` 至 `:213` 和 `backend/src/hatchling/metadata/core.py:1670` 至 `:1683`；`custom` build hook 的 `hatch_build.py` 则在 `backend/src/hatchling/builders/hooks/custom.py:35` 经 `load_plugin_from_script` 执行，底层 `exec_module` 见 `backend/src/hatchling/plugin/utils.py:18`。
3. **版本命令也有同样分界。** 静态 `project.version` 时，`hatch version` 只在 `src/hatch/cli/version/__init__.py:28` 至 `:49` 读 TOML；动态版本则会准备构建环境并运行 `python -m hatchling version`（`src/hatch/cli/version/__init__.py:70` 至 `:81`），后者在 `backend/src/hatchling/cli/version/__init__.py:51` 至 `:53` 调用版本源，code source 因而会执行项目代码。

## 插件从哪里加载和实例化

- 第三方插件由 pluggy 加载 `hatch` entry-point group：`backend/src/hatchling/plugin/manager.py:109` 至 `:110`。
- `ClassRegister.get/collect` 负责 entry-point 扫描、注册和按 `PLUGIN_NAME` 建索引：`backend/src/hatchling/plugin/manager.py:68` 至 `:101`。
- 真正的 build hook 解析和构造在 `backend/src/hatchling/builders/plugin/interface.py:389` 至 `:403`；构造参数定义在 `backend/src/hatchling/builders/hooks/plugin/interface.py:42` 至 `:58`。
- hook 名来自全局 `tool.hatch.build.hooks` 和 target 表 `tool.hatch.build.targets.<target>.hooks`；target 中同名键会在 `backend/src/hatchling/builders/config.py:243` 替换全局配置，随后还会按环境变量过滤，见 `:245` 以后。审批应同时固定两张原始表和解析后的配置。

## 同名来源切换与可证明条件

A/B 两个来源都使用：

- distribution Name：`probe-recorder`
- entry point：`[hatch] probe = probe_recorder`
- class `PLUGIN_NAME = "probe"`
- 相同 pyproject hook 配置和相同生命周期参数

不同的是目录、dist-info、版本元数据和文件 SHA-256。准备 A 审批后，脚本把同一个 `.work/active` 路径切到 B。

要在执行前核实来源，必须满足：

1. 审批门早于第一次 `EntryPoint.load()`/`exec_module()`，包括 Hatch 的依赖预检子进程，而不是只放在 `initialize()`。
2. 用最终运行 hook 的解释器/构建环境解析 entry point，固定 entry-point 名/值、distribution、dist-info、模块真实路径和 SHA-256；生产环境还应固定整个 distribution `RECORD`、依赖闭包、index/artifact 摘要或签名。
3. 在读取字节后执行同一份已校验字节，或使用不可变、摘要寻址的 artifact/自定义 loader；普通“先 hash 路径，再让 import 重新读路径”仍有检查与使用之间的 TOCTOU 窗口。`gate/sitecustomize.py` 的 `APPROVAL_SAFE_EXEC=1` 对这个单文件 demo 演示了 read-once/hash/exec 同一字节串。
4. 动态版本/metadata 项目代码和 `build-system`/`backend-path` 也要纳入同一审批；只校验 build hook entry point 无法覆盖先发生的 `version.py`/metadata hook/backend 代码。
5. 审批清单必须随目标、模式、配置和来源重新解析；依赖安装后若 entry point 可能变化，应在最终环境再次校验。
6. 生产解析器不应为了定位 `pkg.hooks` 而调用会导入父包的 `find_spec("pkg.hooks")`；应直接依据 distribution 的 `RECORD`/文件路径做非导入解析，并校验父包及整个依赖闭包。本 demo 特意使用顶层单文件模块 `probe_recorder`，所以示例 gate 的 `find_spec` 不会先执行父包初始化。

## 为什么已有回调参数本身不够

`initialize(version, build_data)`、`finalize(version, build_data, artifact_path)`、`clean(versions)` 的显式参数不含 distribution、entry-point 路径、文件摘要或来源地址；`build_data["build_hooks"]` 也只是 hook 名元组，见 `backend/src/hatchling/builders/plugin/interface.py:154`。构造函数虽有 `root/config/metadata/directory/target_name/app`，但同样没有来源证明，而且进入构造函数时 entry-point 模块已经 import，顶层代码已经执行。

`records/callback-comparison.json` 显示 A/B 两次 `initialize` 的回调参数完全相同：

```json
{"version": "standard", "build_data_build_hooks": ["probe"]}
```

但二者的 `module_sha256` 不同。若平台只保存/接收序列化后的生命周期回调参数，无法判断背后是 A 还是 B。即使在进程内用 `type(hook).__module__`、`inspect.getfile()` 或 pluggy distribution 信息做事后识别，也只能告诉我们“刚刚加载了谁”，不能撤回模块顶层代码或构造函数已经造成的执行；对于同名路径切换、`sys.modules` 复用、editable/自定义 finder、二进制扩展或缺少 RECORD 的情况，还需要 loader 记录的摘要和不可变来源才能确认实际执行字节。

## 重新确认与日常发版路径

建议把审批做成“首次信任 + 内容寻址缓存”，审批键包含：

- 规范化命令模式和 target 集合（包含 `--all` workspace members）；
- 命中的 hook 名、顺序、启用条件和全局/target 配置；
- 每个 entry point 的 distribution、entry point、真实路径、SHA-256/RECORD/签名；
- 可执行的动态版本/metadata/custom 脚本路径与摘要；
- `build-system.requires`、`backend-path` 和可能影响二进制插件的运行环境标识。

以下变化应重新确认：target 变化、hook 来源/摘要变化、hook 配置或启用开关变化、动态代码变化、构建后端/构建依赖变化。单纯修改静态 `project.version`，或未改动的 `version.py` 计算出 Auto/SCM 新版本，不应使缓存失效；这样日常发版仍走原来的 `hatch build`/`hatch publish` 路径，只是外层发布平台在启动 Hatch 前多一次可复查的清单生成与缓存校验。
