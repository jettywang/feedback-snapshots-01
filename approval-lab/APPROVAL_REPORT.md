# Poetry Core 构建脚本审批实测报告

## 实测对象与取证方式

- Poetry Core：工作区源码 `poetry-core 2.5.0`，入口为 `src/poetry/core/masonry/api.py`。
- Python：3.12.11；平台标签：`macosx_26_0_arm64` / CPython 3.12。
- setuptools：`84.2.1`，仅用于 `generate-setup-file = true` 会调用的 `setup.py build` 路径；实验时从本地 wheel 解到 `approval-lab/pylibs`。
- 两个最小源项目：
  - `approval-lab/projects/plainpkg`：无构建脚本对照。
  - `approval-lab/projects/hookpkg`：含 `build.py`、`hookpkg/__init__.py` 和最小 C 扩展 `hookpkg/native.c`。
- `direct.toml`、`setup-native.toml`、`legacy-string.toml` 只是同一 `hookpkg` 的配置变体；`hook-existing-setup` 是编排器在临时副本中额外生成旧 `setup.py` 的边界实验，不是第三个源项目。
- `approval-lab/run_matrix.py` 为每个入口启动全新 Python 子进程，通过 `approval-lab/pep517_worker.py` 调用真实 PEP 517 hook。
- 构建脚本只把 JSON 事件写入 `APPROVAL_EVENT_LOG` 指向的 `$TMPDIR/poetry-approval-lab/events/*.jsonl`；运行结束后复制到 `approval-lab/evidence/events/`。
- 最终干净复跑：55 个 hook 调用全部返回 0；20 个 wheel/editable 解包导入探针全部返回 0。机器可读汇总见 `approval-lab/evidence/summary.json`、`calls.json`、`runtime.json`、`archive-findings.json`。

下文把行为分成三类：

1. **当前步骤实际执行**：本次 PEP 517 调用中运行了项目 Python/原生编译代码。
2. **产物写入、将来执行**：当前步骤可能没有执行某脚本，但把它或运行时代码放进 sdist/wheel/editable 路径，后续构建、安装或导入会执行。
3. **完全无构建脚本执行**：该 hook 不运行 `build.py`/`setup.py`，但仍会解析 `pyproject.toml`、读取 README/许可证等输入文件。

## 入口与可观察行为矩阵

事件数来自 `approval-lab/evidence/events/` 中本次探针记录；事件名和 argv 可逐行复核。

| Poetry Core 入口 | `plainpkg` 无脚本 | `hookpkg`：`generate-setup-file=false` | `hookpkg`：`generate-setup-file=true` + C 扩展 | 旧写法 `tool.poetry.build = "build.py"` |
|---|---:|---:|---:|---:|
| `get_requires_for_build_wheel/sdist/editable` | 0 事件，返回 `[]` | 0 | 0；不会动态补出 setuptools 依赖 | 0 |
| `prepare_metadata_for_build_wheel/editable` | 0 事件；生成 `plainpkg-0.1.0.dist-info` | 0 事件；元数据 `WHEEL` 已写 `Root-Is-Purelib: false` 和 `cp312-cp312-...` 标签 | 同左，但仍未运行 `build.py` | 0 |
| `build_sdist` 当前执行 | 0 事件 | 0 事件 | 0 事件 | 0 事件 |
| sdist 归档中的未来执行内容 | 无 `build.py`、无 `setup.py` | 有 `build.py`；无 `setup.py` | 有 `build.py` 和 Poetry 生成的 `setup.py`；后者含 `from build import *` 与 `build(setup_kwargs)` | 有 `build.py`；无 `setup.py` |
| 普通 wheel，直接构建 | 0 事件；`py3-none-any.whl`；内含 `plainpkg/__init__.py` | 3 事件；1 个 `python build.py` 子进程，`__name__="__main__"` | 4 事件；1 个 `python setup.py build ...` 子进程，`build.py` 以 `__name__="build"` 导入并调用 `build(setup_kwargs)` | 与 false 模式相同：3 事件、直接执行 `build.py` |
| 普通 wheel，由 sdist 重建 | 0 事件 | 3 事件，序列相同 | 4 事件，序列相同；wheel 内含 `hookpkg/_native.cpython-312-darwin.so`，导入返回 `answer=42` | 3 事件，序列相同 |
| editable，直接构建 | 0 事件；editable wheel 仅含 `.pth` + `.dist-info` | 3 事件；执行一次 `build.py` | 8 事件 = 两个不同 PID 的 `setup.py` 进程：先 `build_ext --inplace`，再 `build ...` | 3 事件 |
| editable，由 sdist 重建 | 0 事件；`.pth` 指向解包后的 sdist 根目录 | 3 事件；`.pth` 指向 `.../sdist-sources/.../hookpkg-0.1.0` | 8 事件；`.pth` 指向解包 sdist；就地生成的 `.so` 从该源树成功加载 | 3 事件 |
| wheel 安装/解包后导入 | 从 wheel 解包目录执行 `__init__.py` | 同左；无 `.so` | 从 wheel 解包目录执行 `__init__.py` 和 `_native...so` | 同 direct false |
| editable 导入 | `.pth` 加路径后，从源树执行 `__init__.py` | 同源树 | 从 `.pth` 指向的源树执行 `__init__.py` 和就地 `.so` | 同源树 |

关键归档证据：

- 无脚本 wheel：`approval-lab/evidence/artifacts/plain-control/direct-source/wheel-plainpkg-0.1.0-py3-none-any.whl`。
- direct-false wheel：`approval-lab/evidence/artifacts/hook-direct-false/direct-source/wheel-hookpkg-0.1.0-cp312-cp312-macosx_26_0_arm64.whl`；归档清单有 `hookpkg/__init__.py`、`hookpkg/native.c`，但没有 `.so`，`WHEEL` 仍为 `Root-Is-Purelib: false`。
- 原生 wheel：`approval-lab/evidence/artifacts/hook-setup-native/direct-source/wheel-hookpkg-0.1.0-cp312-cp312-macosx_26_0_arm64.whl`；清单含 `hookpkg/_native.cpython-312-darwin.so`。
- sdist 内生成的 `setup.py`：`approval-lab/evidence/archive-content/hook-setup-native/direct-source/sdist-hookpkg-0.1.0.tar.gz/setup.py`。
- editable `.pth` 内容样本：`approval-lab/evidence/archive-content/hook-setup-native/direct-source/editable-hookpkg-...whl/hookpkg.pth`。
- 预读元数据样本：`approval-lab/evidence/prepared-metadata/`。
- 导入路径与 native answer：`approval-lab/evidence/runtime.json`。

## 源码分支如何解释矩阵

- PEP 517 入口只构造 Poetry 对象并调用对应 Builder：`src/poetry/core/masonry/api.py:20`、`src/poetry/core/masonry/api.py:39`、`src/poetry/core/masonry/api.py:49`、`src/poetry/core/masonry/api.py:66`、`src/poetry/core/masonry/api.py:79`。
- `get_requires_for_build_wheel` 在创建 Poetry 对象前直接返回 `[]`，因此不会读取项目构建脚本，也不会替 `generate-setup-file=true` 补充 setuptools。
- wheel/editable 的执行分支在 `src/poetry/core/masonry/builders/wheel.py:127`：
  - editable 先 `_build()`，再 `_add_pth()`，且不把包目录复制进 editable wheel。
  - 非 editable 且 `build_should_generate_setup()` 为真时，先 `_copy_module()`，再 `_build()`。
  - 其余情况先 `_build()`，再 `_copy_module()`。
- 有 `build_script` 时，`_build()` 的两条执行路径在 `src/poetry/core/masonry/builders/wheel.py:173`：
  - `generate-setup-file=false`：`chdir(project_root)` 后 `_run_build_script()`；实际命令是 `[sys.executable, build.py]`，见 `src/poetry/core/masonry/builders/wheel.py:302`。
  - `generate-setup-file=true`：进入 `SdistBuilder.setup_py()` 上下文并运行 setup 命令。
- setup 模式的子进程命令在 `src/poetry/core/masonry/builders/wheel.py:278`：editable 会先执行 `setup.py build_ext --inplace`，随后无条件再执行 `setup.py build ...`；普通 wheel 只执行后者。
- sdist 构建本身只打包；当 `build_should_generate_setup()` 为真时把生成的 `setup.py` 写入 tar，见 `src/poetry/core/masonry/builders/sdist.py:95`。生成内容包含 `from <build_module> import *` 和 `build(setup_kwargs)`，见 `src/poetry/core/masonry/builders/sdist.py:116` 到 `src/poetry/core/masonry/builders/sdist.py:128`。
- 若根目录已有 `setup.py`，`setup_py()` 不覆盖它，只打印 “A setup.py file already exists. Using it.”，见 `src/poetry/core/masonry/builders/sdist.py:219` 到 `src/poetry/core/masonry/builders/sdist.py:234`。
- 本版默认值是 false：`src/poetry/core/packages/project_package.py:123`；schema 默认值同样为 false，见 `src/poetry/core/json/schemas/poetry-schema.json:702`。
- 旧字符串 `[tool.poetry] build = "build.py"` 会被归一化成 `{"script": "build.py"}`，见 `src/poetry/core/factory.py:545`。

## 已有 `setup.py` 的额外边界

编排器的 `hook-existing-setup` 变体验证了一个旧项目高风险差异：

- 直接从源码构建 wheel 时，事件是 `existing_setup_py_enter/exit`，没有 `build.py` 事件；证明 Poetry 直接执行了源码树里的旧 `setup.py`，且该 `setup.py` 可以不导入已审批的 `build.py`。
- 直接 editable 时有 4 个旧 `setup.py` 事件，对应两次 setup 子进程。
- 该最小布局生成的 sdist 中只有一个 `setup.py` 成员，其内容是 Poetry 生成版本，不含实验写入的 `existing_setup_py_enter` 标记，且含 `from build import *`。
- 从这个 sdist 重建时，事件变为 `build_py_module_enter/build_function_enter/...`，不再执行源码树里的原始 `setup.py`。

因此，**源码直接构建的权限边界与 sdist 重建并不天然相同**。平台不能只审批 `build.py` 而忽略现存 `setup.py`；也不能假设源码里的任意 `setup.py` 都会原样进入 sdist。必须分别检查直接工作树和 sdist 成员。

## 直接构建与 sdist 重建的权限边界

### 直接源码构建

- 信任对象是代码提交/源码树：`pyproject.toml`、`build.py`、它导入或调用的所有项目模块、现存 `setup.py`、C/Cython 源、`build-system.requires` 中的后端和工具。
- false/legacy 模式在当前 hook 中给予 `build.py` 任意 Python 执行权；true 模式给予 `setup.py`、`build.py`、setuptools 命令和编译器任意执行权。
- 审批应绑定提交哈希、源码树摘要和这些文件的独立 SHA-256，而不是只绑定包名/版本。

### `build_sdist` 与 sdist 重建

- `build_sdist` 本身不运行构建脚本，但会把执行权传播给未来的重建：
  - false/legacy：sdist 内的 `build.py` 会在未来 wheel/editable 时被 `python build.py` 执行。
  - true：sdist 内的 `setup.py` 和 `build.py` 都会在未来重建时执行；入口是 `setup.py`，随后进入 `build(setup_kwargs)`。
- sdist 是新的信任边界。源码审批只能通过平台生成的出处证明（provenance）关联到某个 sdist SHA-256；不能仅凭“同一个包名版本”自动延续。
- 重建时事件序列与直接构建一致，但 cwd 和 editable `.pth` 路径变成解包 sdist 目录。平台应审批 sdist 摘要及其中所有可执行成员摘要。

### editable 的特殊边界

- editable wheel 里没有完整包代码；实测只有 `*.pth` 和 `.dist-info`。
- Poetry 生成的 `<name>.pth` 是一行绝对目录，不是 `import ...` 形式的 `.pth` 启动钩子；它本身只把目录加入 `sys.path`。
- 真正的代码执行发生在之后导入包时：Python 从 `.pth` 指向的源树加载 `__init__.py`；setup/native editable 还会从该源树加载 `build_ext --inplace` 写出的 `.so`。
- 从 sdist 构建 editable 时，`.pth` 指向构建机上的 sdist 解包目录。该 wheel 跨机器不可移植，临时解包目录被清理后也会失效。
- 所以 editable 审批不能只记录 wheel 哈希；必须记录允许的源绝对路径、源码树摘要、创建时间和使用主体。发布平台不应把 sdist 生成的 editable wheel 当作可分发发布物。

## 可兑现的审批策略

Poetry Core 自身没有“询问/记住构建脚本审批”的策略引擎；审批必须由控制 PEP 517 前端和构建环境的发布平台在调用 hook 前强制执行。

### 分级授权

| 级别 | 允许动作 | 必要条件 |
|---|---|---|
| L0 元数据预读 | `get_requires_for_build_*`、`prepare_metadata_for_build_wheel/editable` | 固定 `poetry-core==2.5.0` 或经审批版本；低权限沙箱；可解析 `pyproject.toml` 和读取元数据引用文件；无网络 |
| L1 sdist 生成与清点 | `build_sdist` | 可自动执行，但必须计算 sdist SHA-256、列出 `build.py`/`setup.py`/脚本/原生源；发现构建脚本时把后续级别标记为需审批 |
| L2 无脚本 wheel | 无 `build_script` 的 `build_wheel` | 自动构建；校验 wheel 为 `py3-none-any` 或预期标签、`WHEEL` 中 `Root-Is-Purelib: true`、归档内容与源码树一致 |
| L3 Python 构建脚本 | 有 `build_script` 的 `build_wheel` | 必须有匹配哈希的审批单；按 false/legacy 与 true/setup 两种调用语义审批；隔离、无网络、受限文件系统 |
| L4 原生扩展 | L3 + 编译器/平台 ABI | 审批 C/Cython/其他源、编译参数、工具链版本、目标平台；构建后必须看到预期 `.so/.dylib/.pyd` 和非 any 标签，并扫描原生依赖 |
| L5 editable | `build_editable` | 先满足 L3/L4；另批源路径和源码树哈希；只允许从持久、受控 checkout 安装；禁止分发 sdist 临时目录生成的 editable wheel |
| L6 sdist 重建 | 对 sdist 调用 metadata/wheel/editable | 单独审批 sdist SHA-256、归档内 `build.py`/`setup.py` 等可执行成员哈希、setuptools/编译器依赖；源码审批仅在有 provenance 时关联 |

### 平台执行点

1. 不让开发者在发布 runner 中直接运行任意 `poetry build`/`python -m build`；使用平台封装器先解析配置、生成审批键，再调用 PEP 517 hook。
2. 审批键至少包含：规范化包名、版本、Poetry Core 版本、提交 SHA、源码树哈希、`pyproject.toml` SHA-256、`build.py` SHA-256、模式（`direct_script`/`generated_setup`）、现存 `setup.py` 策略及哈希、C/扩展源哈希、`build-system.requires` 和工具链锁定信息。
3. 对 `generate-setup-file=true`，要求 `[build-system].requires` 显式包含经审批的 `setuptools`（必要时还有 `wheel`、Cython、cmake 等）；`get_requires_for_build_wheel` 返回 `[]`，不会替平台补依赖。
4. 若包内存在根 `setup.py`，策略应二选一：禁止并要求删除/迁移；或把它作为独立可执行文件审批，并校验直接构建与 sdist 成员差异。不能只审批 `build.py`。
5. 构建后校验证据：事件日志、返回码、wheel 文件名标签、`WHEEL`、`RECORD`、归档文件清单、`.so` 列表、sdist 成员和哈希。任何“声明有构建脚本但事件缺失”或“未审批文件被执行”都拒绝产物。
6. 原生构建默认断网；依赖只来自平台预置 wheelhouse。构建工作树使用一次性副本，因为 setup editable 会执行 `build_ext --inplace`，在源树写 `.so`。
7. editable 安装应优先在目标开发/CI 工作区从已批准提交直接执行；平台保存的凭证应写明绝对路径和树哈希。跨机器分发普通 wheel，而不是 editable wheel。

## 旧项目延续已批准构建的条件

旧项目可以延续原审批，但必须满足以下条件；任一不满足则按新构建重新审批：

- 本版仍接受旧键 `[tool.poetry] build = "build.py"`，实测其行为等同默认 `generate-setup-file=false`：当前执行 `python build.py`，且 `__name__ == "__main__"`。
- 审批哈希必须与当前提交完全一致，尤其是 `pyproject.toml`、`build.py`、`build.py` 导入/调用的本地文件、现存 `setup.py`、原生源和编译配置。
- 如果旧审批描述的是“生成 `setup.py`、导入 `build()`、构建扩展”的流程，必须把配置显式迁移/确认为：

  ```toml
  [tool.poetry.build]
  script = "build.py"
  generate-setup-file = true
  ```

  不能依赖跨版本默认值；在本版代码中缺省值是 false，调用语义不同。
- 如果旧审批描述的是直接运行 `build.py` 的 `__main__` 流程，可保留旧字符串或显式写 `generate-setup-file = false`，但审批单应记录这一语义。
- 旧项目若有手工维护的 `setup.py`，必须单独审批；直接源码构建会使用该文件，且它可能绕过 `build.py`。平台还必须检查 sdist 中实际打包的是哪个 `setup.py`，不能只看源树文件。
- 旧审批只覆盖直接源码构建；若发布流程改为“先出 sdist，再由 sdist 重建 wheel”，必须新增 sdist 摘要和归档可执行成员审批。
- editable 不自动包含在普通 wheel 审批中；需要路径绑定、源树完整性和就地构建产物策略。

## 复现实验

```bash
# 若使用 generate-setup-file = true，先准备 setuptools；示例：
python3 -m pip install --target approval-lab/pylibs "setuptools==84.2.1"

# 运行 5 个配置案例 × 直接/sdist 重建矩阵，并刷新 evidence/
python3 approval-lab/run_matrix.py
```

主要证据索引：

- 调用结果：`approval-lab/evidence/calls.json`
- 运行时导入：`approval-lab/evidence/runtime.json`
- 归档清单与标志：`approval-lab/evidence/archive-findings.json`
- 输入文件哈希：`approval-lab/evidence/identities.json`
- 逐次事件：`approval-lab/evidence/events/*.jsonl`
- hook stdout/stderr：`approval-lab/evidence/logs/`
- 实际 sdist/wheel 副本：`approval-lab/evidence/artifacts/`
