# poetry-core 离线发布范围审核

## 能回答什么

poetry-core 没有提供现成的 CLI 子命令做“发布范围预览”，但它的构建后端把
“选哪些文件”完全实现为纯源码阶段的可复用方法，因此可以离线审核而不执行任何
项目构建脚本：

- `Factory().create_poetry(path)`：按 builder 完全相同的入口解析 `pyproject.toml`
  （packages / include / exclude / build 配置）。
- `SdistBuilder` / `WheelBuilder.find_files_to_add()`：返回该格式真正会打包的
  `BuildIncludeFile` 集合；`BuildIncludeFile.relative_to_target_root()` 给出
  wheel 内的最终路径（含 `from`/`to` 重定位），sdist 用
  `relative_to_source_root()`。
- `Builder.find_excluded_files()`：合并 VCS 忽略（`git ls-files --others -i
  --exclude-standard`，只读）与 `tool.poetry.exclude`，再减去显式 include。
- 以上方法只读取源码树和 git 元数据；`Builder.build()` 与 `_run_build_script()`
  从不被调用（见 `audit_release_scope.py`）。

## 规则为什么生效（归因来源）

- 显式 include / packages：`Module` 把每个配置项构造成 `PackageInclude`/`Include`，
  审核脚本逐项回读其 `include`、`from`、`to`、`formats` 作为“why”。
- VCS 忽略：`Builder.find_excluded_files()` 调 `get_vcs().get_ignored_files()`；
  显式 include 会从忽略集合中被减掉（同文件会标注“覆盖 VCS 忽略”）。
- `__pycache__` / `*.pyc`：`Builder.is_excluded()` 中的硬编码规则。
- 格式差异：`Include.formats` 过滤；裸字符串 include 默认仅 sdist；
  `to` 重定位只在 `format == "wheel"` 时生效（sdist 保留源相对路径）。
- sdist 额外强制成员：pyproject.toml、readme、license、file 脚本
  （`SdistBuilder.find_files_to_add()`）。

## 源码阶段无法判定的生成物

- 无 build script 时，仅后端合成的元数据：wheel 的 `*.dist-info/`（METADATA、
  WHEEL、RECORD、licenses 等），sdist 的 `PKG-INFO`（默认不再生成 setup.py，
  除非 `build.generate-setup-file=true`）。
- 有 build script 时：`WheelBuilder._build()` 会执行项目脚本并拷入
  `build/lib*` 产物（编译扩展、脚本生成的包），wheel tag 也变为平台相关；
  这些在源码阶段不存在，审核输出列入 `undeterminable`。若声明的包目录要等
  脚本生成，sdist/wheel 的源码选择会直接失败——审核捕获同一异常并标注，
  而不是执行脚本去“凑预览”。

## 文件

- `audit_release_scope.py`：离线审核器（源码阶段，零构建）。
- `verify_against_archives.py`：一次性真实构建归档，与审核成员做集合对照，
  把差异归类为“后端生成”或“脚本生成（源码不可预测）”。
- `audit-demo-a.{txt,json}` / `verify-demo-a.txt`：普通项目结果与对照。
- `audit-demo-b.{txt,json}` / `verify-demo-b.txt`：构建脚本项目的不可判定标注。

## 复现

```bash
python audit_release_scope.py <project> --json report.json
python verify_against_archives.py <project> report.json   # 仅在允许真实构建时运行
```
