# pipx 环境恢复取证方案

场景：维护机恢复后只剩 pipx 环境目录（`PIPX_HOME`，含 `venvs/`）和保留的入口文件
（`PIPX_BIN_DIR`）。目标：基于现有 `health` 功能的检查逻辑，对每个命令给出可
区分的结论，并说明每条结论能证明什么、不能证明什么。

全程只读：不执行回收目录里的任何程序，不修改回收目录。

## 与 health 功能的对应

`src/pipx/commands/health.py` 的 `_check_health` 分三级：

| health 判定 | 依据（health.py） | 取证只读对应 |
| --- | --- | --- |
| `MISSING` | venv 目录不存在（L67） | `test -d <venvs>/<pkg>` |
| `BROKEN` | 解释器文件不存在（L76） | `test -f <venv>/bin/python` |
| `BROKEN` | 解释器无法启动/非零退出（L84–98） | **跳过**：该步会执行 `python --version`，取证副本上不做 |
| `HEALTHY` | 以上全过 | 只读核对最多到"解释器文件存在"，不给 HEALTHY 结论 |

因此本方案只复刻 health 中不执行程序的部分；`check.py` 的结论上限是
"文件层面自洽"，不等于 `pipx health` 的 healthy。

## 证据层级（由弱到强）

1. **配置声称**：`venvs/<pkg>/pipx_metadata.json` 的 `main_package.apps` /
   `app_paths`。这是安装时写下的声明，路径还是原机绝对路径，只能证明
   "配置声称如此"。
2. **入口存在**：`PIPX_BIN_DIR/<cmd>` 存在。证明恢复时该名字在 PATH 目录里
   有文件，但还不能说明它属于哪套环境。
3. **入口归属**：符号链接目标（或脚本 shebang）解析后落在回收的
   `venvs/<pkg>/` 内，且该 venv 解释器文件存在。三层互相印证，是只读核对
   能给出的最强结论。

## 三种状态的判定

| 状态 | 判定条件 | 结论边界 |
| --- | --- | --- |
| A 命令缺失 | 无入口文件，且元数据无对应声称（或 venv 目录本身不在） | 无法证明该命令曾可用；不能排除"入口曾被手动删除" |
| B 指向其他环境 | 入口存在，但解析结果在回收的 `PIPX_HOME` 之外 | 该命令存在，但由另一套环境提供，不能计入本次恢复的 pipx 资产 |
| C 只能证明配置声称如此 | 元数据 `apps` 声称暴露了该命令，但入口目录无对应文件 | 只能证明安装时 pipx 打算暴露它；命令是否真在 PATH 上可用过，无磁盘证据 |

补充第四种常见情况：入口是指向本环境的悬空链接（目标 venv 已丢失），
对应 health 的 `MISSING`。

## 演示环境（纯本地目录 + 假元数据）

`make_fixtures.sh` 在 `forensics/fixtures/` 下生成五个样例，假解释器是
无执行位的文本文件，元数据为手工构造的 JSON：

- `ok-tool`：对照组，venv + 入口 + 元数据三层互证
- `missing-tool`：状态 A
- `foreign-tool`：状态 B（入口符号链接指向 `fixtures/elsewhere/`）
- `claimed-tool`：状态 C（`app_paths` 写的是不存在的原机路径）
- `ghost-tool`：悬空入口，对应 health 的 MISSING

## 只读核对步骤

```sh
# 0. 构建演示环境（只写 forensics/fixtures/，不碰真实回收目录）
sh forensics/make_fixtures.sh

# 1. 留痕：对回收目录做只读哈希快照（示例用演示目录代替）
find forensics/fixtures -type f -exec shasum -a 256 {} + | sort -k2

# 2. 自动核对（只读，退出码恒 0，只出报告）
python3 forensics/check.py \
    --pipx-home forensics/fixtures/pipx_home \
    --bin-dir   forensics/fixtures/bin

# 3. 手工等价命令（核对单个命令时）
ls -la forensics/fixtures/bin                       # 入口是否存在、是否符号链接
readlink forensics/fixtures/bin/foreign-tool        # 链接指向哪套环境
test -f forensics/fixtures/pipx_home/venvs/ok-tool/bin/python && echo interpreter-present
python3 -m json.tool forensics/fixtures/pipx_home/venvs/claimed-tool/pipx_metadata.json
head -1 forensics/fixtures/pipx_home/venvs/ok-tool/bin/ok-tool   # 脚本入口看 shebang
```

对真实回收目录使用时，把 `--pipx-home` / `--bin-dir` 换成实际路径即可；
脚本只读取，不写入。

## 证据说明（写报告时的措辞）

- 状态 A：只能说"回收物中无该命令的证据"，不能说"该命令从未安装"。
- 状态 B：入口文件本身可作为"该名字曾在 PATH 上"的证据，但其归属是另一
  套环境；如需进一步定性，应对那套环境单独取证，而不是动回收目录。
- 状态 C：元数据是 pipx 安装时自写的声明（含原机绝对路径），属于单方
  陈述；只有与入口文件、venv 磁盘内容互相印证时才能升级结论。
- 只读核对不执行解释器，因此给不出 health 的 `HEALTHY`；"解释器文件存在"
  不等于"解释器可运行"。
