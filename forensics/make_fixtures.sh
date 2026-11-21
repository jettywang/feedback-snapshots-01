#!/bin/sh
# 构建演示用的假 pipx 环境：纯本地目录 + 假元数据。
# 不复制、不修改任何真实回收目录；生成的 "python" 只是普通文本文件，永不执行。
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)/fixtures
HOME_DIR="$ROOT/pipx_home"          # 扮演回收到的 PIPX_HOME
VENVS="$HOME_DIR/venvs"
BIN_DIR="$ROOT/bin"                 # 扮演回收到的 PIPX_BIN_DIR
ELSEWHERE="$ROOT/elsewhere"         # 扮演机器上另一套环境

rm -rf "$ROOT"
mkdir -p "$VENVS" "$BIN_DIR" "$ELSEWHERE/foreign-venv/bin"

fake_interpreter() {
    # 假解释器：普通文本文件，故意不加可执行位，核对时绝不运行
    printf 'FAKE INTERPRETER - evidence only, do not execute\n' > "$1"
    chmod 0444 "$1"
}

fake_metadata() {
    # $1=venv 目录  $2=包名  $3=声称的 apps（JSON 数组，空表示无声称）
    cat > "$1/pipx_metadata.json" <<JSON
{
    "injected_packages": {},
    "main_package": {
        "app_paths": [],
        "app_paths_of_dependencies": {},
        "apps": $3,
        "apps_of_dependencies": [],
        "include_apps": true,
        "include_dependencies": false,
        "man_pages": [],
        "man_pages_of_dependencies": [],
        "man_paths": [],
        "man_paths_of_dependencies": {},
        "package": "$2",
        "package_or_url": "$2",
        "package_version": "0.0.0",
        "pip_args": [],
        "suffix": ""
    },
    "pipx_metadata_version": "0.4",
    "python_version": "Python 3.11.0 (fake evidence)",
    "source_interpreter": null,
    "venv_args": []
}
JSON
}

# --- 对照组 ok-tool：venv、入口、元数据三者互相印证 ---
mkdir -p "$VENVS/ok-tool/bin"
fake_interpreter "$VENVS/ok-tool/bin/python"
printf '#!%s/venvs/ok-tool/bin/python\nprint("fake ok-tool")\n' "$VENVS" > "$VENVS/ok-tool/bin/ok-tool"
printf 'home = /usr/bin\ninclude-system-site-packages = false\n' > "$VENVS/ok-tool/pyvenv.cfg"
fake_metadata "$VENVS/ok-tool" ok-tool '["ok-tool"]'
ln -s "$VENVS/ok-tool/bin/ok-tool" "$BIN_DIR/ok-tool"

# --- 状态A missing-tool：venv 在，但无入口、元数据也不声称任何 app ---
mkdir -p "$VENVS/missing-tool/bin"
fake_interpreter "$VENVS/missing-tool/bin/python"
printf 'home = /usr/bin\n' > "$VENVS/missing-tool/pyvenv.cfg"
fake_metadata "$VENVS/missing-tool" missing-tool '[]'

# --- 状态C claimed-tool：元数据声称暴露 claimed-tool，但 bin 目录没有入口 ---
mkdir -p "$VENVS/claimed-tool/bin"
fake_interpreter "$VENVS/claimed-tool/bin/python"
printf 'home = /usr/bin\n' > "$VENVS/claimed-tool/pyvenv.cfg"
fake_metadata "$VENVS/claimed-tool" claimed-tool '["claimed-tool"]'
# 元数据里的 app_paths 写的是原机路径，恢复机上并不存在——正说明它只是"声称"
python3 - "$VENVS/claimed-tool/pipx_metadata.json" <<'PY'
import json, sys
path = sys.argv[1]
data = json.load(open(path))
data["main_package"]["app_paths"] = ["/orig/home/.local/share/pipx/venvs/claimed-tool/bin/claimed-tool"]
json.dump(data, open(path, "w"), indent=4)
PY

# --- 状态B foreign-tool：入口存在，但解析后落在回收环境之外 ---
mkdir -p "$VENVS/foreign-tool/bin"
fake_interpreter "$VENVS/foreign-tool/bin/python"
printf 'home = /usr/bin\n' > "$VENVS/foreign-tool/pyvenv.cfg"
fake_metadata "$VENVS/foreign-tool" foreign-tool '["foreign-tool"]'
printf '#!/bin/sh\necho fake foreign-tool\n' > "$ELSEWHERE/foreign-venv/bin/foreign-tool"
ln -s "$ELSEWHERE/foreign-venv/bin/foreign-tool" "$BIN_DIR/foreign-tool"

# --- 补充 ghost-tool：入口指向本环境，但 venv 目录已丢失（对应 health: MISSING）---
ln -s "$VENVS/ghost-tool/bin/ghost-tool" "$BIN_DIR/ghost-tool"

chmod -R u+w "$ROOT"
echo "fixtures built under $ROOT"
