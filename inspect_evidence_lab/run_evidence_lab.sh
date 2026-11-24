#!/usr/bin/env bash
# 一键重跑 A/B 证据轨迹、边界探针与逐步对照表。
# 可用 PYTHON=/path/to/python 覆盖解释器（需要能 import dynaconf）。
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PY_BIN="${PYTHON:-}"

if [[ -z "${PY_BIN}" ]]; then
  if [[ -x "${HERE}/../.venv/bin/python" ]]; then
    PY_BIN="${HERE}/../.venv/bin/python"   # 本仓库自带 venv（可编辑安装的 dynaconf）
  elif command -v python3 >/dev/null 2>&1; then
    PY_BIN="python3"
  else
    echo "找不到 python3，请用 PYTHON=/path/to/python $0" >&2
    exit 127
  fi
fi

if ! "${PY_BIN}" -c "import dynaconf" >/dev/null 2>&1; then
  echo "${PY_BIN} 无法 import dynaconf；请安装 dynaconf 或用 PYTHON=... 指定解释器" >&2
  exit 1
fi

echo "[lab] python : ${PY_BIN}"
echo "[lab] dynaconf: $("${PY_BIN}" -c 'import dynaconf;print(dynaconf.__file__)')"
exec "${PY_BIN}" "${HERE}/evidence_lab.py" all
