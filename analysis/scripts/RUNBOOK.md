# 复现手册

## 1. 准备夹具
Beacon 样本以口令 `dissect.cobaltstrike` 压缩在 `tests/beacons/*.zip`。
先解压到一个工作目录（脚本默认读 `$TMPDIR/fb25/beacons`）：

```bash
mkdir -p "$TMPDIR/fb25/beacons"
for z in tests/beacons/*.zip; do
  .venv/bin/python -c "import zipfile;zipfile.ZipFile('$z').extractall('$TMPDIR/fb25/beacons',pwd=b'dissect.cobaltstrike')"
done
```

如需改路径，设置环境变量 `TMPDIR` 或修改脚本中的 glob 根目录即可（脚本统一用
`os.environ['TMPDIR'] + /fb25/beacons`）。

## 2. 脚本与产出
| 脚本 | 作用 | 关键产出 |
|---|---|---|
| inventory.py | 8 样本 TLV 清单（索引/类型/长度/原字节前缀） | out/inventory.json |
| roundtrip.py | 生成 profile 并再解析，统计覆盖率与自洽性 | out/roundtrip_summary.json, out/*.profile |
| http_triple.py | HTTP 变换 L0 原字节→L1 程序→L2 文本→L3 再解析 | 控制台 |
| dns_triple.py | DNS/DoH 三层对照 | 控制台 |
| unknown_triple.py | transform-obfuscate / beacon_gate / dns_resolver | 控制台 |
| coverage_matrix.py | expressed/synthesized/dropped/not-implemented 矩阵 | 控制台 |
| escape_semantic4.py | GET latin-1 与 POST repr 转义往返差异 | 控制台 |
| improvement_prototype.py | 统一转义原型 + DoH 类型化值可用性验证 | 控制台 |
| more_loss.py / multiuri.py / fidelity.py | 丢弃项、多 URI、X 占位补充证据 | 控制台 |

运行：`.venv/bin/python analysis/scripts/<script>.py`

## 3. CLI 复核
```bash
.venv/bin/beacon-dump -t c2profile <beacon> -x 0xaf          # 生成
.venv/bin/c2profile-dump -t properties <generated.profile>   # 再解析为属性
```

## 4. 测试基线
`.venv/bin/python -m pytest tests/ -q --ignore=tests/test_client.py`
（108 passed；test_client.py 因环境缺 pytest_httpserver 无法收集，与本次分析无关。）
