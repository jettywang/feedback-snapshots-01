# EFI 双入口“同一性”核查实验

## 结论先行

接收服务的承诺——“分区表入口与 El Torito 入口内容相同，所以两个入口就是同一
实体”——**不成立**。内容相等（哈希相等、挂载后读到同一文件）只证明“字节序列相
等”，不证明“存储来源相同”。同一性必须由**两套寻址元数据解出的字节区间是否重合**
来判定。可运行反例见 `images/hybrid_B.iso`：两个入口 SHA-256 完全相同，却落在两段
互不相交的物理范围上，是两份独立副本，不是同一实体。

本实验不挂载任何镜像、不执行任何启动代码；介质内部结构自洽只用于证明“解析正确”，
绝不外推为“来源可信”。

## 单位与寻址（三套坐标，落到同一条字节流）

| 结构 | 计数单位 | 关键字段 | 换算到字节偏移 |
|---|---|---|---|
| ISO 9660 / El Torito | 逻辑块 = 2048 B | BRVD 在块 17；catalog RBA；entry load RBA + virtual sectors(512B) | `off = RBA * 2048` |
| GPT | 扇区 = 512 B | 分区项 first/last LBA | `off = LBA * 512` |
| MBR | 扇区 = 512 B | 表项 starting LBA + number of sectors | `off = LBA * 512` |

isohybrid 把 ISO 块网格铺在同一条字节流上，因此 1 逻辑块 = 4 扇区，
`RBA*2048 == LBA*512` 可直接比较。catalog 自身占一个 2048 字节块（本实验 RBA 18，
字节 36864..38911），其内部记录每条 32 字节，UEFI 平台 ID `0xEF` 位于 **section
header**，随后的 boot entry 给出镜像 RBA。

## 三种关系的判据

把每个入口解析成半开区间 `[start, end)`，再做集合比较（与哈希无关）：

- **物理重合（coincident）**：两区间完全相等 → 同一存储实体。哈希在这里只是旁证。
- **独立同内容副本（disjoint）**：`end_a <= start_b` 或反之，区间不相交；哈希可相等
  也可不等。哈希相等时即为反例 B，直接推翻“同内容即同实体”。
- **部分重叠（partial overlap）**：区间相交但互不相等，交集为共享存储、差集各自独立。
  若一个区间完全包住另一个，归为 containment 子类。

判定流程（可落地为接收服务的规则）：
1. 从 BRVD→catalog 解 El Torito 区间，从 GPT 头→ESP 分区项解 GPT 区间，校验各自
   校验和/魔数；MBR 0xEF 作为第三路佐证。
2. 比较区间，而非比较内容。
3. 仅当区间**逐字节相等**才允许写“同一实体”；disjoint 写“独立副本”；intersect 写
   “部分共享”，并报告交集字节范围。
4. 哈希只用于检测副本是否被篡改，不参与同一性结论。
5. 可信来源另需带外签名/出处证明；介质内部 CRC/GUID 自洽不构成来源信任。

## 三个短合成介质（各 64 KiB，32 块 / 128 扇区）

固定几何：MBR@0，GPT 主头@LBA1、分区项@LBA2..5，BRVD@块17，catalog@块18，
载荷从块20 开始，备份 GPT 在末尾 LBA123..127。

| 镜像 | El Torito UEFI 字节范围 | GPT ESP 字节范围 | 区间关系 | 哈希相等? | 同一实体? |
|---|---|---|---|---|---|
| `hybrid_A.iso` | 40960..45055 (块20-21) | 40960..45055 (LBA80-87) | 重合 | 是 | **是** |
| `hybrid_B.iso` | 40960..45055 (块20-21) | 45056..49151 (LBA88-95, 块22-23) | 不相交 | 是 | **否（反例）** |
| `hybrid_C.iso` | 40960..45055 (块20-21) | 43008..47103 (LBA84-91, 块21-22) | 部分重叠，共享 43008..45055 | 否 | 否 |

## 材料损坏时还能确认什么

`run_lab.py` 只在内存副本上注入损坏，原文件不变：

- **BRVD 魔数被破坏**：无法定位 El Torito 入口（该路出处丢失），但 GPT/备份 GPT 仍
  能解出 ESP 几何——丢的是“El Torito 这一路的来源声明”，不是字节本身。
- **主 GPT 头 CRC 损坏**：主头失效，备份头 CRC 仍有效并给出同一 ESP 区间，几何可恢复。
- **disjoint 副本中只损坏一份（反例 B）**：另一份字节逐位不变且仍可解析 → 反向坐实
  两段是独立存储；注意 GPT entry CRC 只覆盖分区项、不覆盖载荷，所以翻转载荷字节不会
  使 entry CRC 失败，这正说明 CRC 不能替代内容/来源核验。
- **重合区/重叠区损坏（A、C）**：一次翻转同时经两个入口可见 → 证明交集确实是共享物
  理存储（区分“共享存储”与“恰好同内容”）；但此时已无法证明内容完整性，只能确认几何。

边界：若两套元数据同时被毁到无法解析区间，则同一性**不可判定**，应明确标记
unknown，而不是用剩余哈希去猜测。

## 复算方式（全部只读，无需挂载）

```sh
# 重新生成并打印区间对照 + 损坏分析
python3 run_lab.py

# 第三方 El Torito 解析交叉校验（仓库自带 pycdlib 低层解析器）
../.venv/bin/python crosscheck_pycdlib.py

# 手工复算反例 B 的两段哈希（结果相同，范围不同）
dd if=images/hybrid_B.iso bs=1 skip=40960 count=4096 2>/dev/null | shasum -a 256
dd if=images/hybrid_B.iso bs=1 skip=45056 count=4096 2>/dev/null | shasum -a 256

# 查看 BRVD/catalog/GPT/MBR 原始字节
xxd -s 34816 -l 16 images/hybrid_A.iso      # BRVD: 00 CD001 "EL TORITO"
fdisk images/hybrid_B.iso                   # MBR 0xEE 保护项 + 0xEF 项
```

## 文件说明

- `build_lab.py`：字节级构造器（MBR/GPT/BRVD/catalog/载荷），严格按规格填字段与校验和。
- `verify_lab.py`：独立解析器与区间关系分类，结构校验和逐项验证。
- `run_lab.py`：生成三介质、打印可复算对照表、注入损坏并给结论矩阵。
- `crosscheck_pycdlib.py`：用 pycdlib 低层解析器独立复核 El Torito，结果与 verify_lab 对齐。
- `report.txt`：一次完整运行的留存输出。
