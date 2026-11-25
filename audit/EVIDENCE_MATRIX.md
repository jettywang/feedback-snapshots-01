# FTP 审计核对办法与证据矩阵

审计保留的是几次 FTP 的目录清单和传输回执。目录切换之后出现同名同大小的文件，
两个服务器记录时间的精度不同。本文给出可执行的核对办法；配套脚本：

```sh
# 仓库根目录下, 可重复执行
.feedback/bundle-env exec ruby -Ilib audit/collect.rb   # 两次采集, 记录型控制+数据连接
.feedback/bundle-env exec ruby audit/compare.rb         # 对照并生成 evidence/comparison.md
```

采集在进程内经 `UNIXSocket.pair` 承载控制与数据连接(沙箱禁止 bind/connect),
Net::FTP 的协议引擎(sendcmd/transfercmd/parse227/BufferedSocket)全部真实走一遍;
服务器侧逐行记录控制连接收发与每条数据连接的字节数和 SHA256。

## 各命令能证明什么

| 命令/记录 | 能直接证明 | 不能证明 |
|---|---|---|
| `LIST` | 该次目录状态下存在某名称条目；服务器自述的大小；`月-日-时刻` 或 `月-日-年份` 二选一 | 年份或时刻(取决于格式)、秒、时区、对象唯一性、内容；格式未标准化, 解析依赖服务器实现 |
| `MLSD` | 目录内各条目的机器事实(RFC 3659): `Type`/`Size`/`Modify`(UTC 秒级)/`Unique`/`Perm` | 事实集合以服务器当时实现为准; 不证明内容 |
| `MLST`(事后单文件查询) | 查询时刻单个路径的事实集合 | 不能回溯证明当时状态; 当时缺失的事实(如采集 1 的 502)无法由它回填 |
| `RETR` 回执(150/226+字节数+SHA256) | 该次传输中该路径交付了这些字节 | 不证明此前或此后该路径指向同一对象 |

## 路径相对性

- 采集 1: 第一次 `LIST` 相对于 `PWD /`; `CWD archive` 之后第二次 `LIST` 相对于
  `PWD /archive` —— 同名 `report.csv` 是在目录切换后的另一次目录状态下出现的。
- 采集 2: `MLSD /`、`MLSD /archive`、`RETR /report.csv`、`MLST` 全部使用绝对路径,
  回执中的 `resolved_path` 即确认过的对应路径。

## 字段可比性

- 可直接比较: 名称、大小(Size 事实 ↔ LIST 尺寸列 ↔ 回执字节数)、类型、
  内容哈希(仅采集 2 内部)、`Unique`(仅同一服务器内)。
- 只能做时间关联: server-a 的 LIST 时间(分钟级无年份, 或年精度无时刻, 且无时区声明)
  与 server-b 的 `Modify`(UTC 秒级)。精度不对等时只能核对到两者较粗的一档。

## 证据矩阵(同名记录对)

| 编号 | 记录甲 | 记录乙 | 可直接比较 | 时间关联 | 结论 |
|---|---|---|---|---|---|
| P1 | B: MLSD `/` 中 report.csv | B: RETR `/report.csv` 回执 | 路径、Size=4096、SHA256 三重一致; MLST 的 Unique 与 MLSD 相同 | 同一控制连接内, 无需跨时钟 | **确认关联** |
| P2 | A: LIST(CWD 后 `/archive`) report.csv | B: MLSD `/archive` report.csv | 名称、大小一致 | 只能日级(2025-03-03) | 留待确认 |
| P3 | A: LIST(`/` 下) report.csv | B: MLSD `/` report.csv | 名称、大小一致 | 只能分钟级(09:41, 秒不可知, 年份按采集年推定) | 留待确认 |
| P4 | A: `/` 下 report.csv | A: `/archive` 下 report.csv | 名称、大小一致 | 无共同时间基准, LIST 无对象唯一性 | 留待确认 |

## 判定原则

- P1 是同事务内对照: 清单事实与下载回执在路径、大小、内容哈希上三重一致,
  足以确认"清单所描述的即所下载的"。
- P2/P3/P4 只有名称和大小可直接比较; 时间只能降精度关联; 采集 1 当时没有
  取得 `Unique` 或内容事实(`collection1_mlsd_attempt.txt` 中的 502 为证),
  事后单文件查询(MLST)拿到的事实不能替代当时缺失的事实, 故只能留待确认。

## 证据文件

`audit/evidence/` 由 `collect.rb` 重新生成: 两次采集的控制连接全程记录
(`collection*_control_transcript.txt`)、LIST 原文、MLSD/MLST 事实 JSON、
下载文件 `collection2_retr_report.csv`、服务器侧与客户端侧回执 JSON、
以及 `compare.rb` 生成的 `comparison.md`。两次运行的对照结果(除生成时间戳行)
逐字节一致。
