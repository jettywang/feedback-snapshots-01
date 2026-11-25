# FTP 同名记录对照结果

生成时间(采集机时钟, UTC): 2026-11-25T16:14:18Z

## 记录来源

- 采集 1 (server-a, 当时): `collection1_list_root.txt` 相对于 PWD `/`；`collection1_list_archive.txt` 相对于 CWD `archive` 之后的 PWD `/archive`；`collection1_mlsd_attempt.txt` 证明当时无机器事实(502)。
- 采集 2 (server-b, 事后): `collection2_mlsd_*.json` 为绝对路径机器事实；`collection2_server_receipts.json` 为确认路径 `/report.csv` 的下载回执；`collection2_mlst_*.json` 为事后单文件查询。

## 同名记录对照

### P1 — 确认关联

- 记录甲: B: MLSD "/" 中 report.csv (Unique=9F3A01)
- 记录乙: B: RETR /report.csv 传输回执
- 可直接比较: 路径、Size=4096、SHA256 均可直接比较
- 时间关联: 同一控制连接内先后发生，无需跨时钟关联
  - 路径一致 (MLSD pathname == RETR resolved_path): 一致
  - 大小一致 (Size 事实 == 回执字节数 == 落盘字节数): 一致
  - 内容一致 (服务器回执 SHA256 == 客户端落盘 SHA256): 一致
  - 对象一致 (MLST 事后单文件查询 Unique 与 MLSD 相同): 一致
- 结论: 确认关联

### P2 — 留待确认

- 记录甲: A: LIST (CWD archive 后) 中 report.csv — "Mar  3  2025", 4096
- 记录乙: B: MLSD "/archive" 中 report.csv (Modify=20250303182215Z, Unique=9F3A02)
- 可直接比较: 名称一致=true，大小一致=true
- 时间关联: 只能日级关联：A 侧无时刻/时区，B 侧 modify 落在 2025-03-03 这一天内=true
  - 名称: 一致
  - 大小: 一致
  - 日级时间关联: 一致
- 结论: 留待确认

### P3 — 留待确认

- 记录甲: A: LIST (PWD "/") 中 report.csv — "Nov 26 09:41", 4096
- 记录乙: B: MLSD "/" 中 report.csv (Modify=20261126094107Z, Unique=9F3A01)
- 可直接比较: 名称一致=true，大小一致=true
- 时间关联: 只能分钟级关联：月/日/时/分一致=true；A 侧无年份(按采集年推定)、无秒、无时区，B 侧秒=07 无法核对
  - 名称: 一致
  - 大小: 一致
  - 分钟级时间关联: 一致
- 结论: 留待确认

### P4 — 留待确认

- 记录甲: A: LIST (PWD "/") 中 report.csv — "Nov 26 09:41"
- 记录乙: A: LIST (CWD archive 后) 中 report.csv — "Mar  3  2025"
- 可直接比较: 名称一致=true，大小一致=true
- 时间关联: 无共同时间基准：两条记录精度不同(分钟 vs 年)，LIST 不提供对象唯一性，无法判断同一对象还是副本
  - 名称: 一致
  - 大小: 一致
- 结论: 留待确认

## 判定时限

- P1 为同事务内对照(清单事实 ↔ 下载回执), 路径/大小/内容哈希三重一致, 可确认关联。
- P2/P3/P4 只有名称与大小可直接比较; 时间精度不对等(分钟/年 vs UTC 秒), 且采集 1 当时未取得 Unique 或内容事实(502 为证), 事后 MLST 拿到的事实不能回填, 故只能留待确认。
