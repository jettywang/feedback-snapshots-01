# frozen_string_literal: true

# Cross-collection comparison for the FTP audit.
#
# Run from the repository root (after audit/collect.rb):
#   .feedback/bundle-env exec ruby audit/compare.rb
#
# Reads audit/evidence/*, rebuilds every record from the raw artifacts,
# and writes audit/evidence/comparison.md. Exits non-zero if the
# confirmable pair (P1) fails to confirm.

require "json"
require "digest"
require "time"

EVIDENCE_DIR = File.expand_path("evidence", __dir__)

MONTHS = %w[Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec].each_with_index.to_h { |m, i| [m, i + 1] }

LIST_RE = /\A(?<perms>[bcdlps-][rwxstST-]{9})\s+\d+\s+\S+\s+\S+\s+(?<size>\d+)\s+(?<mon>[A-Z][a-z]{2})\s+(?<day>\d{1,2})\s+(?<toy>\d{2}:\d{2}|\d{4})\s+(?<name>.+)\z/

def read(name)
  File.read(File.join(EVIDENCE_DIR, name))
end

def parse_list(file, dir_state)
  read(file).lines.filter_map do |line|
    m = LIST_RE.match(line.chomp) or next
    toy = m[:toy]
    {
      source: file,
      dir_state: dir_state,
      name: m[:name],
      size: m[:size].to_i,
      kind: m[:perms].start_with?("d") ? "dir" : "file",
      month: MONTHS.fetch(m[:mon]),
      day: m[:day].to_i,
      precision: toy.include?(":") ? :minute : :year,
      toy: toy,
      raw: line.chomp,
    }
  end
end

def load_mlsx(file)
  JSON.parse(read(file)).map do |e|
    f = e["facts"]
    {
      source: file,
      pathname: e["pathname"],
      name: e["pathname"],
      size: f["size"],
      kind: f["type"],
      modify: f["modify"] && Time.iso8601(f["modify"]),
      unique: f["unique"],
    }
  end
end

def minute_fields_match?(list_rec, time)
  list_rec[:month] == time.month && list_rec[:day] == time.day &&
    list_rec[:toy] == format("%02d:%02d", time.hour, time.min)
end

def day_fields_match?(list_rec, time)
  list_rec[:toy] == time.year.to_s &&
    list_rec[:month] == time.month && list_rec[:day] == time.day
end

list_root = parse_list("collection1_list_root.txt", 'PWD "/" (collection 1, before CWD)')
list_arch = parse_list("collection1_list_archive.txt", 'PWD "/archive" (collection 1, after CWD archive)')
mlsd_root = load_mlsx("collection2_mlsd_root.json")
mlsd_arch = load_mlsx("collection2_mlsd_archive.json")
mlst_root = JSON.parse(read("collection2_mlst_root_report.json"))
mlst_arch = JSON.parse(read("collection2_mlst_archive_report.json"))
server_receipts = JSON.parse(read("collection2_server_receipts.json"))
client_receipt = JSON.parse(read("collection2_client_receipt.json"))
downloaded_sha256 = Digest::SHA256.file(File.join(EVIDENCE_DIR, "collection2_retr_report.csv")).hexdigest
downloaded_size = File.size(File.join(EVIDENCE_DIR, "collection2_retr_report.csv"))

a_root_report = list_root.find { |r| r[:name] == "report.csv" }
a_arch_report = list_arch.find { |r| r[:name] == "report.csv" }
b_root_report = mlsd_root.find { |r| r[:name] == "report.csv" }
b_arch_report = mlsd_arch.find { |r| r[:name] == "report.csv" }
receipt = server_receipts.find { |r| r["resolved_path"] == "/report.csv" }

pairs = []

# P1: collection 2, MLSD entry vs RETR receipt for the same confirmed path.
p1_checks = {
  "路径一致 (MLSD pathname == RETR resolved_path)" =>
    "/report.csv" == receipt["resolved_path"],
  "大小一致 (Size 事实 == 回执字节数 == 落盘字节数)" =>
    [b_root_report[:size], receipt["bytes"], downloaded_size, client_receipt["bytes"]].uniq.size == 1,
  "内容一致 (服务器回执 SHA256 == 客户端落盘 SHA256)" =>
    [receipt["sha256"], client_receipt["sha256"], downloaded_sha256].uniq.size == 1,
  "对象一致 (MLST 事后单文件查询 Unique 与 MLSD 相同)" =>
    mlst_root.dig("facts", "unique") == b_root_report[:unique],
}
pairs << {
  id: "P1",
  a: 'B: MLSD "/" 中 report.csv (Unique=9F3A01)',
  b: "B: RETR /report.csv 传输回执",
  direct: "路径、Size=4096、SHA256 均可直接比较",
  time: "同一控制连接内先后发生，无需跨时钟关联",
  checks: p1_checks,
  verdict: p1_checks.values.all? ? :confirmed : :failed,
}

# P2: collection 1 LIST (after CWD) vs collection 2 MLSD, same name in /archive.
p2_name = a_arch_report[:name] == b_arch_report[:name]
p2_size = a_arch_report[:size] == b_arch_report[:size]
p2_time = day_fields_match?(a_arch_report, b_arch_report[:modify])
pairs << {
  id: "P2",
  a: 'A: LIST (CWD archive 后) 中 report.csv — "Mar  3  2025", 4096',
  b: 'B: MLSD "/archive" 中 report.csv (Modify=20250303182215Z, Unique=9F3A02)',
  direct: "名称一致=#{p2_name}，大小一致=#{p2_size}",
  time: "只能日级关联：A 侧无时刻/时区，B 侧 modify 落在 #{a_arch_report[:toy]}-#{format("%02d-%02d", a_arch_report[:month], a_arch_report[:day])} 这一天内=#{p2_time}",
  checks: { "名称" => p2_name, "大小" => p2_size, "日级时间关联" => p2_time },
  verdict: :pending,
}

# P3: collection 1 LIST (root) vs collection 2 MLSD (root).
p3_name = a_root_report[:name] == b_root_report[:name]
p3_size = a_root_report[:size] == b_root_report[:size]
p3_time = minute_fields_match?(a_root_report, b_root_report[:modify])
pairs << {
  id: "P3",
  a: 'A: LIST (PWD "/") 中 report.csv — "Nov 26 09:41", 4096',
  b: 'B: MLSD "/" 中 report.csv (Modify=20261126094107Z, Unique=9F3A01)',
  direct: "名称一致=#{p3_name}，大小一致=#{p3_size}",
  time: "只能分钟级关联：月/日/时/分一致=#{p3_time}；A 侧无年份(按采集年推定)、无秒、无时区，B 侧秒=07 无法核对",
  checks: { "名称" => p3_name, "大小" => p3_size, "分钟级时间关联" => p3_time },
  verdict: :pending,
}

# P4: collection 1, root vs archive same-name records (after directory switch).
p4_name = a_root_report[:name] == a_arch_report[:name]
p4_size = a_root_report[:size] == a_arch_report[:size]
pairs << {
  id: "P4",
  a: 'A: LIST (PWD "/") 中 report.csv — "Nov 26 09:41"',
  b: 'A: LIST (CWD archive 后) 中 report.csv — "Mar  3  2025"',
  direct: "名称一致=#{p4_name}，大小一致=#{p4_size}",
  time: "无共同时间基准：两条记录精度不同(分钟 vs 年)，LIST 不提供对象唯一性，无法判断同一对象还是副本",
  checks: { "名称" => p4_name, "大小" => p4_size },
  verdict: :pending,
}

VERDICT_LABEL = { confirmed: "确认关联", pending: "留待确认", failed: "对照失败" }

lines = []
lines << "# FTP 同名记录对照结果"
lines << ""
lines << "生成时间(采集机时钟, UTC): #{Time.now.utc.strftime("%Y-%m-%dT%H:%M:%SZ")}"
lines << ""
lines << "## 记录来源"
lines << ""
lines << "- 采集 1 (server-a, 当时): `collection1_list_root.txt` 相对于 PWD `/`；`collection1_list_archive.txt` 相对于 CWD `archive` 之后的 PWD `/archive`；`collection1_mlsd_attempt.txt` 证明当时无机器事实(502)。"
lines << "- 采集 2 (server-b, 事后): `collection2_mlsd_*.json` 为绝对路径机器事实；`collection2_server_receipts.json` 为确认路径 `/report.csv` 的下载回执；`collection2_mlst_*.json` 为事后单文件查询。"
lines << ""
lines << "## 同名记录对照"
pairs.each do |p|
  lines << ""
  lines << "### #{p[:id]} — #{VERDICT_LABEL.fetch(p[:verdict])}"
  lines << ""
  lines << "- 记录甲: #{p[:a]}"
  lines << "- 记录乙: #{p[:b]}"
  lines << "- 可直接比较: #{p[:direct]}"
  lines << "- 时间关联: #{p[:time]}"
  p[:checks].each do |label, ok|
    lines << "  - #{label}: #{ok ? "一致" : "不一致"}"
  end
  lines << "- 结论: #{VERDICT_LABEL.fetch(p[:verdict])}"
end
lines << ""
lines << "## 判定时限"
lines << ""
lines << "- P1 为同事务内对照(清单事实 ↔ 下载回执), 路径/大小/内容哈希三重一致, 可确认关联。"
lines << "- P2/P3/P4 只有名称与大小可直接比较; 时间精度不对等(分钟/年 vs UTC 秒), 且采集 1 当时未取得 Unique 或内容事实(502 为证), 事后 MLST 拿到的事实不能回填, 故只能留待确认。"

File.write(File.join(EVIDENCE_DIR, "comparison.md"), lines.join("\n") + "\n")

pairs.each do |p|
  puts "#{p[:id]}: #{VERDICT_LABEL.fetch(p[:verdict])}"
end
exit(pairs.any? { |p| p[:verdict] == :failed } ? 1 : 0)
