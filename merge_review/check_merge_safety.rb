# frozen_string_literal: true

# =============================================================================
# 上线前检查：合并策略 vs 旧策略集合，确认"权限没有扩大"。
#
#   ruby check_merge_safety.rb          # 全部通过时退出码 0
#
# 证据结构：
#   A. 判定矩阵：所有 (用户 × 记录 × 规则 × 入口) 上，merged=allow ⇒ legacy=allow
#   B. 收缩项必须全部来自 allowlist 化的通用前置检查（suspended_user）
#   C. 拒绝 reason 的标识符对客户端保持兼容（merged ⊇ legacy）
#   D. 子类跳过、旧别名、未知规则的行为逐项对齐
#   E. pre_check 过滤器目标 lint（别名在过滤前解析，过滤器引用别名即为死规则）
#   F. 阴性对照：故意引入 allow! 型前置检查的变体必须被本检查判定为"扩大"
# =============================================================================

begin
  require "ruby-next"
rescue LoadError
  $LOAD_PATH.unshift(File.expand_path("vendor", __dir__))
end

begin
  require "action_policy"
rescue LoadError
  # 仓库内运行：直接使用本仓库的 lib
  $LOAD_PATH.unshift(File.expand_path("../lib", __dir__))
end

require_relative "merged_policy"

$stdout.sync = true
FAILURES = []
NOTES = []

def check(name)
  ok = yield
  puts(format("%-4s %s", ok ? "PASS" : "FAIL", name))
  FAILURES << name unless ok
  ok
rescue StandardError => e
  puts(format("%-4s %s (exception: %s: %s)", "FAIL", name, e.class, e.message))
  FAILURES << name
  false
end

# --- 测试矩阵 ---------------------------------------------------------------
USERS = {
  admin: User.new(1, :admin, nil, false),
  owner: User.new(2, :member, nil, false),
  top_owner: User.new(3, :member, :top, false),
  analyst: User.new(4, :analyst, nil, false),
  issuer: User.new(5, :member, nil, false),
  shared: User.new(6, :member, nil, false),
  stranger: User.new(8, :member, nil, false),
  suspended_admin: User.new(7, :admin, nil, true)
}.freeze

RECORDS = {
  document: Document.new(2, [6], false),
  confidential_document: Document.new(3, [], true),
  published_report: Report.new(true),
  draft_report: Report.new(false),
  paid_invoice: Invoice.new(5, :paid),
  unpaid_invoice: Invoice.new(5, :issued)
}.freeze

RULES = %i[show? preview? download? wipe?].freeze

def decide(policy_class, record, user, rule)
  result = policy_class.new(record, user: user).apply_r(rule)
  {outcome: result.success? ? :allow : :deny, reasons: result.reasons.details}
rescue ActionPolicy::UnknownRule
  {outcome: :unknown_rule, reasons: {}}
end

def matrix(policy_class)
  USERS.each_with_object({}) do |(user_name, user), acc|
    RECORDS.each do |record_name, record|
      RULES.each do |rule|
        legacy = decide(MergeSpec.legacy_policy_class(record), record, user, rule)
        merged = decide(policy_class, record, user, rule)
        acc[[user_name, record_name, rule]] = {legacy: legacy, merged: merged}
      end
    end
  end
end

puts "== A. 判定矩阵：权限不得扩大 =="
results = matrix(MergedReadPolicy)
expansions = results.select { |_, r| r[:merged][:outcome] == :allow && r[:legacy][:outcome] != :allow }
restrictions = results.select { |_, r| r[:merged][:outcome] != :allow && r[:legacy][:outcome] == :allow }
error_mismatch = results.select do |_, r|
  [r[:merged][:outcome], r[:legacy][:outcome]].include?(:unknown_rule) &&
    r[:merged][:outcome] != r[:legacy][:outcome]
end

check("A1 无任何 merged=allow 且 legacy!=allow 的组合（#{USERS.size * RECORDS.size * RULES.size} 个判定）") { expansions.empty? }
check("A2 UnknownRule 边界完全一致（未知规则不被静默放行）") { error_mismatch.empty? }
expansions.each_key { |k| puts "       EXPANSION: #{k.inspect}" }
error_mismatch.each_key { |k| puts "       MISMATCH:  #{k.inspect}" }

puts "== B. 收缩项必须全部来自 allowlist 化的通用前置检查 =="
unaccounted = restrictions.reject do |_, r|
  r[:merged][:reasons].fetch(:merged_read, []).include?(:suspended_user)
end
check("B1 所有新增拒绝都带 merged_read: [:suspended_user] reason（共 #{restrictions.size} 处收缩）") { unaccounted.empty? }
check("B2 收缩确实发生（通用前置检查生效，非死代码）") { !restrictions.empty? }
unaccounted.each_key { |k| puts "       UNACCOUNTED: #{k.inspect}" }

puts "== C. 拒绝 reason 兼容性 =="
reason_regressions = results.select do |_, r|
  next false unless r[:legacy][:outcome] == :deny && r[:merged][:outcome] == :deny
  # 停用账号被通用前置检查短路，子策略 reason 不再计算 —— 属已归因的收缩，跳过
  next false if r[:merged][:reasons].fetch(:merged_read, []).include?(:suspended_user)

  legacy_keys = r[:legacy][:reasons].keys
  !legacy_keys.empty? && !(legacy_keys - r[:merged][:reasons].keys).empty?
end
check("C1 旧策略给出的 reason 标识符在合并后全部保留（merged ⊇ legacy，短路除外）") { reason_regressions.empty? }
reason_regressions.each_key { |k| puts "       REASON LOST: #{k.inspect}" }

puts "== D. 关键行为逐项对齐 =="
check("D1 子类跳过：admin 读普通文档放行（父类 pre_check 仍在）") do
  DocumentPolicy.new(RECORDS[:document], user: USERS[:admin]).apply(:show?) == true
end
check("D2 子类跳过：admin 无机密许可读机密文档被拒（skip_pre_check 生效）") do
  ConfidentialDocumentPolicy.new(RECORDS[:confidential_document], user: USERS[:admin]).apply(:show?) == false
end
check("D3 子类跳过：top clearance 所有者读机密文档放行") do
  ConfidentialDocumentPolicy.new(RECORDS[:confidential_document], user: USERS[:top_owner]).apply(:show?) == true
end
check("D4 旧别名：preview? 与 show? 在旧策略和合并策略中判定一致") do
  %i[published_report draft_report].all? do |rec|
    %i[analyst stranger].all? do |usr|
      record = RECORDS[rec]
      user = USERS[usr]
      ReportPolicy.new(record, user: user).apply(:preview?) ==
        MergedReadPolicy.new(record, user: user).apply(:preview?)
    end
  end
end
check("D5 旧别名不扩散：preview? 作用于 Invoice 维持旧兜底（manage? 拒绝，不抛错不放行）") do
  MergedReadPolicy.new(RECORDS[:paid_invoice], user: USERS[:issuer]).apply(:preview?) == false
end
check("D6 拒绝 reason 实例：非开票人读发票得到 :not_issuer") do
  res = MergedReadPolicy.new(RECORDS[:paid_invoice], user: USERS[:stranger]).apply_r(:show?)
  res.fail? && res.reasons.details[:invoice]&.include?(:not_issuer)
end
check("D7 拒绝 reason 详情：未付款发票下载的 details 与旧策略完全一致") do
  merged = MergedReadPolicy.new(RECORDS[:unpaid_invoice], user: USERS[:issuer]).apply_r(:download?)
  legacy = InvoicePolicy.new(RECORDS[:unpaid_invoice], user: USERS[:issuer]).apply_r(:download?)
  merged.fail? && merged.reasons.details == legacy.reasons.details &&
    merged.all_details[:invoice_state] == :issued
end

puts "== E. pre_check 过滤器目标 lint =="
def lint_pre_check_targets(policy_class)
  policy_class.pre_checks.each_with_object([]) do |check_item, findings|
    targets = check_item.instance_variable_get(:@whitelist).to_a +
              check_item.instance_variable_get(:@blacklist).to_a
    targets.each do |name|
      if (target = policy_class.lookup_alias(name))
        findings << "#{policy_class}##{check_item.name}: 过滤器引用别名 #{name}，" \
                    "但 pre_check 看到的是解析后的 #{target}，过滤器永不命中"
      elsif !policy_class.method_defined?(name)
        findings << "#{policy_class}##{check_item.name}: 过滤器引用不存在的规则 #{name}"
      end
    end
  end
end

# 陷阱样例：only: :preview? 看似拒绝预览，实际别名先解析为 show?，过滤器失效。
class TrapPolicy < ActionPolicy::Base
  authorize :user

  alias_rule :preview?, to: :show?
  pre_check :deny_preview, only: :preview?

  def show? = true

  private

  def deny_preview = deny!(:preview_denied)
end

check("E1 正式策略（旧三套 + 合并）无死过滤器") do
  [DocumentPolicy, ConfidentialDocumentPolicy, ReportPolicy, InvoicePolicy, MergedReadPolicy]
    .all? { |klass| lint_pre_check_targets(klass).empty? }
end
check("E2 lint 能识别别名陷阱（TrapPolicy 被标记）") do
  lint_pre_check_targets(TrapPolicy).any? { |f| f.include?("preview?") }
end
check("E3 别名陷阱的行为证据：only: :preview? 的拒绝前置检查实际不生效") do
  TrapPolicy.new(nil, user: USERS[:stranger]).apply(:preview?) == true
end

puts "== F. 阴性对照：扩大权限的变体必须被抓到 =="
class BrokenMergedReadPolicy < MergedReadPolicy
  pre_check :allow_all_admins

  private

  def allow_all_admins
    allow! if user.admin?
  end
end

broken_results = matrix(BrokenMergedReadPolicy)
broken_expansions = broken_results.select { |_, r| r[:merged][:outcome] == :allow && r[:legacy][:outcome] != :allow }
check("F1 对照变体产生至少一处扩大（证明矩阵有鉴别力，#{broken_expansions.size} 处）") { !broken_expansions.empty? }
broken_expansions.first(3).each { |k, _| puts "       (对照样例) EXPANSION: #{k.inspect}" }

puts
if FAILURES.empty?
  puts "RESULT: PASS — 未发现权限扩大；#{restrictions.size} 处收缩均已归因；reason 兼容。"
  NOTES.each { |n| puts "NOTE: #{n}" }
  exit 0
else
  puts "RESULT: FAIL — #{FAILURES.size} 项未通过"
  FAILURES.each { |f| puts "  - #{f}" }
  exit 1
end
