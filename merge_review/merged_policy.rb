# frozen_string_literal: true

require_relative "legacy_policies"

# 旧策略分派表：合并前后的"规格"，检查脚本与过渡策略共用同一份，
# 避免两边各自维护导致检查失效。
module MergeSpec
  def self.legacy_policy_class(record)
    case record
    when Document then record.confidential ? ConfidentialDocumentPolicy : DocumentPolicy
    when Report then ReportPolicy
    when Invoice then InvoicePolicy
    else raise ActionPolicy::NotFound, record
    end
  end
end

# =============================================================================
# 过渡策略：三套读策略合并为一套，带通用前置检查。
#
# 设计约束（对应 check_merge_safety.rb 中的断言）：
#   1. 通用 pre_check 只允许"收缩"（deny-only）。新增 allow! 型前置检查
#      会对 Report/Invoice 等旧策略构成权限扩大，检查脚本必须能抓到。
#   2. 旧别名 preview? 只对 Report 有效。不能裸用 alias_rule 全局放行：
#      对 Document/Invoice，旧体系中 preview? 走 default_rule :manage?
#      （默认拒绝），全局别名会把它变成 show? —— 这是权限扩大。
#   3. 具体判定一律委托回旧策略类（with:），并用 inline_reasons 合并
#      子策略 reason，保证拒绝 reason 的标识符（document / report /
#      invoice）和内容对客户端保持不变。
#   4. 不覆盖 default_rule：未知规则（如 wipe?）依旧回落到 manage?，
#      并委托给旧策略，完整复现旧体系"manage? 兜底 + 旧 pre_check"的
#      行为（包括 DocumentPolicy 上 admin 经 allow_admins 放行的怪癖）。
# =============================================================================
class MergedReadPolicy < ActionPolicy::Base
  authorize :user

  # 通用前置检查（只收缩）：停用账号一律拒绝，并留下 reason。
  pre_check :deny_suspended_users

  def show?
    delegate(:show?)
  end

  def download?
    delegate(:download?)
  end

  # 旧别名：仅 Report 保留 preview? -> show? 的别名语义；
  # 其它类型维持旧体系的 default_rule 兜底行为（等同于 manage?）。
  # 注意：不能写 alias_rule :preview?, to: :show? —— 别名是类级全局的，
  # 且 method_added 与继承的交互会让"按类型生效"无法实现。
  def preview?
    return allowed_to?(:show?, record, with: ReportPolicy, inline_reasons: true) if record.is_a?(Report)

    delegate(:manage?)
  end

  # default_rule :manage? 的兜底（来自 Policy::Defaults）：
  # 未知规则最终落到这里，委托旧策略复现旧行为。
  def manage?
    delegate(:manage?)
  end

  private

  def delegate(rule)
    allowed_to?(rule, record, with: MergeSpec.legacy_policy_class(record), inline_reasons: true)
  end

  def deny_suspended_users
    deny! :suspended_user if user.suspended
  end
end
