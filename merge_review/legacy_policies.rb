# frozen_string_literal: true

require "action_policy"

# =============================================================================
# 旧体系：三套各自为政的读策略（合并对象）
# 纯 Ruby，不依赖 Rails。record 用简单的 Struct 代替 AR 模型。
# =============================================================================

Document = Struct.new(:owner_id, :shared_with, :confidential) do
  def shared_with?(user) = shared_with.include?(user.id)
end
Report = Struct.new(:published)
Invoice = Struct.new(:issuer_id, :state) do
  def paid? = state == :paid
end

User = Struct.new(:id, :role, :clearance, :suspended) do
  def admin? = role == :admin
  def analyst? = role == :analyst
end

# --- 策略 1：子类跳过（skip_pre_check 的继承语义）----------------------------
class DocumentPolicy < ActionPolicy::Base
  authorize :user

  pre_check :allow_admins

  def show?
    record.owner_id == user.id || record.shared_with?(user)
  end

  private

  def allow_admins
    allow! if user.admin?
  end
end

class ConfidentialDocumentPolicy < DocumentPolicy
  # 子类跳过：机密文件不允许 admin 通过 pre_check 直通，必须走显式规则。
  # skip_pre_check 只作用于子类副本（pre_checks 在继承时被 dup），父类不受影响。
  skip_pre_check :allow_admins

  def show?
    record.owner_id == user.id && user.clearance == :top
  end
end

# --- 策略 2：旧别名（alias_rule）---------------------------------------------
class ReportPolicy < ActionPolicy::Base
  authorize :user

  # 旧入口（报表预览端点）仍在调用 preview?，合并时必须保留该别名。
  alias_rule :preview?, to: :show?

  def show?
    user.analyst? && record.published
  end
end

# --- 策略 3：拒绝 reason（deny! / details）-----------------------------------
class InvoicePolicy < ActionPolicy::Base
  authorize :user

  def show?
    return true if record.issuer_id == user.id

    deny! :not_issuer
  end

  def download?
    return true if record.issuer_id == user.id && record.paid?

    details[:invoice_state] = record.state
    deny! :unpaid_invoice
  end
end
