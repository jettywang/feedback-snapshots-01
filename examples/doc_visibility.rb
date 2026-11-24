# frozen_string_literal: true

# Documentation visibility for partner-facing constraint docs.
#
# Run with: ruby -Ilib examples/doc_visibility.rb
#
# This example defines a nested order form whose constraint documentation is
# shared with an integration partner. Some value sets and error examples are
# internal-only, so the partner-facing export is produced with
# `info(visibility: :public)` while the full export stays available via
# `info`. Validation itself never changes.

require "dry/schema"
require "pp"

Dry::Schema.load_extensions(:info)

# A custom rule that only records calls. It observes every value it sees and
# always passes, proving that documentation policy has no effect on actual
# input validation.
AUDIT_LOG = []

module AuditPredicates
  include Dry::Logic::Predicates

  def self.audit_only?(input)
    AUDIT_LOG << input
    true
  end
end

# A composed sub-schema with its own internal-only error example.
PaymentSchema = Dry::Schema.JSON do
  configure do |config|
    config.info_examples = {
      "card" => [{value: "4111-1111-1111-1111", valid: false}]
    }
  end

  required(:card).filled(:string)
  required(:amount).filled(:integer, gt?: 0)
end

OrderForm = Dry::Schema.JSON do
  configure do |config|
    config.predicates = AuditPredicates

    # Documentation metadata: valid examples are public, error examples are
    # internal-only by default.
    config.info_examples = {
      "email" => ["jane@doe.org", {value: "not-an-email", valid: false}],
      "coupon" => [{value: "SUMMER-SALE", valid: true}],
      "address.room" => [{value: "13B", valid: false}]
    }

    # Documentation visibility policy applied by `info(visibility: :public)`.
    config.info_visibility = {
      keys: %w[audit_token address.room],   # internal-only keys (dot paths)
      values: {"state" => %w[blocked]}      # internal-only enum members
    }
  end

  required(:email).filled(:string, format?: /@/)
  required(:state).filled(:string, included_in?: %w[active suspended blocked])
  required(:audit_token).filled(:string)
  optional(:coupon).maybe(:string, :audit_only?)

  required(:address).hash do
    required(:street).filled(:string)
    required(:zipcode).filled(:string)
    optional(:room).maybe(:string)
  end

  required(:lines).array(:hash) do
    required(:sku).filled(:string)
    required(:qty).filled(:integer, gt?: 0)
  end

  required(:payment).schema(PaymentSchema)
end

puts "=== INTERNAL doc (schema.info) — 内部完整约束文档 ==="
pp OrderForm.info

puts
puts "=== PUBLIC doc (schema.info(visibility: :public)) — 发给合作方的约束文档 ==="
public_doc = OrderForm.info(visibility: :public)
pp public_doc

puts
puts "=== 公开性对照 ==="
puts "可公开: 类型/必填性 (email: string, lines[].qty: integer)"
puts "可公开: 获准枚举 state.values => #{public_doc[:keys][:state][:values].inspect}"
puts "可公开: 有效示例 email => #{public_doc[:keys][:email][:examples].inspect}"
puts "需内部另核对: 内部枚举成员 'blocked' (公开文档已过滤, 校验仍接受)"
puts "需内部另核对: 内部键 audit_token, address.room (公开文档已移除)"
puts "需内部另核对: 错误示例 email 'not-an-email', address.room '13B', payment.card"
puts "未泄露: 组合 schema PaymentSchema 的私有示例未进入 OrderForm 文档"
puts "未泄露: 自定义 predicate audit_only? 的参数不出现在任何导出中"

input = {
  email: "jane@doe.org",
  state: "blocked", # 内部状态: 公开文档不列出, 但校验照常接受
  audit_token: "secret-token",
  coupon: "SUMMER-SALE",
  address: {street: "Main St", zipcode: "00-001", room: "13B"},
  lines: [{sku: "A-1", qty: 2}],
  payment: {card: "4111-1111-1111-1111", amount: 100}
}

puts
puts "=== 实测校验 (文档政策不影响验证) ==="
result = OrderForm.call(input)
puts "valid input (含内部值 blocked/audit_token/room): success=#{result.success?}"

invalid = OrderForm.call(input.merge(state: "unknown", email: "nope"))
puts "invalid input errors: #{invalid.errors.to_h.inspect}"

puts
puts "=== 自定义规则调用记录 (audit_only? 只记录不拦截) ==="
puts "AUDIT_LOG => #{AUDIT_LOG.inspect}"
