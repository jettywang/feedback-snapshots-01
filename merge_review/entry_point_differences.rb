# frozen_string_literal: true

# =============================================================================
# 不同外部调用入口上的可观察安全差别（演示脚本，只打印不断言）
#   ruby entry_point_differences.rb
# =============================================================================

begin
  require "ruby-next"
rescue LoadError
  $LOAD_PATH.unshift(File.expand_path("vendor", __dir__))
end

begin
  require "action_policy"
rescue LoadError
  $LOAD_PATH.unshift(File.expand_path("../lib", __dir__))
end

require_relative "merged_policy"

admin = User.new(1, :admin, nil, false)
stranger = User.new(8, :member, nil, false)
doc = Document.new(2, [6], false)
invoice = Invoice.new(5, :issued)

puts "== 1. 直接调用规则方法 vs apply：pre_check 被绕过 =="
policy = DocumentPolicy.new(doc, user: admin)
puts "  policy.show?          => #{policy.show?.inspect}   (pre_check 未执行，admin 直通丢失)"
puts "  policy.apply(:show?)  => #{policy.apply(:show?).inspect}   (pre_check 执行，admin 放行)"

puts
puts "== 2. 直接调用含 deny!/allow! 的规则：抛 UncaughtThrowError 而非返回 false =="
begin
  InvoicePolicy.new(invoice, user: stranger).show?
  puts "  没有抛错（意外）"
rescue UncaughtThrowError => e
  puts "  invoice_policy.show?  => 抛 #{e.class}（deny! 的 throw 只在 apply/authorize! 内被捕获）"
end
res = InvoicePolicy.new(invoice, user: stranger).apply_r(:show?)
puts "  apply_r(:show?)       => #{res.inspect}"

puts
puts "== 3. Behaviour 层三个入口：同样的拒绝，可观察信息完全不同 =="
class ApiCaller
  include ActionPolicy::Behaviour

  authorize :user

  attr_reader :user

  def initialize(user) = @user = user
end

caller_as_stranger = ApiCaller.new(stranger)

begin
  caller_as_stranger.authorize!(invoice, to: :show?, with: InvoicePolicy)
rescue ActionPolicy::Unauthorized => e
  puts "  authorize!   => 抛 ActionPolicy::Unauthorized, reasons=#{e.result.reasons.details.inspect}"
end
puts "  allowed_to?  => #{caller_as_stranger.allowed_to?(:show?, invoice, with: InvoicePolicy).inspect} (reason 被丢弃，只剩布尔值)"
allowance = caller_as_stranger.allowance_to(:show?, invoice, with: InvoicePolicy)
puts "  allowance_to => #{allowance.inspect}, reasons=#{allowance.reasons.details.inspect}"

puts
puts "== 4. 框架入口的'兜底网'不一样（静态证据） =="
require "action_policy/rails/controller"
require "action_policy/rails/channel"
controller_hooks = %i[verify_authorized verify_authorized_scoped skip_verify_authorized!] &
  ActionPolicy::Controller.instance_methods
channel_hooks = %i[verify_authorized verify_authorized_scoped skip_verify_authorized!] &
  ActionPolicy::Channel.instance_methods
puts "  Controller 提供漏授权兜底: #{controller_hooks.inspect}"
puts "  Channel    提供漏授权兜底: #{channel_hooks.inspect} (空 = 忘记 authorize! 不会有任何报错)"

puts
puts "== 5. 合并策略自身的入口差异：deny reason 只在结果对象通道可见 =="
merged = MergedReadPolicy.new(invoice, user: stranger)
puts "  merged.apply(:show?)        => #{merged.apply(:show?).inspect} (布尔，reason 不可见)"
merged2 = MergedReadPolicy.new(invoice, user: stranger)
puts "  merged.apply_r(:show?)      => reasons=#{merged2.apply_r(:show?).reasons.details.inspect}"
