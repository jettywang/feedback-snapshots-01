# frozen_string_literal: true

# 场景: 依赖版本降回(loofah < 2.25.3)。
# 1) 解析层: gemspec 约束拒绝降版。
# 2) 运行层: 模拟降版后缺失 scrub_attribute_value 的失败形态, 证明启动探针的必要性。
require "rails-html-sanitizer"

spec = Gem::Specification.load("rails-html-sanitizer.gemspec")
spec.dependencies.each { |d| puts "gemspec 约束: #{d.name} #{d.requirement}" }
puts "当前解析: loofah=#{Loofah::VERSION} nokogiri=#{Nokogiri::VERSION}"

puts "\n-- 模拟 loofah 降回 < 2.25.3 (移除 Scrub.scrub_attribute_value) --"
Loofah::HTML5::Scrub.singleton_class.send(:remove_method, :scrub_attribute_value)
puts "respond_to?(:scrub_attribute_value) = #{Loofah::HTML5::Scrub.respond_to?(:scrub_attribute_value)}"
begin
  Rails::HTML5::SafeListSanitizer.new.sanitize('<a href="/x">l</a>', tags: %w(a), attributes: %w(href))
  puts "结果: 未报错(意外)"
rescue NoMethodError => e
  puts "结果: NoMethodError: #{e.message.lines.first.strip}"
end
puts "结论: 降版后任何带 attributes 的 SafeList 调用都会 500, 启动探针可在部署前拦截"
