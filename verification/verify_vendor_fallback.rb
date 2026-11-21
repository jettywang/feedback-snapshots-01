# frozen_string_literal: true

# 场景: vendor 无法选择 HTML5(如 JRuby 无 libgumbo, 或 Loofah.html5_support? 为 false)。
# 在加载 rails-html-sanitizer 之前强制 html5_support?=false, 验证回退分支。
require "loofah"
Loofah.define_singleton_method(:html5_support?) { false }
require "rails-html-sanitizer"

puts "Loofah.html5_support? = #{Loofah.html5_support?}"
puts "Rails::HTML::Sanitizer.html5_support? = #{Rails::HTML::Sanitizer.html5_support?}"
puts "best_supported_vendor = #{Rails::HTML::Sanitizer.best_supported_vendor}"
puts "Rails::HTML5 defined? = #{defined?(Rails::HTML5) ? "yes" : "no(HTML5 解析器模块未定义)"}"
puts "Rails::HTML::Concern::Parser::HTML5 defined? = #{defined?(Rails::HTML::Concern::Parser::HTML5) ? "yes" : "no"}"

s = Rails::HTML::Sanitizer.best_supported_vendor.safe_list_sanitizer.new
input = %q{<b>hi</b><script>x</script><a href="javascript:alert(1)" onclick="e()">l</a>}
puts "HTML4 SafeList 基本净化: #{s.sanitize(input).inspect}"
puts "HTML4 sanitize_css 仍走 Loofah::HTML5::Scrub.scrub_css: #{s.sanitize_css('width: expression(alert(1)); color: blue').inspect}"
puts "allowed_uri? 仍可用: #{Rails::HTML::Sanitizer.allowed_uri?("https://example.com/").inspect}"
