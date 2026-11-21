# frozen_string_literal: true

# Loofah 升级兼容验证：覆盖三条实际调用路径 + vendor 选择 + 版本下限探针。
# 运行方式（仓库根目录，完全离线）：
#   .feedback/bundle-env exec ruby -Ilib verification/verify_loofah_upgrade.rb

require "rails-html-sanitizer"

$failures = []
def check(label, actual, expected: nil, allow: nil)
  ok = expected.nil? ? allow.call(actual) : (actual == expected)
  puts format("%-72s %s", label, ok ? "PASS" : "FAIL")
  puts "  actual:   #{actual.inspect}" unless ok
  puts "  expected: #{expected.inspect}" unless ok && expected
  $failures << label unless ok
end

puts "== 0. 依赖与 vendor 选择 =="
puts "loofah=#{Loofah::VERSION} nokogiri=#{Nokogiri::VERSION} " \
     "nokogiri-uses-libgumbo=#{Nokogiri.respond_to?(:uses_libgumbo?) ? Nokogiri.uses_libgumbo? : "n/a"}"
puts "Loofah.html5_support? = #{Loofah.html5_support?}"
puts "best_supported_vendor = #{Rails::HTML::Sanitizer.best_supported_vendor}"
check("版本下限: Scrub.scrub_attribute_value 存在(loofah>=2.25.3)",
      Loofah::HTML5::Scrub.respond_to?(:scrub_attribute_value), expected: true)
check("版本下限: Scrub.scrub_css_attribute 存在",
      Loofah::HTML5::Scrub.respond_to?(:scrub_css_attribute), expected: true)
check("vendor: CRuby+libgumbo 下选中 HTML5",
      Rails::HTML::Sanitizer.best_supported_vendor == Rails::HTML5::Sanitizer, expected: true)

sanitizer = Rails::HTML::Sanitizer.best_supported_vendor.safe_list_sanitizer.new

puts "\n== 1. 路径A: 普通 SafeList (PermitScrubber) =="
check("A1 保留白名单标签", sanitizer.sanitize("<b>hi</b> <u>x</u>"), expected: "<b>hi</b> x")
check("A2 script 标签剥离(子文本保留为纯文本)", sanitizer.sanitize("<script>alert(1)</script>ok"),
      allow: ->(o) { !o.include?("<script") && o.include?("ok") })
check("A3 移除事件属性", sanitizer.sanitize('<a href="/x" onclick="evil()">l</a>'),
      expected: '<a href="/x">l</a>')
check("A4 javascript: URI 被中和", sanitizer.sanitize('<a href="javascript:alert(1)">l</a>'),
      allow: ->(o) { !o.include?("javascript:") })
check("A5 自定义 tags/attributes 生效",
      sanitizer.sanitize('<table><tr><td id="a" class="b">c</td></tr></table>',
                         tags: %w(table tr td), attributes: %w(class)),
      expected: '<table><tr><td class="b">c</td></tr></table>')
check("A6 SVG use 外链 href 被移除(GHSA-cj75-f6xr-r4g7)",
      sanitizer.sanitize('<svg><use href="https://evil.example/x.svg#p"></use></svg>',
                         tags: %w(svg use), attributes: %w(href)),
      allow: ->(o) { !o.include?("evil.example") })
check("A7 SVG use 本地锚点保留",
      sanitizer.sanitize('<svg><use href="#local"></use></svg>', tags: %w(svg use), attributes: %w(href)),
      allow: ->(o) { o.include?('href="#local"') })
check("A8 mglyph 强制移除", sanitizer.sanitize("<math><mglyph><style><img src=x onerror=alert(1)></style></mglyph></math>"),
      allow: ->(o) { !o.include?("mglyph") && !o.include?("onerror") })
check("A9 style 属性内 CSS 被净化", sanitizer.sanitize('<span style="color:red;width:expression(alert(1))">s</span>',
                                                       tags: %w(span), attributes: %w(style)),
      allow: ->(o) { o.include?("color:red") && !o.include?("expression") })
check("A10 并发调用不串配置(GHSA-h7wh-q2qr-458c)",
      8.times.map {
        [Thread.new { sanitizer.sanitize("<b>a</b><i>c</i>", tags: %w(b)) },
         Thread.new { sanitizer.sanitize("<b>a</b><i>c</i>", tags: %w(b i)) }]
      }.flat_map { |a, b| [a.value, b.value] }.each_slice(2).all? { |x, y| x == "<b>a</b>c" && y == "<b>a</b><i>c</i>" },
      expected: true)

puts "\n== 2. 路径B: 自定义 scrubber =="
class UpcaseScrubber < Loofah::Scrubber
  def initialize
    @direction = :bottom_up
  end

  def scrub(node)
    node.content = node.content.upcase if node.text?
    Loofah::Scrubber::CONTINUE
  end
end
check("B1 Loofah::Scrubber 子类经 options[:scrubber] 生效",
      sanitizer.sanitize("<b>hello</b>", scrubber: UpcaseScrubber.new), expected: "<b>HELLO</b>")

class KeepOnlyB < Rails::HTML::PermitScrubber
  def initialize
    super
    self.tags = %w(b)
    self.attributes = %w()
  end
end
check("B2 PermitScrubber 子类生效", sanitizer.sanitize('<b>x</b><i>y</i>', scrubber: KeepOnlyB.new),
      expected: "<b>x</b>y")
check("B3 非 Loofah::Scrubber 被拒绝",
      begin
        sanitizer.sanitize("<b>x</b>", scrubber: Object.new)
        "not-raised"
      rescue NoMethodError, RuntimeError, TypeError => e
        e.class.name
      end,
      allow: ->(o) { o != "not-raised" })

puts "\n== 3. 路径C: 独立 CSS 净化 =="
check("C1 合法声明保留(允许序列化差异: 去空格/补分号)", sanitizer.sanitize_css("color: red; background-color: #fff"),
      allow: ->(o) { o.delete(" ").include?("color:red") && o.include?("background-color") })
check("C2 expression() 被移除", sanitizer.sanitize_css("width: expression(alert(1)); color: blue"),
      allow: ->(o) { !o.include?("expression") && o.delete(" ").include?("color:blue") })
check("C3 javascript: url 被移除", sanitizer.sanitize_css("background: url(javascript:alert(1))"),
      allow: ->(o) { !o.downcase.include?("javascript") })
check("C4 -moz-binding 被移除", sanitizer.sanitize_css("-moz-binding: url(http://evil/x.xml#xss)"),
      allow: ->(o) { !o.include?("-moz-binding") })
check("C5 allowed_uri? 委托", Rails::HTML::Sanitizer.allowed_uri?("https://example.com/"), expected: true)
check("C6 allowed_uri? 拦截 javascript:", !Rails::HTML::Sanitizer.allowed_uri?("javascript:alert(1)"), expected: true)

puts "\n== 结果 =="
if $failures.empty?
  puts "ALL PASS"
else
  puts "#{$failures.size} FAILURES: #{$failures.join(", ")}"
  exit 1
end
