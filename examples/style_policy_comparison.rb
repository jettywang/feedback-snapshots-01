# frozen_string_literal: true

# Run from the repository root:
#
#   .feedback/bundle-env exec ruby -Ilib examples/style_policy_comparison.rb
#
# Demonstrates one style policy used for a standalone style string and for an
# HTML fragment. Everything here is local; no network or external service.

require "rails-html-sanitizer"

# Business-approved color and width. `cursor` is a valid CSS property and is
# allowed by the default HTML sanitizer, but email clients do not support it,
# so the email policy does not include it.
EMAIL_POLICY = Rails::HTML::StylePolicy.new(
  properties: %w(color width),
  values: {
    "color" => %w(#0b57d0),
    "width" => %w(600px 100%),
  },
)

STYLE = "color: #0b57d0; width: 600px; cursor: pointer;"
HTML = %(<p style="#{STYLE}">Your order has shipped.</p>)

sanitizer = Rails::HTML5::SafeListSanitizer.new

puts "Input style: #{STYLE}"
puts
puts "Standalone style"
puts "  default:  #{sanitizer.sanitize_css(STYLE).inspect}"
puts "  policy:   #{sanitizer.sanitize_css(STYLE, style_policy: EMAIL_POLICY).inspect}"
puts
puts "HTML fragment"
puts "  input:    #{HTML.inspect}"
puts "  default:  #{sanitizer.sanitize(HTML, attributes: %w(style)).inspect}"
puts "  policy:   #{sanitizer.sanitize(HTML, attributes: %w(style), style_policy: EMAIL_POLICY).inspect}"
puts
puts "Diagnostics (no original style or values are stored)"
report = Rails::HTML::StylePolicy::Report.new
sanitizer.sanitize(HTML, attributes: %w(style), style_policy: EMAIL_POLICY, style_report: report)
report.entries.each do |entry|
  puts "  #{entry[:property]}: #{entry[:disposition]} (#{entry[:reason]})"
end
