# frozen_string_literal: true

require "json"
require_relative "test_helper"

module SanitizerReportTests
  def module_under_test
    self.class.instance_variable_get(:@module_under_test)
  end

  def report
    Rails::HTML::Sanitizer::Report.new
  end

  def safe_list_sanitize(input, options = {})
    module_under_test::SafeListSanitizer.new.sanitize(input, options)
  end

  def prune_sanitize(input, options = {})
    module_under_test::SafeListSanitizer.new(prune: true).sanitize(input, options)
  end

  def full_sanitize(input, options = {})
    module_under_test::FullSanitizer.new.sanitize(input, options)
  end

  def link_sanitize(input, options = {})
    module_under_test::LinkSanitizer.new.sanitize(input, options)
  end

  def test_prune_disposition_removes_the_whole_subtree
    entries = report
    html = "<div>keep<script>SYNTHETIC_PRUNE_TEXT</script></div>"

    output = prune_sanitize(html, report: entries)

    refute_includes output, "SYNTHETIC_PRUNE_TEXT"
    assert_includes output, "keep"
    assert_equal([[:prune, "script", :not_allowed]], summarize(entries))
  end

  def test_prune_reason_is_attributed_to_the_removed_element
    entries = report

    prune_sanitize("<div><form><p>SYNTHETIC_FORM_TEXT</p></form></div>", report: entries)

    assert_equal([[:prune, "form", :not_allowed]], summarize(entries))
  end

  def test_strip_disposition_unwraps_the_element_and_keeps_children
    entries = report
    html = "<unknown>SYNTHETIC_STRIP_TEXT</unknown>"

    output = safe_list_sanitize(html, report: entries)

    assert_includes output, "SYNTHETIC_STRIP_TEXT"
    assert_equal([[:strip, "unknown", :not_allowed]], summarize(entries))
  end

  def test_namespaced_elements_are_pruned_even_without_prune
    skip "HTML4 parsing does not retain foreign namespaces" unless module_under_test == Rails::HTML5

    entries = report

    safe_list_sanitize("<svg><circle>SYNTHETIC_SVG_TEXT</circle></svg>", report: entries)

    assert_equal(%i[prune], entries.dispositions)
    assert_equal(%w[circle svg], entries.tags.sort)
    assert_equal(%i[namespace], entries.reasons)
  end

  def test_attribute_disposition_removed_attribute
    entries = report
    html = %{<a href="javascript:SYNTHETIC_HREF" title="SYNTHETIC_TITLE">text</a>}

    output = safe_list_sanitize(html, report: entries)

    refute_includes output, "SYNTHETIC_HREF"
    assert_includes output, "SYNTHETIC_TITLE"
    assert_equal([[:attribute, "a", "href", :unsafe_value]], summarize(entries))
  end

  def test_attribute_disposition_adjusted_value
    entries = report
    html = %{<span style="color: red; background: url(SYNTHETIC_CSS)">text</span>}

    output = safe_list_sanitize(html, report: entries, attributes: %w(style))

    assert_includes output, "color:red"
    refute_includes output, "SYNTHETIC_CSS"
    assert_equal([[:attribute, "span", "style", :value_adjusted]], summarize(entries))
  end

  def test_attribute_disposition_empty_value
    entries = report
    html = %{<img src="   " alt="SYNTHETIC_ALT">}

    output = safe_list_sanitize(html, report: entries)

    refute_includes output, "src="
    assert_includes output, "SYNTHETIC_ALT"
    assert_equal([[:attribute, "img", "src", :empty_value]], summarize(entries))
  end

  def test_comment_is_reported_as_a_structural_tag
    entries = report

    output = safe_list_sanitize("a<!-- SYNTHETIC_COMMENT -->b", report: entries)

    assert_equal "ab", output
    assert_equal([[:strip, "comment", :comment]], summarize(entries))
  end

  def test_full_sanitizer_reports_each_stripped_element
    entries = report

    output = full_sanitize("<div><b>text</b></div><!-- comment -->", report: entries)

    assert_equal "text", output
    assert_equal %w[b comment div], entries.tags.sort
    assert_equal %i[strip], entries.dispositions
  end

  def test_link_sanitizer_reports_stripped_links
    entries = report

    output = link_sanitize(%{<div>keep<a href="SYNTHETIC_LINK">link text</a></div>}, report: entries)

    assert_equal "<div>keeplink text</div>", output
    assert_equal([[:strip, "a", :targeted]], summarize(entries))
  end

  def test_html_is_identical_with_and_without_a_report
    inputs = {
      safe_list: "<div>keep<script>SYNTHETIC_TEXT</script><a href='javascript:x'>link</a></div>",
      prune: "<div>keep<span>drop</span><script>SYNTHETIC_TEXT</script></div>",
      full: "<div><b>keep</b><!-- comment --></div>",
      link: %{<div>keep<a href="x" onclick="y">link</a></div>},
    }

    assert_equal safe_list_sanitize(inputs[:safe_list]), safe_list_sanitize(inputs[:safe_list], report: report)
    assert_equal prune_sanitize(inputs[:prune]), prune_sanitize(inputs[:prune], report: report)
    assert_equal full_sanitize(inputs[:full]), full_sanitize(inputs[:full], report: report)
    assert_equal link_sanitize(inputs[:link]), link_sanitize(inputs[:link], report: report)
  end

  def test_report_contains_no_input_text_or_attribute_values
    entries = report
    html = <<~HTML
      <div title="SYNTHETIC_ATTR_VALUE">
        SYNTHETIC_TEXT_BEFORE
        <script>SYNTHETIC_SCRIPT_BODY</script>
        <a href="javascript:SYNTHETIC_HREF" data-note="SYNTHETIC_DATA">SYNTHETIC_LINK_TEXT</a>
        <span style="color: red; background: url(SYNTHETIC_URL)">SYNTHETIC_STYLE_TEXT</span>
        <!-- SYNTHETIC_COMMENT_BODY -->
      </div>
    HTML

    safe_list_sanitize(html, report: entries, tags: %w(div a span), attributes: %w(title href style))

    refute_empty entries.entries
    serialized = entries.entries.map { |entry| entry.to_h.values.compact }.flatten.join("\n")

    %w(SYNTHETIC_ATTR_VALUE SYNTHETIC_TEXT_BEFORE SYNTHETIC_SCRIPT_BODY SYNTHETIC_HREF
       SYNTHETIC_DATA SYNTHETIC_LINK_TEXT SYNTHETIC_URL SYNTHETIC_STYLE_TEXT
       SYNTHETIC_COMMENT_BODY).each do |secret|
      refute_includes serialized, secret
    end

    entries.each do |entry|
      assert_empty(entry.to_h.keys - %i[tag attribute disposition reason])
      assert_includes(%i[prune strip attribute], entry.disposition)
    end
  end

  def test_report_can_be_serialized_without_leaking_input
    entries = report
    secret = "SYNTHETIC_SERIALIZED_BODY"

    safe_list_sanitize("<script>#{secret}</script>", report: entries)

    serialized = entries.entries.map(&:to_h).to_json

    refute_includes serialized, secret
    assert_equal 1, JSON.parse(serialized).size
  end

  def test_an_array_can_receive_the_entries
    entries = []

    safe_list_sanitize("<script>text</script>", report: entries)

    assert_equal 1, entries.size
    assert_equal :strip, entries.first.disposition
  end

  def test_report_is_nil_by_default_and_does_not_change_behavior
    assert_nil Rails::HTML::Sanitizer::Report.sink(nil)
    assert_equal "text", safe_list_sanitize("<script>text</script>")
  end

  def test_a_report_is_not_reused_across_calls
    entries = report
    sanitizer = module_under_test::SafeListSanitizer.new

    sanitizer.sanitize("<script>first</script>", report: entries)
    assert_equal 1, entries.size

    sanitizer.sanitize("<script>second</script>")
    assert_equal 1, entries.size, "a later call without :report must not append"
  end

  def test_link_sanitizer_does_not_keep_a_report_between_calls
    entries = report
    sanitizer = module_under_test::LinkSanitizer.new

    sanitizer.sanitize("<a href='x'>first</a>", report: entries)
    assert_equal 1, entries.size

    sanitizer.sanitize("<a href='x'>second</a>")
    assert_equal 1, entries.size, "a later call without :report must not append"
  end

  def test_permit_scrubber_reports_when_used_directly
    entries = report
    scrubber = Rails::HTML::PermitScrubber.new(report: entries)
    scrubber.tags = %w(div)
    scrubber.attributes = %w(title)

    output = Loofah.scrub_fragment(%{<div title="t" onclick="x">keep<b>drop</b></div>}, scrubber).to_s

    assert_equal %{<div title="t">keepdrop</div>}, output
    assert_equal([[:strip, "b", :not_allowed], [:attribute, "div", "onclick", :not_allowed]], summarize(entries))
  end

  protected
    def summarize(entries)
      entries.map { |entry| [entry.disposition, entry.tag, entry.attribute, entry.reason].compact }
    end
end

class HTML4SanitizerReportTest < Minitest::Test
  @module_under_test = Rails::HTML4
  include SanitizerReportTests
end

class HTML5SanitizerReportTest < Minitest::Test
  @module_under_test = Rails::HTML5
  include SanitizerReportTests
end if Rails::HTML::Sanitizer.html5_support?

class SanitizerReportObjectTest < Minitest::Test
  def test_entries_expose_structural_fields
    entry = Rails::HTML::Sanitizer::Report::Entry.new(tag: "script", disposition: :prune, reason: :not_allowed)

    assert_equal "script", entry.tag
    assert_nil entry.attribute
    assert_equal :prune, entry.disposition
    assert_equal :not_allowed, entry.reason
    assert_equal "script prune (not_allowed)", entry.to_s
  end

  def test_queries_group_entries_by_disposition
    report = Rails::HTML::Sanitizer::Report.new
    report << Rails::HTML::Sanitizer::Report::Entry.new(tag: "script", disposition: :prune, reason: :not_allowed)
    report << Rails::HTML::Sanitizer::Report::Entry.new(tag: "b", disposition: :strip, reason: :not_allowed)
    report << Rails::HTML::Sanitizer::Report::Entry.new(
      tag: "a", attribute: "href", disposition: :attribute, reason: :unsafe_value
    )

    assert_equal %w[a b script], report.tags.sort
    assert_equal ["href"], report.attributes
    assert_equal %i[prune strip attribute], report.dispositions
    assert_equal 1, report.pruned.size
    assert_equal 1, report.stripped.size
    assert_equal 1, report.attribute_changes.size
    assert_equal 3, report.size
    assert_equal 3, report.count
  end

  def test_unknown_report_objects_are_rejected
    error = assert_raises(ArgumentError) do
      Rails::HTML::Sanitizer::Report.sink("not a report")
    end

    assert_match(/report should be/, error.message)
  end

  def test_report_is_available_from_the_html_namespace
    assert_same Rails::HTML::Sanitizer::Report, Rails::HTML::Report
  end
end
