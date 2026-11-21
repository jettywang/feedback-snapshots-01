# frozen_string_literal: true

require_relative "test_helper"

class StylePolicyTest < Minitest::Test
  EMAIL_STYLE = "color: #0b57d0; width: 600px; cursor: pointer;"
  PROPERTIES = %w(color width).freeze
  VALUES = { "color" => %w(#0b57d0), "width" => %w(600px 100%) }.freeze

  def setup
    @policy = Rails::HTML::StylePolicy.new(properties: PROPERTIES, values: VALUES)
    @sanitizer = Rails::HTML5::SafeListSanitizer.new
  end

  def test_standalone_style_sanitization_uses_the_policy
    assert_equal "color:#0b57d0;width:600px;", @sanitizer.sanitize_css(EMAIL_STYLE, style_policy: @policy)
  end

  def test_html_sanitization_uses_the_same_policy
    input = %(<p style="#{EMAIL_STYLE}">Hello <b>there</b></p>)
    expected = %(<p style="color:#0b57d0;width:600px;">Hello <b>there</b></p>)

    assert_equal expected, @sanitizer.sanitize(input, attributes: %w(style), style_policy: @policy)
  end

  def test_default_cleanup_still_applies_without_a_policy
    assert_equal "color:#0b57d0;width:600px;",
      @sanitizer.sanitize_css("color: #0b57d0; width: 600px; position: absolute;")

    assert_equal %(<p style="color:#0b57d0;">x</p>),
      @sanitizer.sanitize(%(<p style="color: #0b57d0; background-image: url(https://example.com/x.png);">x</p>), attributes: %w(style))
  end

  def test_default_cleanup_runs_before_the_policy_narrows
    assert_equal "", @sanitizer.sanitize_css("background-image: url(javascript:alert(1)); color: red;", style_policy: @policy)
  end

  def test_values_must_be_approved_per_property
    assert_equal "color:#0b57d0;", @sanitizer.sanitize_css("color: #0b57d0; width: 601px;", style_policy: @policy)
    assert_equal "width:100%;", @sanitizer.sanitize_css("color: red; width: 100%;", style_policy: @policy)
  end

  def test_value_matching_is_case_insensitive_and_whitespace_normalized
    assert_equal "color:#0B57D0;", @sanitizer.sanitize_css("color:   #0B57D0  ;", style_policy: @policy)
  end

  def test_important_flag_is_preserved
    assert_equal "width:600px !important;",
      @sanitizer.sanitize_css("width: 600px !important;", style_policy: @policy)
  end

  def test_important_flag_is_not_part_of_the_value_match
    assert_equal "width:600px !important;",
      @sanitizer.sanitize_css("width: 600px !important;", style_policy: { properties: %w(width), values: { "width" => "600px" } })
  end

  def test_empty_property_list_removes_the_style_attribute
    policy = Rails::HTML::StylePolicy.new(properties: [])
    assert_equal "", @sanitizer.sanitize_css("color: red;", style_policy: policy)
    assert_equal "<p>x</p>",
      @sanitizer.sanitize(%(<p style="color: red;">x</p>), attributes: %w(style), style_policy: policy)
  end

  def test_properties_only_policy_keeps_default_values
    policy = Rails::HTML::StylePolicy.new(properties: %w(color))
    assert_equal "color:rgb(1,2,3);", @sanitizer.sanitize_css("color: rgb(1,2,3); width: 1px;", style_policy: policy)
  end

  def test_values_only_policy_keeps_default_properties
    policy = Rails::HTML::StylePolicy.new(values: { "width" => "600px" })
    assert_equal "color:red;width:600px;height:10px;",
      @sanitizer.sanitize_css("color: red; width: 600px; height: 10px;", style_policy: policy)
  end

  def test_regexp_and_proc_constraints
    policy = Rails::HTML::StylePolicy.new(
      values: {
        "color" => /\A#[0-9a-f]{6}\z/,
        "width" => ->(value) { value.end_with?("px") && value.to_i <= 600 },
      },
    )

    assert_equal "color:#0b57d0;width:600px;",
      @sanitizer.sanitize_css("color: #0b57d0; width: 600px;", style_policy: policy)
    assert_equal "width:100px;",
      @sanitizer.sanitize_css("color: red; width: 100px;", style_policy: policy)
  end

  def test_report_records_property_names_and_reasons_without_values
    report = Rails::HTML::StylePolicy::Report.new
    result = @sanitizer.sanitize_css(EMAIL_STYLE, style_policy: @policy, style_report: report)

    assert_equal "color:#0b57d0;width:600px;", result
    assert_equal %w(cursor), report.properties
    assert_equal [:property_not_allowed], report.reasons
    report.entries.each do |entry|
      assert_equal :removed, entry[:disposition]
      refute entry.key?(:value)
    end
  end

  def test_report_records_value_rejections_without_values
    report = []
    result = @sanitizer.sanitize_css("color: red; width: 601px;", style_policy: @policy, style_report: report)

    assert_equal "", result
    assert_equal [{ property: "color", disposition: :removed, reason: :value_not_allowed },
                  { property: "width", disposition: :removed, reason: :value_not_allowed }], report
    refute_includes report.inspect, "red"
    refute_includes report.inspect, "601px"
  end

  def test_report_from_html_sanitization_does_not_contain_the_style_string
    report = Rails::HTML::StylePolicy::Report.new
    input = %(<p style="#{EMAIL_STYLE}">Hello</p>)

    result = @sanitizer.sanitize(input, attributes: %w(style), style_policy: @policy, style_report: report)

    assert_equal %(<p style="color:#0b57d0;width:600px;">Hello</p>), result
    assert_equal %w(cursor), report.properties
    refute_includes report.inspect, "pointer"
  end

  def test_report_does_not_change_the_sanitized_output
    options = { attributes: %w(style), style_policy: @policy }
    input = %(<p style="#{EMAIL_STYLE}">x</p>)

    without_report = @sanitizer.sanitize(input, options)
    with_report = @sanitizer.sanitize(input, options.merge(style_report: Rails::HTML::StylePolicy::Report.new))

    assert_equal without_report, with_report
  end

  def test_class_level_policy_applies_to_sanitize_and_sanitize_css
    old_policy = Rails::HTML5::SafeListSanitizer.allowed_style_policy
    Rails::HTML5::SafeListSanitizer.allowed_style_policy = @policy

    assert_equal "color:#0b57d0;", @sanitizer.sanitize_css("color: #0b57d0; cursor: pointer;")
    assert_equal %(<p style="color:#0b57d0;">x</p>),
      @sanitizer.sanitize(%(<p style="color: #0b57d0; cursor: pointer;">x</p>), attributes: %w(style))
  ensure
    Rails::HTML5::SafeListSanitizer.allowed_style_policy = old_policy
  end

  def test_call_option_overrides_class_level_policy
    old_policy = Rails::HTML5::SafeListSanitizer.allowed_style_policy
    Rails::HTML5::SafeListSanitizer.allowed_style_policy = Rails::HTML::StylePolicy.new(properties: [])

    assert_equal "width:600px;", @sanitizer.sanitize_css("color: red; width: 600px;", style_policy: { properties: %w(width) })
  ensure
    Rails::HTML5::SafeListSanitizer.allowed_style_policy = old_policy
  end

  def test_html_sanitization_without_allowing_style_still_strips_it
    assert_equal "<p>x</p>",
      @sanitizer.sanitize(%(<p style="color: #0b57d0; cursor: pointer;">x</p>), style_policy: @policy)
  end

  def test_permit_scrubber_accepts_a_policy
    scrubber = Rails::HTML::PermitScrubber.new
    scrubber.tags = %w(p)
    scrubber.attributes = %w(style)
    scrubber.style_policy = @policy

    fragment = Loofah.fragment(%(<p style="#{EMAIL_STYLE}">x</p>)).scrub!(scrubber)

    assert_equal %(<p style="color:#0b57d0;width:600px;">x</p>), fragment.to_s
  end

  def test_policy_is_immutable
    assert @policy.frozen?
    assert @policy.properties.frozen?
    assert @policy.values.frozen?
    assert_raises(FrozenError) { @policy.properties << "cursor" }
  end

  def test_building_a_policy_copies_and_freezes_inputs
    properties = %w(color)
    values = { "color" => %w(red) }
    policy = Rails::HTML::StylePolicy.new(properties: properties, values: values)

    properties << "width"
    values["color"] << "blue"

    assert_equal %w(color), policy.properties
    assert_equal({ "color" => %w(red) }, policy.values)
  end

  def test_invalid_configuration_is_rejected
    assert_raises(ArgumentError) { Rails::HTML::StylePolicy.new(properties: "color") }
    assert_raises(ArgumentError) { Rails::HTML::StylePolicy.new(properties: ["not a property"]) }
    assert_raises(ArgumentError) { Rails::HTML::StylePolicy.new(values: "color") }
    assert_raises(ArgumentError) { Rails::HTML::StylePolicy.new(values: { "color" => Object.new }) }
  end

  def test_invalid_option_is_rejected
    error = assert_raises(ArgumentError) do
      @sanitizer.sanitize_css("color: red;", style_policy: Object.new)
    end

    assert_match(/style_policy/, error.message)
  end

  def test_hash_option_is_accepted
    assert_equal "color:#0b57d0;",
      @sanitizer.sanitize_css("color: #0b57d0; width: 600px;", style_policy: { properties: %w(color) })
  end

  def test_accepts_a_duck_typed_policy
    duck = Object.new
    def duck.sanitize(style, report: nil)
      "color:red;"
    end

    assert_equal "color:red;", @sanitizer.sanitize_css("anything", style_policy: duck)
  end

  def test_missing_style_attribute_is_untouched
    assert_equal "<p>x</p>", @sanitizer.sanitize("<p>x</p>", attributes: %w(style), style_policy: @policy)
  end

  def test_text_and_siblings_are_preserved
    input = %(<p style="#{EMAIL_STYLE}">Hello</p><span>World</span>)
    output = @sanitizer.sanitize(input, attributes: %w(style), style_policy: @policy)
    document = Nokogiri::HTML5.fragment(output)

    assert_equal %w(p span), document.children.map(&:name)
    assert_equal "Hello", document.at_css("p").text
    assert_equal "World", document.at_css("span").text
    assert_equal "color:#0b57d0;width:600px;", document.at_css("p")["style"]
  end

  def test_unsafe_properties_are_never_restored_by_the_policy
    policy = Rails::HTML::StylePolicy.new(properties: %w(position behavior -moz-binding))
    assert_equal "", @sanitizer.sanitize_css("position: absolute; behavior: url(x); -moz-binding: url(y);", style_policy: policy)
  end
end

class HTML4StylePolicyTest < StylePolicyTest
  def setup
    @policy = Rails::HTML::StylePolicy.new(properties: PROPERTIES, values: VALUES)
    @sanitizer = Rails::HTML4::SafeListSanitizer.new
  end

  def test_class_level_policy_applies_to_sanitize_and_sanitize_css
    old_policy = Rails::HTML4::SafeListSanitizer.allowed_style_policy
    Rails::HTML4::SafeListSanitizer.allowed_style_policy = @policy

    assert_equal "color:#0b57d0;", @sanitizer.sanitize_css("color: #0b57d0; cursor: pointer;")
    assert_equal %(<p style="color:#0b57d0;">x</p>),
      @sanitizer.sanitize(%(<p style="color: #0b57d0; cursor: pointer;">x</p>), attributes: %w(style))
  ensure
    Rails::HTML4::SafeListSanitizer.allowed_style_policy = old_policy
  end

  def test_call_option_overrides_class_level_policy
    old_policy = Rails::HTML4::SafeListSanitizer.allowed_style_policy
    Rails::HTML4::SafeListSanitizer.allowed_style_policy = Rails::HTML::StylePolicy.new(properties: [])

    assert_equal "width:600px;", @sanitizer.sanitize_css("color: red; width: 600px;", style_policy: { properties: %w(width) })
  ensure
    Rails::HTML4::SafeListSanitizer.allowed_style_policy = old_policy
  end
end
