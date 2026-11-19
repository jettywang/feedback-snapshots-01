require_relative '../test'

# Tests for values emitted into JavaScript contexts.
#
# The same fixture input is placed in HTML, a quoted JavaScript string, a
# JavaScript expression, and JSON data to check that findings depend on the
# actual output position rather than on the presence of raw/html_safe/j.
class ScriptContextTests < Minitest::Test
  include BrakemanTester::FindWarning
  include BrakemanTester::CheckExpected

  def expected
    {
      :controller => 0,
      :model => 0,
      :template => 20,
      :generic => 0
    }
  end

  def report
    @@report ||= BrakemanTester.run_scan "rails_script_context", "Rails script context",
      :run_all_checks => true
  end

  def warnings
    report[:template_warnings].select { |w| w.warning_type == "Cross-Site Scripting" }
  end

  def warning_at path, line
    warnings.find { |w| w.file.relative == path and w.line == line }
  end

  def assert_no_xss path, line
    found = warning_at(path, line)
    assert_nil found, "Expected no XSS warning at #{path}:#{line}, got: #{found && found.message}"
  end

  def assert_xss path, line, message
    found = warning_at(path, line)
    refute_nil found, "Expected an XSS warning at #{path}:#{line}"
    assert_match message, found.message.to_s
  end

  # The same request value in four output positions.

  def test_plain_value_in_html_is_not_a_script_warning
    assert_no_xss "app/views/users/show.html.erb", 1
  end

  def test_plain_value_in_html_attribute_is_not_a_script_warning
    assert_no_xss "app/views/users/show.html.erb", 3
  end

  def test_plain_value_in_quoted_script_string_is_engine_escaped
    # Rails HTML escaping prevents breaking out of a quoted JavaScript string.
    assert_no_xss "app/views/users/show.html.erb", 6
  end

  def test_plain_value_in_script_expression_warns
    assert_xss "app/views/users/show.html.erb", 10, /JavaScript expression/
  end

  def test_plain_value_in_json_data_is_engine_escaped
    # The script element is data, not executed, and HTML escaping prevents the
    # value from closing it.
    assert_no_xss "app/views/users/show.html.erb", 18
  end

  # HTML-safe conversions.

  def test_raw_in_html_warns_as_html_xss
    assert_xss "app/views/users/show.html.erb", 2, /Unescaped parameter value/
  end

  def test_html_safe_helper_returning_content_tag_in_quoted_string_is_safe
    # The helper returns a content_tag, which escapes quotes.
    assert_no_xss "app/views/users/show.html.erb", 8
  end

  def test_raw_in_quoted_script_string_warns
    assert_xss "app/views/users/show.html.erb", 9, /HTML-safe output is not JavaScript-safe/
  end

  def test_html_safe_helper_in_script_expression_warns
    assert_xss "app/views/users/show.html.erb", 12, /HTML-safe output is not JavaScript-safe/
  end

  # j/escape_javascript.

  def test_j_in_quoted_script_string_is_safe
    assert_no_xss "app/views/users/show.html.erb", 7
  end

  def test_j_in_script_expression_warns
    assert_xss "app/views/users/show.html.erb", 11, /escape_javascript.*only escapes JavaScript string contents/m
  end

  # JSON.

  def test_raw_to_json_in_expression_is_safe
    assert_no_xss "app/views/users/show.html.erb", 13
  end

  def test_j_to_json_in_expression_warns
    assert_xss "app/views/users/show.html.erb", 14, /escape_javascript.*to_json/m
  end

  def test_serialized_json_in_json_data_is_safe
    assert_no_xss "app/views/users/edge.html.erb", 16
  end

  def test_j_serialized_json_in_json_data_is_safe
    assert_no_xss "app/views/users/edge.html.erb", 17
  end

  def test_raw_value_in_json_data_warns
    # raw() bypasses HTML escaping, so the value can close the script element.
    assert_xss "app/views/users/edge.html.erb", 18, /JSON data/
  end

  # Context boundaries.

  def test_plain_value_in_html_attribute_does_not_warn
    assert_no_xss "app/views/users/edge.html.erb", 1
  end

  def test_raw_in_html_attribute_warns_as_html_xss
    assert_xss "app/views/users/edge.html.erb", 2, /Unescaped parameter value/
  end

  def test_template_literal_warns
    assert_xss "app/views/users/edge.html.erb", 9, /template literal/
  end

  def test_script_comments_are_script_context
    assert_xss "app/views/users/edge.html.erb", 5, /JavaScript expression/
  end

  def test_non_javascript_script_type_is_unknown
    assert_no_xss "app/views/users/edge.html.erb", 21
  end

  # Helper return values.

  def test_content_tag_helper_in_script_string_is_safe
    assert_no_xss "app/views/users/helpers.html.erb", 5
  end

  def test_j_around_html_safe_helper_in_script_expression_warns
    assert_xss "app/views/users/helpers.html.erb", 6, /escape_javascript/
  end

  def test_raw_helper_in_script_expression
    assert_xss "app/views/users/helpers.html.erb", 7, /helper\(raw_wrapper\)/
  end

  def test_json_helper_in_script_expression_is_safe
    assert_no_xss "app/views/users/helpers.html.erb", 8
  end

  def test_json_helper_in_script_string_is_safe
    # to_json escapes quotes, so the serialized text cannot end the string,
    # even though the helper marks the result HTML-safe.
    assert_no_xss "app/views/users/helpers.html.erb", 9
  end

  def test_passthrough_helper_in_expression
    assert_xss "app/views/users/helpers.html.erb", 10, /helper\(passthrough\)/
  end

  def test_j_is_safe_in_quoted_string_even_for_html_safe_helper
    assert_no_xss "app/views/users/helpers.html.erb", 4
  end

  def test_h_in_quoted_string_is_safe
    assert_no_xss "app/views/users/helpers.html.erb", 16
  end

  def test_h_in_script_expression_warns
    assert_xss "app/views/users/helpers.html.erb", 17, /JavaScript expression/
  end

  def test_content_tag_in_quoted_string_is_safe
    # content_tag escapes quotes, so it cannot end the string.
    assert_no_xss "app/views/users/helpers.html.erb", 21
  end

  def test_content_tag_in_script_expression_warns
    assert_xss "app/views/users/helpers.html.erb", 22, /HTML-safe output is not JavaScript-safe/
  end

  # Uncertainty.

  def test_unknown_helper_expression_is_medium_confidence
    found = warning_at("app/views/users/unknown.html.erb", 2)
    refute_nil found
    assert_equal 1, found.confidence
    assert_match /unknown\(some_helper\)/, found.message.to_s
  end

  def test_unknown_helper_in_string_is_medium_confidence
    found = warning_at("app/views/users/unknown.html.erb", 3)
    refute_nil found
    assert_equal 1, found.confidence
    assert_match /JavaScript string/, found.message.to_s
  end

  def test_dynamic_tag_makes_context_unknown
    # The tag name is controlled by a parameter, so later contexts cannot be
    # determined from the template.
    assert_no_xss "app/views/users/dynamic.html.erb", 2
    assert_no_xss "app/views/users/dynamic.html.erb", 4
    assert_no_xss "app/views/users/dynamic.html.erb", 12
  end

  def test_conditional_inside_script_is_unknown
    assert_no_xss "app/views/users/conditional.html.erb", 8
  end

  def test_conditional_does_not_make_later_context_unknown
    assert_no_xss "app/views/users/conditional.html.erb", 6
    assert_no_xss "app/views/users/conditional.html.erb", 10
  end

  def test_conditional_branches_that_agree_on_context_are_reported
    assert_xss "app/views/users/conditional.html.erb", 14, /JavaScript expression/
  end

  def test_conditional_html_branch_is_not_script_context
    assert_no_xss "app/views/users/conditional.html.erb", 2
  end
end
