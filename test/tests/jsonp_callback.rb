require_relative '../test'
require 'fileutils'

# Exercises the JSONP callback-name source check (CheckJSONPCallback).
#
# The fixture controller contains, side by side:
#   * plain JSON with no callback (safe)
#   * fixed literal callback names (safe)
#   * callbacks drawn from a provably finite allowlist (safe)
#   * helper methods returning fixed/allowlisted names (safe)
#   * arbitrary user text, including weakly filtered and re-concatenated
#     input (reported, located at the callback source rather than the JSON)
class JSONPCallbackTests < Minitest::Test
  CONTROLLER = <<-RUBY
class JsonpController < ApplicationController
  ALLOWED = ["cb", "update"].freeze

  # Safe: plain JSON, no JSONP wrapper.
  def plain_json
    render json: { name: "widget" }
  end

  # Safe: fixed callback names.
  def fixed_string
    render json: { name: "widget" }, callback: "cb"
  end

  def fixed_symbol
    render json: { name: "widget" }, callback: :cb
  end

  # Safe: provably finite allowlist via a guarded parameter.
  def allowlisted_ternary
    cb = ["cb", "update"].include?(params[:cb]) ? params[:cb] : "cb"
    render json: { name: "widget" }, callback: cb
  end

  def allowlisted_case
    cb = case params[:cb]
         when "cb", "update" then params[:cb]
         else "cb"
         end
    render json: { name: "widget" }, callback: cb
  end

  def allowlisted_inline
    render json: { name: "widget" }, callback: (ALLOWED.include?(params[:cb]) ? params[:cb] : "cb")
  end

  # Safe: name is sampled from a finite literal collection.
  def finite_collection
    render json: { name: "widget" }, callback: ["cb", "update", "notify"].sample
  end

  # Safe: helper returns an allowlisted value.
  def via_safe_helper
    render json: { name: "widget" }, callback: allowlisted_callback
  end

  # Safe: helper returns a name from a finite literal collection.
  def via_literal_helper
    render json: { name: "widget" }, callback: literal_callback
  end

  # Safe: callback inside a fixed option hash.
  def merged_safe
    options = { json: { name: "widget" }, callback: "cb" }
    render options
  end

  # Safe: interpolation only wraps an allowlist-constrained value.
  def guarded_interpolation
    name = ["cb", "update"].include?(params[:cb]) ? params[:cb] : "cb"
    render json: { name: "widget" }, callback: "wrap_\#{name}"
  end

  # Unsafe: arbitrary parameter used directly.
  def raw_parameter
    render json: { name: "widget" }, callback: params[:cb]
  end

  # Unsafe: only a couple of characters are stripped, the source is still free text.
  def weakly_filtered
    render json: { name: "widget" }, callback: params[:cb].gsub("(", "").gsub(")", "")
  end

  # Unsafe: user input concatenated back into the callback expression.
  def concatenated
    render json: { name: "widget" }, callback: "cb_\#{params[:cb]}"
  end

  # Unsafe: request header value.
  def request_header
    render json: { name: "widget" }, callback: request.env["HTTP_X_CALLBACK"]
  end

  # Unsafe: cookie value.
  def cookie_value
    render json: { name: "widget" }, callback: cookies[:cb]
  end

  # Unsafe: free-text parameter merged into the option hash.
  def merged_unsafe
    options = { json: { name: "widget" } }
    render options.merge(callback: params[:cb])
  end

  # Unsafe: one branch still yields arbitrary input.
  def unguarded_branch
    render json: { name: "widget" }, callback: params[:alt] || "cb"
  end

  # Unsafe: helper returns arbitrary parameter text.
  def via_unsafe_helper
    render json: { name: "widget" }, callback: raw_callback
  end

  private

  def allowlisted_callback
    name = params[:cb]
    ["cb", "update"].include?(name) ? name : "cb"
  end

  def literal_callback
    ["cb", "update", "notify"].sample
  end

  def raw_callback
    params[:cb].to_s
  end
end
  RUBY

  def report
    @report ||= Dir.mktmpdir("brakeman-jsonp-test") do |dir|
      FileUtils.mkdir_p File.join(dir, "app", "controllers")
      FileUtils.mkdir_p File.join(dir, "config")

      File.write File.join(dir, "config", "application.rb"), <<-RUBY
module JsonpTest
  class Application < Rails::Application
    config.load_defaults 7.0
  end
end
      RUBY

      File.write File.join(dir, "app", "controllers", "application_controller.rb"), <<-RUBY
class ApplicationController < ActionController::Base
end
      RUBY

      File.write File.join(dir, "app", "controllers", "jsonp_controller.rb"), CONTROLLER

      Brakeman.run(
        app_path: dir,
        parallel_checks: false,
        run_checks: ["CheckJSONPCallback"]
      ).report.to_hash
    end
  end

  def unsafe_actions
    [
      :raw_parameter,
      :weakly_filtered,
      :concatenated,
      :request_header,
      :cookie_value,
      :merged_unsafe,
      :unguarded_branch,
      :via_unsafe_helper
    ]
  end

  def safe_actions
    [
      :plain_json,
      :fixed_string,
      :fixed_symbol,
      :allowlisted_ternary,
      :allowlisted_case,
      :allowlisted_inline,
      :finite_collection,
      :via_safe_helper,
      :via_literal_helper,
      :merged_safe,
      :guarded_interpolation
    ]
  end

  def jsonp_warnings
    report[:generic_warnings].select { |w| w.check_name == "JSONPCallback" }
  end

  def warning_for action
    jsonp_warnings.find { |w| w.method == action }
  end

  def test_reports_each_unsafe_callback_source
    unsafe_actions.each do |action|
      warning = warning_for action

      refute_nil warning, "Expected a JSONP warning for ##{action}"
      assert_equal 130, warning.warning_code
      assert_equal "Cross-Site Scripting", warning.warning_type
      assert_equal [79], warning.cwe_id
      assert_equal "app/controllers/jsonp_controller.rb", warning.file.relative
    end
  end

  def test_reports_exactly_the_unsafe_actions
    assert_equal unsafe_actions.sort, jsonp_warnings.map(&:method).sort
    assert_equal unsafe_actions.length, jsonp_warnings.length
  end

  def test_does_not_report_safe_callbacks
    reported = jsonp_warnings.map(&:method)

    safe_actions.each do |action|
      refute_includes reported, action, "Expected no warning for safe callback in ##{action}"
    end
  end

  def test_warning_points_at_callback_source_not_json_payload
    warning = warning_for :raw_parameter

    refute_nil warning
    assert_equal :params, warning.user_input_type
    assert_equal s(:call, s(:params), :[], s(:lit, :cb)), warning.user_input
  end

  def test_weak_filtering_is_not_treated_as_safe
    warning = warning_for :weakly_filtered

    refute_nil warning
    assert_equal :params, warning.user_input_type
    assert_equal :gsub, warning.code.method
  end

  def test_concatenated_input_is_not_treated_as_safe
    warning = warning_for :concatenated

    refute_nil warning
    assert_equal :params, warning.user_input_type
    assert_equal :dstr, warning.code.node_type
  end

  def test_merged_hash_unsafe_callback_is_detected
    warning = warning_for :merged_unsafe

    refute_nil warning
    assert_equal :params, warning.user_input_type
  end

  def test_unsafe_helper_return_is_followed
    warning = warning_for :via_unsafe_helper

    refute_nil warning
    assert_equal :params, warning.user_input_type
  end
end
