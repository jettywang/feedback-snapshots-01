require_relative '../test'
require 'brakeman/sink_identity'
require 'brakeman/warning'

class SinkIdentityTests < Minitest::Test
  include Brakeman::Util

  TemplateStub = Struct.new(:name, :render_path, :file)

  def warning code:, code_exp:, file: "app/models/user.rb", line: 1, template: nil
    warning = Brakeman::Warning.new(
      warning_code: code,
      warning_type: "SQL Injection",
      message: "Possible SQL injection",
      code: code_exp,
      file: Brakeman::FilePath.new(file, file),
      line: line,
      confidence: :high,
      template: template
    )
    warning
  end

  def test_whitespace_and_line_do_not_change_identity
    one = warning code: :sql_injection, code_exp: s(:call, s(:const, :User), :where, s(:call, s(:call, nil, :params), :[], s(:lit, :a))), line: 3
    two = warning code: :sql_injection, code_exp: s(:call, s(:const, :User), :where, s(:call, s(:call, nil, :params), :[], s(:lit, :a))), line: 9

    assert_equal one.sink_identity_key, two.sink_identity_key
    refute_equal one.sink_instance_key, two.sink_instance_key
  end

  def test_different_source_does_not_change_template_sink_identity
    template = TemplateStub.new(:"users/show", ["UsersController#show"], nil)
    one = warning code: :cross_site_scripting, code_exp: s(:call, s(:call, s(:const, :User), :find, s(:call, s(:call, nil, :params), :[], s(:lit, :id))), :name), template: template, line: 1
    two = warning code: :cross_site_scripting, code_exp: s(:call, s(:call, s(:const, :User), :find, s(:call, s(:call, nil, :params), :[], s(:lit, :admin_id))), :name), template: template, line: 1

    assert_equal one.sink_identity_key, two.sink_identity_key
    assert_equal one.template_site_key, two.template_site_key
    refute_equal one.sink_instance_key, two.sink_instance_key
  end

  def test_different_call_is_different_sink
    one = warning code: :sql_injection, code_exp: s(:call, s(:const, :User), :where, s(:call, s(:call, nil, :params), :[], s(:lit, :a)))
    two = warning code: :sql_injection, code_exp: s(:call, s(:const, :Account), :where, s(:call, s(:call, nil, :params), :[], s(:lit, :a)))

    refute_equal one.sink_identity_key, two.sink_identity_key
  end

  def test_literal_arguments_remain_significant
    one = warning code: :sql_injection, code_exp: s(:call, s(:const, :User), :where, s(:str, "a = 1"))
    two = warning code: :sql_injection, code_exp: s(:call, s(:const, :User), :where, s(:str, "b = 2"))

    refute_equal one.sink_identity_key, two.sink_identity_key
  end

  def test_evidence_collects_all_sources
    exp = s(:call, s(:call, nil, :params), :[], s(:lit, :a))
    other = s(:call, s(:call, nil, :params), :[], s(:lit, :b))
    w = warning code: :sql_injection, code_exp: s(:call, s(:const, :User), :where, s(:call, exp, :+, other))

    assert_equal ["params[:a]", "params[:b]"], w.evidence.map(&:code)
    assert_equal [:params, :params], w.evidence.map(&:type)
  end

  def test_merge_unions_evidence_and_render_paths
    exp = s(:call, s(:call, nil, :params), :[], s(:lit, :a))
    one = warning code: :cross_site_scripting, code_exp: exp
    two = warning code: :cross_site_scripting, code_exp: exp

    template = TemplateStub.new(:"users/show", ["UsersController#show"], nil)
    one = warning code: :cross_site_scripting, code_exp: exp, template: template
    two = warning code: :cross_site_scripting, code_exp: exp, template: template
    one.render_paths << ["UsersController#show"]
    two.render_paths << ["AdminController#show"]
    one.merge_sink!(two)

    assert_equal [["UsersController#show"], ["AdminController#show"]], one.render_paths.map { |p| p.is_a?(Array) ? p : p.to_a }
    assert_equal 1, one.evidence.length
  end
end
