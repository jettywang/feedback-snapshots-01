require_relative '../test'

class SafeYamlTests < Minitest::Test
  include BrakemanTester::FindWarning
  include BrakemanTester::CheckExpected

  def expected
    @expected ||= {
      :controller => 0,
      :model => 0,
      :template => 0,
      :warning => 6 }
  end

  def report
    @@report ||= BrakemanTester.run_scan "safe_yaml", "SafeYaml"
  end

  def test_safe_load_without_options_is_safe
    assert_no_warning :type => :warning,
      :warning_code => 25,
      :warning_type => "Remote Code Execution",
      :line => 8,
      :relative_path => "app/controllers/yaml_configs_controller.rb"
  end

  def test_safe_load_with_plain_data_classes_is_safe
    assert_no_warning :type => :warning,
      :warning_code => 25,
      :warning_type => "Remote Code Execution",
      :line => 11,
      :relative_path => "app/controllers/yaml_configs_controller.rb"
  end

  def test_safe_load_with_plain_data_constant_is_safe
    assert_no_warning :type => :warning,
      :warning_code => 25,
      :warning_type => "Remote Code Execution",
      :line => 14,
      :relative_path => "app/controllers/yaml_configs_controller.rb"
  end

  def test_safe_load_with_empty_class_list_is_safe
    assert_no_warning :type => :warning,
      :warning_code => 25,
      :warning_type => "Remote Code Execution",
      :line => 17,
      :relative_path => "app/controllers/yaml_configs_controller.rb"
  end

  def test_safe_load_permitting_objects
    assert_warning :type => :warning,
      :warning_code => 25,
      :warning_type => "Remote Code Execution",
      :line => 22,
      :message => /^`YAML\.safe_load`\ called\ with\ parameter\ value\ permits\ deserialization\ of\ `ImportJob`\ objects/,
      :confidence => 0,
      :relative_path => "app/controllers/yaml_configs_controller.rb",
      :code => s(:call, s(:const, :YAML), :safe_load, s(:call, s(:params), :[], s(:lit, :yaml)), s(:hash, s(:lit, :permitted_classes), s(:array, s(:const, :Symbol), s(:const, :ImportJob)))),
      :user_input => s(:call, s(:params), :[], s(:lit, :yaml))
  end

  def test_safe_load_permitting_objects_via_constant
    assert_warning :type => :warning,
      :warning_code => 25,
      :warning_type => "Remote Code Execution",
      :line => 25,
      :message => /^`YAML\.safe_load`\ called\ with\ parameter\ value\ permits\ deserialization\ of\ `ImportJob`\ objects/,
      :confidence => 0,
      :relative_path => "app/controllers/yaml_configs_controller.rb",
      :user_input => s(:call, s(:params), :[], s(:lit, :yaml))
  end

  def test_safe_load_with_unknown_class_list
    assert_warning :type => :warning,
      :warning_code => 25,
      :warning_type => "Remote Code Execution",
      :line => 30,
      :message => /^`YAML\.safe_load`\ called\ with\ parameter\ value\ permitted\ classes\ cannot\ be\ determined\ statically\ \(permitted\ classes\ come\ from\ allowed_class_list/,
      :confidence => 1,
      :relative_path => "app/controllers/yaml_configs_controller.rb",
      :code => s(:call, s(:const, :YAML), :safe_load, s(:call, s(:params), :[], s(:lit, :yaml)), s(:hash, s(:lit, :permitted_classes), s(:call, nil, :allowed_class_list))),
      :user_input => s(:call, s(:params), :[], s(:lit, :yaml))
  end

  def test_safe_load_with_modified_whitelist
    assert_warning :type => :warning,
      :warning_code => 25,
      :warning_type => "Remote Code Execution",
      :line => 33,
      :message => /^`YAML\.safe_load`\ called\ with\ parameter\ value\ permitted\ classes\ cannot\ be\ determined\ statically\ \(CHANGED_CLASSES\ is\ modified\ after\ assignment\ \(adds\ AuditRecord\)\)/,
      :confidence => 1,
      :relative_path => "app/controllers/yaml_configs_controller.rb",
      :user_input => s(:call, s(:params), :[], s(:lit, :yaml))
  end

  def test_safe_load_with_modified_local_list
    assert_warning :type => :warning,
      :warning_code => 25,
      :warning_type => "Remote Code Execution",
      :line => 40,
      :message => /^`YAML\.safe_load`\ called\ with\ parameter\ value\ permits\ deserialization\ of\ `ImportJob`\ objects/,
      :confidence => 0,
      :relative_path => "app/controllers/yaml_configs_controller.rb",
      :code => s(:call, s(:const, :YAML), :safe_load, s(:call, s(:params), :[], s(:lit, :yaml)), s(:hash, s(:lit, :permitted_classes), s(:array, s(:const, :Symbol), s(:const, :ImportJob)))),
      :user_input => s(:call, s(:params), :[], s(:lit, :yaml))
  end

  def test_safe_load_with_aliases
    assert_warning :type => :warning,
      :warning_code => 25,
      :warning_type => "Remote Code Execution",
      :line => 45,
      :message => /^`YAML\.safe_load`\ called\ with\ parameter\ value\ allows\ YAML\ aliases\ with\ `aliases:\ true`/,
      :confidence => 2,
      :relative_path => "app/controllers/yaml_configs_controller.rb",
      :code => s(:call, s(:const, :YAML), :safe_load, s(:call, s(:params), :[], s(:lit, :yaml)), s(:hash, s(:lit, :aliases), s(:true))),
      :user_input => s(:call, s(:params), :[], s(:lit, :yaml))
  end

  def test_safe_load_without_user_input_is_safe
    assert_no_warning :type => :warning,
      :warning_code => 25,
      :warning_type => "Remote Code Execution",
      :line => 49,
      :relative_path => "app/controllers/yaml_configs_controller.rb"
  end
end
