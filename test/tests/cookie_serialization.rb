require_relative '../test'

# Regression tests for cookie serialization migration scanning.
#
# The fixture application combines a Rails version whose framework default
# would be Marshal (6.1) with explicit serializer configuration in several
# locations. Only the final, effective setting represents the current state
# of the application:
#
#   config/application.rb                 -> :marshal (overridden)
#   config/environments/staging.rb        -> :marshal (environment not evaluated)
#   config/initializers/cookies_serializer.rb
#     line 3                              -> :json (overridden)
#     line 12                             -> custom serializer (overridden)
#     line 16                             -> :hybrid (effective)
#
# The scan is purely static: it does not boot Rails, does not generate real
# session cookies, and does not rely on a version check alone.
class CookieSerializationTests < Minitest::Test
  include BrakemanTester::FindWarning
  include BrakemanTester::CheckExpected

  def report
    @@report ||= BrakemanTester.run_scan "cookie_serialization", "Cookie Serialization"
  end

  def expected
    @@expected ||= {
      :controller => 0,
      :model => 0,
      :template => 0,
      :generic => 2
    }
  end

  # Dual-read migration: the effective setting writes JSON but still reads
  # Marshal-serialized cookies, so the legacy deserialization capability
  # remains and must be warned about. The warning basis distinguishes
  # content authentication (signed/encrypted reads) from the ability to
  # instantiate arbitrary objects during deserialization.
  def test_remote_code_execution_hybrid_dual_read
    assert_warning :type => :warning,
      :warning_code => 110,
      :fingerprint => "9ae68e59cfee3e5256c0540dadfeb74e6b72c91997fdb60411063a6e8518144a",
      :warning_type => "Remote Code Execution",
      :line => 16,
      :message => /^Use\ of\ unsafe\ cookie\ serialization\ strategy\ `:hybrid`\ might\ lead\ to\ remote\ code\ execution\.\ `:hybrid`\ writes\ JSON\ but\ still\ reads\ Marshal\-serialized\ cookies\.\ Signed\ and\ encrypted\ cookie\ reads\ authenticate\ cookie\ contents,\ but\ do\ not\ restrict\ which\ objects\ are\ instantiated\ when\ deserializing\ with\ `Marshal\.load`/,
      :confidence => 1,
      :relative_path => "config/initializers/cookies_serializer.rb",
      :code => s(:attrasgn, s(:call, s(:call, s(:call, s(:const, :Rails), :application), :config), :action_dispatch), :cookies_serializer=, s(:lit, :hybrid)),
      :user_input => nil
  end

  # Legacy format in config/application.rb is overridden by the initializer,
  # so it is not the current state and must not be warned about.
  def test_no_warning_for_overridden_marshal_in_application_config
    assert_no_warning :type => :warning,
      :warning_code => 110,
      :warning_type => "Remote Code Execution",
      :relative_path => "config/application.rb"
  end

  # Environments other than production are not evaluated by the scan,
  # so configuration in config/environments/staging.rb is not the current
  # state and must not be warned about.
  def test_no_warning_for_unevaluated_environment
    assert_no_warning :type => :warning,
      :warning_code => 110,
      :warning_type => "Remote Code Execution",
      :relative_path => "config/environments/staging.rb"
  end

  # Pure data format: only JSON primitives can be instantiated. The
  # assignment is also overridden, so either way there is no warning.
  def test_no_warning_for_overridden_json
    assert_no_warning :type => :warning,
      :warning_code => 110,
      :warning_type => "Remote Code Execution",
      :code => s(:attrasgn, s(:call, s(:call, s(:call, s(:const, :Rails), :application), :config), :action_dispatch), :cookies_serializer=, s(:lit, :json))
  end

  # Unknown serializer: the scan cannot determine its behavior, and the
  # assignment is overridden, so there is no basis for a warning.
  def test_no_warning_for_unknown_serializer
    assert_no_warning :type => :warning,
      :warning_code => 110,
      :warning_type => "Remote Code Execution",
      :code => s(:attrasgn, s(:call, s(:call, s(:call, s(:const, :Rails), :application), :config), :action_dispatch), :cookies_serializer=, s(:colon2, s(:const, :MyApp), :CookieSerializer))
  end

  # The Rails 6.1 framework default would be Marshal, but explicit
  # configuration takes precedence over version-based defaults: the scan
  # must not fall back to a version-only judgment.
  def test_no_warning_from_rails_version_default
    assert_no_warning :type => :warning,
      :warning_code => 110,
      :warning_type => "Remote Code Execution",
      :message => /^No\ cookie\ serializer\ is\ configured/
  end

  # The Rails version is still reported on its own: Rails 6.1 is
  # unmaintained, independently of the serializer configuration.
  def test_unmaintained_dependency_rails
    assert_warning :type => :warning,
      :warning_code => 120,
      :fingerprint => "e9d00416c23870f08d30cfda6ad07e2138e0ce51ab6b684814eb69e789cfa631",
      :warning_type => "Unmaintained Dependency",
      :line => 3,
      :message => /^Support\ for\ Rails\ 6\.1\.7\ ended\ on\ 2024\-10\-01/,
      :confidence => 0,
      :relative_path => "Gemfile",
      :code => nil,
      :user_input => nil
  end
end

# Unit-level coverage for the Rails version default fallback in
# Brakeman::CheckCookieSerialization, which the fixture application
# cannot exercise because it configures the serializer explicitly.
class CookieSerializationDefaultTests < Minitest::Test
  def warnings_for_rails_version version
    tracker = BrakemanTester.new_tracker

    if version
      tracker.config.add_gem :rails, version, "Gemfile", 1
      tracker.config.set_rails_version
    end

    check = Brakeman::CheckCookieSerialization.new(tracker)
    check.run_check
    check.warnings
  end

  # Without explicit configuration, Rails before 7.1 defaults to Marshal:
  # signed/encrypted cookie reads can instantiate arbitrary objects
  def test_marshal_is_default_before_rails_7_1
    warnings = warnings_for_rails_version "6.1.7"

    assert_equal 1, warnings.length
    assert_equal 110, warnings.first.warning_code
    assert_match(/^No cookie serializer is configured and this version of Rails defaults to `:marshal`.*`Marshal\.load`/, warnings.first.message.to_s)
  end

  # Since Rails 7.1 the framework default is JSON, a pure data format
  def test_json_is_default_since_rails_7_1
    assert_empty warnings_for_rails_version("7.1.0")
  end

  # Unknown Rails version means no basis for a version-based judgment
  def test_no_default_warning_for_unknown_rails_version
    assert_empty warnings_for_rails_version(nil)
  end
end
