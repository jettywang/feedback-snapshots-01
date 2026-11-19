require_relative '../test'

class HeaderSplittingTests < Minitest::Test
  include BrakemanTester::FindWarning
  include BrakemanTester::CheckExpected

  def report
    @@report ||= BrakemanTester.run_scan "header_splitting", "Response Header Splitting",
      :run_all_checks => true, :min_confidence => 3
  end

  def expected
    @@expected ||= {
      :controller => 0,
      :model => 0,
      :template => 0,
      :generic => 21
    }
  end

  def test_direct_header_value
    assert_warning :type => :warning,
      :warning_code => 130,
      :fingerprint => "66cd1d9560467475966a9fa2f87ff753cd45502a8706ee28fa3394422442314e",
      :warning_type => "Response Splitting",
      :line => 4,
      :message => /^Request parameter used in response header value/,
      :confidence => 2,
      :relative_path => "app/controllers/response_headers_controller.rb",
      :code => s(:attrasgn, s(:call, s(:call, nil, :response), :headers), :[]=, s(:str, "X-Foo"), s(:call, s(:params), :[], s(:lit, :foo))),
      :user_input => s(:call, s(:params), :[], s(:lit, :foo)),
      :cwe_id => [113]
  end

  def test_bare_headers_value
    assert_warning :type => :warning,
      :warning_code => 130,
      :warning_type => "Response Splitting",
      :line => 8,
      :message => /^Request parameter used in response header value/,
      :confidence => 2,
      :relative_path => "app/controllers/response_headers_controller.rb",
      :user_input => s(:call, s(:cookies), :[], s(:lit, :baz))
  end

  def test_set_header_value
    assert_warning :type => :warning,
      :warning_code => 130,
      :warning_type => "Response Splitting",
      :line => 12,
      :message => /^Request parameter used in response header value/,
      :confidence => 2,
      :relative_path => "app/controllers/response_headers_controller.rb",
      :user_input => s(:call, s(:params), :[], s(:lit, :bar))
  end

  def test_tainted_header_name
    assert_warning :type => :warning,
      :warning_code => 130,
      :warning_type => "Response Splitting",
      :line => 17,
      :message => /^Request parameter used in response header name/,
      :confidence => 2,
      :relative_path => "app/controllers/response_headers_controller.rb",
      :user_input => s(:call, s(:params), :[], s(:lit, :header_name))
  end

  def test_set_header_tainted_name
    assert_warning :type => :warning,
      :warning_code => 130,
      :warning_type => "Response Splitting",
      :line => 21,
      :message => /^Request parameter used in response header name/,
      :confidence => 2,
      :relative_path => "app/controllers/response_headers_controller.rb",
      :user_input => s(:call, s(:params), :[], s(:lit, :header_name))
  end

  def test_interpolated_value
    assert_warning :type => :warning,
      :warning_code => 130,
      :warning_type => "Response Splitting",
      :line => 26,
      :message => /^Request parameter used in response header value/,
      :confidence => 2,
      :relative_path => "app/controllers/response_headers_controller.rb",
      :user_input => s(:call, s(:params), :[], s(:lit, :piece))
  end

  def test_request_header_value
    assert_warning :type => :warning,
      :warning_code => 130,
      :warning_type => "Response Splitting",
      :line => 31,
      :message => /^Request parameter used in response header value/,
      :confidence => 2,
      :relative_path => "app/controllers/response_headers_controller.rb",
      :user_input => s(:call, s(:call, s(:call, nil, :request), :env), :[], s(:str, "HTTP_X_TOKEN"))
  end

  def test_local_hash_alias
    assert_warning :type => :warning,
      :warning_code => 130,
      :warning_type => "Response Splitting",
      :line => 37,
      :message => /^Request parameter used in response header value/,
      :confidence => 2,
      :relative_path => "app/controllers/response_headers_controller.rb",
      :user_input => s(:call, s(:params), :[], s(:lit, :aliased))
  end

  def test_instance_hash_alias
    assert_warning :type => :warning,
      :warning_code => 130,
      :warning_type => "Response Splitting",
      :line => 43,
      :message => /^Request parameter used in response header value/,
      :confidence => 2,
      :relative_path => "app/controllers/response_headers_controller.rb",
      :user_input => s(:call, s(:params), :[], s(:lit, :ivared))
  end

  def test_merge_assignment
    assert_warning :type => :warning,
      :warning_code => 130,
      :warning_type => "Response Splitting",
      :line => 48,
      :message => /^Request parameter used in response header value/,
      :confidence => 2,
      :relative_path => "app/controllers/response_headers_controller.rb",
      :user_input => s(:call, s(:params), :[], s(:lit, :merged))
  end

  def test_update_assignment
    assert_warning :type => :warning,
      :warning_code => 130,
      :warning_type => "Response Splitting",
      :line => 52,
      :message => /^Request parameter used in response header value/,
      :confidence => 2,
      :relative_path => "app/controllers/response_headers_controller.rb",
      :user_input => s(:call, s(:params), :[], s(:lit, :updated))
  end

  def test_invalid_filters_still_warn
    [81, 85, 89].each do |line|
      assert_warning :type => :warning,
        :warning_code => 130,
        :warning_type => "Response Splitting",
        :line => line,
        :message => /^Request parameter used in response header value/,
        :confidence => 2,
        :relative_path => "app/controllers/response_headers_controller.rb"
    end
  end

  def test_sanitizing_another_variable_does_not_protect_assignment
    assert_warning :type => :warning,
      :warning_code => 130,
      :warning_type => "Response Splitting",
      :line => 96,
      :message => /^Request parameter used in response header value/,
      :confidence => 2,
      :relative_path => "app/controllers/response_headers_controller.rb",
      :user_input => s(:call, s(:params), :[], s(:lit, :value))
  end

  def test_guarding_another_variable_does_not_protect_assignment
    assert_warning :type => :warning,
      :warning_code => 130,
      :warning_type => "Response Splitting",
      :line => 130,
      :message => /^Request parameter used in response header value/,
      :confidence => 2,
      :relative_path => "app/controllers/response_headers_controller.rb",
      :user_input => s(:call, s(:params), :[], s(:lit, :value))
  end

  def test_last_assignment_taint_wins
    assert_warning :type => :warning,
      :warning_code => 130,
      :warning_type => "Response Splitting",
      :line => 149,
      :message => /^Request parameter used in response header value/,
      :confidence => 2,
      :relative_path => "app/controllers/response_headers_controller.rb",
      :user_input => s(:call, s(:params), :[], s(:lit, :value))
  end

  def test_helper_sink
    assert_warning :type => :warning,
      :warning_code => 130,
      :warning_type => "Response Splitting",
      :line => 4,
      :message => /^Request parameter used in response header value/,
      :confidence => 2,
      :relative_path => "app/helpers/response_headers_helper.rb",
      :user_input => s(:call, s(:params), :[], s(:lit, :helper_value))
  end

  def test_helper_aliased_hash_sink
    assert_warning :type => :warning,
      :warning_code => 130,
      :warning_type => "Response Splitting",
      :line => 13,
      :message => /^Request parameter used in response header value/,
      :confidence => 2,
      :relative_path => "app/helpers/response_headers_helper.rb",
      :user_input => s(:call, s(:params), :[], s(:lit, :helper_alias))
  end

  def test_provable_newline_removal_is_safe
    [58, 62, 66, 71, 76].each do |line|
      assert_no_warning :type => :warning,
        :warning_code => 130,
        :line => line,
        :relative_path => "app/controllers/response_headers_controller.rb"
    end
  end

  def test_provable_newline_rejection_is_safe
    [103, 109, 115, 121, 157, 164].each do |line|
      assert_no_warning :type => :warning,
        :warning_code => 130,
        :line => line,
        :relative_path => "app/controllers/response_headers_controller.rb"
    end
  end

  def test_replacement_that_keeps_newline_still_warns
    assert_warning :type => :warning,
      :warning_code => 130,
      :warning_type => "Response Splitting",
      :line => 169,
      :message => /^Request parameter used in response header value/,
      :confidence => 2,
      :relative_path => "app/controllers/response_headers_controller.rb",
      :user_input => s(:call, s(:call, s(:params), :[], s(:lit, :value)), :gsub, s(:lit, /[\r\n]/), s(:str, "\n"))
  end

  def test_plain_hash_is_not_a_response_header_sink
    assert_no_warning :type => :warning,
      :warning_code => 130,
      :line => 175,
      :relative_path => "app/controllers/response_headers_controller.rb"
  end

  def test_constants_are_safe
    [135, 136, 142].each do |line|
      assert_no_warning :type => :warning,
        :warning_code => 130,
        :line => line,
        :relative_path => "app/controllers/response_headers_controller.rb"
    end
  end

  def test_helper_constant_is_safe
    assert_no_warning :type => :warning,
      :warning_code => 130,
      :line => 18,
      :relative_path => "app/helpers/response_headers_helper.rb"
  end
end
