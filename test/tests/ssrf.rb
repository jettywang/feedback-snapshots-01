require_relative '../test'

class SSRFTests < Minitest::Test
  include BrakemanTester::FindWarning

  def report
    @@report ||= BrakemanTester.run_scan "rails6", "Rails 6", run_all_checks: true
  end

  SSRF_FILE = "app/controllers/ssrf_controller.rb"

  def test_absolute_url_override_is_full_control
    assert_warning :type => :warning,
      :warning_code => 130,
      :warning_type => "SSRF",
      :line => 6,
      :message => /^Possible SSRF: .* can control the scheme and\/or host/,
      :confidence => 0,
      :relative_path => SSRF_FILE,
      :code => s(:call, s(:colon2, s(:const, :Net), :HTTP), :get, s(:call, s(:const, :URI), :parse, s(:call, s(:params), :[], s(:lit, :target)))),
      :user_input => s(:call, s(:params), :[], s(:lit, :target))
  end

  def test_open_absolute_user_url_is_full_control
    assert_warning :type => :warning,
      :warning_code => 130,
      :warning_type => "SSRF",
      :line => 11,
      :message => /can control the scheme and\/or host/,
      :confidence => 0,
      :relative_path => SSRF_FILE,
      :code => s(:call, nil, :open, s(:call, s(:params), :[], s(:lit, :url))),
      :user_input => s(:call, s(:params), :[], s(:lit, :url))
  end

  def test_uri_open_user_controlled_is_full_control
    assert_warning :type => :warning,
      :warning_code => 130,
      :warning_type => "SSRF",
      :line => 16,
      :message => /can control the scheme and\/or host/,
      :confidence => 0,
      :relative_path => SSRF_FILE,
      :code => s(:call, s(:const, :URI), :open, s(:call, s(:params), :[], s(:lit, :url))),
      :user_input => s(:call, s(:params), :[], s(:lit, :url))
  end

  def test_fixed_authority_path_interpolation_is_path_only
    assert_warning :type => :warning,
      :warning_code => 130,
      :warning_type => "SSRF",
      :line => 21,
      :message => /only reaches the path, query, or fragment/,
      :confidence => 2,
      :relative_path => SSRF_FILE,
      :code => s(:call, s(:colon2, s(:const, :Net), :HTTP), :get, s(:call, nil, :URI, s(:dstr, "https://api.internal.example.com/v1/", s(:evstr, s(:call, s(:params), :[], s(:lit, :id)))))),
      :user_input => s(:call, s(:params), :[], s(:lit, :id))
  end

  def test_fixed_authority_path_concat_is_path_only
    assert_warning :type => :warning,
      :warning_code => 130,
      :warning_type => "SSRF",
      :line => 27,
      :message => /only reaches the path, query, or fragment/,
      :confidence => 2,
      :relative_path => SSRF_FILE,
      :code => s(:call, s(:const, :HTTParty), :get, s(:call, s(:str, "https://api.internal.example.com/users/"), :+, s(:call, s(:params), :[], s(:lit, :id)))),
      :user_input => s(:call, s(:params), :[], s(:lit, :id))
  end

  def test_scheme_relative_value_is_full_control
    assert_warning :type => :warning,
      :warning_code => 130,
      :warning_type => "SSRF",
      :line => 33,
      :message => /can control the scheme and\/or host/,
      :confidence => 0,
      :relative_path => SSRF_FILE,
      :code => s(:call, nil, :open, s(:dstr, "//", s(:evstr, s(:call, s(:params), :[], s(:lit, :host))), s(:str, "/callback"))),
      :user_input => s(:call, s(:params), :[], s(:lit, :host))
  end

  def test_uri_join_with_tainted_relative_argument_is_full_control
    assert_warning :type => :warning,
      :warning_code => 130,
      :warning_type => "SSRF",
      :line => 39,
      :message => /can control the scheme and\/or host/,
      :confidence => 0,
      :relative_path => SSRF_FILE,
      :code => s(:call, s(:const, :HTTParty), :get, s(:call, s(:call, s(:const, :URI), :join, s(:str, "https://api.internal.example.com/v1/"), s(:call, s(:params), :[], s(:lit, :path))), :to_s)),
      :user_input => s(:call, s(:params), :[], s(:lit, :path))
  end

  def test_net_http_user_host_is_full_control
    assert_warning :type => :warning,
      :warning_code => 130,
      :warning_type => "SSRF",
      :line => 59,
      :message => /can control the scheme and\/or host/,
      :confidence => 0,
      :relative_path => SSRF_FILE,
      :code => s(:call, s(:colon2, s(:const, :Net), :HTTP), :start, s(:call, s(:params), :[], s(:lit, :host)), s(:call, s(:params), :[], s(:lit, :port))),
      :user_input => s(:call, s(:params), :[], s(:lit, :host))
  end

  def test_helper_return_value_is_traced
    assert_warning :type => :warning,
      :warning_code => 130,
      :warning_type => "SSRF",
      :line => 64,
      :message => /can control the scheme and\/or host/,
      :confidence => 0,
      :relative_path => SSRF_FILE,
      :code => s(:call, s(:const, :HTTParty), :get, s(:call, nil, :build_target_url, s(:call, s(:params), :[], s(:lit, :target)))),
      :user_input => s(:call, s(:params), :[], s(:lit, :target))
  end

  def test_faraday_user_url_is_full_control
    assert_warning :type => :warning,
      :warning_code => 130,
      :warning_type => "SSRF",
      :line => 69,
      :message => /can control the scheme and\/or host/,
      :confidence => 0,
      :relative_path => SSRF_FILE,
      :code => s(:call, s(:const, :Faraday), :new, s(:hash, s(:lit, :url), s(:call, s(:params), :[], s(:lit, :target)))),
      :user_input => s(:call, s(:params), :[], s(:lit, :target))
  end

  def test_fixed_targets_do_not_warn
    assert_no_warning :warning_code => 130,
      :relative_path => SSRF_FILE,
      :line => 44

    assert_no_warning :warning_code => 130,
      :relative_path => SSRF_FILE,
      :line => 49

    assert_no_warning :warning_code => 130,
      :relative_path => SSRF_FILE,
      :line => 54

    assert_no_warning :warning_code => 130,
      :relative_path => SSRF_FILE,
      :line => 75
  end

  def test_all_ssrf_warnings_have_cwe
    report[:generic_warnings].select { |w| w.warning_type == "SSRF" }.each do |warning|
      assert_equal [918], warning.cwe_id
    end
  end
end
