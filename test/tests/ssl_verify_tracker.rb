require_relative '../test'

class SSLVerifyTrackerTests < Minitest::Test
  LOCATION = {
    :type => :class,
    :class => :SslClient,
    :method => :use_client,
    :file => "lib/ssl_client.rb"
  }.freeze

  def findings_for code
    src = RubyParser.new.parse("def use_client\n#{code}\nend")
    Brakeman::SSLVerifyTracker.new(nil).process_source(src, LOCATION.dup)
  end

  def confidence_for code, request_line
    matches = findings_for(code).select { |finding| finding[:call].line == request_line }

    refute_empty matches, "expected a finding on line #{request_line}"
    matches.map { |finding| finding[:confidence] }
  end

  def test_direct_none_on_request_is_high
    code = <<-RUBY
      http = Net::HTTP.new(host, 443)
      http.use_ssl = true
      http.verify_mode = OpenSSL::SSL::VERIFY_NONE
      http.get("/path")
    RUBY

    assert_equal [:high], confidence_for(code, 5)
  end

  def test_explicit_peer_is_not_flagged
    code = <<-RUBY
      conn = Net::HTTP.new(host, 443)
      conn.use_ssl = true
      conn.verify_mode = OpenSSL::SSL::VERIFY_PEER
      conn.get("/other")
    RUBY

    assert_empty findings_for(code)
  end

  def test_alias_keeps_tracking_the_same_object
    code = <<-RUBY
      a = Net::HTTP.new(host)
      a.use_ssl = true
      b = a
      b.verify_mode = OpenSSL::SSL::VERIFY_NONE
      a.get("/alias")
    RUBY

    assert_equal [:high], confidence_for(code, 6)
  end

  def test_reassigned_variable_uses_the_new_object_state
    code = <<-RUBY
      x = Net::HTTP.new(host)
      x.use_ssl = true
      x.verify_mode = OpenSSL::SSL::VERIFY_NONE
      x = Net::HTTP.new(host)
      x.use_ssl = true
      x.verify_mode = OpenSSL::SSL::VERIFY_PEER
      x.get("/")
    RUBY

    assert_empty findings_for(code)
  end

  def test_secure_default_overridden_before_request_is_high
    code = <<-RUBY
      client = Net::HTTP.new(host, 443)
      client.use_ssl = true
      client.verify_mode = OpenSSL::SSL::VERIFY_PEER
      client.verify_mode = OpenSSL::SSL::VERIFY_NONE
      client.get("/insecure")
    RUBY

    assert_equal [:high], confidence_for(code, 6)
  end

  def test_two_interwoven_connections_are_tracked_independently
    code = <<-RUBY
      client = Net::HTTP.new(host, 443)
      client.use_ssl = true
      client.verify_mode = OpenSSL::SSL::VERIFY_PEER
      other = Net::HTTP.new(host, 8443)
      other.use_ssl = true
      other.verify_mode = OpenSSL::SSL::VERIFY_NONE
      client.verify_mode = OpenSSL::SSL::VERIFY_NONE
      client.get("/insecure")
      other.get("/also-insecure")
    RUBY

    findings = findings_for(code)

    assert_equal 2, findings.length
    assert_equal [:high, :high], findings.map { |finding| finding[:confidence] }
    assert_equal ["/insecure", "/also-insecure"],
      findings.map { |finding| finding[:call].first_arg.value }
  end

  def test_mixed_branch_is_not_assumed_safe
    code = <<-RUBY
      c = Net::HTTP.new(host)
      c.use_ssl = true
      if flag
        c.verify_mode = OpenSSL::SSL::VERIFY_PEER
      else
        c.verify_mode = OpenSSL::SSL::VERIFY_NONE
      end
      c.request(req)
    RUBY

    assert_equal [:medium], confidence_for(code, 9)
  end

  def test_one_sided_branch_leaves_state_unknown
    code = <<-RUBY
      c = Net::HTTP.new(host)
      c.use_ssl = true
      if flag
        c.verify_mode = OpenSSL::SSL::VERIFY_PEER
      end
      c.request(req)
    RUBY

    assert_equal [:medium], confidence_for(code, 7)
  end

  def test_unresolved_connection_state_is_medium_not_high
    code = <<-RUBY
      c = build_connection
      c.use_ssl = true
      c.get("/helper")
    RUBY

    assert_equal [:medium], confidence_for(code, 4)
  end

  def test_verification_setting_without_ssl_is_not_reported
    code = <<-RUBY
      c = Net::HTTP.new(host)
      c.verify_mode = OpenSSL::SSL::VERIFY_NONE
      c.get("/plain")
    RUBY

    assert_empty findings_for(code)
  end

  def test_net_http_start_with_none_is_high_on_start_call
    code = <<-RUBY
      Net::HTTP.start(host, port, :use_ssl => true, :verify_mode => OpenSSL::SSL::VERIFY_NONE)
    RUBY

    findings = findings_for(code)

    assert_equal 1, findings.length
    assert_equal :high, findings.first[:confidence]
    assert_equal :start, findings.first[:call].method
  end

  def test_net_http_start_block_reports_once_on_start_call
    code = <<-RUBY
      Net::HTTP.start(host, port, :use_ssl => true, :verify_mode => OpenSSL::SSL::VERIFY_NONE) do |http|
        http.get("/block")
      end
    RUBY

    findings = findings_for(code)

    assert_equal 1, findings.length
    assert_equal :high, findings.first[:confidence]
    assert_equal :start, findings.first[:call].method
  end

  def test_use_ssl_true_alone_is_medium
    code = <<-RUBY
      c = Net::HTTP.new(host)
      c.use_ssl = true
      c.get("/no-verify-mode")
    RUBY

    assert_equal [:medium], confidence_for(code, 4)
  end

  def test_explicit_use_ssl_false_is_not_reported
    code = <<-RUBY
      c = Net::HTTP.new(host)
      c.use_ssl = false
      c.verify_mode = OpenSSL::SSL::VERIFY_NONE
      c.get("/no-tls")
    RUBY

    assert_empty findings_for(code)
  end

  def test_unless_leaves_unset_branch_unknown
    code = <<-RUBY
      c = Net::HTTP.new(host)
      c.use_ssl = true
      unless flag
        c.verify_mode = OpenSSL::SSL::VERIFY_NONE
      end
      c.get("/unless")
    RUBY

    assert_equal [:medium], confidence_for(code, 7)
  end

  def test_inline_if_assignment_combines_branch_states
    code = <<-RUBY
      c = Net::HTTP.new(host)
      c.use_ssl = true
      c.verify_mode =
        if flag
          OpenSSL::SSL::VERIFY_PEER
        else
          OpenSSL::SSL::VERIFY_NONE
        end
      c.get("/inline-if")
    RUBY

    assert_equal [:medium], confidence_for(code, 10)
  end

  def test_instance_variable_connection_is_tracked
    code = <<-RUBY
      @c = Net::HTTP.new(host)
      @c.use_ssl = true
      @c.verify_mode = OpenSSL::SSL::VERIFY_NONE
      @c.get("/ivar")
    RUBY

    assert_equal [:high], confidence_for(code, 5)
  end

  def test_verify_peer_start_option_is_not_flagged
    code = <<-RUBY
      Net::HTTP.start(host, port, :use_ssl => true, :verify_mode => OpenSSL::SSL::VERIFY_PEER)
    RUBY

    assert_empty findings_for(code)
  end
end

class SSLVerifyCheckIntegrationTests < Minitest::Test
  def run_check_on code
    tracker = BrakemanTester.new_tracker
    src = RubyParser.new.parse(code)
    Brakeman::LibraryProcessor.new(tracker).process_library src, "lib/ssl_client.rb"

    # Populate the call index so the legacy find_call paths work.
    tracker.find_call(:method => :verify_mode=)

    check = Brakeman::CheckSSLVerify.new(tracker)
    check.run_check
    check.warnings
  end

  def test_attributes_warning_to_request_with_last_effective_config
    code = <<-RUBY
      class SslClient
        def use_client(host)
          client = Net::HTTP.new(host, 443)
          client.use_ssl = true
          client.verify_mode = OpenSSL::SSL::VERIFY_PEER

          other = Net::HTTP.new(host, 8443)
          other.use_ssl = true
          other.verify_mode = OpenSSL::SSL::VERIFY_NONE

          client.verify_mode = OpenSSL::SSL::VERIFY_NONE
          client.get("/insecure")
          other.get("/also-insecure")
        end

        def explicitly_verified(host)
          connection = Net::HTTP.new(host, 443)
          connection.use_ssl = true
          connection.verify_mode = OpenSSL::SSL::VERIFY_PEER
          connection.get("/secure")
        end
      end
    RUBY

    warnings = run_check_on(code)

    messages = warnings.map { |warning| warning.message.to_s }
    assert_equal 2, warnings.length
    assert messages.all? { |message| message.include?("verification was bypassed") }
    assert warnings.all? { |warning| warning.confidence == 0 }
    assert_equal ["/insecure", "/also-insecure"], warnings.map { |warning| request_path(warning) }
  end

  def test_verify_peer_in_same_file_does_not_clear_findings
    code = <<-RUBY
      class SslClient
        def safe(host)
          connection = Net::HTTP.new(host, 443)
          connection.use_ssl = true
          connection.verify_mode = OpenSSL::SSL::VERIFY_PEER
          connection.get("/secure")
        end

        def unsafe(host)
          connection = Net::HTTP.new(host, 443)
          connection.use_ssl = true
          connection.verify_mode = OpenSSL::SSL::VERIFY_NONE
          connection.get("/insecure")
        end
      end
    RUBY

    warnings = run_check_on(code)

    assert_equal 1, warnings.length
    assert_equal "/insecure", request_path(warnings.first)
    assert_equal 0, warnings.first.confidence
  end

  def test_unresolved_receiver_still_uses_legacy_warning
    code = <<-RUBY
      class ApplicationController
        def bypass_ssl_check
          self.verify_mode = OpenSSL::SSL::VERIFY_NONE
        end
      end
    RUBY

    warnings = run_check_on(code)

    assert_equal 1, warnings.length
    assert_equal 0, warnings.first.confidence
    assert warnings.first.message.to_s.include?("verification was bypassed")
  end

  private

  def request_path warning
    warning.code.first_arg.value
  end
end
