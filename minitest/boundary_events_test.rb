require File.expand_path(File.dirname(__FILE__) + '/test_helper')
require File.expand_path(File.dirname(__FILE__) + '/../test/boundary_event_harness')

test_class = defined?(Minitest::Test) ? Minitest::Test : MiniTest::Unit::TestCase

# Boundary-event acceptance for WebMock-guarded adapters. Runs fully
# offline: allowed traffic is stubbed, denied traffic is rejected by WebMock
# before any socket is opened. See test/boundary_event_harness.md.
class BoundaryEventsTest < test_class
  def setup
    super
    @log = BoundaryEventHarness::EventLog.new
    BoundaryEventHarness.install_webmock_evidence(@log)
  end

  def teardown
    WebMock.reset_callbacks
    super
  end

  def run_suite
    BoundaryEventHarness.run_suite(:net_http, log: @log) do
      stub_request(:get, 'http://www.example.com/').to_return(status: 200, body: 'ok')
    end
  end

  def test_allowed_stub_records_all_four_boundary_events_in_order
    run_suite
    assert_equal %i[connection_intent boundary_invocation adjudication completion_callback],
      @log.kinds_for('allowed-stub')
    assert_equal 'allowed', @log.adjudication_for('allowed-stub')
  end

  def test_client_cancel_before_request_construction_leaves_only_connection_intent
    run_suite
    assert_equal %i[connection_intent], @log.kinds_for('client-cancel')
  end

  def test_denied_request_records_adjudication_without_completion_callback
    run_suite
    assert_equal %i[connection_intent boundary_invocation adjudication],
      @log.kinds_for('rule-denied')
    assert_equal 'denied', @log.adjudication_for('rule-denied')
  end

  def test_upper_level_observation_is_identical_for_cancel_and_deny
    result = run_suite
    assert_equal result.outcomes['client-cancel'], result.outcomes['rule-denied']
    refute result.outcomes['client-cancel'].completed
    refute_equal result.outcomes['allowed-stub'], result.outcomes['rule-denied']
    assert_equal '200', result.outcomes['allowed-stub'].http_status
  end

  def test_request_registry_counts_denied_attempts_so_it_is_not_completion_evidence
    run_suite
    pattern = WebMock::RequestPattern.new(:get, 'http://www.example.net/')
    assert_equal 1, WebMock::RequestRegistry.instance.times_executed(pattern)
  end

  def test_calls_outside_double_registration_never_mix_into_a_record
    run_suite
    event_count = @log.events.length

    stray = BoundaryEventHarness::BoundaryDouble.new(@log, 'net_http#request')
    stray.invoked('note' => 'disarmed double, before registration')
    assert_equal event_count, @log.events.length

    stray.arm!
    stray.invoked('note' => 'armed, but every record is closed')
    assert_equal event_count, @log.events.length
    assert_equal 1, @log.quarantine.length
    assert_nil @log.quarantine.first.record_id

    assert_equal %i[connection_intent boundary_invocation adjudication completion_callback],
      @log.kinds_for('allowed-stub')
  end

  def test_records_round_trip_through_json_for_offline_replay
    run_suite
    restored = BoundaryEventHarness::EventLog.from_json(@log.to_json)
    assert_equal @log.verdicts, restored.verdicts
    assert_equal @log.to_h, restored.to_h
  end

  def test_suite_runs_fully_offline
    refute WebMock.net_connect_allowed?
    result = run_suite
    assert result.outcomes['allowed-stub'].completed
  end
end
