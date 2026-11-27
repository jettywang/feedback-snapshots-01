# frozen_string_literal: true

require "minitest/autorun"
require_relative "../../diagnostics/sentinel_decommission_matrix"

class RedisClient
  class DecommissionDiagnosticTest < Minitest::Test
    def setup
      @scenarios = SentinelDiagnostic.scenarios
    end

    def test_matrix_is_reproducible_and_internally_consistent
      @scenarios.each do |scenario|
        scenario.run
        assert_empty scenario.verify!, "#{scenario.name} drifted from its recorded expectations"
      end
    end

    def test_reconnect_from_cache_never_queries_sentinel_again
      scenario = @scenarios.find { |candidate| candidate.name == :cached_rebuild }.run

      assert_equal %i[Y Y], scenario.summary[:business_dials]
      assert_equal %i[S1], scenario.summary[:sentinel_dials]
      assert_equal %i[Y], scenario.summary[:cache_stores]
    end

    def test_role_change_forces_rediscovery_before_reaching_new_master
      scenario = @scenarios.find { |candidate| candidate.name == :role_change_rebuild }.run

      assert_equal %i[X X Y], scenario.summary[:business_dials]
      assert_equal %i[S1 S1], scenario.summary[:sentinel_dials]
      assert_equal ["X:slave expected master"], scenario.summary[:role_failures]
    end

    def test_timeout_alone_does_not_invalidate_the_cached_master
      scenario = @scenarios.find { |candidate| candidate.name == :timeout_keeps_cache }.run

      assert_equal %i[X X], scenario.summary[:business_dials]
      assert_equal %i[S1], scenario.summary[:sentinel_dials]
      assert_equal "RedisClient::FailoverError", scenario.summary[:final][:error]
    end

    def test_reset_alone_invalidates_the_cached_master
      scenario = @scenarios.find { |candidate| candidate.name == :reset_rediscovers }.run

      assert_equal %i[X Y], scenario.summary[:business_dials]
      assert_equal %i[S1 S1], scenario.summary[:sentinel_dials]
    end

    def test_in_flight_reset_with_sentinels_down_discards_healthy_cache
      scenario = @scenarios.find { |candidate| candidate.name == :reset_sentinel_down_transient }.run

      assert_equal %i[X], scenario.summary[:business_dials]
      assert_equal "RedisClient::ConnectionError", scenario.summary[:final][:error]
      assert_equal "No sentinels available", scenario.summary[:final][:message]
    end

    def test_client_with_cached_node_still_dials_it_after_demotion
      scenario = @scenarios.find { |candidate| candidate.name == :role_change_rebuild }.run
      demotion = scenario.demotion_seq

      refute_nil demotion
      assert_equal 1, scenario.business_dials_to("X", after_seq: demotion).size
    end

    def test_two_clients_converge_on_the_new_master
      scenario = @scenarios.find { |candidate| candidate.name == :two_clients_converge }.run

      assert_equal %i[Y Y], scenario.summary[:client_dials]["A"]
      assert_equal %i[X X Y], scenario.summary[:client_dials]["B"]
      assert_equal SentinelDiagnostic::SAMPLE_VALUE, scenario.summary[:final][:clients]["A"][:value]
      assert_equal SentinelDiagnostic::SAMPLE_VALUE, scenario.summary[:final][:clients]["B"][:value]
    end

    def test_swapping_report_order_changes_what_gets_dialed_but_not_the_destination
      role_first = @scenarios.find { |candidate| candidate.name == :role_reported_before_timeout }.run
      timeout_first = @scenarios.find { |candidate| candidate.name == :timeout_reported_before_role }.run

      assert_equal :Y, role_first.summary[:business_dials].last
      assert_equal :Y, timeout_first.summary[:business_dials].last
      assert_equal 1, role_first.business_dials_to("X", after_seq: role_first.demotion_seq).size
      assert_equal 1, timeout_first.business_dials_to("X", after_seq: timeout_first.demotion_seq).size
      assert_equal %i[X X Y], timeout_first.summary[:business_dials]
      assert_equal %i[X X Y Y], role_first.summary[:business_dials]
    end

    def test_live_socket_is_never_role_checked
      scenario = @scenarios.find { |candidate| candidate.name == :live_connection_not_rechecked }.run

      assert_equal 1, scenario.summary[:role_checks].size
      assert_equal %i[X], scenario.summary[:business_dials]
    end

    def test_idle_ping_does_not_detect_demotion
      scenario = @scenarios.find { |candidate| candidate.name == :idle_ping_succeeds_on_stale_replica }.run

      assert_equal %i[X], scenario.summary[:business_dials]
      assert_equal ["X:master/master"], scenario.summary[:role_checks]
      assert_equal SentinelDiagnostic::SAMPLE_VALUE, scenario.summary[:final][:value]
    end

    def test_live_socket_still_serves_reads_but_rejects_writes
      scenario = @scenarios.find { |candidate| candidate.name == :live_replica_readonly_rejected }.run

      assert_equal SentinelDiagnostic::SAMPLE_VALUE, scenario.summary[:final][:read][:value]
      assert_equal %i[X], scenario.summary[:readonly_rejections]
    end
  end
end
