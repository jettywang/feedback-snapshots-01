# frozen_string_literal: true

require "test_helper"

require "active_support"
require "active_support/notifications"
require "action_policy/rails/lookup_chain"

ActionPolicy.singleton_class.prepend ActionPolicy::Rails::LookupChain

module LookupInstrNS
  class Record; end

  class RecordPolicy; end
end

class LookupInstrRecordPolicy; end

class TestLookupInstrumentation < Minitest::Test
  def setup
    @events = []
    ActiveSupport::Notifications.subscribe("action_policy.lookup") do |event, *, data|
      @events << [event, data]
    end
  end

  attr_reader :events

  def test_records_the_resolved_policy_class
    policy_class = ActionPolicy.lookup(
      LookupInstrNS::Record,
      namespace: LookupInstrNS,
      strict_namespace: true
    )

    assert_equal LookupInstrNS::RecordPolicy, policy_class
    assert_equal 1, events.size

    event, data = events.pop

    assert_equal "action_policy.lookup", event
    assert_equal LookupInstrNS::RecordPolicy, data[:policy]
    assert_equal LookupInstrNS, data[:namespace]
    assert_equal true, data[:strict_namespace]
  end

  def test_records_nil_when_lookup_finds_nothing
    assert_nil ActionPolicy.lookup(
      :missing_instr_thing,
      namespace: LookupInstrNS,
      strict_namespace: true,
      allow_nil: true
    )

    _event, data = events.pop

    assert_nil data[:policy]
    assert_equal true, data[:strict_namespace]
  end

  def test_records_the_fallback_policy_for_a_regular_call
    policy_class = ActionPolicy.lookup(:lookup_instr_record)

    assert_equal LookupInstrRecordPolicy, policy_class

    _event, data = events.pop

    assert_equal LookupInstrRecordPolicy, data[:policy]
    assert_equal false, data[:strict_namespace]
  end
end
