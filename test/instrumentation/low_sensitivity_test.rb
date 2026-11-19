require 'test_helper'
require 'flipper/adapters/instrumented'
require 'flipper/instrumenters/low_sensitivity'
require 'flipper/instrumentation/statsd_subscriber'

class LowSensitivityTest < MiniTest::Test
  class FakeStatsdClient
    attr_reader :counters

    def initialize
      @counters = Hash.new(0)
    end

    def increment(metric)
      @counters[metric] += 1
    end

    def timing(_metric, _duration)
    end
  end

  def setup
    Flipper.register(:pilot) do |actor|
      actor.flipper_properties['pilot'] == true
    end
    @instrumenter = Flipper::Instrumenters::LowSensitivity.new(Flipper::Instrumenters::Memory.new)
    @adapter = Flipper::Adapters::Instrumented.new(
      Flipper::Adapters::Memory.new,
      instrumenter: @instrumenter
    )
    @flipper = Flipper.new(@adapter, instrumenter: @instrumenter)
    @allowed = Flipper::Actor.new('User;101', 'pilot' => true, 'email' => 'one@example.com')
    @denied = Flipper::Actor.new('User;202', 'pilot' => false, 'email' => 'two@example.com')
  end

  def teardown
    Flipper.unregister_groups
    Flipper::Instrumentation::StatsdSubscriber.client = nil
  end

  def events
    @instrumenter.instrumenter.events
  end

  def payloads
    events.map(&:payload)
  end

  def test_decisions_match_plain_flipper_for_group_and_percentage_gates
    plain = Flipper.new(Flipper::Adapters::Memory.new)
    [@flipper, plain].each do |flipper|
      flipper.enable_group(:search, :pilot)
      flipper.enable_percentage_of_actors(:search, 50)
    end

    [@allowed, @denied].each do |actor|
      assert_equal plain.enabled?(:search, actor), @flipper.enabled?(:search, actor)
    end
  end

  def test_events_report_stable_gate_categories_and_boundaries
    @flipper.enable_group(:search, :pilot)
    @flipper.enabled?(:search, @allowed)
    @flipper.enabled?(:search, @denied)

    checks = payloads.select { |payload| payload[:operation] == :enabled? }
    assert_equal [:group, :none], checks.map { |payload| payload[:gate_name] }
    assert_equal [true, false], checks.map { |payload| payload[:result] }

    @flipper.enable_percentage_of_actors(:search, 100)
    @flipper.enabled?(:search, @denied)
    assert_equal :percentage_of_actors, payloads.last[:gate_name]
  end

  def test_events_never_include_actor_identifiers_or_things
    @flipper.enable_group(:search, :pilot)
    @flipper.enable_actor(:search, @denied)
    @flipper.enabled?(:search, @allowed)
    @flipper.enabled?(:search, @denied)

    serialized = payloads.map(&:inspect).join("\n")
    refute_includes serialized, 'User;101'
    refute_includes serialized, 'User;202'
    refute_includes serialized, 'one@example.com'
    refute_includes serialized, 'two@example.com'
  end

  def test_events_keep_only_allowlisted_keys
    allowed = Set[:feature_name, :feature_names, :operation, :adapter_name, :result, :gate_name]
    @flipper.enable_group(:search, :pilot)
    @flipper.enabled?(:search, @allowed)

    payloads.each do |payload|
      assert payload.keys.to_set.subset?(allowed), "unexpected keys: #{payload.keys.inspect}"
    end
  end

  def test_adapter_results_are_not_included
    @flipper.enable_group(:search, :pilot)
    @flipper.enabled?(:search, @allowed)

    get = payloads.detect { |payload| payload[:operation] == :get }
    assert_equal Set[:feature_name, :operation, :adapter_name], get.keys.to_set
  end

  def test_exceptions_do_not_leak_messages
    error = assert_raises(RuntimeError) do
      @instrumenter.instrument(Flipper::Feature::InstrumentationName, feature_name: :search) do
        raise 'secret-customer-detail'
      end
    end
    assert_equal 'secret-customer-detail', error.message

    payload = payloads.last
    refute payload.key?(:exception)
    refute payload.key?(:exception_object)
    refute_includes payload.inspect, 'secret-customer-detail'
  end

  def test_outer_wrappers_get_the_sanitized_result
    seen = []
    memory = @instrumenter.instrumenter
    outer = Object.new
    outer.define_singleton_method(:instrument) do |name, payload = {}, &block|
      seen << payload
      memory.instrument(name, payload, &block)
    end

    wrapped = Flipper::Instrumenters::LowSensitivity.new(outer)
    wrapped.instrument(Flipper::Feature::InstrumentationName, feature_name: :search, thing: @allowed) do |payload|
      payload[:result] = true
    end

    assert_equal true, seen.last[:result]
    assert_nil seen.last[:thing]
    refute_includes seen.last.inspect, 'User;101'
  end

  def test_statsd_counts_gate_categories_without_actor_ids
    client = FakeStatsdClient.new
    Flipper::Instrumentation::StatsdSubscriber.client = client

    instrumenter = Flipper::Instrumenters::LowSensitivity.new(Flipper::Instrumenters::Memory.new)
    adapter = Flipper::Adapters::Instrumented.new(Flipper::Adapters::Memory.new, instrumenter: instrumenter)
    flipper = Flipper.new(adapter, instrumenter: instrumenter)

    flipper.enable_group(:search, :pilot)
    flipper.enabled?(:search, @allowed)
    flipper.disable_group(:search, :pilot)
    flipper.enabled?(:search, @allowed)
    flipper.enabled?(:search, @allowed)
    flipper.enable_percentage_of_actors(:search, 100)
    flipper.enabled?(:search, @denied)
    flipper.enabled?(:search, @denied)
    flipper.enabled?(:search, @allowed)

    # Feed the subscriber the same sanitized events a real subscriber would
    # receive from Flipper::Instrumenters::LowSensitivity.
    now = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    instrumenter.instrumenter.events.each do |event|
      Flipper::Instrumentation::StatsdSubscriber.call(event.name, now, now + 0.001, nil, event.payload)
    end

    gate_counters = client.counters.select { |metric, _| metric.include?('.gate.') }
    assert_equal({
      'flipper.feature.search.gate.group.enabled' => 1,
      'flipper.feature.search.gate.none.disabled' => 2,
      'flipper.feature.search.gate.percentage_of_actors.enabled' => 3,
    }, gate_counters)

    gate_counters.each_key do |metric|
      refute_includes metric, 'User;101'
      refute_includes metric, 'User;202'
    end
  end
end
