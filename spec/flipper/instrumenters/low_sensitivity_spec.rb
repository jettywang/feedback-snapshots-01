require 'set'
require 'active_support'
require 'active_support/notifications'
require 'flipper'
require 'flipper/adapters/instrumented'
require 'flipper/instrumenters/low_sensitivity'
require 'flipper/instrumenters/memory'

RSpec.describe Flipper::Instrumenters::LowSensitivity do
  let(:inner) { Flipper::Instrumenters::Memory.new }
  let(:instrumenter) { described_class.new(inner) }
  let(:adapter) do
    Flipper::Adapters::Instrumented.new(Flipper::Adapters::Memory.new, instrumenter: instrumenter)
  end
  let(:flipper) { Flipper.new(adapter, instrumenter: instrumenter) }
  let(:actor_one) { Flipper::Actor.new('User;101', 'email' => 'one@example.com') }
  let(:actor_two) { Flipper::Actor.new('User;202', 'email' => 'two@example.com') }

  before do
    Flipper.register(:pilot_group) do |actor|
      actor.flipper_properties['email'] == 'one@example.com'
    end
  end

  after do
    Flipper.unregister_groups
  end

  def feature_events
    inner.events.select { |event| event.name == Flipper::Feature::InstrumentationName }
  end

  def adapter_events
    inner.events.select { |event| event.name == Flipper::Adapters::Instrumented::InstrumentationName }
  end

  def payloads
    inner.events.map(&:payload)
  end

  describe 'feature decisions' do
    it 'matches original decisions for an allowed and a denied actor in a group' do
      [flipper, Flipper.new(Flipper::Adapters::Memory.new)].each do |instance|
        instance.enable_group(:pilot, :pilot_group)
      end

      expect(flipper.enabled?(:pilot, actor_one)).to be(true)
      expect(flipper.enabled?(:pilot, actor_two)).to be(false)
    end

    it 'matches original decisions for a percentage gate' do
      [flipper, Flipper.new(Flipper::Adapters::Memory.new)].each do |instance|
        instance.enable_percentage_of_actors(:pilot, 100)
      end

      expect(flipper.enabled?(:pilot, actor_one)).to be(true)
      expect(flipper.enabled?(:pilot, actor_two)).to be(true)
    end

    it 'reports the gate category that decided each check' do
      flipper.enable_group(:pilot, :pilot_group)
      flipper.enabled?(:pilot, actor_one)
      flipper.enabled?(:pilot, actor_two)

      check_payloads = feature_events.map(&:payload).select { |payload| payload[:operation] == :enabled? }
      expect(check_payloads.map { |payload| payload[:gate_name] }).to eq([:group, :none])
      expect(check_payloads.map { |payload| payload[:result] }).to eq([true, false])
    end

    it 'reports percentage_of_actors when that gate opens the check' do
      flipper.enable_percentage_of_actors(:pilot, 100)
      flipper.enabled?(:pilot, actor_one)

      check_payload = feature_events.map(&:payload).last
      expect(check_payload[:gate_name]).to eq(:percentage_of_actors)
      expect(check_payload[:result]).to be(true)
    end

    it 'uses :none as the boundary for a denied check' do
      flipper.enabled?(:pilot, actor_two)

      check_payload = feature_events.map(&:payload).last
      expect(check_payload[:operation]).to eq(:enabled?)
      expect(check_payload[:result]).to be(false)
      expect(check_payload[:gate_name]).to eq(:none)
    end

    it 'maps unknown gate names to :other' do
      instrumenter.instrument(Flipper::Feature::InstrumentationName, {
        feature_name: :pilot,
        operation: :enabled?,
        result: true,
        gate_name: :secret_customer_gate,
      })

      expect(inner.events.last.payload[:gate_name]).to eq(:other)
    end
  end

  describe 'low-sensitivity payloads' do
    before do
      flipper.enable_group(:pilot, :pilot_group)
      flipper.enabled?(:pilot, actor_one)
      flipper.enabled?(:pilot, actor_two)
      flipper.enable_actor(:pilot, actor_two)
    end

    it 'never exposes actor ids, actors, or things' do
      serialized = payloads.map(&:inspect).join("\n")
      expect(serialized).not_to include('User;101')
      expect(serialized).not_to include('User;202')
      expect(serialized).not_to include('one@example.com')
    end

    it 'keeps only allowlisted keys' do
      allowed = Set[:feature_name, :feature_names, :operation, :adapter_name, :result, :gate_name]
      payloads.each do |payload|
        expect(payload.keys.to_set.subset?(allowed)).to be(true), "unexpected keys: #{payload.keys.inspect}"
      end
    end

    it 'removes adapter result values and exception text' do
      adapter_payload = adapter_events.map(&:payload).detect { |payload| payload[:operation] == :get }
      expect(adapter_payload.keys).to contain_exactly(:feature_name, :operation, :adapter_name)

      expect {
        instrumenter.instrument('feature_operation.flipper', feature_name: :pilot) do
          raise 'secret-customer-detail'
        end
      }.to raise_error(RuntimeError)

      last = inner.events.last.payload
      expect(last.inspect).not_to include('secret-customer-detail')
      expect(last).not_to have_key(:exception)
      expect(last).not_to have_key(:exception_object)
    end

    it 'drops disallowed keys a wrapped instrumenter tries to add' do
      payload = described_class::Payload.new.merge!(feature_name: :pilot, operation: :enabled?)
      inner.instrument('feature_operation.flipper', payload) do |inner_payload|
        inner_payload[:thing] = actor_one
        inner_payload[:result] = true
      end

      expect(inner.events.last.payload[:thing]).to be_nil
      expect(inner.events.last.payload[:result]).to be(true)
    end

    it 'gives an outer wrapper only the sanitized payload' do
      seen = []
      memory = inner
      outer = Object.new
      outer.define_singleton_method(:instrument) do |name, outer_payload = {}, &block|
        seen << outer_payload
        memory.instrument(name, outer_payload, &block)
      end

      wrapped = described_class.new(outer)
      wrapped.instrument('feature_operation.flipper', feature_name: :pilot, thing: actor_one) do |inner_payload|
        inner_payload[:result] = true
      end

      expect(seen.last[:result]).to be(true)
      expect(seen.last[:thing]).to be_nil
      expect(seen.last.inspect).not_to include('User;101')
    end
  end

  describe 'wrapping' do
    it 'wraps once' do
      expect(described_class.wrap(instrumenter)).to be(instrumenter)
    end

    it 'unwraps nested wrappers' do
      expect(described_class.unwrap(described_class.new(described_class.new(inner)))).to be(inner)
    end
  end
end
