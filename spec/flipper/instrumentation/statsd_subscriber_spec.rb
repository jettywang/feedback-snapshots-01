require 'flipper/adapters/instrumented'
require 'flipper/instrumentation/statsd'

begin
  require 'active_support/isolated_execution_state'
rescue LoadError
  # ActiveSupport::IsolatedExecutionState is only available in Rails 5.2+
end

RSpec.describe Flipper::Instrumentation::StatsdSubscriber do
  let(:statsd_client) { Statsd.new }
  let(:socket) { FakeUDPSocket.new }
  let(:adapter) do
    memory = Flipper::Adapters::Memory.new
    Flipper::Adapters::Instrumented.new(memory, instrumenter: ActiveSupport::Notifications)
  end
  let(:flipper) do
    Flipper.new(adapter, instrumenter: ActiveSupport::Notifications)
  end

  let(:user) { Flipper::Actor.new('1') }

  before do
    described_class.client = statsd_client
    Thread.current[:statsd_socket] = socket
  end

  after do
    described_class.client = nil
    Thread.current[:statsd_socket] = nil
  end

  after(:all) do
    ActiveSupport::Notifications.unsubscribe("flipper")
  end

  def assert_timer(metric)
    regex = /#{Regexp.escape metric}\:\d+\|ms/
    result = socket.buffer.detect { |op| op.first =~ regex }
    expect(result).not_to be_nil
  end

  def assert_counter(metric)
    result = socket.buffer.detect { |op| op.first == "#{metric}:1|c" }
    expect(result).not_to be_nil
  end

  context 'for enabled feature' do
    it 'updates feature metrics when calls happen' do
      flipper[:stats].enable(user)
      assert_timer 'flipper.feature_operation.enable'

      flipper[:stats].enabled?(user)
      assert_timer 'flipper.feature_operation.enabled'
      assert_counter 'flipper.feature.stats.enabled'
    end
  end

  context 'for disabled feature' do
    it 'updates feature metrics when calls happen' do
      flipper[:stats].disable(user)
      assert_timer 'flipper.feature_operation.disable'

      flipper[:stats].enabled?(user)
      assert_timer 'flipper.feature_operation.enabled'
      assert_counter 'flipper.feature.stats.disabled'
    end
  end

  context 'gate hit counters' do
    let(:other_user) { Flipper::Actor.new('2') }

    before do
      Flipper.register(:pilot_group) do |actor|
        actor.flipper_id == '1'
      end
    end

    after do
      Flipper.unregister_groups
    end

    it 'counts the gate category that allowed a check' do
      flipper[:stats].enable_group(:pilot_group)
      flipper[:stats].enabled?(user)

      assert_counter 'flipper.feature.stats.gate.group.enabled'
    end

    it 'counts denied checks against the none boundary' do
      flipper[:stats].enabled?(user)

      assert_counter 'flipper.feature.stats.gate.none.disabled'
    end

    it 'counts percentage gates without changing the decision' do
      flipper[:stats].enable_percentage_of_actors(100)

      expect(flipper[:stats].enabled?(user)).to be(true)
      expect(flipper[:stats].enabled?(other_user)).to be(true)
      assert_counter 'flipper.feature.stats.gate.percentage_of_actors.enabled'
    end

    it 'works with the low-sensitivity instrumenter' do
      Flipper.register(:secret_pilot_group) { |_actor| true }
      secret_actor = Flipper::Actor.new('User;secret-1')
      instrumenter = Flipper::Instrumenters::LowSensitivity.new(ActiveSupport::Notifications)
      low_sensitivity = Flipper.new(adapter, instrumenter: instrumenter)
      low_sensitivity[:stats].enable_group(:secret_pilot_group)
      low_sensitivity[:stats].enabled?(secret_actor)

      assert_counter 'flipper.feature.stats.gate.group.enabled'
      expect(socket.buffer.map(&:first).join).not_to include('secret-1')
    ensure
      Flipper.unregister_groups
    end
  end

  it 'updates adapter metrics when calls happen' do
    flipper[:stats].enable(user)
    assert_timer 'flipper.adapter.memory.enable'

    flipper[:stats].enabled?(user)
    assert_timer 'flipper.adapter.memory.get'

    flipper[:stats].disable(user)
    assert_timer 'flipper.adapter.memory.disable'
  end

  # Events the gem instruments that have no metrics of their own.
  %w(synchronizer_call synchronizer_exception synchronizer_stale poller telemetry_error telemetry_retry).each do |operation|
    it "ignores #{operation} events without printing" do
      expect {
        ActiveSupport::Notifications.instrument("#{operation}.flipper", {})
      }.not_to output.to_stdout
      expect(socket.buffer).to be_empty
    end
  end

  context 'when client is nil' do
    before do
      described_class.client = nil
    end

    it 'does not raise error' do
      expect { flipper[:stats].enable(user) }.not_to raise_error
    end

    it 'does not update metrics' do
      flipper[:stats].enable(user)
      expect(socket.buffer).to be_empty
    end
  end
end
