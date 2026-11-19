require 'dalli'
require 'flipper/adapters/failover'
require 'net/http'
require 'pstore'
require 'redis'
require 'flipper/adapters/operation_logger'

RSpec.describe Flipper::Adapters::Failover do
  subject { described_class.new(primary, secondary, options) }

  let(:primary) { Flipper::Adapters::Memory.new }
  let(:secondary) { Flipper::Adapters::Memory.new }
  let(:options) { {} }
  let(:flipper) { Flipper.new(subject) }

  context 'when the primary is a functioning adapter' do
    it_should_behave_like 'a flipper adapter'
    it_should_behave_like 'an adapter that stores its sync version'

    it 'records the sync version in the primary only' do
      subject.sync_version = Flipper::SyncVersion.new("scope", 10)
      expect(primary.sync_version).to eq(subject.sync_version)
      expect(secondary.sync_version).to be_nil
    end

    context 'when dual_write is enabled for the sync version' do
      let(:options) { { dual_write: true } }

      it 'records the sync version in both adapters' do
        subject.sync_version = Flipper::SyncVersion.new("scope", 10)
        expect(primary.sync_version).to eq(subject.sync_version)
        expect(secondary.sync_version).to eq(subject.sync_version)
      end
    end

    it 'should not call the secondary' do
      expect(secondary).not_to receive(:features)
      subject.features
    end

    it 'should not write to secondary' do
      expect(secondary).not_to receive(:add)
      expect(secondary).not_to receive(:enable)

      flipper[:flag].enable
    end

    context 'when dual_write is enabled' do
      let(:options) { { dual_write: true } }

      it_should_behave_like 'a flipper adapter'

      it 'writes to both primary and secondary' do
        expect(primary).to receive(:add).and_call_original
        expect(primary).to receive(:enable).and_call_original

        expect(secondary).to receive(:add)
        expect(secondary).to receive(:enable)

        flipper[:flag].enable
      end
    end
  end

  context 'when primary fails during read operations' do
    before do
      allow(primary).to receive(:features).and_raise(Redis::ConnectionError)
      allow(primary).to receive(:get).and_raise(Dalli::NetworkError)
    end

    it 'fails over to the secondary adapter for the sync version' do
      allow(primary).to receive(:sync_version).and_raise(Redis::ConnectionError)
      secondary.sync_version = Flipper::SyncVersion.new("scope", 10)
      expect(subject.sync_version).to eq(secondary.sync_version)
    end

    it 'fails over to the secondary adapter for reads' do
      expect(secondary).to receive(:features)
      subject.features

      flipper[:flag].enable
      expect(secondary).to receive(:get).and_call_original
      flipper[:flag].enabled?
    end

    context 'when dual_write is enabled' do
      let(:options) { { dual_write: true } }

      it_should_behave_like 'a flipper adapter'
    end
  end

  context 'when primary fails during write operations' do
    before do
      allow(primary).to receive(:add).and_raise(PStore::Error)
    end

    let(:options) { { dual_write: true } }

    it 'fails and does not write to secondary adapter' do
      expect(secondary).not_to receive(:add)
      expect(secondary).not_to receive(:enable)

      expect { flipper[:flag].enable }.to raise_error(PStore::Error)
    end
  end

  context 'when primary is instrumented and fails' do
    before do
      allow(memory_adapter).to receive(:get).and_raise(Net::ReadTimeout)
    end

    let(:memory_adapter) { Flipper::Adapters::Memory.new }
    let(:primary) do
      Flipper::Adapters::Instrumented.new(
        memory_adapter,
        instrumenter: instrumenter,
      )
    end
    let(:instrumenter) { Flipper::Instrumenters::Memory.new }

    it 'logs the raised exception' do
      flipper[:flag].enabled?

      expect(instrumenter.events.count).to be 1

      payload = instrumenter.events[0].payload
      expect(payload.keys).to include(:exception, :exception_object)
      expect(payload[:exception_object]).to be_a Net::ReadTimeout
    end
  end

  context 'when adapter raises a SyntaxError' do
    before do
      allow(primary).to receive(:features).and_raise(SyntaxError)
    end

    it 'does not rescue this type by default' do
      expect {
        subject.features
      }.to raise_error(SyntaxError)
    end

    context 'when Failover adapter is configured to catch SyntaxError' do
      let(:options) { { errors: [ SyntaxError ] } }

      it 'fails over to secondary adapter' do
        expect(secondary).to receive(:features)
        subject.features
      end
    end
  end

  describe '#adapter_stack' do
    it 'returns the tree representation' do
      expect(subject.adapter_stack).to eq("failover(primary: memory, secondary: memory)")
    end

    it 'shows nested adapters in the tree' do
      strict_primary = Flipper::Adapters::Strict.new(primary)
      adapter = described_class.new(strict_primary, secondary)
      expect(adapter.adapter_stack).to eq("failover(primary: strict -> memory, secondary: memory)")
    end
  end

  context 'with critical features and a stale secondary snapshot' do
    let(:secondary) do
      adapter = Flipper::Adapters::Memory.new
      stale = Flipper.new(adapter)
      stale.enable(:search)
      stale.enable(:checkout_payments)
      stale.enable(:refunds)
      adapter
    end
    let(:options) do
      {
        critical_features: [:checkout_payments, :refunds],
        safe_value: {},
        safe_values: {refunds: {boolean: false, percentage_of_time: 0}},
      }
    end
    let(:flipper) { Flipper.new(subject) }

    before do
      primary_flipper = Flipper.new(primary)
      primary_flipper.enable(:search)
      primary_flipper.disable(:checkout_payments)
      primary_flipper.enable(:refunds)
    end

    def primary_unavailable!
      allow(primary).to receive(:get).and_raise(Redis::ConnectionError)
      allow(primary).to receive(:get_multi).and_raise(Redis::ConnectionError)
      allow(primary).to receive(:get_all).and_raise(Redis::ConnectionError)
      allow(primary).to receive(:features).and_raise(Redis::ConnectionError)
      allow(primary).to receive(:sync_version).and_raise(Redis::ConnectionError)
    end

    it 'serves ordinary flags from the secondary when the primary is unavailable' do
      primary_unavailable!

      expect(flipper.enabled?(:search)).to be(true)
    end

    it 'returns the configured safe value for critical flags instead of the stale snapshot' do
      primary_unavailable!

      expect(flipper.enabled?(:checkout_payments)).to be(false)
      expect(flipper.enabled?(:refunds)).to be(false)
    end

    it 'uses per-feature safe values over the shared one' do
      primary_unavailable!

      expect(subject.get(flipper[:refunds]).fetch(:percentage_of_time)).to eq("0")
      expect(subject.get(flipper[:refunds]).fetch(:boolean)).to be_nil
    end

    it 'keeps critical flags represented without reusing stale gate values in get_multi' do
      primary_unavailable!

      result = subject.get_multi([flipper[:search], flipper[:checkout_payments], flipper[:missing]])

      expect(result["search"]).to eq(subject.default_config.merge(boolean: "true"))
      expect(result["checkout_payments"]).to eq(subject.default_config)
      expect(result["missing"]).to eq(subject.default_config)
    end

    it 'replaces critical values from the stale snapshot in get_all' do
      primary_unavailable!

      result = subject.get_all

      expect(result["search"]).to eq(subject.default_config.merge(boolean: "true"))
      expect(result["checkout_payments"]).to eq(subject.default_config)
      expect(result["refunds"].fetch(:percentage_of_time)).to eq("0")
      expect(result["refunds"].fetch(:boolean)).to be_nil
    end

    it 'lists critical features even when the stale snapshot does not know them' do
      secondary.remove(Flipper::Feature.new(:refunds, secondary))
      primary_unavailable!

      expect(subject.features).to include("search", "checkout_payments", "refunds")
    end

    it 'sends every read to the primary again so recovery restores actual values' do
      primary_unavailable!
      expect(flipper.enabled?(:checkout_payments)).to be(false)
      expect(flipper.enabled?(:search)).to be(true)

      # Config changes while the primary is unreachable must be visible once
      # it comes back, not masked by the values served during the outage.
      primary_flipper = Flipper.new(primary)
      primary_flipper.enable(:checkout_payments)
      primary_flipper.disable(:search)

      allow(primary).to receive(:get).and_call_original
      allow(primary).to receive(:get_multi).and_call_original
      allow(primary).to receive(:get_all).and_call_original
      allow(primary).to receive(:features).and_call_original
      allow(primary).to receive(:sync_version).and_call_original

      expect(flipper.enabled?(:checkout_payments)).to be(true)
      expect(flipper.enabled?(:search)).to be(false)
    end

    it 'records primary read attempts so recovery can be verified from the memory adapters' do
      logged_primary = Flipper::Adapters::OperationLogger.new(primary)
      logged_secondary = Flipper::Adapters::OperationLogger.new(secondary)
      adapter = described_class.new(logged_primary, logged_secondary, options)

      primary_unavailable!

      adapter.get(Flipper::Feature.new(:checkout_payments, adapter))
      adapter.get(Flipper::Feature.new(:search, adapter))

      expect(logged_primary.count(:get)).to eq(2)
      expect(logged_secondary.count(:get)).to eq(1)

      logged_primary.reset
      logged_secondary.reset

      allow(primary).to receive(:get).and_call_original
      expect(adapter.get(Flipper::Feature.new(:checkout_payments, adapter))[:boolean]).to be_nil
      expect(logged_primary.count(:get)).to eq(1)
      expect(logged_secondary.count(:get)).to eq(0)
    end

    it 'records a degradation event with the operation and fallback' do
      instrumenter = Flipper::Instrumenters::Memory.new
      adapter = described_class.new(primary, secondary, options.merge(instrumenter: instrumenter))
      primary_unavailable!

      adapter.get(Flipper::Feature.new(:checkout_payments, adapter))
      adapter.get(Flipper::Feature.new(:search, adapter))
      adapter.get_all

      events = instrumenter.events_by_name("failover_degraded.flipper")
      expect(events.size).to eq(3)

      critical_event, ordinary_event, all_event = events
      expect(critical_event.payload[:operation]).to eq(:get)
      expect(critical_event.payload[:fallback]).to eq(:critical_safe_value)
      expect(critical_event.payload[:critical_feature_keys]).to eq(["checkout_payments"])
      expect(critical_event.payload[:error_class]).to eq("Redis::ConnectionError")

      expect(ordinary_event.payload[:operation]).to eq(:get)
      expect(ordinary_event.payload[:fallback]).to eq(:secondary_snapshot)
      expect(ordinary_event.payload[:critical_feature_keys]).to eq([])

      expect(all_event.payload[:operation]).to eq(:get_all)
      expect(all_event.payload[:critical_feature_keys]).to match_array(["checkout_payments", "refunds"])
    end

    it 'reports the primary sync version once it is readable again' do
      primary_unavailable!
      expect(subject.sync_version).to eq(secondary.sync_version)

      recovered = Flipper::SyncVersion.new("scope", 12)
      primary.sync_version = recovered
      allow(primary).to receive(:sync_version).and_call_original

      expect(subject.sync_version).to eq(recovered)
    end
  end

  describe 'critical feature configuration' do
    it 'defaults critical features to none' do
      expect(subject.critical_features).to eq(Set.new)
    end

    it 'accepts symbols and strings for critical features' do
      adapter = described_class.new(primary, secondary, critical_features: ["checkout_payments", :refunds])
      expect(adapter.critical_features).to eq(Set["checkout_payments", "refunds"])
    end

    it 'raises when safe values name a feature that is not critical' do
      expect {
        described_class.new(primary, secondary, safe_values: {refunds: {boolean: false}})
      }.to raise_error(ArgumentError, /refunds/)
    end

    it 'raises for unknown gates in a safe value' do
      expect {
        described_class.new(primary, secondary, critical_features: [:refunds], safe_value: {boolean_enabled: false})
      }.to raise_error(ArgumentError, /boolean_enabled/)
    end

    it 'normalizes expression safe values to their hash form' do
      expression = Flipper.property(:plan).eq("basic")
      adapter = described_class.new(primary, secondary, critical_features: [:refunds], safe_value: {expression: expression})

      allow(primary).to receive(:get).and_raise(Redis::ConnectionError)
      expect(adapter.get(Flipper::Feature.new(:refunds, adapter))[:expression]).to eq(expression.value)
    end

    it 'returns a copy of the safe value so callers cannot mutate the configuration' do
      adapter = described_class.new(primary, secondary, critical_features: [:refunds], safe_value: {actors: Set["1"]})
      allow(primary).to receive(:get).and_raise(Redis::ConnectionError)

      adapter.get(Flipper::Feature.new(:refunds, adapter))[:actors] << "2"

      expect(adapter.get(Flipper::Feature.new(:refunds, adapter))[:actors]).to eq(Set["1"])
    end
  end
end
