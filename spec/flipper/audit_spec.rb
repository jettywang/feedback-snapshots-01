require 'flipper'
require 'flipper/audit'
require 'flipper/instrumenters/memory'

RSpec.describe Flipper::Audit do
  let(:adapter) { Flipper::Adapters::Memory.new }
  let(:instrumenter) { Flipper::Instrumenters::Memory.new }
  let(:audit) { described_class.new(adapter, instrumenter: instrumenter) }
  let(:flipper) { Flipper.new(audit, memoize: false) }

  def with_operator(id, &block)
    described_class.with_operator(id, &block)
  end

  it_should_behave_like 'a flipper adapter' do
    subject { described_class.new(Flipper::Adapters::Memory.new) }
  end

  it_should_behave_like 'an adapter that stores its sync version' do
    subject { described_class.new(Flipper::Adapters::Memory.new) }
  end

  describe 'opening, repeating, overriding, and failing an import' do
    it 'reconciles applied, repeated, overridden, and failed writes on one adapter' do
      # Open a gate.
      with_operator('ops-100') { flipper.enable_percentage_of_actors(:search, 10) }
      # Repeat the same open, which is a successful call but not a change.
      with_operator('ops-100') { flipper.enable_percentage_of_actors(:search, 10) }
      # Override the existing gate by fully enabling the feature.
      with_operator('ops-200') { flipper.enable(:search) }
      # A broken import changes nothing and is still recorded.
      expect {
        with_operator('ops-300') { flipper.import(broken_export) }
      }.to raise_error(Flipper::Exporters::Json::JsonError)

      opens = audit.events_for(:search).select { |event| event.operation == :enable }
      expect(opens.map(&:operator_id)).to eq(%w[ops-100 ops-100 ops-200])
      expect(opens.map(&:outcome)).to eq(%i[applied unchanged applied])
      expect(opens.last.changes.map(&:to_h)).to eq([
        { gate_name: :boolean, from: nil, to: true },
        { gate_name: :percentage_of_actors, from: 10, to: nil },
      ])

      failed_import = audit.events.last
      expect(failed_import).to have_attributes(operation: :import, outcome: :failed, reason: :error)
      expect(failed_import.operator_id).to eq('ops-300')
      expect(failed_import.feature_changes).to be_empty
      expect(audit.events_for(:search).last).to equal(opens.last)

      expect(flipper[:search].state).to eq(:on)
      expect(flipper[:search].boolean_value).to eq(true)
      expect(flipper[:search].percentage_of_actors_value).to eq(0)
      expect(audit).to be_reconciled
      expect(audit.applied_events.map(&:operation)).to include(:enable)
      expect(audit.ineffective_events.map(&:reason)).to include(:unchanged, :error)
      expect(audit.failed_events.size).to eq(1)
      expect(audit.summary).to include(applied: 3, unchanged: 3, failed: 1)
    end
  end

  describe '.with_operator' do
    it 'records only the public id' do
      operator = Struct.new(:flipper_id, :name, :email).new('user-42', 'Ada Lovelace', 'ada@example.com')

      with_operator(operator) { flipper.enable(:search) }

      event = audit.last_event
      expect(event.operator_id).to eq('user-42')
      expect(event.to_h.values.flatten.grep(/Ada|ada@example/)).to be_empty
    end

    it 'accepts a hash with a public id' do
      with_operator(operator_id: 'support-7') { flipper.enable(:search) }
      expect(audit.last_event.operator_id).to eq('support-7')
    end

    it 'restores the previous operator even when the block raises' do
      described_class.operator_id = 'outer'
      expect {
        with_operator('inner') { raise 'boom' }
      }.to raise_error('boom')
      expect(described_class.operator_id).to eq('outer')
    ensure
      described_class.operator_id = nil
    end

    it 'does not record arbitrary objects' do
      with_operator(Object.new) { flipper.enable(:search) }
      expect(audit.last_event.operator_id).to be_nil
    end

    it 'keeps operator ids separate per thread' do
      threads = 5.times.map do |index|
        Thread.new do
          with_operator("thread-#{index}") { flipper.enable(:"flag_#{index}") }
        end
      end
      threads.each(&:join)

      by_feature = audit.events.select { |event| event.operation == :enable }
        .each_with_object({}) { |event, result| result[event.feature_name] = event.operator_id }

      expect(by_feature).to eq(
        'flag_0' => 'thread-0',
        'flag_1' => 'thread-1',
        'flag_2' => 'thread-2',
        'flag_3' => 'thread-3',
        'flag_4' => 'thread-4'
      )
    end
  end

  describe '#enable and #disable' do
    it 'records the effective gate change' do
      with_operator('ops-1') { flipper.enable(:search) }

      event = audit.last_event
      expect(event).to have_attributes(
        operation: :enable,
        feature_name: 'search',
        gate_name: :boolean,
        value: true,
        effective?: true,
        applied?: true,
        outcome: :applied,
        reason: nil
      )
      expect(event.changes.map(&:to_h)).to eq([{ gate_name: :boolean, from: nil, to: true }])
      expect(event.intent).to eq(:enable)
    end

    it 'records a repeat enable as unchanged instead of a new change' do
      with_operator('ops-1') { flipper.enable(:search) }
      with_operator('ops-1') { flipper.enable(:search) }

      event = audit.last_event
      expect(event).to have_attributes(effective?: false, applied?: false, reason: :unchanged, outcome: :unchanged)
      expect(event.changes).to be_empty
      expect(audit.applied_events.size).to eq(2) # one add and one enable
    end

    it 'records the gate override and the gates the adapter cleared' do
      with_operator('ops-1') { flipper.enable_actor(:search, Flipper::Actor.new('User;1')) }
      with_operator('ops-2') { flipper.enable(:search) }

      event = audit.last_event
      expect(event.changes.map(&:to_h)).to eq([
        { gate_name: :boolean, from: nil, to: true },
        { gate_name: :actors, from: Set['User;1'], to: Set.new },
      ])
      expect(flipper[:search].actors_value).to eq(Set.new)
      expect(audit).to be_reconciled
    end
  end

  describe '#import' do
    it 'records the imported feature changes' do
      source = Flipper::Adapters::Memory.new
      source_flipper = Flipper.new(source, memoize: false)
      source_flipper.enable_actor(:search, Flipper::Actor.new('User;1'))
      source_flipper.enable_percentage_of_time(:logging, 10)

      with_operator('ops-import') { flipper.import(source) }

      event = audit.last_event
      expect(event).to have_attributes(operation: :import, effective?: true, outcome: :applied)
      expect(event.operator_id).to eq('ops-import')
      expect(event.feature_changes.map(&:feature_name)).to eq(%w[logging search])
      expect(event.before.keys).to match_array(%w[logging search])
      expect(flipper[:search].actors_value).to eq(Set['User;1'])
      expect(audit).to be_reconciled
    end

    it 'records a stale import as unchanged with a reason' do
      adapter.sync_version = Flipper::SyncVersion.new('scope', 10)
      source = Flipper::Adapters::Memory.new
      Flipper.new(source, memoize: false).enable(:search)
      source.sync_version = Flipper::SyncVersion.new('scope', 8)

      flipper.import(source)

      event = audit.last_event
      expect(event).to have_attributes(effective?: false, reason: :stale, outcome: :unchanged)
      expect(flipper[:search].boolean_value).to eq(false)
    end

    it 'records a failed import without changing state' do
      with_operator('ops-bad') { flipper.enable(:search) }
      before = adapter.get_all

      expect {
        with_operator('ops-bad') { flipper.import(broken_export) }
      }.to raise_error(Flipper::Exporters::Json::JsonError)

      event = audit.last_event
      expect(event).to have_attributes(operation: :import, effective?: false, failed?: true, reason: :error)
      expect(event.error_class).to eq('Flipper::Exporters::Json::JsonError')
      expect(adapter.get_all).to eq(before)
      expect(audit).to be_reconciled
    end

    it 'records an adapter import failure' do
      subject = described_class.new(Flipper::Adapters::Memory.new)
      allow(subject.adapter).to receive(:import).and_raise(IOError, 'disk gone')

      expect {
        Flipper.new(subject, memoize: false).import(Flipper::Adapters::Memory.new)
      }.to raise_error(IOError)

      event = subject.last_event
      expect(event).to have_attributes(operation: :import, failed?: true, reason: :error)
      expect(event.error_class).to eq('IOError')
    end
  end

  describe 'unsupported imports' do
    it 'records an adapter that refuses to import as unsupported' do
      adapter = Flipper::Adapters::Memory.new
      def adapter.import(_source)
        false
      end
      audit = described_class.new(adapter)
      flipper = Flipper.new(audit, memoize: false)

      flipper.import(Flipper::Adapters::Memory.new)

      expect(audit.last_event).to have_attributes(
        operation: :import,
        outcome: :unchanged,
        reason: :unsupported,
        unsupported?: true
      )
    end
  end

  describe 'failure reasons' do
    it 'records read only writes' do
      read_only = Flipper::Adapters::ReadOnly.new(Flipper::Adapters::Memory.new)
      audit = described_class.new(read_only)

      expect {
        Flipper.new(audit, memoize: false)[:search].enable
      }.to raise_error(Flipper::Adapters::ReadOnly::WriteAttempted)

      expect(audit.last_event).to have_attributes(operation: :add, failed?: true, reason: :read_only)
      expect(audit.last_event.operator_id).to be_nil
    end

    it 'records actor limit failures' do
      limited = Flipper::Adapters::ActorLimit.new(Flipper::Adapters::Memory.new, 1)
      audit = described_class.new(limited)
      flipper = Flipper.new(audit, memoize: false)

      flipper[:search].enable_actor(Flipper::Actor.new('User;1'))
      expect {
        flipper[:search].enable_actor(Flipper::Actor.new('User;2'))
      }.to raise_error(Flipper::Adapters::ActorLimit::LimitExceeded)

      expect(audit.last_event).to have_attributes(operation: :enable, failed?: true, reason: :limit_exceeded)
      expect(flipper[:search].actors_value).to eq(Set['User;1'])
    end
  end

  describe 'partial writes' do
    it 'records a write that raised after changing state' do
      partial_adapter = Class.new(Flipper::Adapters::Memory) do
        def enable(feature, gate, thing)
          super
          raise IOError, 'after write'
        end
      end.new
      audit = described_class.new(partial_adapter)
      flipper = Flipper.new(audit, memoize: false)

      expect { flipper.enable(:search) }.to raise_error(IOError, 'after write')

      event = audit.last_event
      expect(event).to have_attributes(operation: :enable, failed?: true, effective?: true, partial?: true)
      expect(event.changes.map(&:to_h)).to eq([{ gate_name: :boolean, from: nil, to: true }])
    end
  end

  describe '#reconcile' do
    it 'reports drift between the audited state and the adapter' do
      flipper.enable(:search)
      Flipper.new(adapter, memoize: false).disable(:search)

      reconciliation = audit.reconcile
      expect(reconciliation).not_to be_ok
      mismatch = reconciliation.first
      expect(mismatch.feature_name).to eq('search')
      expect(mismatch.changes.map(&:to_h)).to eq([{ gate_name: :boolean, from: true, to: nil }])
    end

    it 'notices removed features' do
      flipper[:search].add
      Flipper.new(adapter, memoize: false)[:search].remove

      mismatch = audit.reconcile.first
      expect(mismatch.expected[:exists]).to be(true)
      expect(mismatch.actual[:exists]).to be(false)
    end
  end

  describe '#clear' do
    it 'records the gates that were cleared' do
      flipper.enable(:search)
      flipper[:search].clear

      expect(audit.last_event).to have_attributes(operation: :clear, effective?: true, outcome: :applied)
      expect(audit.last_event.changes.map(&:to_h)).to eq([{ gate_name: :boolean, from: true, to: nil }])
    end

    it 'records clearing an already clear feature as unchanged' do
      flipper[:search].add
      flipper[:search].clear

      expect(audit.last_event).to have_attributes(operation: :clear, effective?: false, reason: :unchanged)
    end
  end

  describe 'instrumentation' do
    it 'emits an audit event with the public summary' do
      with_operator('ops-1') { flipper.enable(:search) }

      events = instrumenter.events_by_name('audit.flipper')
      expect(events.size).to eq(2)
      payload = events.last.payload
      expect(payload[:operation]).to eq(:enable)
      expect(payload[:feature_name]).to eq('search')
      expect(payload[:operator_id]).to eq('ops-1')
      expect(payload[:outcome]).to eq(:applied)
      expect(payload[:changes]).to eq([{ gate_name: :boolean, from: nil, to: true }])
    end
  end

  def broken_export
    Flipper::Exporters::Json::Export.new(contents: '{not json')
  end
end
