# frozen_string_literal: true

describe Grape::ServeStream::JsonlBody do
  let(:rows) do
    [
      { id: 1, name: 'Ada', secret: 'alpha' },
      { id: 2, name: 'Grace', secret: 'beta' },
      { id: 3, name: 'Linus', secret: 'gamma' }
    ]
  end

  def fields_representation(**options)
    Grape::ServeStream::Representation.new(**options)
  end

  let(:representation) { fields_representation(fields: %i[id name]) }

  # Reads the body the way Rack does, keeping every chunk.
  def read(body)
    chunks = []
    body.each { |chunk| chunks << chunk }
    chunks
  end

  describe 'a complete response' do
    subject(:body) { described_class.new(rows, representation:) }

    it 'renders each record through the frozen field set' do
      expect(read(body)).to eq([%({"id":1,"name":"Ada"}\n), %({"id":2,"name":"Grace"}\n), %({"id":3,"name":"Linus"}\n)])
    end

    it 'accounts for every delivered line' do
      read(body)

      expect(body.ledger.delivered).to eq(3)
      expect(body.ledger.terminal).to eq(:complete)
      expect(body.ledger.reason).to be_nil
      expect(body.ledger.entries.map(&:index)).to eq([0, 1, 2])
      expect(body.ledger.entries.map(&:checkpoint)).to eq([1, 2, 3])
    end

    it 'reads its source once' do
      read(body)
      read(body)

      expect(body.ledger.source_reads).to eq(1)
      expect(body.ledger.delivered).to eq(3)
    end
  end

  describe 'the disclosure is frozen at setup' do
    it 'serves unchanged records when no representation is named' do
      body = described_class.new([{ id: 1, secret: 'a' }], representation: Grape::ServeStream::Representation.new)

      expect(read(body)).to eq([%({"id":1,"secret":"a"}\n)])
    end

    it 'locks the first record\'s fields with fields: :first' do
      body = described_class.new(rows, representation: fields_representation(fields: :first))

      expect(read(body)).to eq([%({"id":1,"name":"Ada","secret":"alpha"}\n), %({"id":2,"name":"Grace","secret":"beta"}\n), %({"id":3,"name":"Linus","secret":"gamma"}\n)])
      expect(body.ledger.representation[:fields]).to eq(%i[id name secret])
    end

    it 'keeps the locked field set when a later record carries another field' do
      records = [{ id: 1, name: 'Ada' }, { id: 2, name: 'Grace', extra: 'hidden' }]
      body = described_class.new(records, representation: fields_representation(fields: :first))

      expect(read(body)).to eq([%({"id":1,"name":"Ada"}\n), %({"id":2,"name":"Grace"}\n)])
    end

    it 'records the representation revision on every entry' do
      body = described_class.new(rows, representation: fields_representation(fields: %i[id], version: 'v7'))

      read(body)

      expect(body.ledger.version).to eq('v7')
      expect(body.ledger.entries.map(&:version).uniq).to eq(['v7'])
    end
  end

  describe 'a policy change mid-stream' do
    let(:policy) { Struct.new(:version, :allow) { def permitted?(_record) = allow }.new('v1', true) }

    subject(:body) do
      described_class.new(rows, representation: fields_representation(fields: %i[id]), policy_source: -> { policy })
    end

    it 'sends the line approved before the change and stops at the next' do
      sent = []
      expect do
        body.each do |chunk|
          sent << chunk
          policy.version = 'v2' if sent.size == 1
        end
      end.to raise_error(Grape::ServeStream::StreamAborted) { |error| expect(error.reason).to eq(:policy_changed) }

      expect(sent).to eq([%({"id":1}\n)])
      expect(body.ledger.terminal).to eq(:aborted)
      expect(body.ledger.delivered).to eq(1)
      expect(body.ledger.aborted_at).to eq(1)
      expect(body.ledger.live_policy_version).to eq('v2')
      expect(body.ledger).to be_policy_changed
    end

    it 'aborts before the first line when the change lands before the body is read' do
      body
      policy.version = 'v2'

      expect { read(body) }.to raise_error(Grape::ServeStream::StreamAborted) do |error|
        expect(error.index).to eq(0)
        expect(error.to_h).to include(delivered: 0, terminal: :aborted, reason: :policy_changed)
      end
    end
  end

  describe 'a policy that denies a record' do
    it 'never renders the denied record' do
      policy = Struct.new(:version, :allow) { def permitted?(_record) = allow }.new('v1', false)
      body = described_class.new(rows, representation: fields_representation(fields: %i[id]), policy:)

      expect { read(body) }.to raise_error(Grape::ServeStream::StreamAborted) { |error| expect(error.reason).to eq(:denied) }
      expect(body.ledger.delivered).to eq(0)
      expect(body.ledger.terminal).to eq(:aborted)
    end
  end

  describe 'a record that fails to render' do
    let(:bad_record) { Object.new }

    before do
      bad_record.define_singleton_method(:to_h) { raise 'cannot project' }
    end

    it 'stops at that record and records where the failure came from' do
      body = described_class.new([rows[0], rows[1], bad_record, rows[2]], representation: fields_representation(fields: %i[id]))

      sent = []
      expect { body.each { |chunk| sent << chunk } }
        .to raise_error(Grape::ServeStream::StreamAborted) { |error| expect(error.reason).to eq(:format_error) }

      expect(sent.size).to eq(2)
      expect(body.ledger.terminal).to eq(:failed)
      expect(body.ledger.delivered).to eq(2)
      expect(body.ledger.aborted_at).to eq(2)
      expect(body.ledger.failure).to include(index: 2, message: 'cannot project')
      expect(body.ledger.failure[:location]).to be_a(String)
    end
  end

  describe 'a source that raises' do
    it 'keeps the source exception and marks the failure as a source error' do
      records = Enumerator.new do |yielder|
        yielder << { id: 1 }
        yielder << { id: 2 }
        raise 'source went away'
      end
      body = described_class.new(records, representation: fields_representation(fields: %i[id]))

      expect { read(body) }.to raise_error(RuntimeError, 'source went away')

      expect(body.ledger.terminal).to eq(:failed)
      expect(body.ledger.reason).to eq(:source_error)
      expect(body.ledger.delivered).to eq(2)
      expect(body.ledger.failure).to include(index: 2, message: 'source went away')
    end
  end

  describe 'closing' do
    it 'records a consumer close after a complete read without changing the status' do
      body = described_class.new(rows, representation:)
      read(body)
      body.close

      expect(body).to be_closed
      expect(body.ledger.terminal).to eq(:complete)
      expect(body.ledger.closed_by).to eq(:consumer)
    end

    it 'records a body closed before it was read' do
      body = described_class.new(rows, representation:)
      body.close

      expect(body.ledger.terminal).to eq(:closed_unread)
      expect(body.ledger.delivered).to eq(0)
      expect(body.ledger.source_reads).to eq(0)
    end

    it 'records a consumer that stopped after the first line' do
      body = described_class.new(rows, representation:)
      body.each { |chunk| break if chunk }

      expect(body.ledger.terminal).to eq(:aborted)
      expect(body.ledger.reason).to eq(:consumer_closed)
      expect(body.ledger.delivered).to eq(1)
      expect(body.ledger).to be_truncated
    end

    it 'records a consumer that raised while writing' do
      body = described_class.new(rows, representation:)

      expect { body.each { raise IOError, 'client gone' } }.to raise_error(IOError)
      expect(body.ledger.terminal).to eq(:aborted)
      expect(body.ledger.reason).to eq(:consumer_error)
      expect(body.ledger.delivered).to eq(1)
      expect(body.ledger.failure).to be_nil
    end

    it 'closes its source, once' do
      source = Class.new do
        attr_reader :closes

        def initialize(records)
          @records = records
          @closes = 0
        end

        def each(&block)
          @records.each(&block)
        end

        def close
          @closes += 1
        end
      end.new(rows)
      body = described_class.new(source, representation:, source:)
      read(body)
      body.close

      expect(source.closes).to eq(1)
      expect(body.ledger.source_closed_by).to eq(:stream)
    end
  end

  describe 'the request env' do
    it 'publishes the ledger under the documented key' do
      env = Rack::MockRequest.env_for('/')
      body = described_class.new(rows, representation:, env:)
      read(body)

      expect(env[Grape::Env::JSONL_LEDGER]).to be(body.ledger)
      expect(Grape::ServeStream::Ledger.from(env)).to be(body.ledger)
    end
  end

  describe 'the terminal notification' do
    it 'announces the settled ledger once' do
      notifications = []
      subscriber = ActiveSupport::Notifications.subscribe(Grape::ServeStream::Ledger::NOTIFICATION) do |*args|
        notifications << args.last[:ledger]
      end
      body = described_class.new(rows, representation:)
      read(body)
      body.close

      expect(notifications.size).to eq(1)
      expect(notifications.first).to include(terminal: :complete, delivered: 3)
    ensure
      ActiveSupport::Notifications.unsubscribe(subscriber) if subscriber
    end
  end
end
