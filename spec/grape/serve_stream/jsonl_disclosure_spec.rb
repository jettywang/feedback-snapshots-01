# frozen_string_literal: true

describe Grape::API do
  describe 'JSON Lines disclosure' do
    # Three rows is the whole data set. The caller reads the first line, then
    # switches the policy or breaks a row's rendering; the rest of the answer
    # has to account for itself.
    let(:rows) do
      [
        { id: 1, name: 'Ada', secret: 'alpha' },
        { id: 2, name: 'Grace', secret: 'beta' },
        { id: 3, name: 'Linus', secret: 'gamma' }
      ]
    end

    let(:source) { JsonlDisclosureSource.new(rows) }
    # Mutation boxes, so an example can change the live policy between lines as
    # a deployment or a permission change would. The route reads them afresh.
    let(:live_version) { ['v1'] }
    let(:permissions) { { allowed: ->(_record) { true } } }
    let(:env_box) { {} }

    let(:app) do
      rows_served = rows
      rows_source = source
      version = live_version
      allowed = permissions
      capture = ->(rack_env) { env_box[:rack] = rack_env }
      Class.new(Grape::API) do
        content_type :jsonl, 'application/jsonl'
        format :jsonl

        get :export do
          capture.call(env)
          jsonl(
            rows_served,
            fields: %i[id name],
            policy_source: -> { Grape::ServeStream::Policy.new(version: version.first, permitted: allowed[:allowed]) },
            source: rows_source
          )
        end
      end
    end

    let(:env) { env_box.fetch(:rack) }
    let(:ledger) { Grape::ServeStream::Ledger.from(env) }

    def call
      app.call(Rack::MockRequest.env_for('/export'))
    end

    def read(body)
      chunks = []
      error = nil
      begin
        body.each { |chunk| chunks << chunk }
      rescue Grape::ServeStream::StreamAborted => e
        error = e
      ensure
        body.close
      end
      [chunks, error]
    end

    it 'sends the approved fields of every row when the policy allows them' do
      status, headers, body = call
      chunks, error = read(body)

      expect(status).to eq(200)
      expect(headers['content-type']).to eq('application/jsonl')
      expect(chunks).to eq([%({"id":1,"name":"Ada"}\n), %({"id":2,"name":"Grace"}\n), %({"id":3,"name":"Linus"}\n)])
      expect(error).to be_nil
      expect(ledger.terminal).to eq(:complete)
      expect(ledger.delivered).to eq(3)
      expect(source.closures).to eq(1)
      expect(ledger.source_closed_by).to eq(:stream)
    end

    context 'when the policy stops allowing the rest after the first line' do
      let(:permissions) { { allowed: ->(record) { record[:id] == 1 } } }

      it 'delivers the first line only and marks the response denied' do
        _status, _headers, body = call
        chunks, error = read(body)

        expect(chunks).to eq([%({"id":1,"name":"Ada"}\n)])
        expect(error.reason).to eq(:denied)
        expect(ledger.terminal).to eq(:aborted)
        expect(ledger.reason).to eq(:denied)
        expect(ledger.delivered).to eq(1)
        expect(ledger.aborted_at).to eq(1)
        expect(ledger.last_checkpoint).to eq(1)
      end
    end

    context 'when the policy revision changes while the body streams' do
      it 'stops at the first line beyond the approved revision' do
        _status, _headers, body = call
        chunks = []
        expect do
          body.each do |chunk|
            chunks << chunk
            live_version[0] = 'v2'
          end
        end.to raise_error(Grape::ServeStream::StreamAborted) { |error| expect(error.reason).to eq(:policy_changed) }

        expect(chunks).to eq([%({"id":1,"name":"Ada"}\n)])
        expect(ledger.terminal).to eq(:aborted)
        expect(ledger.delivered).to eq(1)
        expect(ledger.live_policy_version).to eq('v2')
        expect(ledger).to be_policy_changed
      end
    end

    context 'when a row fails to render' do
      let(:broken) do
        Object.new.tap do |object|
          object.define_singleton_method(:to_h) { raise 'cannot project secret row' }
        end
      end

      it 'sends the rows before it and records a failure with its location' do
        rows[1] = broken

        _status, _headers, body = call
        chunks, error = read(body)

        expect(chunks).to eq([%({"id":1,"name":"Ada"}\n)])
        expect(error.reason).to eq(:format_error)
        expect(ledger.terminal).to eq(:failed)
        expect(ledger.delivered).to eq(1)
        expect(ledger.failure).to include(index: 1, message: 'cannot project secret row')
        expect(ledger.failure[:location]).to be_a(String)
      end
    end

    it 'keeps the ledger readable from the request env after the response' do
      _status, _headers, body = call
      read(body)

      expect(ledger.to_h).to include(terminal: :complete, delivered: 3, source_reads: 1)
      expect(ledger.representation[:fields]).to eq(%i[id name])
    end

    it 'closes the source when the body is closed unread' do
      _status, _headers, body = call
      body.close

      expect(source.closures).to eq(1)
      expect(ledger.terminal).to eq(:closed_unread)
      expect(ledger.source_reads).to eq(0)
      expect(ledger.closed_by).to eq(:consumer)
      expect(ledger.source_closed_by).to eq(:consumer)
    end

    it 'announces the settled ledger to an audit subscriber' do
      seen = []
      subscriber = ActiveSupport::Notifications.subscribe(Grape::ServeStream::Ledger::NOTIFICATION) do |*args|
        seen << args.last[:ledger]
      end
      permissions[:allowed] = ->(record) { record[:id] == 1 }

      _status, _headers, body = call
      expect { body.each { |chunk| chunk } }.to raise_error(Grape::ServeStream::StreamAborted)

      expect(seen.last).to include(terminal: :aborted, reason: :denied, delivered: 1)
    ensure
      ActiveSupport::Notifications.unsubscribe(subscriber)
    end
  end
end
