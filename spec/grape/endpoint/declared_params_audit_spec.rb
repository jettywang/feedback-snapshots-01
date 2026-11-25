# frozen_string_literal: true

# A default provider whose number of invocations the examples can observe. The
# params block is instance_eval'd, so it has to reach a constant rather than a
# let or an instance variable, and the default must be a Proc for Grape to call
# it (a plain object is stored as a static value).
class AuditDefaultCounter
  attr_reader :calls, :provider

  def initialize
    @calls = 0
    @provider = -> { @calls += 1; "default-#{@calls}" }
  end

  def reset!
    @calls = 0
  end
end

AUDIT_DEFAULT_COUNTER = AuditDefaultCounter.new

describe 'declared_params.grape audit event' do
  subject(:api) { Class.new(Grape::API) }

  let(:app) { api }
  let(:events) { [] }

  let(:subscriber) do
    ActiveSupport::Notifications.subscribe('declared_params.grape') do |*args|
      events << ActiveSupport::Notifications::Event.new(*args)
    end
  end

  before do
    AUDIT_DEFAULT_COUNTER.reset!
    subscriber

    api.format :json
    api.version %w[v1 v2], using: :path

    api.params do
      # Renamed for the external view while the handler keeps the request name.
      requires :client_name, type: String, as: :name
      # A per-call computed default.
      optional :token, type: String, default: AUDIT_DEFAULT_COUNTER.provider
      # Distinguishes an explicit nil from a key that was never sent.
      optional :note, type: String
      optional :profile, type: Hash do
        optional :city, type: String
        optional :ssn, type: String, as: :tax_id
      end
      optional :items, type: Array do
        optional :sku, type: String, as: :product_code
        optional :quantity, type: Integer
      end
    end

    api.post '/orders' do
      {
        handler_params: params,
        handler_declared: declared(params),
        default_calls: AUDIT_DEFAULT_COUNTER.calls
      }
    end
  end

  after do
    ActiveSupport::Notifications.unsubscribe(subscriber) if subscriber
  end

  def audit
    expect(events.size).to eq(1)
    events.last.payload[:audit]
  end

  def post_order(version, body)
    AUDIT_DEFAULT_COUNTER.reset!
    post "/#{version}/orders", body, 'HTTP_ACCEPT' => 'application/json'
    expect(last_response.status).to eq(201)
    JSON.parse(last_response.body)
  end

  describe 'the emitted view' do
    context 'when optional and defaulted fields are missing' do
      let(:response_body) { post_order('v1', client_name: 'Acme') }

      before { response_body }

      it 'filters to declared fields and applies the rename and the default' do
        expect(audit.view).to eq(
          'name' => 'Acme',
          'token' => 'default-1',
          'note' => nil,
          'profile' => { 'city' => nil, 'tax_id' => nil },
          'items' => []
        )
      end

      it 'matches the transformed value the handler receives through declared()' do
        expect(audit.view).to eq(response_body['handler_declared'])
      end

      it 'keeps approved adjacent fields once an undeclared nested field is dropped' do
        expect(audit.view['profile'].keys).to contain_exactly('city', 'tax_id')
      end

      it 'records the provenance and identity of every leaf' do
        provenance = audit.provenance
        expect(provenance['name'].source).to eq(:provided)
        expect(provenance['name'].input_key).to eq('client_name')
        expect(provenance['name'].output_key).to eq('name')

        expect(provenance['token'].source).to eq(:default)
        expect(provenance['token'].value).to eq('default-1')

        expect(provenance['note'].source).to eq(:missing)
        expect(provenance['note'].value).to be_nil

        expect(provenance['profile[city]'].source).to eq(:missing)
        expect(provenance['profile[tax_id]'].source).to eq(:missing)
        expect(provenance['profile[tax_id]'].input_key).to eq('profile[ssn]')
      end

      it 'invokes the default provider exactly once' do
        expect(response_body['default_calls']).to eq(1)
        expect(AUDIT_DEFAULT_COUNTER.calls).to eq(1)
      end
    end

    context 'when every field is provided, including an explicit nil' do
      let(:response_body) do
        post_order(
          'v1',
          client_name: 'Acme',
          token: 'sent-token',
          note: nil,
          profile: { city: 'Berlin', ssn: '111', hacker_field: 'drop-me' },
          items: [{ sku: 'SKU-1', quantity: 3, junk: 'drop-me' }]
        )
      end

      before { response_body }

      it 'keeps the provided values and drops undeclared nested fields' do
        expect(audit.view).to eq(
          'name' => 'Acme',
          'token' => 'sent-token',
          'note' => nil,
          'profile' => { 'city' => 'Berlin', 'tax_id' => '111' },
          'items' => [{ 'product_code' => 'SKU-1', 'quantity' => 3 }]
        )
      end

      it 'matches the transformed value the handler receives through declared()' do
        expect(audit.view).to eq(response_body['handler_declared'])
      end

      it 'marks an explicit nil as provided rather than missing or defaulted' do
        expect(audit.provenance['note'].source).to eq(:provided)
        expect(audit.provenance['note'].value).to be_nil
      end

      it 'marks provided nested and array leaves and preserves their identities' do
        provenance = audit.provenance
        expect(provenance['profile[tax_id]'].source).to eq(:provided)
        expect(provenance['profile[tax_id]'].input_key).to eq('profile[ssn]')
        expect(provenance['items[0][product_code]'].source).to eq(:provided)
        expect(provenance['items[0][product_code]'].input_key).to eq('items[0][sku]')
        expect(provenance['items[0][quantity]'].source).to eq(:provided)
      end

      it 'never invokes the default provider' do
        expect(response_body['default_calls']).to eq(0)
        expect(AUDIT_DEFAULT_COUNTER.calls).to eq(0)
      end
    end
  end

  describe 'read-only guarantees' do
    let(:response_body) { post_order('v2', client_name: 'Acme') }

    before { response_body }

    it 'does not change the params the handler reads' do
      expect(response_body['handler_params']).to eq(
        'client_name' => 'Acme',
        'token' => 'default-1'
      )
    end

    it 'does not re-run the default provider when the audit is published' do
      calls_at_handler = response_body['default_calls']
      audit
      expect(AUDIT_DEFAULT_COUNTER.calls).to eq(calls_at_handler)
    end

    it 'exposes the pre-validation request snapshot under the names the client used' do
      expect(audit.as_sent.to_hash).to eq('client_name' => 'Acme')
    end
  end

  describe 'across the two registered versions' do
    it 'publishes one audit event per request on each version with the same field identity' do
      post_order('v1', client_name: 'One')
      v1 = audit.provenance['name']
      expect(events.size).to eq(1)

      events.clear
      post_order('v2', client_name: 'Two')
      v2 = audit.provenance['name']

      expect(v1.input_key).to eq('client_name')
      expect(v1.output_key).to eq('name')
      expect(v2.input_key).to eq('client_name')
      expect(v2.output_key).to eq('name')
    end

    it 'treats a defaulted field independently per call' do
      post_order('v1', client_name: 'One')
      expect(audit.provenance['token'].source).to eq(:default)

      events.clear
      post_order('v2', client_name: 'Two', token: 'explicit')
      expect(audit.provenance['token'].source).to eq(:provided)
    end
  end

  describe 'without a subscriber' do
    let(:subscriber) { nil }

    it 'still serves the request and applies defaults normally' do
      post '/v1/orders', { client_name: 'Acme' }, 'HTTP_ACCEPT' => 'application/json'
      expect(last_response.status).to eq(201)
      expect(JSON.parse(last_response.body)['handler_declared']['token']).to eq('default-1')
      expect(events).to be_empty
    end
  end

  describe 'coercion and empty containers' do
    subject(:typed_api) { Class.new(Grape::API) }

    let(:app) { typed_api }

    before do
      typed_api.format :json
      typed_api.version 'v1', using: :path
      typed_api.params do
        optional :count, type: Integer
        optional :flags, type: Array[String]
        optional :profile, type: Hash do
          optional :city, type: String
        end
      end
      typed_api.post('/things') { { declared: declared(params) } }
    end

    it 'records the coerced effective value while the snapshot keeps the raw input' do
      post '/v1/things', { count: '42', flags: %w[x y] }, 'HTTP_ACCEPT' => 'application/json'

      expect(audit.view['count']).to eq(42)
      expect(audit.provenance['count'].source).to eq(:provided)
      expect(audit.as_sent['count']).to eq('42')
      expect(audit.view['flags']).to eq(%w[x y])
      expect(audit.provenance['flags'].source).to eq(:provided)
    end

    it 'answers omitted containers with their empty values and marks them missing' do
      post '/v1/things', {}, 'HTTP_ACCEPT' => 'application/json'

      expect(audit.view).to eq(
        'count' => nil,
        'flags' => [],
        'profile' => { 'city' => nil }
      )
      expect(audit.view).to eq(JSON.parse(last_response.body)['declared'])
      expect(audit.provenance['count'].source).to eq(:missing)
      expect(audit.provenance['flags'].source).to eq(:missing)
      expect(audit.provenance['flags'].value).to eq([])
      expect(audit.provenance['profile[city]'].source).to eq(:missing)
    end
  end
end
