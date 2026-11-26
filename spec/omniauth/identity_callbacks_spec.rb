require 'helper'

describe OmniAuth::IdentityCallbacks do
  subject(:registry) { described_class::Registry.new }

  after { registry.clear }

  it 'requires a callable callback' do
    expect { registry.register(:missing, 'not callable') }
      .to raise_error(ArgumentError, /must be callable/)
  end

  it 'registers callable objects and exposes registry helpers' do
    callback = Class.new do
      def call(view, env)
        env['seen'] = view
      end
    end.new

    registry.register(:plugin, callback, :allowed => ['uid'])

    expect(registry[:plugin].handler).to equal(callback)
    expect(registry.key?('plugin')).to be(true)
    expect(registry.names).to eq([:plugin])
    expect(registry.empty?).to be(false)
  end

  it 'adapts zero, one, optional-one, and two argument handlers' do
    seen = []
    env = {'omniauth.auth' => {'uid' => 'u'}}

    registry.register(:zero, proc { seen << :zero })
    registry.register(:one, ->(view) { seen << view.class })
    registry.register(:optional, ->(view = nil) { seen << view.correlation_id })
    registry.register(:two, ->(view, callback_env) { seen << [view.uid, callback_env.equal?(env)] })

    registry.dispatch(env, :correlation_id => 'corr-args')

    expect(seen[0]).to eq(:zero)
    expect(seen[1]).to eq(OmniAuth::AuthHash)
    expect(seen[2]).to eq('corr-args')
    expect(seen[3]).to eq([nil, true])
  end

  it 'uses a callable object Method arity and passes view plus env' do
    callback = Class.new do
      attr_reader :seen

      def initialize
        @seen = nil
      end

      def call(view, env)
        @seen = [view, env]
      end
    end.new

    env = {'omniauth.auth' => {'uid' => 'u'}}
    registry.register(:object, callback)
    registry.dispatch(env, :correlation_id => 'corr-object')

    expect(callback.seen.first.correlation_id).to eq('corr-object')
    expect(callback.seen.last).to equal(env)
  end

  it 'logs outside a strategy and continues after a failure handler raises' do
    allow(OmniAuth.logger).to receive(:error)
    failure_handler = proc { raise('failure handler broken') }
    registry.register(:broken, :on_failure => failure_handler) { raise('plugin broken') }

    receipts = registry.dispatch({}, :correlation_id => 'corr-failure')

    expect(receipts.first).to be_failed
    expect(OmniAuth.logger).to have_received(:error).twice
  end

  it 'stores receipt collections in the Rack environment' do
    registry.register(:ok) { |_view| 'done' }
    env = {}

    receipts = registry.dispatch(env, :correlation_id => 'corr-env')

    expect(receipts.first.returned_value).to eq('done')
    expect(env['omniauth.identity_receipts']).to eq(receipts)
    expect(env['omniauth.callback_receipts']).to eq(receipts)
    expect(env['omniauth.identity_failures']).to eq([])
    expect(env['omniauth.failure_materials']).to eq([])
    expect(env['omniauth.failure_material']).to be_nil
  end
end

describe OmniAuth::IdentityReceipt do
  let(:view) { OmniAuth::AuthView.project({'uid' => 'u'}, :fields => ['uid'], :correlation_id => 'c') }

  it 'exposes aliases and a string-keyed safe material object' do
    error = RuntimeError.new('boom')
    receipt = described_class.new(
      :name => :plugin,
      :correlation_id => 'c',
      :view => view,
      :error => error
    )

    expect(receipt.callback_name).to eq(:plugin)
    expect(receipt.callback).to eq(:plugin)
    expect(receipt).to be_error
    expect(receipt.error_class).to eq('RuntimeError')
    expect(receipt.public_message).to eq('boom')
    expect(receipt.material).to be_a(OmniAuth::AuthHash)
    expect(receipt.failure_material['error_message']).to eq('boom')
    expect(receipt.to_h['auth']['uid']).to eq('u')
  end

  it 'omits error fields for successful receipts' do
    receipt = described_class.new(
      :name => :plugin,
      :correlation_id => 'c',
      :view => view,
      :returned_value => 'ok'
    )

    expect(receipt.status).to eq(:success)
    expect(receipt).not_to be_failed
    expect(receipt.error_class).to be_nil
    expect(receipt.to_h).not_to have_key('error_class')
    expect(receipt.to_h).not_to have_key('error_message')
  end
end

describe OmniAuth::IdentityRedactor do
  it 'scrubs private values from arrays and leaves nil messages alone' do
    redactor = described_class.new(
      {'token' => 'public-token', 'nested' => ['array-secret']},
      OmniAuth::AuthHash.new('token' => 'public-token')
    )

    expect(redactor.scrub(nil)).to be_nil
    expect(redactor.scrub('array-secret leaked')).to eq('[FILTERED] leaked')
    expect(redactor.scrub('public-token allowed')).to eq('public-token allowed')
  end

  it 'does not replace short private values' do
    redactor = described_class.new({'code' => 'ab'}, {})

    expect(redactor.scrub('ab')).to eq('ab')
  end
end
