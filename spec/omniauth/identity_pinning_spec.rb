require 'helper'

describe OmniAuth::Strategy::IdentityPinning do
  let(:app) { ->(_env) { [200, {}, ['ok']] } }
  let(:contract) do
    OmniAuth::IdentityMigration::Contract.new(
      :registrations => [{'name' => 'pin', 'provider' => 'pin'}]
    )
  end

  def strategy_with(options = {})
    strategy = ExampleStrategy.new(app, {:name => 'pin'}.merge(options))
    env = Rack::MockRequest.env_for(
      'http://app.example/auth/pin/callback',
      'rack.session' => options.delete(:session) || {}
    )
    env['omniauth.auth'] = OmniAuth::AuthHash.new(:provider => 'pin', :uid => '9')
    strategy.instance_variable_set(:@env, env)
    strategy
  end

  it 'uses a provider-scoped initiation when no state-bound identity is present' do
    payload = {'registration' => 'pin', 'provider' => 'pin', 'mapping_version' => 'v1'}
    session = {'omniauth.identity_initiations' => {'pin' => payload, 'other' => {}}}
    strategy = strategy_with(:identity_contract => contract, :session => session)

    receipt = strategy.send(:apply_identity_contract!)

    expect(receipt).to be_ordinary
    expect(strategy.env['omniauth.principal'].to_s).to eq('pin:9')
    expect(session['omniauth.identity_initiations']).to eq('other' => {})
  end

  it 'ignores a malformed provider initiation store' do
    session = {'omniauth.identity_initiations' => 'junk'}
    strategy = strategy_with(:identity_contract => contract, :session => session)

    expect(strategy.send(:current_identity_initiation)).to be_nil
  end

  it 'builds a local initiation payload for a contract without pin_initiation' do
    custom_contract = Object.new
    strategy = ExampleStrategy.new(
      app,
      :name => 'custom-entry',
      :identity_contract => custom_contract,
      :identity_registration => 'custom-directory',
      :identity_mapping_version => 'v9'
    )
    env = Rack::MockRequest.env_for('http://app.example/auth/custom-entry/request', 'rack.session' => {})
    strategy.instance_variable_set(:@env, env)

    payload = strategy.pin_identity_initiation!

    expect(payload).to eq(
      'registration' => 'custom-directory',
      'provider' => 'custom-entry',
      'mapping_version' => 'v9'
    )
    expect(env['rack.session']['omniauth.identity_initiations']['custom-entry']).to eq(payload)
  end

  it 'remembers identity explicitly with strategy-owned sign-in data' do
    strategy = strategy_with(:identity_contract => contract)

    strategy.remember_identity('state-key', 'verifier' => 'pkce')

    sign_in = strategy.env['rack.session']['omniauth.sign_ins']['state-key']
    expect(sign_in['verifier']).to eq('pkce')
    expect(sign_in['identity']['registration']).to eq('pin')
    expect(strategy.pin_identity['provider']).to eq('pin')
  end

  it 'does not remember identity when no contract is configured' do
    strategy = strategy_with
    expect(strategy.remember_identity('state-key')).to be_nil
  end

  it 'invokes one-argument callable contracts with the Rack environment and wraps hash results' do
    seen_env = nil
    callable = proc do |env|
      seen_env = env
      {'status' => 'ordinary'}
    end
    strategy = strategy_with(:identity_contract => callable)

    receipt = strategy.send(:apply_identity_contract!)

    expect(seen_env).to equal(strategy.env)
    expect(receipt).to be_a(OmniAuth::IdentityMigration::Receipt)
    expect(receipt).to be_ordinary
  end

  it 'invokes two-argument callable contracts with auth and initiation' do
    arguments = nil
    callable = ->(auth, initiation) { arguments = [auth, initiation]; OmniAuth::IdentityMigration::Receipt.new }
    strategy = strategy_with(:identity_contract => callable)
    strategy.env['omniauth.identity_initiation'] = {'registration' => 'pin'}

    strategy.send(:apply_identity_contract!)

    expect(arguments.first).to equal(strategy.env['omniauth.auth'])
    expect(arguments.last).to eq('registration' => 'pin')
  end

  it 'invokes splat callable contracts with the Rack environment' do
    arguments = nil
    callable = ->(*args) { arguments = args; OmniAuth::IdentityMigration::Receipt.new }
    strategy = strategy_with(:identity_contract => callable)

    strategy.send(:apply_identity_contract!)

    expect(arguments).to eq([strategy.env])
  end

  it 'supports evaluate-only and resolve-only contract objects' do
    evaluator = Object.new
    def evaluator.evaluate(auth, _initiation)
      OmniAuth::IdentityMigration::Receipt.new(:auth_provider => auth.provider, :status => 'ordinary')
    end

    resolver = Object.new
    def resolver.resolve(_auth, _initiation)
      OmniAuth::IdentityMigration::Receipt.new(:status => 'pending_review')
    end

    evaluate_strategy = strategy_with(:identity_contract => evaluator)
    expect(evaluate_strategy.send(:apply_identity_contract!).auth_provider).to eq('pin')

    resolve_strategy = strategy_with(:identity_contract => resolver)
    expect(resolve_strategy.send(:apply_identity_contract!)).to be_pending_review
  end

  it 'does not write a receipt when the contract returns nil' do
    strategy = strategy_with(:identity_contract => proc { nil })

    expect(strategy.send(:apply_identity_contract!)).to be_nil
    expect(strategy.env).not_to have_key('omniauth.migration_receipt')
  end
end
