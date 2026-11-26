require 'helper'

describe OmniAuth::Strategy::Receivers do
  class ReceiverRecordingStrategy
    include OmniAuth::Strategy

    def self.events
      @events ||= []
    end

    option :name, 'recorded'

    def request_phase
      self.class.events << [:request_phase, name]
      redirect(callback_url)
    end

    def callback_phase
      self.class.events << [:callback_phase, name]
      [200, {'content-type' => 'text/plain'}, ["#{name} complete"]]
    end
  end

  let(:events) { ReceiverRecordingStrategy.events }
  let(:session) { {} }
  let(:app) { ->(_env) { [204, {}, []] } }
  let(:receiver_env_key) { 'test.gateway_receiver' }
  let(:protected_options) do
    {
      :allowed_receivers => 'managed-gateway',
      :receiver_env_key => receiver_env_key,
      :full_host => 'https://login.example'
    }
  end
  let(:protected_strategy) { ReceiverRecordingStrategy.new(app, protected_options) }
  let(:public_strategy) { ReceiverRecordingStrategy.new(app, :name => 'ordinary', :full_host => 'https://login.example') }

  around do |example|
    original_failure_environments = OmniAuth.config.failure_raise_out_environments
    original_hook = OmniAuth.config.before_callback_phase
    OmniAuth.config.failure_raise_out_environments = []
    OmniAuth.config.before_callback_phase = ->(env) { events << [:hook, env['omniauth.strategy']&.name] }
    example.run
  ensure
    OmniAuth.config.failure_raise_out_environments = original_failure_environments
    OmniAuth.config.before_callback_phase = original_hook
    events.clear
  end

  def request_env(path, method: 'POST', receiver: nil, script_name: '')
    query = Rack::Utils.build_query(
      'code' => 'auth-code',
      'state' => 'state-token',
      'origin' => '/after-login?from=email'
    )
    env = Rack::MockRequest.env_for(
      "https://login.example#{path}?#{query}",
      :method => method
    )
    env['rack.session'] = session
    env['SCRIPT_NAME'] = script_name
    env['PATH_INFO'] = path
    env[receiver_env_key] = receiver if receiver
    env
  end

  def callback_env(receiver: 'public-gateway', session_value: session, script_name: '')
    path = '/auth/recorded/callback'
    env = Rack::MockRequest.env_for(
      "https://login.example#{path}?code=auth-code&state=state-token",
      :method => 'GET'
    )
    env['rack.session'] = session_value
    env['SCRIPT_NAME'] = script_name
    env['PATH_INFO'] = path
    env[receiver_env_key] = receiver
    env
  end

  it 'rejects a public receiver before hooks or session recall, then allows completion from the managed receiver' do
    request_response = protected_strategy.call(request_env('/auth/recorded'))

    expect(request_response[0]).to eq(302)
    expect(request_response[1]['location']).to start_with('https://login.example/auth/recorded/callback?')
    expect(session).to have_key('omniauth.params')
    expect(session['omniauth.origin']).to eq('/after-login?from=email')

    events.clear
    public_env = callback_env(:receiver => 'public-gateway')
    public_response = protected_strategy.call(public_env)

    expect(public_response[0]).to eq(403)
    expect(public_env['omniauth.error.type']).to eq(:invalid_receiver)
    expect(public_env['omniauth.receiver.reason']).to eq(:mismatch)
    expect(public_env['omniauth.receiver']).to eq('public-gateway')
    expect(events).to be_empty
    expect(session['omniauth.origin']).to eq('/after-login?from=email')
    expect(session).to have_key('omniauth.params')

    managed_env = callback_env(:receiver => 'managed-gateway')
    managed_response = protected_strategy.call(managed_env)

    expect(managed_response[0]).to eq(200)
    expect(managed_response[2]).to eq(['recorded complete'])
    expect(events).to eq([[:hook, 'recorded'], [:callback_phase, 'recorded']])
    expect(session).not_to have_key('omniauth.origin')
    expect(session).not_to have_key('omniauth.params')
  end

  it 'reports a missing verified receiver without touching the flow session' do
    session['omniauth.origin'] = '/keep-me'
    env = callback_env(:receiver => nil)
    env.delete(receiver_env_key)

    response = protected_strategy.call(env)

    expect(response[0]).to eq(403)
    expect(env['omniauth.receiver.reason']).to eq(:missing)
    expect(env['omniauth.error.type']).to eq(:invalid_receiver)
    expect(events).to be_empty
    expect(session['omniauth.origin']).to eq('/keep-me')
  end

  it 'leaves an ordinary strategy available on the public receiver' do
    env = callback_env(:receiver => 'public-gateway')
    env['PATH_INFO'] = '/auth/ordinary/callback'
    env['SCRIPT_NAME'] = ''

    response = public_strategy.call(env)

    expect(response[0]).to eq(200)
    expect(response[2]).to eq(['ordinary complete'])
    expect(events).to eq([[:hook, 'ordinary'], [:callback_phase, 'ordinary']])
  end

  it 'keeps callback matching and configured URLs under nested mounts' do
    strategy = ReceiverRecordingStrategy.new(
      app,
      :name => 'recorded',
      :allowed_receivers => 'managed-gateway',
      :receiver_env_key => receiver_env_key,
      :full_host => 'https://login.example'
    )
    env = callback_env(:receiver => 'managed-gateway', :script_name => '/gateway/internal')
    env['PATH_INFO'] = '/auth/recorded/callback'

    response = strategy.call!(env)

    expect(response[0]).to eq(200)
    expect(strategy.callback_path).to eq('/gateway/internal/auth/recorded/callback')
    expect(strategy.callback_url).to start_with('https://login.example/gateway/internal/auth/recorded/callback?')
  end

  it 'dispatches the same strategy through two Rack::URLMap layers' do
    mounted = Rack::URLMap.new('/outer' => Rack::URLMap.new('/inner' => protected_strategy))
    env = Rack::MockRequest.env_for('https://login.example/outer/inner/auth/recorded/callback?code=auth-code')
    env['rack.session'] = session
    env[receiver_env_key] = 'managed-gateway'

    response = mounted.call(env)

    expect(response[0]).to eq(200)
    expect(response[2]).to eq(['recorded complete'])
  end

  it 'accepts canonical Rack receiver information and declaration aliases' do
    strategy = ReceiverRecordingStrategy.new(app, :allowed_ingress => /managed/)
    env = callback_env(:receiver => nil)
    env.delete(receiver_env_key)
    env['omniauth.ingress'] = 'managed-zone-a'

    expect(strategy.call(env)[0]).to eq(200)
  end

  it 'guards a direct callback_call before setup or hooks' do
    env = callback_env(:receiver => 'public-gateway')
    protected_strategy.instance_variable_set(:@env, env)

    expect(protected_strategy.callback_call[0]).to eq(403)
    expect(events).to be_empty
  end

  describe 'declaration normalization' do
    let(:strategy) { ReceiverRecordingStrategy.new(app) }

    before { strategy.instance_variable_set(:@env, {}) }

    it 'normalizes nil, boolean, array, hash, and scalar declarations' do
      expect(strategy.send(:normalize_receiver_allowlist, nil)).to be_nil
      expect(strategy.send(:normalize_receiver_allowlist, false)).to be_nil
      expect(strategy.send(:normalize_receiver_allowlist, true)).to eq([:present])
      expect(strategy.send(:normalize_receiver_allowlist, ['managed'])).to eq(['managed'])
      expect(strategy.send(:normalize_receiver_allowlist, 'managed' => true)).to eq(['managed'])
      expect(strategy.send(:normalize_receiver_allowlist, 'managed')).to eq(['managed'])
    end

    it 'finds semantically named custom declarations and env keys' do
      strategy = ReceiverRecordingStrategy.new(app, :only_from_managed_gateways => ['managed'])
      env_strategy = ReceiverRecordingStrategy.new(app, :allowed_receivers => ['managed'], :gateway_receiver_env => 'gw.id')

      expect(strategy.send(:receiver_allowlist)).to eq(['managed'])
      expect(env_strategy.send(:receiver_env_key_option)).to eq('gw.id')
    end

    it 'treats a static receiver option as the allowed identifier but a callable as a resolver' do
      static = ReceiverRecordingStrategy.new(app, :receiver => 'managed')
      callable = ReceiverRecordingStrategy.new(app, :receiver => ->(env) { env['receiver'] })

      expect(static.send(:receiver_allowlist)).to eq(['managed'])
      expect(callable.send(:receiver_allowlist)).to be_nil
    end

    it 'supports presence and zero-, one-, and two-argument receiver rules' do
      expect(strategy.send(:receiver_matches_any?, 'managed', [:present])).to be(true)
      expect(strategy.send(:receiver_matches_any?, nil, [:present])).to be(false)
      expect(strategy.send(:receiver_matches_any?, 'managed', [-> { true }])).to be(true)
      expect(strategy.send(:receiver_matches_any?, 'managed', [->(receiver) { receiver == 'managed' }])).to be(true)
      rule = ->(receiver, env) { receiver == 'managed' && env['rack.test'] == true }
      strategy.instance_variable_set(:@env, 'rack.test' => true)

      expect(strategy.send(:receiver_matches_any?, 'managed', [rule])).to be(true)
    end

    it 'supports callable receiver resolvers and the global resolver' do
      original_allowlist = OmniAuth.config.allowed_receivers
      original_resolver = OmniAuth.config.receiver_resolver
      OmniAuth.config.allowed_receivers = ['global']
      expect(strategy.send(:receiver_allowlist)).to eq(['global'])

      strategy = ReceiverRecordingStrategy.new(
        app,
        :receiver => ->(env) { env['verified.receiver'] }
      )
      strategy.instance_variable_set(:@env, 'verified.receiver' => 'managed')
      expect(strategy.current_receiver).to eq('managed')

      zero_arg = ReceiverRecordingStrategy.new(app, :receiver => -> { 'zero' })
      zero_arg.instance_variable_set(:@env, {})
      expect(zero_arg.current_receiver).to eq('zero')

      two_arg = ReceiverRecordingStrategy.new(app, :receiver => ->(env, options) { env[options[:key]] }, :key => 'custom')
      two_arg.instance_variable_set(:@env, 'custom' => 'two')
      expect(two_arg.current_receiver).to eq('two')

      OmniAuth.config.receiver_resolver = ->(env) { env['global.receiver'] }
      strategy.instance_variable_set(:@env, 'global.receiver' => 'global')
      expect(strategy.current_receiver).to eq('global')
    ensure
      OmniAuth.config.receiver_resolver = original_resolver
      OmniAuth.config.allowed_receivers = original_allowlist
    end
  end
end
