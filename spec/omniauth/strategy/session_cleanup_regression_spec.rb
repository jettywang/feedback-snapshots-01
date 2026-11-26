require 'helper'

# The underlying application in the regression: it records exactly what
# OmniAuth put in the Rack environment and what the session contains while
# the app handles the callback.
class SessionCleanupRegressionApp
  attr_reader :calls

  def initialize
    @calls = []
  end

  def call(env)
    @calls << {
      :origin => env['omniauth.origin'],
      :params => deep_dup(env['omniauth.params']),
      :auth => env['omniauth.auth'] && {
        'provider' => env['omniauth.auth'].provider,
        'uid' => env['omniauth.auth'].uid
      },
      :reads => env['session_cleanup.reads'],
      :session => env['rack.session']&.to_hash
    }

    [200, {'content-type' => 'text/plain'}, ['underlying app']]
  end

  def last
    @calls.last
  end

  private

  def deep_dup(value)
    case value
    when Hash
      value.each_with_object({}) do |(key, nested), copy|
        copy[key] = deep_dup(nested)
      end
    when Array
      value.collect { |nested| deep_dup(nested) }
    else
      value
    end
  end
end

# A provider double that follows the keyed sign-in contract: it remembers
# under the state it generated and reads the state the provider sends back.
class SessionCleanupKeyedProvider
  include OmniAuth::Strategy

  def request_phase
    key = request.params.fetch('state')
    remember_sign_in(key, 'provider_nonce' => "nonce-#{key}")
    redirect("https://provider.example/authorize?state=#{Rack::Utils.escape(key)}")
  end

  def callback_sign_in_key
    request.params['state']
  end

  def callback_phase
    lookup_key = callback_sign_in_key
    reads = [remembered_sign_in, remembered_sign_in, remembered_sign_in]

    env['session_cleanup.reads'] = {
      'request_key' => request.params['state'],
      'lookup_key' => lookup_key,
      'same_object' => reads.all? { |read| read.equal?(reads.first) },
      'sign_in' => reads.first
    }

    call_app!
  end
end

# A deliberately wrong provider double: instead of using the callback's key,
# it assumes the newest stored registration is the matching one.
class SessionCleanupLatestGuesser < SessionCleanupKeyedProvider
  def callback_sign_in_key
    return @latest_guess if defined?(@latest_guess)

    sign_ins = session['omniauth.sign_ins']
    keys = sign_ins.is_a?(Hash) ? sign_ins.keys : []
    @latest_guess = keys.last
  end
end

# An older strategy that never opts into keyed sign-ins.
class SessionCleanupLegacyProvider
  include OmniAuth::Strategy

  def request_phase
    redirect('https://provider.example/legacy/authorize')
  end

  def callback_phase
    env['omniauth.auth'] = OmniAuth::AuthHash.new('provider' => name, 'uid' => 'legacy-uid')
    call_app!
  end
end

describe 'session cleanup across real Rack requests' do
  let(:spy_app) { SessionCleanupRegressionApp.new }

  let(:app) do
    spy = spy_app
    omniauth = OmniAuth::Builder.new(spy) do
      provider SessionCleanupKeyedProvider, :name => 'keyed'
      provider SessionCleanupLatestGuesser, :name => 'latest_guesser'
      provider SessionCleanupLegacyProvider, :name => 'legacy'
    end

    Rack::Builder.new do
      use Rack::Session::Cookie, :secret => SecureRandom.hex(64)
      run omniauth
    end
  end

  around do |example|
    original_max_sign_ins = OmniAuth.config.max_remembered_sign_ins
    OmniAuth.config.max_remembered_sign_ins = 2
    example.run
  ensure
    OmniAuth.config.max_remembered_sign_ins = original_max_sign_ins
  end

  def start_keyed(key, overrides = {})
    params = {
      'state' => key,
      'origin' => "/origin/#{key}",
      'tab' => "tab-#{key}"
    }.merge(overrides)

    post('/auth/keyed', params)
    expect(last_response.status).to eq(302)
    expect(last_response['Location']).to include("state=#{key}")
  end

  def complete_keyed(key)
    get('/auth/keyed/callback', 'state' => key)
    expect(last_response.status).to eq(200)
  end

  def stored_session
    last_request.env.fetch('rack.session').to_hash
  end

  def omniauth_state(session)
    session.select { |key, _| key.start_with?('omniauth.') }
  end

  def keyed_params(key)
    {
      'state' => key,
      'origin' => "/origin/#{key}",
      'tab' => "tab-#{key}"
    }
  end

  it 'keeps a surviving registration repeatable in one callback and consumes it once' do
    %w[old middle newest].each { |key| start_keyed(key) }

    expect(stored_session['omniauth.sign_ins'].keys).to eq(%w[middle newest])

    complete_keyed('middle')

    expect(spy_app.calls.length).to eq(1)
    expect(spy_app.last[:origin]).to eq('/origin/middle')
    expect(spy_app.last[:params]).to eq(keyed_params('middle'))
    expect(spy_app.last[:reads]).to include(
      'request_key' => 'middle',
      'lookup_key' => 'middle',
      'same_object' => true
    )
    expect(spy_app.last[:reads]['sign_in']).to eq(
      'provider_nonce' => 'nonce-middle',
      'origin' => '/origin/middle',
      'params' => keyed_params('middle')
    )

    # OmniAuth deleted the fallback keys before invoking the strategy, and
    # consuming "middle" left only "newest" in the keyed collection.
    expect(omniauth_state(spy_app.last[:session]).keys).to eq(['omniauth.sign_ins'])
    expect(spy_app.last[:session]['omniauth.sign_ins'].keys).to eq(['newest'])
    expect(omniauth_state(stored_session).keys).to eq(['omniauth.sign_ins'])
    expect(stored_session['omniauth.sign_ins'].keys).to eq(['newest'])

    # A replay is another Rack request/strategy instance, but the stored
    # registration was consumed and cannot be handed to the app again.
    complete_keyed('middle')

    expect(spy_app.calls.length).to eq(2)
    expect(spy_app.calls.first[:origin]).to eq('/origin/middle')
    expect(spy_app.last[:origin]).to be_nil
    expect(spy_app.last[:params]).to eq({})
    expect(spy_app.last[:reads]['sign_in']).to be_nil
    expect(stored_session['omniauth.sign_ins'].keys).to eq(['newest'])

    complete_keyed('newest')

    expect(spy_app.calls.length).to eq(3)
    expect(spy_app.last[:origin]).to eq('/origin/newest')
    expect(spy_app.last[:params]).to eq(keyed_params('newest'))
    expect(stored_session['omniauth.sign_ins']).to eq({})
  end

  it 'does not return an evicted registration from the keyed collection' do
    %w[old middle newest].each { |key| start_keyed(key) }

    get('/auth/keyed/callback', 'state' => 'old')
    expect(last_response.status).to eq(200)

    # The keyed lookup misses. The old top-level params fallback still carries
    # the newest ordinary request's params, but its origin had moved into the
    # newest keyed registration, so the app must not receive that origin.
    expect(spy_app.last[:reads]).to include(
      'request_key' => 'old',
      'lookup_key' => 'old',
      'sign_in' => nil
    )
    expect(spy_app.last[:origin]).to be_nil
    expect(spy_app.last[:params]).to eq(keyed_params('newest'))

    # The fallback delete removes top-level params, but a missed keyed lookup
    # must not consume either surviving registration.
    expect(spy_app.last[:session]['omniauth.sign_ins'].keys).to eq(%w[middle newest])
    expect(spy_app.last[:session]['omniauth.sign_ins'].size).to eq(2)
    expect(stored_session['omniauth.sign_ins'].keys).to eq(%w[middle newest])
    expect(stored_session['omniauth.sign_ins'].size).to eq(2)
    expect(stored_session['omniauth.sign_ins']['newest']['origin']).to eq('/origin/newest')
  end

  it 'shows the key, occupancy, and app data that distinguish a latest-guessing double' do
    %w[old middle newest].each do |key|
      post('/auth/latest_guesser', keyed_params(key))
      expect(last_response.status).to eq(302)
    end

    get('/auth/latest_guesser/callback', 'state' => 'old')
    expect(last_response.status).to eq(200)

    # The HTTP/provider callback says "old", but this faulty strategy chooses
    # "newest". Assertions on only params would be ambiguous because the legacy
    # fallback for an evicted key also exposes newest's params. The lookup key,
    # remaining occupancy, and origin identify the mistaken match.
    expect(spy_app.last[:reads]).to include(
      'request_key' => 'old',
      'lookup_key' => 'newest'
    )
    expect(spy_app.last[:reads]['sign_in']['origin']).to eq('/origin/newest')
    expect(spy_app.last[:origin]).to eq('/origin/newest')
    expect(spy_app.last[:params]).to eq(keyed_params('newest'))
    expect(stored_session['omniauth.sign_ins'].keys).to eq(['middle'])
    expect(stored_session['omniauth.sign_ins'].size).to eq(1)
    expect(spy_app.last[:session]['omniauth.sign_ins'].keys).to eq(['middle'])
    expect(spy_app.last[:session]['omniauth.sign_ins'].size).to eq(1)
  end

  it 'finishes an old single-origin/params strategy with its existing contract' do
    post('/auth/legacy', 'origin' => '/from-legacy', 'campaign' => 'spring')
    expect(last_response.status).to eq(302)
    expect(last_response['Location']).to eq('https://provider.example/legacy/authorize')

    expect(omniauth_state(stored_session).keys).to contain_exactly('omniauth.origin', 'omniauth.params')
    expect(stored_session['omniauth.origin']).to eq('/from-legacy')
    expect(stored_session['omniauth.params']).to eq(
      'origin' => '/from-legacy',
      'campaign' => 'spring'
    )

    get('/auth/legacy/callback', 'code' => 'provider-code')
    expect(last_response.status).to eq(200)

    expect(spy_app.last[:origin]).to eq('/from-legacy')
    expect(spy_app.last[:params]).to eq(
      'origin' => '/from-legacy',
      'campaign' => 'spring'
    )
    expect(spy_app.last[:auth]).to eq('provider' => 'legacy', 'uid' => 'legacy-uid')
    expect(omniauth_state(spy_app.last[:session])).to eq({})
    expect(omniauth_state(stored_session)).to eq({})
    expect(stored_session).to have_key('session_id')
  end

  context 'with a small params byte limit' do
    around do |example|
      original_bytesize = OmniAuth.config.max_remembered_params_bytesize
      OmniAuth.config.max_remembered_params_bytesize = 64
      example.run
    ensure
      OmniAuth.config.max_remembered_params_bytesize = original_bytesize
    end

    it 'keeps an oversized ordinary nested param out of the registration but keeps its origin' do
      nested_params = {
        'state' => 'large',
        'origin' => '/return',
        'filter' => {
          'name' => 'x' * 80,
          'tags' => %w[ruby security]
        }
      }

      post('/auth/keyed', nested_params)
      expect(last_response.status).to eq(302)

      stored_params = Rack::Utils.parse_nested_query(
        Rack::Utils.build_nested_query(nested_params)
      )

      # The origin moves into the keyed registration. The nested params are too
      # large to copy there, while the legacy top-level params intentionally
      # remain as the latest single-login fallback until callback cleanup.
      expect(stored_session).not_to have_key('omniauth.origin')
      expect(stored_session['omniauth.sign_ins'].keys).to eq(['large'])
      registration = stored_session['omniauth.sign_ins']['large']
      expect(registration['origin']).to eq('/return')
      expect(registration['provider_nonce']).to eq('nonce-large')
      expect(registration).not_to have_key('params')
      expect(stored_session['omniauth.params']).to eq(stored_params)

      get('/auth/keyed/callback', 'state' => 'large')
      expect(last_response.status).to eq(200)

      expect(spy_app.last[:origin]).to eq('/return')
      expect(spy_app.last[:params]).to eq({})
      expect(omniauth_state(spy_app.last[:session]).keys).to eq(['omniauth.sign_ins'])
      expect(spy_app.last[:session]['omniauth.sign_ins']).to eq({})
      expect(stored_session['omniauth.params']).to be_nil
      expect(stored_session['omniauth.origin']).to be_nil
    end
  end
end
