require 'helper'
require 'json'

# A recording application that captures exactly what OmniAuth handed it on
# each callback, independent of how the strategy built it.
class ConsentFlowApp
  attr_reader :calls

  def initialize
    @calls = []
  end

  def call(env)
    consent = env['omniauth.consent']
    @calls << {
      'path' => env['PATH_INFO'],
      'provider' => env['omniauth.auth'] && env['omniauth.auth'].provider,
      'uid' => env['omniauth.auth'] && env['omniauth.auth'].uid,
      'origin' => env['omniauth.origin'],
      'params' => env['omniauth.params'],
      'consent' => consent && consent.to_hash
    }
    [200, {'content-type' => 'application/json'}, [JSON.generate(@calls.last)]]
  end

  def last
    @calls.last
  end
end

# A local provider that carries a state back to the callback, and whose
# consent answer is whatever the callback's query string says. It makes no
# network request: the provider side of the redirect is simulated by the
# spec calling the callback with the state it generated.
class ConsentFlowProvider
  include OmniAuth::Strategy

  option :name, 'records'

  def request_phase
    state = request.params.fetch('state')
    remember_sign_in(state, 'nonce' => "nonce-#{state}")
    if request.params['consent'] == 'import'
      request_consent(state, 'directory' => %w[organization_name contact_email])
    end
    redirect("https://provider.example/authorize?state=#{Rack::Utils.escape(state)}")
  end

  def callback_sign_in_key
    request.params['state']
  end

  def consent_decision
    JSON.parse(request.params.fetch('decision', '{}'))
  end

  uid { "uid-#{request.params['state']}" }
  info { {'name' => 'Example User'} }
end

describe 'consent end to end' do
  let(:recorder) { ConsentFlowApp.new }

  let(:app) do
    inner = recorder
    omniauth = OmniAuth::Builder.new(inner) do
      provider ConsentFlowProvider
    end

    Rack::Builder.new do
      use Rack::Session::Cookie, :secret => SecureRandom.hex(64)
      run omniauth
    end
  end

  around do |example|
    validation_phase = OmniAuth.config.request_validation_phase
    OmniAuth.config.request_validation_phase = nil
    example.run
  ensure
    OmniAuth.config.request_validation_phase = validation_phase
  end

  def start(state, params = {})
    post('/auth/records', {'state' => state}.merge(params))
    expect(last_response.status).to eq(302)
    expect(last_response['Location']).to include("state=#{state}")
  end

  def finish(state, params = {})
    get('/auth/records/callback', {'state' => state}.merge(params))
    expect(last_response.status).to eq(200)
    recorder.last
  end

  def stored_session
    last_request.env.fetch('rack.session').to_hash
  end

  it 'keeps an ordinary login and a consent import apart when finished in reverse' do
    start('login')
    start('import', 'consent' => 'import')

    expect(stored_session['omniauth.sign_ins'].keys).to eq(%w[login import])

    # Finish the import first, with only the organization name approved and
    # the contact email declined, then the ordinary login.
    import = finish('import', 'decision' => JSON.generate(
      'directory' => {'status' => 'approved', 'claims' => ['organization_name'], 'declined_claims' => ['contact_email']}
    ))
    login = finish('login')

    expect(import['uid']).to eq('uid-import')
    expect(import['consent']['identity']).to eq('confirmed' => true, 'provider' => 'records', 'uid' => 'uid-import')
    expect(import['consent']['approved']).to eq('directory' => {'provider' => 'records', 'claims' => ['organization_name']})
    expect(import['consent']['pending']).to eq([])
    expect(import['consent']['cancelled']).to eq([])
    expect(import['consent']['purposes']['directory']).to include(
      'status' => 'approved',
      'claims' => ['organization_name'],
      'declined_claims' => ['contact_email'],
      'pending_claims' => [],
      'provider' => 'records'
    )

    # The ordinary login is confirmed on its own and carries no consent.
    expect(login['uid']).to eq('uid-login')
    expect(login['consent']).to be_nil
    expect(login['params']['state']).to eq('login')

    expect(stored_session['omniauth.sign_ins']).to eq({})
  end

  it 'reports an approval, a wait, and a cancellation on their own requests' do
    start('again', 'consent' => 'import')
    approved = finish('again', 'decision' => JSON.generate('directory' => 'approved'))
    expect(approved['consent']['approved']).to eq('directory' => {'provider' => 'records', 'claims' => %w[organization_name contact_email]})
    expect(approved['consent']['pending']).to eq([])
    expect(approved['consent']['cancelled']).to eq([])

    # The same import is requested again and left waiting.
    start('again', 'consent' => 'import')
    waiting = finish('again', 'decision' => '{}')
    expect(waiting['consent']['approved']).to eq({})
    expect(waiting['consent']['pending']).to eq(['directory'])
    expect(waiting['consent']['cancelled']).to eq([])
    expect(waiting['consent']['identity']['confirmed']).to be(true)

    # A third time the user declines the additional sharing; the login
    # itself still succeeds and the identity remains confirmed.
    start('again', 'consent' => 'import')
    cancelled = finish('again', 'decision' => JSON.generate('directory' => {'status' => 'cancelled'}))
    expect(cancelled['uid']).to eq('uid-again')
    expect(cancelled['consent']['approved']).to eq({})
    expect(cancelled['consent']['pending']).to eq([])
    expect(cancelled['consent']['cancelled']).to eq(['directory'])
    expect(cancelled['consent']['identity']['confirmed']).to be(true)
    expect(cancelled['consent']['purposes']['directory']['declined_claims']).to eq(%w[organization_name contact_email])
  end

  it 'does not let one sign-in answer for another' do
    start('login')
    start('import', 'consent' => 'import')

    login = finish('login')
    expect(login['consent']).to be_nil

    import = finish('import', 'decision' => JSON.generate('directory' => {'status' => 'approved'}))
    expect(import['consent']['approved']).to eq('directory' => {'provider' => 'records', 'claims' => %w[organization_name contact_email]})
  end
end
