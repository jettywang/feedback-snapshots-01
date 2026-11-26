require 'helper'
require 'json'

# A strategy whose provider returns the key it was given, and whose consent
# decision comes from a lambda, so a spec can script an approval, a
# cancellation, or no answer at all. It records the receipt it delivered.
class ConsentStrategy
  include OmniAuth::Strategy

  option :name, 'consent'

  def request_phase
    key = request.params.fetch('key')
    remember_sign_in(key, 'state' => "state-#{key}")
    request_consent(key, 'directory' => %w[organization_name contact_email]) if request.params['consent'] == 'yes'
    redirect "https://provider.example/?key=#{key}"
  end

  def callback_sign_in_key
    request.params['key']
  end

  def consent_decision
    decision = options[:decision]
    decision.respond_to?(:call) ? decision.call(self) : (decision || {})
  end

  uid { "uid-#{request.params['key']}" }
  info { {'name' => 'Example User'} }

  def callback_phase
    super
    env['consent.delivered'] = env['omniauth.consent']
  end
end

# A strategy that requests consent but does not override #consent_decision,
# so OmniAuth's default answer (none) applies.
class ConsentDefaultStrategy
  include OmniAuth::Strategy

  option :name, 'consent'

  def request_phase
    key = request.params.fetch('key')
    request_consent(key, 'directory' => %w[organization_name contact_email])
    redirect "https://provider.example/?key=#{key}"
  end

  def callback_sign_in_key
    request.params['key']
  end

  uid { "uid-#{request.params['key']}" }
  info { {'name' => 'Example User'} }
end

# The top-level describe is OmniAuth::Strategy rather than
# OmniAuth::Strategy::Consent so mutant keeps selecting every
# OmniAuth::Strategy example for the Consent subjects.
describe OmniAuth::Strategy, 'consent' do
  let(:seen) { [] }
  let(:app) { lambda { |env| seen << env; [200, {}, ['ok']] } }
  let(:session) { {} }
  let(:options) { {} }
  let(:strategy) { ConsentStrategy.new(app, options) }

  around do |example|
    validation_phase = OmniAuth.config.request_validation_phase
    OmniAuth.config.request_validation_phase = nil
    example.run
  ensure
    OmniAuth.config.request_validation_phase = validation_phase
  end

  def start(key, params = {})
    current = params.delete(:strategy) || strategy
    query = Rack::Utils.build_query({'key' => key}.merge(params))
    current.call(Rack::MockRequest.env_for("http://app.example/auth/consent?#{query}", :method => 'POST', 'rack.session' => session))
  end

  def finish(key, params = {})
    current = params.delete(:strategy) || strategy
    query = Rack::Utils.build_query({'key' => key}.merge(params))
    current.call(Rack::MockRequest.env_for("http://app.example/auth/consent/callback?#{query}", 'rack.session' => session))
    seen.last
  end

  def receipt
    seen.last['omniauth.consent']
  end

  def finish_with(key, decision, params = {})
    options[:decision] = decision
    start(key, {'consent' => 'yes'}.merge(params))
    finish(key)
  end

  it 'leaves an ordinary login without a consent receipt' do
    start('plain')
    finish('plain')

    expect(seen.last).not_to have_key('omniauth.consent')
    expect(seen.last['omniauth.auth'].uid).to eq('uid-plain')
  end

  it 'reports a pending purpose before the provider answers' do
    start('import', 'consent' => 'yes')
    finish('import')

    expect(receipt.identity_confirmed?).to be(true)
    expect(receipt.pending).to eq(['directory'])
    expect(receipt.pending_claims_for('directory')).to eq(%w[organization_name contact_email])
    expect(receipt.approved).to eq({})
  end

  it 'reports only the claims the provider approved, attributed to the provider' do
    finish_with('import', 'directory' => {'status' => 'approved', 'claims' => ['organization_name'], 'declined_claims' => ['contact_email']})

    expect(receipt.approved).to eq('directory' => {'provider' => 'consent', 'claims' => ['organization_name']})
    expect(receipt.claims_for('directory')).to eq(['organization_name'])
    expect(receipt.declined_claims_for('directory')).to eq(['contact_email'])
    expect(receipt.identity_confirmed?).to be(true)
  end

  it 'reports a cancelled purpose while the identity stays confirmed' do
    finish_with('import', 'directory' => {'status' => 'cancelled'})

    expect(receipt.cancelled).to eq(['directory'])
    expect(receipt.declined_claims_for('directory')).to eq(%w[organization_name contact_email])
    expect(receipt.identity_confirmed?).to be(true)
    expect(seen.last['omniauth.auth'].uid).to eq('uid-import')
  end

  it 'approves every requested claim for an approval without a list' do
    finish_with('import', 'directory' => 'approved')

    expect(receipt.approved).to eq('directory' => {'provider' => 'consent', 'claims' => %w[organization_name contact_email]})
    expect(receipt.pending).to eq([])
  end

  it 'treats an array decision as the approved claims' do
    finish_with('import', :directory => [:organization_name])

    expect(receipt.claims_for(:directory)).to eq(['organization_name'])
    expect(receipt.declined_claims_for('directory')).to eq([])
    expect(receipt.pending_claims_for('directory')).to eq(['contact_email'])
  end

  it 'treats an unrecognized or missing status as pending' do
    finish_with('import', 'directory' => {'status' => 'maybe'})

    expect(receipt.pending).to eq(['directory'])
    expect(receipt.approved).to eq({})
  end

  it 'ignores a purpose and claims that were not requested at the start' do
    finish_with('import', 'directory' => {'status' => 'approved', 'claims' => %w[organization_name phone_number]}, 'contacts' => {'status' => 'approved'})

    expect(receipt.claims_for('directory')).to eq(['organization_name'])
    expect(receipt.pending_claims_for('directory')).to eq(['contact_email'])
    expect(receipt.status_for('contacts')).to be_nil
    expect(receipt.purposes.keys).to eq(['directory'])
  end

  it 'keeps a purpose out of a sign-in that did not request it' do
    options[:decision] = {'directory' => 'approved'}
    start('plain')
    start('import', 'consent' => 'yes')
    finish('plain')

    expect(seen.last).not_to have_key('omniauth.consent')
    finish('import')
    expect(receipt.approved).to eq('directory' => {'provider' => 'consent', 'claims' => %w[organization_name contact_email]})
  end

  it 'leaves every purpose pending for a strategy that does not override the decision' do
    default_strategy = ConsentDefaultStrategy.new(app, options)
    start('import', :strategy => default_strategy)
    finish('import', :strategy => default_strategy)

    expect(receipt.identity_confirmed?).to be(true)
    expect(receipt.pending).to eq(['directory'])
    expect(receipt.approved).to eq({})
  end

  it 'leaves every purpose pending when the callback does not confirm the identity' do
    options[:decision] = {'directory' => 'approved'}
    without_uid = Class.new(ConsentStrategy) do
      uid {}
    end.new(app, options)
    start('import', 'consent' => 'yes', :strategy => without_uid)
    finish('import', :strategy => without_uid)

    expect(receipt.identity_confirmed?).to be(false)
    expect(receipt.approved).to eq({})
    expect(receipt.pending).to eq(['directory'])
  end

  context 'when registering the request' do
    let(:env) { Rack::MockRequest.env_for('http://app.example/auth/consent?key=a', 'rack.session' => session) }

    before { strategy.instance_variable_set(:@env, env) }

    it 'ignores a key that is not a non-empty string' do
      [nil, '', :a, []].each { |key| strategy.request_consent(key, 'directory' => ['organization_name']) }
      expect(session).not_to have_key('omniauth.sign_ins')
    end

    it 'registers the purposes without a prior remember_sign_in' do
      strategy.request_consent('a', 'directory' => ['organization_name'])
      expect(session['omniauth.sign_ins']).to eq('a' => {'consent' => {'provider' => 'consent', 'purposes' => {'directory' => ['organization_name']}}})
    end

    it 'accepts an array of purposes, with no claims' do
      strategy.request_consent('a', %i[directory billing])
      expect(session['omniauth.sign_ins']['a']['consent']['purposes']).to eq('directory' => [], 'billing' => [])
    end

    it 'leaves out a blank purpose and blank or repeated claims' do
      strategy.request_consent('a', '' => ['x'], 'directory' => ['', :organization_name, 'organization_name'])
      expect(session['omniauth.sign_ins']['a']['consent']['purposes']).to eq('directory' => ['organization_name'])
    end

    it 'merges the strategy data passed with the consent' do
      strategy.request_consent('a', {'directory' => []}, 'verifier' => 'v')
      expect(session['omniauth.sign_ins']['a']).to eq('verifier' => 'v', 'consent' => {'provider' => 'consent', 'purposes' => {'directory' => []}})
    end

    it 'keeps values already remembered for the same key' do
      strategy.remember_sign_in('a', 'verifier' => 'v')
      strategy.request_consent('a', 'directory' => [])
      expect(session['omniauth.sign_ins']['a']).to include('verifier' => 'v')
    end
  end

  context 'when building the receipt' do
    let(:env) { Rack::MockRequest.env_for('http://app.example/auth/consent?key=a', 'rack.session' => session) }

    before { strategy.instance_variable_set(:@env, env) }

    it 'memoizes the receipt for the callback' do
      strategy.request_consent('a', 'directory' => [])
      strategy.instance_variable_set(:@consent_request, session['omniauth.sign_ins']['a']['consent'])
      first = strategy.consent_receipt
      expect(strategy.consent_receipt).to equal(first)
    end

    it 'is nil when the callback did not request consent' do
      expect(strategy.consent_receipt).to be_nil
    end

    it 'does not reuse a receipt for a later callback on the same instance' do
      options[:decision] = {'directory' => 'approved'}
      reuse = ConsentStrategy.new(app, options)
      start('import', 'consent' => 'yes', :strategy => reuse)
      finish('import', :strategy => reuse)
      expect(seen.last['omniauth.consent']).to be_a(OmniAuth::ConsentReceipt)

      # A second, ordinary callback on the same instance must not deliver the
      # first callback's receipt.
      start('plain', :strategy => reuse)
      finish('plain', :strategy => reuse)
      expect(seen.last).not_to have_key('omniauth.consent')
    end

    it 'lets a strategy that overrides callback_phase pass the receipt itself' do
      override_class = Class.new(ConsentStrategy) do
        def callback_phase
          env['omniauth.auth'] = auth_hash
          env['delivered'] = consent_receipt
          call_app!
        end
      end
      options[:decision] = {'directory' => 'approved'}
      override = override_class.new(app, options)
      start('import', 'consent' => 'yes', :strategy => override)
      finish('import', :strategy => override)

      expect(seen.last['delivered']).to be_a(OmniAuth::ConsentReceipt)
      expect(seen.last['delivered'].claims_for('directory')).to eq(%w[organization_name contact_email])
      expect(seen.last).not_to have_key('omniauth.consent')
    end

    it 'treats tampered purposes that are not a hash as no purposes' do
      strategy.instance_variable_set(:@consent_request, 'provider' => 'consent', 'purposes' => 'junk')
      expect(strategy.consent_receipt.purposes).to eq({})
      expect(strategy.consent_receipt.identity_confirmed?).to be(true)
    end

    it 'treats a decision that is not a hash as no answer' do
      strategy.instance_variable_set(:@consent_request, 'provider' => 'consent', 'purposes' => {'directory' => []})
      allow(strategy).to receive(:consent_decision).and_return('approved')
      expect(strategy.consent_receipt.pending).to eq(['directory'])
    end
  end
end