require 'helper'

class MigrationFlowStrategy
  include OmniAuth::Strategy

  def request_phase
    key = request.params['flow'] || 'default-flow'
    remember_sign_in(key)
    query = Rack::Utils.build_query('flow' => key, 'uid' => options.fetch(:uid, '1000'))
    redirect("/auth/#{name}/callback?#{query}")
  end

  def callback_sign_in_key
    request.params['flow']
  end

  uid do
    request.params['uid'] || options[:uid] || '1000'
  end

  info do
    {'name' => "Employee #{uid}"}
  end
end

class MigrationRecordingApp
  attr_reader :deliveries

  def initialize
    @deliveries = []
  end

  def call(env)
    @deliveries << snapshot(env)
    [200, {'content-type' => 'application/json'}, ['{"ok":true}']]
  end

  private

  def snapshot(env)
    auth = env['omniauth.auth']
    {
      :provider => auth.provider,
      :uid => auth.uid,
      :auth_class => auth.class,
      :bracket_uid => auth['uid'],
      :info_name => auth.info.name,
      :auth_identity => auth['identity']&.to_h,
      :registration => env['omniauth.registration'],
      :principal => env['omniauth.principal']&.to_s,
      :source_principal => env['omniauth.source_principal']&.to_s,
      :attributed_principal => env['omniauth.attributed_principal']&.to_s,
      :context => env['omniauth.identity']&.to_h,
      :receipt => env['omniauth.migration_receipt'],
      :mapping => env['omniauth.mapping'],
      :identity_env_present => env.key?('omniauth.identity'),
      :migration_env_present => env.key?('omniauth.migration_receipt')
    }
  end
end

RSpec.describe 'provider migration identity pinning' do
  let(:session) { {} }
  let(:recorder) { MigrationRecordingApp.new }
  let(:contract) do
    OmniAuth::IdentityMigration::Contract.new(
      :preferred_provider => 'legacy',
      :registrations => [
        {'name' => 'legacy', 'provider' => 'legacy', 'mapping_version' => 'migration-v1'},
        {'name' => 'current', 'provider' => 'current', 'mapping_version' => 'migration-v1'}
      ]
    )
  end
  let(:app) do
    migration_contract = contract
    recorder_app = recorder
    Rack::Builder.new do
      use MigrationFlowStrategy,
          :name => 'legacy',
          :uid => '1000',
          :identity_contract => migration_contract,
          :identity_registration => 'legacy',
          :identity_mapping_version => 'migration-v1'
      use MigrationFlowStrategy,
          :name => 'current',
          :uid => '1000',
          :identity_contract => migration_contract,
          :identity_registration => 'current',
          :identity_mapping_version => 'migration-v1'
      run recorder_app
    end.to_app
  end

  def request_phase(provider, flow)
    env = Rack::MockRequest.env_for(
      "http://app.example/auth/#{provider}?flow=#{flow}",
      :method => 'POST',
      'rack.session' => session
    )
    app.call(env)
  end

  def callback_phase(provider, flow, uid = '1000')
    env = Rack::MockRequest.env_for(
      "http://app.example/auth/#{provider}/callback?flow=#{flow}&uid=#{uid}",
      :method => 'GET',
      'rack.session' => session
    )
    app.call(env)
  end

  it 'pins registrations, withholds unapproved merges, and records the approved conversion' do
    old_request = request_phase('legacy', 'old-flow')
    expect(old_request[0]).to eq(302)
    expect(session['omniauth.sign_ins']['old-flow']['identity']).to eq(
      'registration' => 'legacy',
      'provider' => 'legacy',
      'mapping_version' => 'migration-v1',
      'preferred_provider' => 'legacy'
    )

    contract.preferred_provider = 'current'
    expect(contract.default_provider).to eq('current')
    new_request = request_phase('current', 'new-flow')
    expect(new_request[0]).to eq(302)
    expect(session['omniauth.sign_ins'].keys).to contain_exactly('old-flow', 'new-flow')
    expect(session['omniauth.sign_ins']['old-flow']['identity']['registration']).to eq('legacy')

    new_callback = callback_phase('current', 'new-flow')
    expect(new_callback[0]).to eq(200)
    expect(session['omniauth.sign_ins'].keys).to contain_exactly('old-flow')

    old_callback = callback_phase('legacy', 'old-flow')
    expect(old_callback[0]).to eq(200)
    expect(session['omniauth.sign_ins']).to eq({})
    expect(session['omniauth.identity_initiations']).to eq({})

    expect(recorder.deliveries.length).to eq(2)
    new_delivery, old_delivery = recorder.deliveries

    expect(new_delivery[:auth_class]).to eq(OmniAuth::AuthHash)
    expect(new_delivery[:provider]).to eq('current')
    expect(new_delivery[:uid]).to eq('1000')
    expect(new_delivery[:bracket_uid]).to eq('1000')
    expect(new_delivery[:info_name]).to eq('Employee 1000')
    expect(new_delivery[:registration]).to eq('current')
    expect(new_delivery[:principal]).to eq('current:1000')
    expect(new_delivery[:source_principal]).to eq('current:1000')
    expect(new_delivery[:attributed_principal]).to eq('current:1000')
    expect(new_delivery[:receipt]).to be_ordinary
    expect(new_delivery[:context]['status']).to eq('ordinary')
    expect(new_delivery[:context]['principal']['qualified_uid']).to eq('current:1000')

    expect(old_delivery[:provider]).to eq('legacy')
    expect(old_delivery[:uid]).to eq('1000')
    expect(old_delivery[:bracket_uid]).to eq('1000')
    expect(old_delivery[:registration]).to eq('legacy')
    expect(old_delivery[:principal]).to eq('legacy:1000')
    expect(old_delivery[:attributed_principal]).to eq('legacy:1000')
    expect(old_delivery[:mapping]).to be_nil
    expect(old_delivery[:receipt]).to be_pending_review
    expect(old_delivery[:receipt].reasons).to eq(['same_uid_unapproved'])
    expect(old_delivery[:context]['registration']).to eq('legacy')
    expect(old_delivery[:context]['registration_record']['mapping_version']).to eq('migration-v1')
    expect(old_delivery[:auth_identity]).to include(
      'registration' => 'legacy',
      'principal' => 'legacy:1000',
      'status' => 'pending_review'
    )

    old_principal = old_delivery[:receipt].principal
    new_principal = new_delivery[:receipt].principal
    mapping = contract.approve_mapping!(
      old_principal,
      new_principal,
      :version => 'migration-v1',
      :approved_by => 'people-ops'
    )
    expect(mapping).to be_approved
    expect(mapping).to be_bilateral

    conversion = contract.convert!(
      old_principal,
      new_principal,
      :reference => 'MIGRATION-160'
    )
    expect(conversion).to be_converted
    expect(conversion.principal).to eq(old_principal)
    expect(conversion.target_principal).to eq(new_principal)
    expect(conversion.attributed_principal).to eq(new_principal)
    expect(conversion.reference).to eq('MIGRATION-160')
    expect(conversion.migration_result['target']['qualified_uid']).to eq('current:1000')

    expect(contract.ledger.entries.length).to eq(3)
    expect(contract.ledger.deliveries.collect { |receipt| [receipt.kind, receipt.status] }).to eq(
      [['login', 'ordinary'], ['login', 'pending_review']]
    )
    expect(contract.ledger.pending_reviews).to contain_exactly(old_delivery[:receipt])
    expect(contract.ledger.conversions).to contain_exactly(conversion)
    expect(contract.ledger.to_h['entries'].length).to eq(3)
  end

  it 'leaves a login without the optional contract on the existing OmniAuth identity shape' do
    recorder = MigrationRecordingApp.new
    app = Rack::Builder.new do
      use MigrationFlowStrategy, :name => 'plain', :uid => 'plain-7'
      run recorder
    end.to_app
    session = {}

    request_env = Rack::MockRequest.env_for(
      'http://app.example/auth/plain?flow=plain-flow',
      :method => 'POST',
      'rack.session' => session
    )
    expect(app.call(request_env)[0]).to eq(302)

    callback_env = Rack::MockRequest.env_for(
      'http://app.example/auth/plain/callback?flow=plain-flow',
      'rack.session' => session
    )
    expect(app.call(callback_env)[0]).to eq(200)

    delivery = recorder.deliveries.first
    expect(delivery[:auth_class]).to eq(OmniAuth::AuthHash)
    expect(delivery[:provider]).to eq('plain')
    expect(delivery[:uid]).to eq('plain-7')
    expect(delivery[:bracket_uid]).to eq('plain-7')
    expect(delivery[:info_name]).to eq('Employee plain-7')
    expect(delivery[:identity_env_present]).to be(false)
    expect(delivery[:migration_env_present]).to be(false)
    expect(delivery[:registration]).to be_nil
    expect(delivery[:principal]).to be_nil
  end
end
