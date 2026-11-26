require 'helper'

class LayeredIdentitySyntheticError < StandardError; end
class LayeredIdentityRejection < StandardError; end

class LayeredIdentityStrategy
  include OmniAuth::Strategy

  option :name, 'layered'

  def request_phase
    [200, {}, ['request phase']]
  end

  def callback_phase
    if options[:reject]
      env['omniauth.auth'] = auth_hash
      return fail!(
        :access_denied,
        LayeredIdentityRejection.new('ordinary rejection credential-token-secret')
      )
    end

    super
  end

  uid { 'uid-164' }

  info do
    {
      'name' => 'App Alice',
      'email' => 'alice@example.test',
      'label' => 'controlled-app-value',
      'nested' => {'city' => 'Shanghai', 'secret' => 'info-nested-secret'}
    }
  end

  credentials do
    {'token' => 'credential-token-secret', 'refresh_token' => 'refresh-secret'}
  end

  extra do
    {
      'private_note' => 'extra-private-secret',
      'plugin_summary' => {
        'label' => 'plugin-summary-value',
        'score' => 42,
        'nested' => {'edition' => 'original'}
      }
    }
  end
end

RSpec.describe 'Layered identity callbacks' do
  let(:correlation_id) { 'corr-164' }
  let(:app_envs) { [] }
  let(:app_profiles) { [] }
  let(:first_views) { [] }
  let(:second_views) { [] }
  let(:inner_app) do
    profiles = app_profiles
    envs = app_envs
    cid = correlation_id
    lambda do |env|
      auth = env['omniauth.auth']
      profiles << OmniAuth.config.auth_views.project(
        :controlled_app,
        auth,
        :correlation_id => cid
      )
      envs << env
      [200, {'content-type' => 'text/plain'}, ['signed in']]
    end
  end
  let(:strategy) { LayeredIdentityStrategy.new(inner_app) }
  let(:env) do
    {
      'REQUEST_METHOD' => 'POST',
      'PATH_INFO' => '/auth/layered/callback',
      'rack.session' => {},
      'rack.input' => StringIO.new(''),
      'omniauth.correlation_id' => correlation_id
    }
  end
  let(:plugin_fields) do
    ['provider', 'uid', {'extra.plugin_summary' => 'summary'}]
  end

  before do
    OmniAuth.config.identity_callbacks.clear
    OmniAuth.config.auth_views.clear
    OmniAuth.config.auth_views.register(
      :controlled_app,
      :fields => ['provider', 'uid', {'info.label' => 'profile.label'}]
    )

    fields = plugin_fields
    first_sink = first_views
    OmniAuth.config.identity_callbacks.register(:first_plugin, :fields => fields) do |view|
      first_sink << view
      view['summary']['label'] = 'mutated-by-first-plugin'
      view['summary']['injected'] = 'mutation'
      view['summary']['nested']['edition'] = 'mutated'
      view['summary']['nested']['added'] = 'deep-mutation'
      raise LayeredIdentitySyntheticError, 'synthetic failure credential-token-secret'
    end

    second_sink = second_views
    OmniAuth.config.identity_callbacks.register(:second_plugin, :fields => fields) do |view|
      second_sink << view
    end
  end

  after do
    OmniAuth.config.identity_callbacks.clear
    OmniAuth.config.auth_views.clear
  end

  it 'isolates callback views, failure material, logs, and the application identity' do
    expect(OmniAuth.logger).to receive(:error).once do |message|
      expect(message).to include(correlation_id)
      expect(message).to include('plugin-summary-value')
      expect(message).to include('LayeredIdentitySyntheticError')
      expect(message).to include('[FILTERED]')
      expect(message).not_to include('credential-token-secret')
      expect(message).not_to include('refresh-secret')
      expect(message).not_to include('extra-private-secret')
      expect(message).not_to include('info-nested-secret')
      expect(message).not_to include('alice@example.test')
    end

    status, _headers, body = strategy.call(env)

    expect(status).to eq(200)
    expect(body).to eq(['signed in'])

    first_view = first_views.fetch(0)
    second_view = second_views.fetch(0)
    app_profile = app_profiles.fetch(0)
    app_env = app_envs.fetch(0)

    expect(first_view['summary']['label']).to eq('mutated-by-first-plugin')
    expect(first_view['summary']['injected']).to eq('mutation')

    expect(second_view['correlation_id']).to eq(correlation_id)
    expect(second_view['summary']['label']).to eq('plugin-summary-value')
    expect(second_view['summary']['score']).to eq(42)
    expect(second_view['summary']['nested']['edition']).to eq('original')
    expect(second_view['summary']).not_to have_key('injected')
    expect(second_view['summary']['nested']).not_to have_key('added')
    expect(second_view.to_hash).not_to have_key('credentials')
    expect(second_view.to_hash).not_to have_key('info')

    expect(app_profile['profile']['label']).to eq('controlled-app-value')
    expect(app_profile['correlation_id']).to eq(correlation_id)
    expect(app_env['omniauth.auth_views']['controlled_app']['profile']['label'])
      .to eq('controlled-app-value')

    auth = app_env['omniauth.auth']
    expect(auth).to be_a(OmniAuth::AuthHash)
    expect(auth['info']['label']).to eq('controlled-app-value')
    expect(auth['info']['email']).to eq('alice@example.test')
    expect(auth['credentials']['token']).to eq('credential-token-secret')
    expect(auth['credentials']['refresh_token']).to eq('refresh-secret')
    expect(auth['extra']['private_note']).to eq('extra-private-secret')
    expect(auth['extra']['plugin_summary']['label']).to eq('plugin-summary-value')

    receipts = env['omniauth.identity_receipts']
    expect(receipts.length).to eq(2)
    failed_receipt, successful_receipt = receipts
    expect(failed_receipt.name).to eq(:first_plugin)
    expect(failed_receipt).to be_failed
    expect(failed_receipt.error).to be_a(LayeredIdentitySyntheticError)
    expect(failed_receipt.correlation_id).to eq(correlation_id)
    expect(failed_receipt.view['summary']['label']).to eq('plugin-summary-value')
    expect(failed_receipt.view['summary']).not_to have_key('injected')
    expect(failed_receipt.public_message).to include('[FILTERED]')
    expect(failed_receipt.public_message).not_to include('credential-token-secret')
    expect(failed_receipt.material['auth']['summary']['label']).to eq('plugin-summary-value')

    expect(successful_receipt.name).to eq(:second_plugin)
    expect(successful_receipt).not_to be_failed

    expect(env['omniauth.failure_material']).to equal(failed_receipt)
    expect(env['omniauth.failure_materials']).to eq([failed_receipt])
    expect(app_env).to equal(env)
  end

  it 'projects ordinary rejection receipts and scrubs public failure logs' do
    OmniAuth.config.auth_views.register(
      :failure,
      :fields => ['uid', {'info.label' => 'profile.label'}]
    )

    expect(OmniAuth.logger).to receive(:error).once do |message|
      expect(message).to include('access_denied')
      expect(message).to include('[FILTERED]')
      expect(message).not_to include('credential-token-secret')
      expect(message).not_to include('refresh-secret')
    end

    rejecting_strategy = LayeredIdentityStrategy.new(inner_app, :reject => true)
    status, headers, = rejecting_strategy.call(env)

    expect(status).to eq(302)
    expect(headers['Location']).to include('/auth/failure?message=access_denied')
    expect(headers['Location']).not_to include('credential-token-secret')
    expect(app_envs).to be_empty

    receipt = env['omniauth.failure_material']
    expect(receipt.name).to eq(:access_denied)
    expect(receipt.error).to be_a(LayeredIdentityRejection)
    expect(receipt.correlation_id).to eq(correlation_id)
    expect(receipt.view['uid']).to eq('uid-164')
    expect(receipt.view['profile']['label']).to eq('controlled-app-value')
    expect(receipt.view.to_hash).not_to have_key('credentials')
    expect(env['omniauth.error']).to equal(receipt.error)
  end

  it('materializes application-only views when no plugins are registered') do
    OmniAuth.config.identity_callbacks.clear

    status, = LayeredIdentityStrategy.new(inner_app).call(env)

    expect(status).to eq(200)
    app_env = app_envs.fetch(0)
    expect(app_env['omniauth.auth_views']['controlled_app']['uid']).to eq('uid-164')
    expect(env['omniauth.identity_receipts']).to be_nil
  end

  it 'does not add an auth_views env key without named view policies' do
    OmniAuth.config.auth_views.clear
    OmniAuth.config.identity_callbacks.clear
    OmniAuth.config.identity_callbacks.register(:plain_plugin) { |view| view }
    simple_app = ->(_callback_env) { [200, {}, ['ok']] }

    status, = LayeredIdentityStrategy.new(simple_app).call(env)

    expect(status).to eq(200)
    expect(env).not_to have_key('omniauth.auth_views')
    expect(env['omniauth.identity_receipts'].length).to eq(1)
  end
end
