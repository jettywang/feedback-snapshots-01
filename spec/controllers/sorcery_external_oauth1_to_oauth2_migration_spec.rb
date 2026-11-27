# frozen_string_literal: true

require 'spec_helper'

# Repeatable acceptance criteria for migrating an external (Sorcery) login
# adapter from OAuth 1 to OAuth 2 while keeping the real controller callbacks
# and the real local ActiveRecord model matching. Only the provider protocol
# is swapped:
#
#   * Sorcery::Providers::LegacyTwitter  -> Protocols::Oauth   (OAuth 1.0)
#   * Sorcery::Providers::TwitterOauth2  -> Protocols::Oauth2  (OAuth 2.0)
#
# Both windows hand back the SAME display profile but DIFFERENT stable
# identities (uid), which is the situation that decides whether an existing
# local binding can be carried over.
describe SorceryController, :active_record, type: :controller do
  LEGACY_UID = 'OAUTH1-UID-777'
  NEW_UID    = 'OAUTH2-STABLE-UID-999'
  DISPLAY_PROFILE = {
    'name' => 'Ada Lovelace', 'username' => 'ada',
    'email' => 'ada@example.com'
  }.freeze

  before(:all) do
    MigrationHelper.migrate("#{Rails.root}/db/migrate/external")
    sorcery_reload!([:external])
    sorcery_controller_property_set(:external_providers, %i[legacy_twitter twitter_oauth2])

    sorcery_controller_external_property_set(:legacy_twitter, :key, 'legacy-consumer-key')
    sorcery_controller_external_property_set(:legacy_twitter, :secret, 'legacy-consumer-secret')
    sorcery_controller_external_property_set(:legacy_twitter, :callback_url, 'http://example.com/oauth1/callback')

    sorcery_controller_external_property_set(:twitter_oauth2, :key, 'oauth2-client-id')
    sorcery_controller_external_property_set(:twitter_oauth2, :secret, 'oauth2-client-secret')
    sorcery_controller_external_property_set(:twitter_oauth2, :callback_url, 'http://example.com/oauth2/callback')
    sorcery_controller_external_property_set(
      :twitter_oauth2, :user_info_mapping, username: 'name', email: 'email'
    )

    sorcery_model_property_set(:authentications_class, Authentication)
  end

  after(:all) do
    MigrationHelper.rollback("#{Rails.root}/db/migrate/external")
  end

  before do
    User.sorcery_adapter.delete_all
    Authentication.sorcery_adapter.delete_all
  end

  # A user bound locally through the OLD OAuth 1 window. The only thing Sorcery
  # stores for the binding is the (provider, uid) pair.
  let(:legacy_user) do
    User.create!(username: 'ada', email: 'ada@example.com').tap do |user|
      user.authentications.create!(provider: 'legacy_twitter', uid: LEGACY_UID)
    end
  end

  def stub_legacy_oauth1!
    consumer = OAuth::Consumer.new('k', 's', site: 'https://api.twitter.com')
    request_token = OAuth::RequestToken.new(consumer, 'rt', 'rts')
    access_token = OAuth::AccessToken.new(consumer)
    response = Object.new
    response.define_singleton_method(:body) do
      DISPLAY_PROFILE.merge('id_str' => LEGACY_UID, 'id' => 777).to_json
    end

    allow(OAuth::Consumer).to receive(:new).and_return(consumer)
    allow(consumer).to receive(:get_request_token).and_return(request_token)
    allow(OAuth::RequestToken).to receive(:new).and_return(request_token)
    allow(request_token).to receive(:get_access_token).and_return(access_token)
    allow(access_token).to receive(:get).and_return(response)
  end

  def stub_new_oauth2!
    client = instance_double(OAuth2::Client)
    strategy = instance_double(OAuth2::Strategy::AuthCode)
    access_token = instance_double(OAuth2::AccessToken)
    response = instance_double(OAuth2::Response)

    allow(OAuth2::Client).to receive(:new).and_return(client)
    allow(client).to receive(:auth_code).and_return(strategy)
    allow(strategy).to receive(:authorize_url).and_return('https://api.twitter.com/oauth2/authorize?ok=1')
    allow(strategy).to receive(:get_token).and_return(access_token)
    allow(access_token).to receive(:get).and_return(response)
    allow(response).to receive(:body).and_return(DISPLAY_PROFILE.merge('id' => NEW_UID).to_json)
    { client: client, strategy: strategy, access_token: access_token }
  end

  # ---------------------------------------------------------------------------
  # 1. Protocol authorization: the two windows speak different protocols.
  # ---------------------------------------------------------------------------
  describe 'protocol authorization' do
    it 'keeps the two providers on distinct OAuth protocol versions' do
      expect(Sorcery::Controller::Config.legacy_twitter.oauth_version).to eq('1.0')
      expect(Sorcery::Controller::Config.twitter_oauth2.oauth_version).to eq('2.0')
    end

    it 'the OAuth 1 window stores a request token and redirects with oauth_callback/oauth_token' do
      stub_legacy_oauth1!

      get :login_at_test_legacy_twitter

      expect(response).to be_a_redirect
      expect(response.location).to include('oauth_token=rt')
      expect(response.location).to include('oauth_callback=')
      expect(session[:request_token]).to eq('rt')
      expect(session[:request_token_secret]).to eq('rts')
    end

    it 'the OAuth 2 window is stateless: code flow redirect, no request token in session' do
      stub_new_oauth2!

      get :login_at_test_twitter_oauth2

      expect(response).to be_a_redirect
      expect(response.location).to eq('https://api.twitter.com/oauth2/authorize?ok=1')
      expect(session[:request_token]).to be_nil
      expect(session[:request_token_secret]).to be_nil
    end
  end

  # ---------------------------------------------------------------------------
  # 2. Profile read: identical display data, different stable identity.
  # ---------------------------------------------------------------------------
  describe 'profile read' do
    it 'both callbacks resolve the same display profile but a different uid', :aggregate_failures do
      stub_legacy_oauth1!
      get :test_migration_user_hash,
          params: { provider: 'legacy_twitter' },
          session: { request_token: 'rt', request_token_secret: 'rts' }
      old_hash = JSON.parse(response.body)

      stub_new_oauth2!
      get :test_migration_user_hash, params: { provider: 'twitter_oauth2', code: 'code-123' }
      new_hash = JSON.parse(response.body)

      expect(new_hash['user_info'].slice('name', 'email')).to eq(
        old_hash['user_info'].slice('name', 'email')
      )
      expect(old_hash['uid']).to eq(LEGACY_UID)
      expect(new_hash['uid']).to eq(NEW_UID)
      expect(new_hash['uid']).not_to eq(old_hash['uid'])
    end

    it 'maps the OAuth 2 profile onto local user attributes through user_info_mapping' do
      stub_new_oauth2!
      # Exercise the same attribute extraction the create path uses.
      provider = Sorcery::Controller::Config.twitter_oauth2
      attrs = controller.send(:user_attrs, provider.user_info_mapping,
                               user_info: DISPLAY_PROFILE.merge('id' => NEW_UID))

      expect(attrs).to eq(username: 'Ada Lovelace', email: 'ada@example.com')
    end
  end

  # ---------------------------------------------------------------------------
  # 3. provider + uid binding: the ONLY carry-over key Sorcery uses.
  # ---------------------------------------------------------------------------
  describe 'provider and uid binding' do
    it 'carries the user over when the exact (provider, uid) pair still matches' do
      legacy_user
      stub_legacy_oauth1!

      get :test_login_from_legacy_twitter,
          params: { oauth_verifier: 'verifier' },
          session: { request_token: 'rt', request_token_secret: 'rts' }

      expect(flash[:notice]).to eq('Success!')
      expect(session[:user_id]).to eq(legacy_user.id.to_s)
    end

    it 'does NOT carry the binding over on a changed uid even with an identical profile' do
      legacy_user
      expect(User).to receive(:load_from_provider)
        .with(:twitter_oauth2, NEW_UID).and_call_original
      stub_new_oauth2!

      get :test_login_from_twitter_oauth2, params: { code: 'code-123' }

      expect(flash[:alert]).to eq('Failed!')
      expect(session[:user_id]).to be_nil
      # The legacy row is untouched; nothing is rewritten to the new uid.
      expect(legacy_user.authentications.first.uid).to eq(LEGACY_UID)
    end

    it 'never merges accounts by display name/email: same profile, zero new rows on a failed login' do
      legacy_user
      stub_new_oauth2!

      expect do
        get :test_login_from_twitter_oauth2, params: { code: 'code-123' }
      end.not_to change { [User.count, Authentication.count] }

      expect(User.where(email: 'ada@example.com').count).to eq(1)
    end

    it 'treats uid as namespaced per provider: same uid under another provider does not match' do
      legacy_user

      expect(User.load_from_provider(:twitter_oauth2, LEGACY_UID)).to be_nil
      expect(User.load_from_provider(:legacy_twitter, NEW_UID)).to be_nil
      expect(User.load_from_provider(:legacy_twitter, LEGACY_UID)).to eq(legacy_user)
    end
  end

  # ---------------------------------------------------------------------------
  # 4. New account creation when no binding matches, incl. a storage failure.
  # ---------------------------------------------------------------------------
  describe 'new account creation' do
    it 'creates a user plus an authentication bound to the new (provider, uid)' do
      stub_new_oauth2!

      expect do
        get :test_create_from_twitter_oauth2, params: { code: 'code-123' }
      end.to change(User, :count).by(1)
        .and change(Authentication, :count).by(1)

      user = User.find_by(email: 'ada@example.com')
      expect(user.username).to eq('Ada Lovelace')
      authentication = user.authentications.first
      expect(authentication.provider).to eq('twitter_oauth2')
      expect(authentication.uid).to eq(NEW_UID)
    end

    it 'queries the binding before any write, and does not start a session from creation alone' do
      stub_new_oauth2!
      events = []
      allow(User).to receive(:load_from_provider).and_wrap_original do |original, *args|
        events << [:query_binding, args]
        original.call(*args)
      end
      allow_any_instance_of(User).to receive(:save).and_wrap_original do |original| # rubocop:disable RSpec/AnyInstance
        events << [:save_user]
        original.call
      end
      allow(Authentication).to receive(:create!).and_wrap_original do |original, *args|
        events << [:write_authentication]
        original.call(*args)
      end

      get :test_create_from_twitter_oauth2, params: { code: 'code-123' }

      expect(events.map(&:first)).to eq(%i[query_binding save_user write_authentication])
      # create_from persists the account but, unlike login_from, never signs the
      # user in: there is no session until a later explicit login.
      expect(session[:user_id]).to be_nil
    end

    it 'on a user-save storage error writes no authentication and starts no session' do
      stub_new_oauth2!
      allow_any_instance_of(User).to receive(:save) # rubocop:disable RSpec/AnyInstance
        .and_raise(ActiveRecord::StatementInvalid.new('disk I/O error'))

      expect do
        expect do
          get :test_create_from_twitter_oauth2, params: { code: 'code-123' }
        end.to raise_error(ActiveRecord::StatementInvalid)
      end.not_to(change { [User.count, Authentication.count] })

      expect(session[:user_id]).to be_nil
    end

    # Documents current, real behaviour so the migration can plan for it rather
    # than assume atomicity. ActiveRecordAdapter#transaction is `@klass.tap`,
    # i.e. it does not open a DB transaction, so a failure while writing the
    # authentication row does not roll the already-saved user back.
    it 'surfaces an authentication-write failure and leaves the session unset' do
      stub_new_oauth2!
      allow(Authentication).to receive(:create!)
        .and_raise(ActiveRecord::StatementInvalid.new('disk I/O error'))

      expect do
        get :test_create_from_twitter_oauth2, params: { code: 'code-123' }
      end.to raise_error(ActiveRecord::StatementInvalid)

      expect(session[:user_id]).to be_nil
      expect(Authentication.count).to eq(0)
      # Known limitation carried by the existing adapter (no real transaction):
      # the user row may already be persisted. See docs/migration criteria.
      expect(User.count).to eq(1)
    end
  end

  # ---------------------------------------------------------------------------
  # 5. Control case: the user abandons the OAuth 2 consent window.
  # ---------------------------------------------------------------------------
  describe 'abandoned consent (control)' do
    it 'raises at token exchange, performs no lookup or write, and starts no session' do
      client = instance_double(OAuth2::Client)
      strategy = instance_double(OAuth2::Strategy::AuthCode)
      error_response = double('oauth2_error_response',
                              error: 'access_denied', parsed: {}, status: 400)
      allow(OAuth2::Client).to receive(:new).and_return(client)
      allow(client).to receive(:auth_code).and_return(strategy)
      allow(strategy).to receive(:get_token).and_raise(OAuth2::Error.new(error_response))

      expect(User).not_to receive(:load_from_provider)
      expect do
        get :test_login_from_twitter_oauth2, params: { code: 'denied' }
      end.to raise_error(OAuth2::Error)

      expect(User.count).to eq(0)
      expect(Authentication.count).to eq(0)
      expect(session[:user_id]).to be_nil
    end
  end

  # ---------------------------------------------------------------------------
  # 6. Coexistence: the OAuth 1 callback must stay mounted during cutover so an
  #    in-flight OAuth 1 window (whose request token lives in the old session)
  #    can still finish against the legacy binding.
  # ---------------------------------------------------------------------------
  describe 'legacy callback coexistence' do
    it 'still completes an OAuth 1 login through the old callback after the OAuth 2 provider is configured' do
      legacy_user
      stub_legacy_oauth1!

      expect do
        get :test_login_from_legacy_twitter,
            params: { oauth_verifier: 'verifier' },
            session: { request_token: 'rt', request_token_secret: 'rts' }
      end.not_to(change { Authentication.count })

      expect(flash[:notice]).to eq('Success!')
      expect(session[:user_id]).to eq(legacy_user.id.to_s)
    end
  end
end
