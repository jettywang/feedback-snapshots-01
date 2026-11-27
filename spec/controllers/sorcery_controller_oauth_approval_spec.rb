# frozen_string_literal: true

require 'spec_helper'
require 'rails_app/app/mailers/sorcery_mailer'

# Exercises the approval boundary between Sorcery's external (OAuth) login and the
# user_activation submodule. Approval is represented by the persisted activation_state:
# only an account that was approved before the handout may receive a session.
describe SorceryController, type: :controller do
  before(:all) do
    MigrationHelper.migrate("#{Rails.root}/db/migrate/external")
    MigrationHelper.migrate("#{Rails.root}/db/migrate/activation")
    MigrationHelper.migrate("#{Rails.root}/db/migrate/remember_me")

    sorcery_reload!(
      %i[user_activation external remember_me],
      user_activation_mailer: SorceryMailer
    )
    sorcery_controller_property_set(:external_providers, [:twitter])
    sorcery_controller_external_property_set(:twitter, :key, 'key')
    sorcery_controller_external_property_set(:twitter, :secret, 'secret')
    sorcery_controller_external_property_set(:twitter, :callback_url, 'http://example.com')
    sorcery_model_property_set(:authentications_class, Authentication)
  end

  after(:all) do
    MigrationHelper.rollback("#{Rails.root}/db/migrate/external")
    MigrationHelper.rollback("#{Rails.root}/db/migrate/remember_me")
    MigrationHelper.rollback("#{Rails.root}/db/migrate/activation")
  end

  before do
    User.sorcery_adapter.delete_all
    Authentication.sorcery_adapter.delete_all
    stub_twitter_requests!
  end

  def stub_twitter_requests!
    consumer = OAuth::Consumer.new('key', 'secret', site: 'http://api.example.com')
    req_token = OAuth::RequestToken.new(consumer)
    acc_token = OAuth::AccessToken.new(consumer)
    response = Object.new
    def response.body
      { 'id' => 123, 'screen_name' => 'nbenari' }.to_json
    end

    session[:request_token] = req_token.token
    session[:request_token_secret] = req_token.secret

    allow(OAuth::Consumer).to receive(:new).and_return(consumer)
    allow(consumer).to receive(:get_request_token).and_return(req_token)
    allow(req_token).to receive(:get_access_token).and_return(acc_token)
    allow(OAuth::RequestToken).to receive(:new).and_return(req_token)
    allow(acc_token).to receive(:get).and_return(response)
  end

  def pending_external_user
    user = create_new_external_user(:twitter, username: 'external_user', email: 'external@example.com')
    expect(user.activation_state).to eq 'pending'
    user
  end

  def approved_external_user
    user = pending_external_user
    user.activate!
    user
  end

  describe 'external account creation' do
    it 'waits for activation and sends no activation needed email' do
      expect do
        pending_external_user
      end.not_to(change { ActionMailer::Base.deliveries.size })
    end

    it 'does not issue an activation token or expiry for external accounts' do
      user = pending_external_user

      expect(user.activation_token).to be_nil
      expect(user.activation_token_expires_at).to be_nil
    end
  end

  describe 'approved path' do
    it 'writes the session for an account approved before the login handoff' do
      user = approved_external_user

      expect(User).to receive(:load_from_provider).with(:twitter, '123').and_return(user)
      get :test_login_from, params: { oauth_verifier: 'verifier' }

      expect(session[:user_id]).to eq user.id.to_s
      expect(flash[:notice]).to eq 'Success!'
    end

    it 'does not set a remember-me cookie when remember was not requested' do
      user = approved_external_user
      expect(User).to receive(:load_from_provider).with(:twitter, '123').and_return(user)

      get :test_login_from, params: { oauth_verifier: 'verifier' }

      expect(cookies.signed['remember_me_token']).to be_nil
    end

    it 'sends the configured approval notification once the approval is persisted' do
      user = pending_external_user

      expect do
        user.activate!
      end.to change { ActionMailer::Base.deliveries.size }.by(1)

      expect(ActionMailer::Base.deliveries.last.subject).to eq 'Your account is now activated'
    end

    it 'records the approval receipt in the database' do
      user = pending_external_user
      token = user.activation_token

      user.activate!

      stored = User.sorcery_adapter.find(user.id)
      expect(stored.activation_state).to eq 'active'
      expect(stored.activation_token).to be_nil
      expect(token).to be_nil
    end
  end

  describe 'pending path' do
    it 'refuses the session for an account that was not approved' do
      user = pending_external_user
      expect(User).to receive(:load_from_provider).with(:twitter, '123').and_return(user)

      get :test_login_from, params: { oauth_verifier: 'verifier' }

      expect(session[:user_id]).to be_nil
      expect(flash[:alert]).to eq 'Failed!'
    end

    it 'leaves no remember-me cookie or token when a pending login asked to be remembered' do
      user = pending_external_user
      allow(User).to receive(:load_from_provider).with(:twitter, '123').and_return(user)

      result = controller.send(:login_from, :twitter, true)

      expect(result).to be false
      expect(session[:user_id]).to be_nil
      expect(cookies.signed['remember_me_token']).to be_nil
      expect(user.reload.remember_me_token).to be_nil
    end

    it 'sends no approval notification' do
      expect do
        pending_external_user
      end.not_to(change { ActionMailer::Base.deliveries.size })
    end
  end

  describe 'database save failure path' do
    it 'sends no approval notification and sets no remember-me cookie' do
      user = pending_external_user
      allow(user.sorcery_adapter).to receive(:save).and_raise(ActiveRecord::StatementInvalid, 'db down')

      expect do
        expect { user.activate! }.to raise_error(ActiveRecord::StatementInvalid)
      end.not_to(change { ActionMailer::Base.deliveries.size })

      expect(cookies.signed['remember_me_token']).to be_nil
      expect(user.reload.remember_me_token).to be_nil
    end

    it 'keeps the stored approval receipt pending and rejects the login afterwards' do
      user = pending_external_user
      allow(user.sorcery_adapter).to receive(:save).and_raise(ActiveRecord::StatementInvalid, 'db down')

      expect { user.activate! }.to raise_error(ActiveRecord::StatementInvalid)

      stored = User.sorcery_adapter.find(user.id)
      expect(stored.activation_state).to eq 'pending'
      expect(user.activation_state).to eq 'pending'

      expect(User).to receive(:load_from_provider).with(:twitter, '123').and_return(stored)
      get :test_login_from, params: { oauth_verifier: 'verifier' }

      expect(session[:user_id]).to be_nil
    end
  end
end
