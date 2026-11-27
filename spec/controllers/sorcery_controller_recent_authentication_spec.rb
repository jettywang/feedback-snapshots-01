# frozen_string_literal: true

require 'spec_helper'

describe SorceryController, type: :controller do
  let!(:user) { User.create!(username: 'duty', email: 'duty@example.com', password: 'password') }

  # ----------------- RECENT (STEP-UP) AUTHENTICATION -----------------------
  context 'with recent authentication features' do
    before(:all) do
      MigrationHelper.migrate("#{Rails.root}/db/migrate/remember_me")
      MigrationHelper.migrate("#{Rails.root}/db/migrate/recent_authentication")
      sorcery_reload!([:remember_me, :session_timeout, :recent_authentication])
      sorcery_controller_property_set(:session_timeout, 10 * 60)
      sorcery_controller_property_set(:recent_authentication_timeout, 30)
    end

    after(:all) do
      MigrationHelper.rollback("#{Rails.root}/db/migrate/recent_authentication")
      MigrationHelper.rollback("#{Rails.root}/db/migrate/remember_me")
    end

    after do
      Sorcery::RecentAuthenticationRecord.delete_all
      sorcery_controller_property_set(:recent_authentication_timeout, 30)
      sorcery_controller_property_set(:recent_authentication_revocation_on_logout, :session)
      sorcery_controller_property_set(:recent_authentication_revocation_on_timeout, :session)
      sorcery_controller_property_set(:session_timeout, 10 * 60)
    end

    def remember_user_in_new_terminal
      session[:user_id] = user.id.to_s
      controller.remember_me!
      session[:user_id] = nil
      controller.instance_eval { remove_instance_variable(:@current_user) if defined?(@current_user) }
    end

    it 'restores the ordinary identity from the remember-me cookie without granting recent authentication' do
      remember_user_in_new_terminal

      get :test_login_from_cookie

      expect(response).to be_successful
      expect(controller.logged_in?).to be true
      expect(controller.recent_authentication_valid_for?(:sensitive)).to be false
    end

    it 'allows ordinary pages after restoration but blocks a sensitive action until confirmed' do
      remember_user_in_new_terminal
      get :test_login_from_cookie

      get :test_should_be_logged_in
      expect(response).to be_successful

      get :test_recent_authentication_sensitive
      expect(response).to be_forbidden
    end

    it 'requires at least one operation to confirm' do
      login_user user

      expect { controller.confirm_recent_authentication! }.to raise_error(ArgumentError)
    end

    it 'does not confirm anything when the visitor is signed out' do
      session[:user_id] = nil

      expect(controller.confirm_recent_authentication!(:sensitive)).to be false
      expect(Sorcery::RecentAuthenticationRecord.count).to eq 0
    end

    it 'records the confirmation time, operation and session for the confirmed terminal' do
      login_user user
      get :test_recent_authentication_confirm, params: { operation: 'sensitive' }

      record = Sorcery::RecentAuthenticationRecord.last
      expect(response).to be_successful
      expect(record.user_id).to eq user.id
      expect(record.operation).to eq 'sensitive'
      expect(record.session_id).to eq controller.recent_authentication_session_id
      expect(record.authenticated_at).to be_within(1).of(Time.now.in_time_zone)
      expect(record.expires_at).to be_within(1).of(Time.now.in_time_zone + 30)
    end

    it 'keeps confirmations for several operations without widening them' do
      login_user user
      get :test_recent_authentication_confirm, params: { operation: 'approve_transfer' }
      get :test_recent_authentication_confirm, params: { operation: 'export' }

      get :test_recent_authentication_sensitive, params: { operation: 'approve_transfer' }
      expect(response).to be_successful

      get :test_recent_authentication_sensitive, params: { operation: 'export' }
      expect(response).to be_successful

      get :test_recent_authentication_sensitive, params: { operation: 'delete_account' }
      expect(response).to be_forbidden
    end

    it 'keeps an unrelated terminal without the confirmation blocked' do
      login_user user
      get :test_recent_authentication_confirm

      other_session_token = controller.recent_authentication_session_id
      Sorcery::RecentAuthenticationRecord.where(session_id: other_session_token).delete_all

      get :test_recent_authentication_sensitive

      expect(response).to be_forbidden
    end

    it 'expires the confirmation independently from the ordinary session' do
      login_user user
      get :test_recent_authentication_confirm

      Timecop.travel(Time.now.in_time_zone + 20) do
        get :test_should_be_logged_in
        expect(response).to be_successful

        get :test_recent_authentication_sensitive
        expect(response).to be_successful
      end

      Timecop.travel(Time.now.in_time_zone + 31) do
        get :test_should_be_logged_in
        expect(response).to be_successful

        get :test_recent_authentication_sensitive
        expect(response).to be_forbidden
      end
    end

    it 'requires a fresh confirmation after expiry' do
      login_user user
      get :test_recent_authentication_confirm

      Timecop.travel(Time.now.in_time_zone + 31) do
        get :test_recent_authentication_confirm
        get :test_recent_authentication_sensitive

        expect(response).to be_successful
      end
    end

    it 'only accepts the operation that was confirmed' do
      login_user user
      get :test_recent_authentication_confirm, params: { operation: 'export' }

      get :test_recent_authentication_sensitive, params: { operation: 'export' }
      expect(response).to be_successful

      get :test_recent_authentication_sensitive, params: { operation: 'sensitive' }
      expect(response).to be_forbidden
    end

    it 'revokes the confirmation on logout' do
      login_user user
      get :test_recent_authentication_confirm
      expect(controller.recent_authentication_valid_for?(:sensitive)).to be true

      get :test_logout

      expect(session[:user_id]).to be_nil
      expect(Sorcery::RecentAuthenticationRecord.where(revoked_at: nil)).to be_empty
    end

    it 'applies the configured timeout policy when the ordinary session times out' do
      sorcery_controller_property_set(:session_timeout, 5)
      login_user user
      get :test_recent_authentication_confirm

      Timecop.travel(Time.now.in_time_zone + 6) do
        get :test_should_be_logged_in

        expect(session[:user_id]).to be_nil
        expect(Sorcery::RecentAuthenticationRecord.where(revoked_at: nil)).to be_empty
      end
    end

    it 'can revoke every confirmation of the user on logout when configured to' do
      sorcery_controller_property_set(:recent_authentication_revocation_on_logout, :user)
      login_user user
      get :test_recent_authentication_confirm
      expect(Sorcery::RecentAuthenticationRecord.where(user_id: user.id, revoked_at: nil).count).to eq 1

      get :test_logout

      expect(Sorcery::RecentAuthenticationRecord.where(revoked_at: nil)).to be_empty
    end

    it 'keeps confirmations on logout when the policy is nil' do
      sorcery_controller_property_set(:recent_authentication_revocation_on_logout, nil)
      login_user user
      get :test_recent_authentication_confirm

      get :test_logout

      expect(Sorcery::RecentAuthenticationRecord.where(revoked_at: nil).count).to eq 1
    end

    it 'can revoke every confirmation of the user when the session times out' do
      sorcery_controller_property_set(:session_timeout, 5)
      sorcery_controller_property_set(:recent_authentication_revocation_on_timeout, :user)
      login_user user
      get :test_recent_authentication_confirm

      Timecop.travel(Time.now.in_time_zone + 6) do
        get :test_should_be_logged_in

        expect(session[:user_id]).to be_nil
        expect(Sorcery::RecentAuthenticationRecord.where(revoked_at: nil)).to be_empty
      end
    end

    it 'leaves confirmations alone when the timeout policy is nil' do
      sorcery_controller_property_set(:session_timeout, 5)
      sorcery_controller_property_set(:recent_authentication_revocation_on_timeout, nil)
      login_user user
      get :test_recent_authentication_confirm

      Timecop.travel(Time.now.in_time_zone + 6) do
        get :test_should_be_logged_in

        expect(session[:user_id]).to be_nil
        expect(Sorcery::RecentAuthenticationRecord.where(revoked_at: nil).count).to eq 1
      end
    end

    it 'does not let a login rotate carry the previous confirmation into the new identity' do
      login_user user
      get :test_recent_authentication_confirm
      expect(Sorcery::RecentAuthenticationRecord.where(revoked_at: nil).count).to eq 1

      user2 = User.create!(username: 'other', email: 'other@example.com', password: 'password')
      controller.send(:auto_login, user2)
      controller.send(:after_login!, user2, [])

      expect(controller.recent_authentication_valid_for?(:sensitive)).to be false
      expect(Sorcery::RecentAuthenticationRecord.where(user_id: user2.id, revoked_at: nil)).to be_empty
    end
  end
end
