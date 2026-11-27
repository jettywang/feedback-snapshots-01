# frozen_string_literal: true

require 'spec_helper'

# Two local sessions reproduce the reset flow:
#
# * Session A completes the password reset.
# * Session B tries to keep using credentials issued before the reset.
#
# A rollback comparison shows that an uncommitted change leaves every old login
# exactly as valid as before the attempt.
describe SorceryController, type: :controller do
  before(:all) do
    MigrationHelper.migrate("#{Rails.root}/db/migrate/remember_me")
    MigrationHelper.migrate("#{Rails.root}/db/migrate/reset_password")
    MigrationHelper.migrate("#{Rails.root}/db/migrate/invalidate_active_sessions")

    sorcery_reload!([:reset_password, :remember_me], reset_password_mailer: SorceryMailer)
    User.sorcery_config.reset_password_invalidate_active_sessions_enabled = true
  end

  after(:all) do
    User.sorcery_config.reset_password_invalidate_active_sessions_enabled = false
    MigrationHelper.rollback("#{Rails.root}/db/migrate/invalidate_active_sessions")
    # Roll back in descending version order: MigrationContext#rollback on one
    # path removes the newest version recorded in schema_migrations.
    MigrationHelper.rollback("#{Rails.root}/db/migrate/remember_me")
    MigrationHelper.rollback("#{Rails.root}/db/migrate/reset_password")
  end

  let(:password) { 'secret' }
  let(:user) { User.create!(username: 'gizmo', email: 'gizmo@example.com', password: password) }

  # Creates a real signed remember-me cookie by logging in with remember=true.
  def signed_remember_cookie(email = user.email, pass = password)
    session = ActionDispatch::Integration::Session.new(Rails.application)
    session.post '/test_login_with_remember', params: { email: email, password: pass }
    session.cookies['remember_me_token']
  end

  def session_with_cookie(cookie)
    ActionDispatch::Integration::Session.new(Rails.application).tap do |session|
      session.cookies['remember_me_token'] = cookie
    end
  end

  def log_in_with_password(email = user.email, pass = password)
    ActionDispatch::Integration::Session.new(Rails.application).tap do |session|
      session.get '/test_login', params: { email: email, password: pass }
    end
  end

  describe 'two local sessions' do
    it 'terminates every login that used the old credentials and keeps the initiating session usable' do
      old_cookie = signed_remember_cookie
      old_token = user.reload.remember_me_token
      user.generate_reset_password_token!

      # Session A logs in with the password and completes the reset.
      log_in = log_in_with_password
      log_in.post '/test_reset_password', params: { token: user.reload.reset_password_token, password: 'new-password' }
      expect(log_in.response).to be_successful

      # The committed change rotated the persistent login and recorded the cutoff.
      expect(user.reload.invalidate_sessions_before).to be_present
      expect(user.remember_me_token).to be_present
      expect(user.remember_me_token).not_to eq old_token
      expect(user.valid_password?('new-password')).to be true
      expect(user.valid_password?('secret')).to be false

      # The initiating session finishes the flow without logging in again.
      log_in.get '/test_should_be_logged_in'
      expect(log_in.response).to be_successful

      # The other session, restored from the old persistent login, is gone.
      other = session_with_cookie(old_cookie)
      other.get '/test_should_be_logged_in'

      expect(other.response).to be_redirect
      expect(other.cookies['remember_me_token'].to_s).to be_empty
    end

    it 'invalidates another signed-in session on its next request' do
      old_cookie = signed_remember_cookie
      user.generate_reset_password_token!

      # Session B is already signed in through its own session cookie.
      other = log_in_with_password
      other.get '/test_should_be_logged_in'
      expect(other.response).to be_successful

      log_in = log_in_with_password
      log_in.post '/test_reset_password', params: { token: user.reload.reset_password_token, password: 'new-password' }
      expect(log_in.response).to be_successful

      # The in-flight request from the old session is treated like a logout.
      other.get '/test_should_be_logged_in'
      expect(other.response).to be_redirect

      # And the old persistent login cannot resurrect it.
      replay = session_with_cookie(old_cookie)
      replay.get '/test_should_be_logged_in'
      expect(replay.response).to be_redirect
    end

    it 'does not leave a stale cookie usable after the reset' do
      old_cookie = signed_remember_cookie
      user.generate_reset_password_token!

      log_in = log_in_with_password
      log_in.post '/test_reset_password', params: { token: user.reload.reset_password_token, password: 'new-password' }
      expect(log_in.response).to be_successful

      replay = session_with_cookie(old_cookie)
      replay.get '/test_login_from_cookie'

      # The old token no longer resolves; the cookie is cleared rather than reused.
      expect(replay.response).to be_successful
      expect(replay.cookies['remember_me_token'].to_s).to be_empty
      expect(replay.request.session[:user_id]).to be_nil
    end

    it 're-issues a persistent login only to a browser that already had one' do
      user.generate_reset_password_token!

      browser = session_with_cookie(signed_remember_cookie)
      browser.get '/test_should_be_logged_in'
      expect(browser.response).to be_successful

      browser.post '/test_reset_password', params: { token: user.reload.reset_password_token, password: 'new-password' }
      expect(browser.response).to be_successful

      new_cookie = browser.cookies['remember_me_token']
      expect(new_cookie).to be_present

      restored = session_with_cookie(new_cookie)
      restored.get '/test_should_be_logged_in'
      expect(restored.response).to be_successful
    end

    it 'does not grant a persistent login to a browser that had none' do
      user.generate_reset_password_token!

      log_in = log_in_with_password
      expect(log_in.cookies['remember_me_token'].to_s).to be_empty

      log_in.post '/test_reset_password', params: { token: user.reload.reset_password_token, password: 'new-password' }
      expect(log_in.response).to be_successful

      expect(log_in.cookies['remember_me_token'].to_s).to be_empty
      log_in.get '/test_should_be_logged_in'
      expect(log_in.response).to be_successful
    end
  end

  describe 'rollback comparison' do
    it 'keeps the old password, token and session validity when the change is rolled back' do
      old_cookie = signed_remember_cookie
      user.generate_reset_password_token!

      log_in = log_in_with_password
      log_in.post '/test_reset_password_rolled_back', params: { token: user.reload.reset_password_token, password: 'other-password' }

      expect(user.reload.invalidate_sessions_before).to be_nil
      expect(user.valid_password?('secret')).to be true
      expect(user.valid_password?('other-password')).to be false

      log_in.get '/test_should_be_logged_in'
      expect(log_in.response).to be_successful

      other = session_with_cookie(old_cookie)
      other.get '/test_should_be_logged_in'
      expect(other.response).to be_successful
    end

    it 'keeps an old cookie usable after a failed save that was not promoted to a change' do
      old_cookie = signed_remember_cookie
      allow_any_instance_of(User).to receive(:save).and_return(false) # rubocop:disable RSpec/AnyInstance

      user.change_password('other-password')

      expect(user.password_change_invalidated_at).to be_nil
      expect(user.reload.invalidate_sessions_before).to be_nil
      expect(user.valid_password?('secret')).to be true

      other = session_with_cookie(old_cookie)
      other.get '/test_should_be_logged_in'
      expect(other.response).to be_successful
    end
  end

  describe 'wiring' do
    it 'stays inert when the model side of the submodule is not loaded' do
      sorcery_reload!([:session_timeout])
      other_user = User.create!(username: 'other', email: 'other@example.com', password: 'secret')

      expect(User.sorcery_config).not_to respond_to(:reset_password_invalidate_active_sessions_enabled)

      controller.send(:auto_login, other_user)
      get :test_should_be_logged_in

      expect(response).to be_successful
    ensure
      sorcery_reload!([:reset_password, :remember_me], reset_password_mailer: SorceryMailer)
      User.sorcery_config.reset_password_invalidate_active_sessions_enabled = true
    end
  end

  describe 'opt-in behavior' do
    it 'leaves existing reset and logout behavior unchanged when disabled' do
      User.sorcery_config.reset_password_invalidate_active_sessions_enabled = false
      old_cookie = signed_remember_cookie
      user.generate_reset_password_token!

      log_in = log_in_with_password
      log_in.post '/test_reset_password', params: { token: user.reload.reset_password_token, password: 'new-password' }

      expect(user.reload.invalidate_sessions_before).to be_nil
      expect(user.valid_password?('new-password')).to be true

      other = session_with_cookie(old_cookie)
      other.get '/test_should_be_logged_in'
      expect(other.response).to be_successful

      # Ordinary logout still works and only affects the current session.
      log_in.get '/test_logout'
      log_in.get '/test_should_be_logged_in'
      expect(log_in.response).to be_redirect

      other.get '/test_should_be_logged_in'
      expect(other.response).to be_successful
    ensure
      User.sorcery_config.reset_password_invalidate_active_sessions_enabled = true
    end

    it 'does not change sessions when no password is submitted' do
      user.generate_reset_password_token!
      token = user.reset_password_token

      user.change_password(nil)

      expect(user.reload.invalidate_sessions_before).to be_nil
      expect(user.reset_password_token).to eq token
    end
  end
end
