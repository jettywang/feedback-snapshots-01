# frozen_string_literal: true

require 'spec_helper'

describe 'remembered login and step-up authentication across two terminals', type: :request do
  before(:all) do
    MigrationHelper.migrate("#{Rails.root}/db/migrate/remember_me")
    MigrationHelper.migrate("#{Rails.root}/db/migrate/recent_authentication")
  end

  after(:all) do
    MigrationHelper.rollback("#{Rails.root}/db/migrate/recent_authentication")
    MigrationHelper.rollback("#{Rails.root}/db/migrate/remember_me")
  end

  before do
    sorcery_reload!([:remember_me, :session_timeout, :recent_authentication])
    sorcery_controller_property_set(:session_timeout, 10 * 60)
    sorcery_controller_property_set(:recent_authentication_timeout, 30)
    # Two terminals share the same user; keep one remember-me token valid for both.
    sorcery_model_property_set(:remember_me_token_persist_globally, true)
    User.create!(username: 'duty', email: 'duty@example.com', password: 'password')
  end

  after do
    User.delete_all
    Sorcery::RecentAuthenticationRecord.delete_all
    sorcery_model_property_set(:remember_me_token_persist_globally, false)
  end

  def start_terminal
    terminal = open_session
    terminal.post '/test_login_with_remember_in_login',
                  params: { email: 'duty@example.com', password: 'password', remember: '1' }
    terminal
  end

  def remembered_terminal
    terminal = start_terminal
    # This terminal only keeps the remember-me cookie; its ordinary session is gone.
    terminal.cookies.delete('_app_root_session')
    terminal
  end

  def confirmed_terminal
    terminal = start_terminal
    terminal.get '/test_recent_authentication_confirm'
    terminal
  end

  it 'keeps the remembered terminal ordinary while the confirmed terminal can act' do
    remembered = remembered_terminal
    confirmed = confirmed_terminal

    remembered.get '/test_should_be_logged_in'
    expect(remembered.response).to be_successful

    remembered.get '/test_recent_authentication_sensitive'
    expect(remembered.response).to be_forbidden

    confirmed.get '/test_recent_authentication_sensitive'
    expect(confirmed.response).to be_successful
  end

  it 'keeps both terminals logged in while the confirmation is still fresh' do
    remembered = remembered_terminal
    confirmed = confirmed_terminal

    Timecop.travel(Time.now.in_time_zone + 20) do
      remembered.get '/test_should_be_logged_in'
      confirmed.get '/test_should_be_logged_in'
      confirmed.get '/test_recent_authentication_sensitive'

      expect(remembered.response).to be_successful
      expect(confirmed.response).to be_successful
    end
  end

  it 'requires the confirmed terminal to renew after the confirmation expires' do
    remembered = remembered_terminal
    confirmed = confirmed_terminal

    Timecop.travel(Time.now.in_time_zone + 31) do
      remembered.get '/test_should_be_logged_in'
      confirmed.get '/test_recent_authentication_sensitive'

      expect(remembered.response).to be_successful
      expect(confirmed.response).to be_forbidden

      confirmed.get '/test_recent_authentication_confirm'
      confirmed.get '/test_recent_authentication_sensitive'

      expect(confirmed.response).to be_successful
    end
  end

  it 'revokes the confirmation when the ordinary session times out, even if remember-me restores the user' do
    sorcery_controller_property_set(:session_timeout, 5)
    sorcery_controller_property_set(:recent_authentication_timeout, 600)

    terminal = confirmed_terminal
    expect(Sorcery::RecentAuthenticationRecord.where(revoked_at: nil).count).to eq 1

    Timecop.travel(Time.now.in_time_zone + 6) do
      terminal.get '/test_should_be_logged_in'
      # The remember-me cookie still restores the ordinary identity.
      expect(terminal.response).to be_successful

      terminal.get '/test_recent_authentication_sensitive'
      expect(terminal.response).to be_forbidden

      terminal.get '/test_recent_authentication_confirm'
      terminal.get '/test_recent_authentication_sensitive'
      expect(terminal.response).to be_successful
    end
  end

  it 'applies the ordinary timeout policy without granting the remembered terminal a confirmation' do
    sorcery_controller_property_set(:session_timeout, 5)
    sorcery_controller_property_set(:recent_authentication_timeout, 60)

    remembered = remembered_terminal
    confirmed = confirmed_terminal
    expect(Sorcery::RecentAuthenticationRecord.where(revoked_at: nil).count).to eq 1

    Timecop.travel(Time.now.in_time_zone + 6) do
      confirmed.get '/test_should_be_logged_in'
      expect(confirmed.response).to be_successful

      remembered.get '/test_should_be_logged_in'
      expect(remembered.response).to be_successful
      expect(remembered.session[:user_id]).not_to be_nil

      remembered.get '/test_recent_authentication_sensitive'
      expect(remembered.response).to be_forbidden
    end
  end
end
