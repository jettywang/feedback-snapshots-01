# frozen_string_literal: true

require 'spec_helper'

describe SorceryController, :active_record, type: :controller do
  before(:all) do
    MigrationHelper.migrate("#{Rails.root}/db/migrate/external")
    MigrationHelper.migrate("#{Rails.root}/db/migrate/external_grants")

    sorcery_reload!([:external, :external_grants])

    sorcery_controller_property_set(:external_providers, %i[example example_provider])
    sorcery_controller_property_set(:external_grant_purposes, admin_console: 'admin:console')

    %i[example example_provider].each do |provider|
      sorcery_controller_external_property_set(provider, :key, 'key')
      sorcery_controller_external_property_set(provider, :secret, 'secret')
      sorcery_controller_external_property_set(provider, :callback_url, 'http://example.com')
    end

    sorcery_model_property_set(:authentications_class, Authentication)
    sorcery_model_property_set(:grants_class, ExternalGrant)
  end

  after(:all) do
    MigrationHelper.rollback("#{Rails.root}/db/migrate/external_grants")
    MigrationHelper.rollback("#{Rails.root}/db/migrate/external")
  end

  let!(:user) do
    User.create!(username: 'gizmo', email: 'gizmo@example.com', password: 'secret').tap do |u|
      u.authentications.create!(provider: 'example', uid: '123')
      u.authentications.create!(provider: 'example_provider', uid: '123')
    end
  end

  def stub_provider_callback!(provider_name, scope: 'profile admin:console')
    access_token = instance_double(
      OAuth2::AccessToken,
      token: 'abcdef',
      refresh_token: nil,
      expires_at: nil,
      params: { 'scope' => scope }
    )
    provider = Sorcery::Controller::Config.send(provider_name)
    allow(provider).to receive(:process_callback).and_return(access_token)
    allow(provider).to receive(:get_user_hash).and_return(uid: '123', user_info: { 'name' => 'Noam Ben Ari' })
  end

  describe 'callback entry' do
    it 'logs in normally and keeps the identity profile readable the old way' do
      stub_provider_callback!(:example)

      get :test_login_from_example

      expect(session[:user_id]).to eq user.id.to_s
      expect(User.load_from_provider('example', '123')).to eq user
    end

    it 'records only approved purposes as unconfirmed grants' do
      stub_provider_callback!(:example)

      get :test_login_from_example

      expect(user.external_grants.count).to eq 1
      expect(user.external_grant_status('example', :admin_console)).to eq 'unconfirmed'
    end

    it 'skips approved purposes the current scope does not cover' do
      stub_provider_callback!(:example, scope: 'profile')

      get :test_login_from_example

      expect(session[:user_id]).to eq user.id.to_s
      expect(user.external_grant_status('example', :admin_console)).to be_nil
    end
  end

  describe 'admin action guard' do
    it 'denies unconfirmed grants' do
      stub_provider_callback!(:example)
      get :test_login_from_example

      get :test_admin_action

      expect(response).to have_http_status(:forbidden)
      expect(response.body).to include('unconfirmed')
    end

    it 'allows grants confirmed for the purpose, provider and current scope' do
      stub_provider_callback!(:example)
      get :test_login_from_example
      user.confirm_external_grant('example', :admin_console)

      get :test_admin_action

      expect(response).to have_http_status(:ok)
    end

    it 'denies stopped grants' do
      stub_provider_callback!(:example)
      get :test_login_from_example
      user.confirm_external_grant('example', :admin_console)
      user.stop_external_grant('example', :admin_console)

      get :test_admin_action

      expect(response).to have_http_status(:forbidden)
      expect(response.body).to include('stopped')
    end

    it 'denies when the current scope no longer covers the purpose' do
      stub_provider_callback!(:example)
      get :test_login_from_example
      user.confirm_external_grant('example', :admin_console)

      stub_provider_callback!(:example, scope: 'profile')
      get :test_login_from_example

      get :test_admin_action
      expect(response).to have_http_status(:forbidden)
      expect(response.body).to include('scope_insufficient')
    end

    it 'sends re-authorized grants back to unconfirmed when the scope changed' do
      stub_provider_callback!(:example)
      get :test_login_from_example
      user.confirm_external_grant('example', :admin_console)

      stub_provider_callback!(:example, scope: 'profile admin:console extra')
      get :test_login_from_example

      expect(user.external_grant_status('example', :admin_console)).to eq 'unconfirmed'
      get :test_admin_action
      expect(response).to have_http_status(:forbidden)
      expect(response.body).to include('unconfirmed')
    end

    it 'keeps the approved source when the grant update fails' do
      stub_provider_callback!(:example)
      get :test_login_from_example
      user.confirm_external_grant('example', :admin_console)

      # simulate a failing grant update during the next callback sync
      allow_any_instance_of(ExternalGrant).to receive(:save).and_raise(ActiveRecord::RecordNotSaved) # rubocop:disable RSpec/AnyInstance
      stub_provider_callback!(:example, scope: 'profile admin:console extra')
      get :test_login_from_example

      # normal login is still auditable
      expect(session[:user_id]).to eq user.id.to_s

      # the action permission still maps one-to-one to the previously approved grant
      get :test_admin_action
      expect(response).to have_http_status(:ok)
      expect(user.external_grant_status('example', :admin_console)).to eq 'granted'
    end

    it 'does not leak grants across providers' do
      stub_provider_callback!(:example)
      get :test_login_from_example
      user.confirm_external_grant('example', :admin_console)

      stub_provider_callback!(:example_provider)
      get :test_login_from_example_provider
      expect(session[:user_id]).to eq user.id.to_s

      get :test_admin_action
      expect(response).to have_http_status(:forbidden)
      expect(response.body).to include('unconfirmed')
    end

    it 'rejects purposes that were never approved' do
      expect(subject.send(:sorcery_external_grant_failure, :not_approved)).to eq :purpose_not_approved
    end
  end
end
