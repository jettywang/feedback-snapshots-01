# frozen_string_literal: true

require 'spec_helper'

describe SorceryController, type: :controller do
  let!(:user) { User.create!(username: 'agent_a', email: 'agent_a@example.com', password: 'password') }
  let!(:other_user) { User.create!(username: 'agent_b', email: 'agent_b@example.com', password: 'password') }

  before(:all) { sorcery_reload!([:session_scope]) }
  after(:all) { Sorcery::Controller::Config.session_scope_default_ttl = nil }

  def decision(action, resource = 'org-1')
    controller.session_scope_decision(action, resource:)
  end

  context 'when no grant exists' do
    it 'reports not_authenticated when there is no current user' do
      expect(decision(:read).reason).to eq(:not_authenticated)
      expect(decision(:read).http_status).to eq(:unauthorized)
    end

    it 'reports no_grant for an authenticated user' do
      login_user(user)

      expect(decision(:read).reason).to eq(:no_grant)
      expect(decision(:read).allowed?).to be false
      expect(decision(:read).http_status).to eq(:forbidden)
    end

    it 'cannot grant without a logged-in user' do
      expect do
        controller.grant_session_scope!('org-1', actions: [:read])
      end.to raise_error(Sorcery::Controller::Submodules::SessionScope::NotAuthenticated)
    end
  end

  context 'with a read-only grant' do
    before do
      login_user(user)
      controller.grant_session_scope!('org-1', actions: [:read])
    end

    it 'allows the granted read' do
      expect(decision(:read)).to be_allowed
    end

    it 'does not allow a write on the same resource' do
      result = decision(:write)

      expect(result.reason).to eq(:action_not_granted)
      expect(result).to be_denied
    end

    it 'does not allow reads on another organization' do
      expect(decision(:read, 'org-2').reason).to eq(:out_of_scope)
    end

    it 'maps GET and HEAD requests to read, other methods to write' do
      request.request_method = 'GET'
      expect(controller.session_scope_request_action).to eq(:read)
      expect(controller.session_scope_allows_request?).to be true

      request.request_method = 'HEAD'
      expect(controller.session_scope_request_action).to eq(:read)

      request.request_method = 'POST'
      expect(controller.session_scope_request_action).to eq(:write)
      expect(controller.session_scope_allows_request?).to be false
    end

    it 'does not widen the grant when a read is allowed' do
      before_state = controller.session_scope_grant('org-1').to_h

      expect(decision(:read)).to be_allowed

      expect(controller.session_scope_grant('org-1').to_h).to eq(before_state)
      expect(decision(:write)).to be_denied
    end
  end

  context 'with a read and write grant' do
    before do
      login_user(user)
      controller.grant_session_scope!('org-1', actions: %i[read write])
    end

    it 'allows both actions on the granted resource' do
      expect(decision(:read)).to be_allowed
      expect(decision(:write)).to be_allowed
    end

    it 'revokes only the requested action' do
      expect(controller.revoke_session_scope!([:write], resource: 'org-1')).to be true

      expect(decision(:read)).to be_allowed
      expect(decision(:write).reason).to eq(:action_revoked)
    end

    it 'revokes the whole grant without ending the login session' do
      expect(controller.revoke_session_scope!(resource: 'org-1')).to be true
      expect(controller.logged_in?).to be true
      expect(session[:user_id]).to eq(user.id.to_s)
      expect(decision(:read).reason).to eq(:scope_revoked)
      expect(decision(:write).reason).to eq(:scope_revoked)
    end

    it 'reports an expired grant' do
      controller.grant_session_scope!('org-1', actions: [:read], expires_at: Time.now - 1)

      expect(decision(:read).reason).to eq(:grant_expired)
    end

    it 'applies the configured default ttl to new grants' do
      Sorcery::Controller::Config.session_scope_default_ttl = 60

      grant = controller.grant_session_scope!('org-3', actions: [:read])

      expect(grant.expires_at).to be_within(2).of(Time.now + 60)
    end

    it 'reports ambiguous_scope when several grants exist and no resource is given' do
      controller.grant_session_scope!('org-2', actions: [:read])

      expect(controller.session_scope_decision(:read).reason).to eq(:ambiguous_scope)
      expect(controller.session_scope_decision(:read, resource: 'org-2')).to be_allowed
    end
  end

  context 'when the subject changes' do
    before do
      login_user(user)
      controller.grant_session_scope!('org-1', actions: [:read])
    end

    it 'rejects the grant for another user in the same session' do
      controller.send(:auto_login, other_user)

      result = decision(:read)

      expect(result.reason).to eq(:subject_changed)
      expect(result.http_status).to eq(:forbidden)
    end
  end

  context 'when the session logs in again' do
    before do
      login_user(user)
      controller.grant_session_scope!('org-1', actions: [:read])
    end

    it 'keeps the grant when the same subject logs in again' do
      controller.send(:login, 'agent_a@example.com', 'password')

      expect(controller.session_scope_grants).not_to be_empty
      expect(decision(:read)).to be_allowed
    end

    it 'drops the grant and reports subject_changed when another subject logs in' do
      controller.send(:login, 'agent_b@example.com', 'password')

      expect(controller.session_scope_grants).to be_empty
      expect(decision(:read).reason).to eq(:subject_changed)
    end
  end

  describe '#authorize_session_scope!' do
    before do
      login_user(user)
      controller.grant_session_scope!('org-1', actions: [:read])
    end

    it 'returns the decision when allowed' do
      expect(controller.authorize_session_scope!(:read, resource: 'org-1')).to be_allowed
    end

    it 'raises Denied with the business reason when not allowed' do
      expect do
        controller.authorize_session_scope!(:write, resource: 'org-1')
      end.to raise_error(Sorcery::Controller::Submodules::SessionScope::Denied) { |error|
        expect(error.reason).to eq(:action_not_granted)
        expect(error.decision.action).to eq('write')
      }
    end
  end

  describe 'session timeout integration' do
    before(:all) do
      sorcery_reload!([:session_scope, :session_timeout])
      sorcery_controller_property_set(:session_timeout, 0.5)
      sorcery_controller_property_set(:session_timeout_from_last_action, true)
    end

    after(:all) do
      sorcery_controller_property_set(:session_timeout, 3600)
      sorcery_controller_property_set(:session_timeout_from_last_action, false)
      sorcery_reload!([:session_scope])
    end

    it 'reports session_expired on the next request after the timeout' do
      login_user(user)
      controller.grant_session_scope!('org-1', actions: [:read])

      Timecop.travel(Time.now.in_time_zone + 0.6) do
        get :test_session_scope_read, params: { organization: 'org-1' }

        expect(response).to have_http_status(:unauthorized)
        expect(JSON.parse(response.body)['reason']).to eq('session_expired')
        expect(session[:user_id]).to be_nil
      end
    end

    it 'reports session_invalidated when active sessions are invalidated' do
      sorcery_controller_property_set(:session_timeout_invalidate_active_sessions_enabled, true)
      login_user(user)
      controller.grant_session_scope!('org-1', actions: [:read])
      allow(user).to receive(:invalidate_sessions_before) { Time.now.in_time_zone }

      get :test_session_scope_read, params: { organization: 'org-1' }

      expect(response).to have_http_status(:unauthorized)
      expect(JSON.parse(response.body)['reason']).to eq('session_invalidated')
      expect(session[:user_id]).to be_nil
    end
  end
end
