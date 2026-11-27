# frozen_string_literal: true

require 'spec_helper'

# End-to-end coverage with two independent cookie sessions and two organizations.
# The sessions never share a grant: granting one has no effect on the other, and
# a read allowance in one never authorizes a later write.
describe 'session scope across two local sessions', type: :request do
  before(:all) do
    MigrationHelper.migrate("#{Rails.root}/db/migrate/activity_logging")
    User.reset_column_information
    sorcery_reload!(%i[session_scope activity_logging])
    enable_activity_logging
  end

  def enable_activity_logging
    sorcery_controller_property_set(:register_login_time, true)
    sorcery_controller_property_set(:register_last_activity_time, true)
    sorcery_controller_property_set(:register_last_ip_address, true)
    sorcery_controller_property_set(:register_logout_time, true)
  end

  after(:all) do
    MigrationHelper.rollback("#{Rails.root}/db/migrate/activity_logging")
    SorceryController.committed_scoped_writes = []
    sorcery_controller_property_set(:register_login_time, true)
    sorcery_controller_property_set(:register_last_activity_time, true)
    sorcery_controller_property_set(:register_last_ip_address, true)
    sorcery_controller_property_set(:register_logout_time, true)
  end

  before { SorceryController.committed_scoped_writes = [] }

  let!(:agent) { User.create!(username: 'agent', email: 'agent@example.com', password: 'secret') }
  let!(:colleague) { User.create!(username: 'colleague', email: 'colleague@example.com', password: 'secret') }

  let(:session_a) { ActionDispatch::Integration::Session.new(Rails.application) }
  let(:session_b) { ActionDispatch::Integration::Session.new(Rails.application) }

  def body_for(response)
    JSON.parse(response.body)
  end

  def login(session, user)
    session.get '/test_login', params: { email: user.email, password: 'secret' }
    expect(session.response).to have_http_status(:ok)
  end

  def grant(session, organization, actions, expires_in: nil)
    params = { organization:, actions: }
    params[:expires_in] = expires_in if expires_in
    session.post '/test_session_scope_grant', params:
  end

  it 'allows a scoped read, keeps writes out, and leaves the other session and organization untouched' do
    login(session_a, agent)
    login(session_b, colleague)

    grant(session_a, 'org-alpha', ['read'])
    expect(JSON.parse(session_a.response.body)['actions']).to eq(['read'])

    session_a.get '/test_session_scope_read', params: { organization: 'org-alpha' }
    expect(session_a.response).to have_http_status(:ok)
    expect(body_for(session_a.response)['allowed']).to be true

    # The allowed read does not itself widen the grant.
    session_a.get '/test_session_scope_write', params: { organization: 'org-alpha' }
    expect(session_a.response).to have_http_status(:forbidden)
    expect(body_for(session_a.response)['reason']).to eq('action_not_granted')

    # The read grant is scoped to one organization only.
    session_a.get '/test_session_scope_read', params: { organization: 'org-beta' }
    expect(session_a.response).to have_http_status(:forbidden)
    expect(body_for(session_a.response)['reason']).to eq('out_of_scope')

    # The colleague's session shares neither the grant nor the organization.
    session_b.get '/test_session_scope_read', params: { organization: 'org-alpha' }
    expect(session_b.response).to have_http_status(:forbidden)
    expect(body_for(session_b.response)['reason']).to eq('no_grant')

    grant(session_b, 'org-beta', %w[read write])
    session_b.post '/test_session_scope_prepare_write', params: { organization: 'org-beta', payload: 'second-org' }
    expect(session_b.response).to have_http_status(:ok)

    session_b.post '/test_session_scope_commit_write', params: { organization: 'org-beta' }
    expect(session_b.response).to have_http_status(:ok)
    expect(body_for(session_b.response)).to include('committed' => true, 'allowed' => true)

    expect(SorceryController.committed_scoped_writes).to eq(
      [{ 'organization' => 'org-beta', 'payload' => 'second-org' }]
    )

    # Session A still cannot write, and did not inherit session B's write grant.
    session_a.post '/test_session_scope_prepare_write', params: { organization: 'org-alpha', payload: 'sneaky' }
    expect(session_a.response).to have_http_status(:forbidden)
    expect(SorceryController.committed_scoped_writes.size).to eq(1)
  end

  it 'blocks a staged write when the scope narrows before commit, while the other session keeps working' do
    login(session_a, agent)
    login(session_b, colleague)

    grant(session_a, 'org-alpha', %w[read write])
    grant(session_b, 'org-alpha', %w[read write])

    session_a.post '/test_session_scope_prepare_write', params: { organization: 'org-alpha', payload: 'staged-a' }
    expect(session_a.response).to have_http_status(:ok)
    expect(body_for(session_a.response)['allowed']).to be true

    # Before session A commits, the business narrows its grant to read-only.
    session_a.post '/test_session_scope_revoke', params: { organization: 'org-alpha', actions: ['write'] }
    expect(body_for(session_a.response)['revoked']).to be true

    # Revocation leaves the login and activity logging alone.
    session_a.get '/test_session_scope_activity'
    expect(body_for(session_a.response)).to include('logged_in' => true, 'user_id' => agent.id)
    expect(agent.reload.last_activity_at).not_to be_nil

    session_a.post '/test_session_scope_commit_write', params: { organization: 'org-alpha' }
    expect(session_a.response).to have_http_status(:forbidden)
    expect(body_for(session_a.response)).to include('committed' => false, 'reason' => 'action_revoked')
    expect(SorceryController.committed_scoped_writes).to be_empty

    # The other session is unaffected and can still complete its write.
    session_b.post '/test_session_scope_prepare_write', params: { organization: 'org-alpha', payload: 'staged-b' }
    session_b.post '/test_session_scope_commit_write', params: { organization: 'org-alpha' }
    expect(session_b.response).to have_http_status(:ok)
    expect(body_for(session_b.response)['committed']).to be true
    expect(SorceryController.committed_scoped_writes).to eq(
      [{ 'organization' => 'org-alpha', 'payload' => 'staged-b' }]
    )

    # The narrowing left session A's read allowance intact.
    session_a.get '/test_session_scope_read', params: { organization: 'org-alpha' }
    expect(session_a.response).to have_http_status(:ok)
    session_a.post '/test_session_scope_commit_write', params: { organization: 'org-alpha' }
    expect(session_a.response).to have_http_status(:forbidden)
    expect(body_for(session_a.response)).to include('committed' => false, 'reason' => 'action_revoked')
  end

  it 'reports a business-readable reason when the subject changes, without touching the other session' do
    login(session_a, agent)
    grant(session_a, 'org-alpha', ['read'])
    login(session_b, colleague)
    grant(session_b, 'org-beta', ['read'])

    # The same browser session re-authenticates as a colleague without an
    # explicit logout; the old grant must not travel to the new subject.
    login(session_a, colleague)

    session_a.get '/test_session_scope_read', params: { organization: 'org-alpha' }
    expect(session_a.response).to have_http_status(:forbidden)
    expect(body_for(session_a.response)['reason']).to eq('subject_changed')

    # The other session is still on its own grant.
    session_b.get '/test_session_scope_read', params: { organization: 'org-beta' }
    expect(session_b.response).to have_http_status(:ok)
  end

  it 'reports session_expired and keeps the activity log of normal requests' do
    sorcery_reload!(%i[session_scope activity_logging session_timeout])
    sorcery_controller_property_set(:session_timeout, 0.5)
    sorcery_controller_property_set(:session_timeout_from_last_action, true)
    enable_activity_logging
    SorceryController.committed_scoped_writes = []

    login(session_a, agent)
    grant(session_a, 'org-alpha', ['read'])

    session_a.get '/test_session_scope_read', params: { organization: 'org-alpha' }
    expect(session_a.response).to have_http_status(:ok)
    expect(agent.reload.last_login_at).not_to be_nil
    expect(agent.reload.last_activity_at).not_to be_nil

    Timecop.travel(Time.now.in_time_zone + 0.6) do
      session_a.get '/test_session_scope_read', params: { organization: 'org-alpha' }

      expect(session_a.response).to have_http_status(:unauthorized)
      expect(body_for(session_a.response)['reason']).to eq('session_expired')

      session_a.get '/test_session_scope_activity'
      expect(body_for(session_a.response)).to include('logged_in' => false, 'user_id' => nil)
    end

    login(session_b, colleague)
    session_b.get '/test_session_scope_read', params: { organization: 'org-alpha' }
    expect(session_b.response).to have_http_status(:forbidden)
    expect(body_for(session_b.response)['reason']).to eq('no_grant')
  ensure
    sorcery_controller_property_set(:session_timeout, 3600)
    sorcery_controller_property_set(:session_timeout_from_last_action, false)
    sorcery_reload!(%i[session_scope activity_logging])
    enable_activity_logging
  end

  it 'records normal activity for an ordinary in-scope request' do
    login(session_a, agent)
    grant(session_a, 'org-alpha', ['read'])

    expect do
      session_a.get '/test_session_scope_read', params: { organization: 'org-alpha' }
    end.to change { agent.reload.last_activity_at }

    session_a.get '/test_session_scope_activity'
    expect(body_for(session_a.response)).to include(
      'logged_in' => true,
      'user_id' => agent.id,
      'last_login_at' => agent.last_login_at.as_json
    )
  end
end
