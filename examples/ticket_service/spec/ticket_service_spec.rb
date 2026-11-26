# frozen_string_literal: true

$LOAD_PATH.unshift File.expand_path('../../../lib', __dir__)

require 'json'
require 'logger'
require 'rack/test'
require_relative '../app'

OmniAuth.config.logger = Logger.new(File::NULL)

RSpec.describe 'Ticket Service operation permits' do
  let(:audit_log) { TicketService::AuditLog.new }
  let(:registry) { TicketService.build_registry }
  let(:rack_app) { TicketService.build_app(registry: registry, audit_log: audit_log) }

  def new_session
    Rack::Test::Session.new(Rack::MockSession.new(rack_app))
  end

  def login(session, provider)
    session.post "/auth/#{provider}"
    expect(session.last_response.status).to eq(302)
  end

  def json_body(session)
    JSON.parse(session.last_response.body)
  end

  describe 'login via both fictional providers' do
    it 'completes for both tenants and yields identical merged profiles' do
      profiles = {}
      %w[alpha_directory beta_directory].each do |provider|
        session = new_session
        login(session, provider)

        session.get '/profile'
        expect(session.last_response.status).to eq(200)
        profiles[provider] = json_body(session)
      end

      alpha = profiles['alpha_directory']
      beta = profiles['beta_directory']

      # Same person, same placeholder role visible in the merged profile.
      expect(alpha.dig('merged_profile', 'name')).to eq('Casey Jordan')
      expect(alpha['merged_profile']).to eq(beta['merged_profile'])
      expect(alpha.dig('merged_profile', 'role')).to eq('ticket_exporter')
    end
  end

  describe 'export check triggered from the tickets page' do
    it 'grants export only to the principal with an approved claim source' do
      alpha = new_session
      login(alpha, 'alpha_directory')
      alpha.get '/tickets'
      expect(alpha.last_response.status).to eq(200)
      alpha.post '/tickets/export'
      expect(alpha.last_response.status).to eq(200)
      expect(alpha.last_response.content_type).to include('text/csv')
      expect(alpha.last_response.body).to include('Printer on fire')

      beta = new_session
      login(beta, 'beta_directory')
      beta.get '/tickets'
      expect(beta.last_response.status).to eq(200)
      beta.post '/tickets/export'
      expect(beta.last_response.status).to eq(403)
      expect(json_body(beta)['error']).to eq('export_not_permitted')
      expect(json_body(beta).dig('permit', 'status')).to eq('unavailable_no_policy')
    end

    it 'audits which claim layer and which tenant took effect' do
      alpha = new_session
      login(alpha, 'alpha_directory')
      alpha.post '/tickets/export'

      beta = new_session
      login(beta, 'beta_directory')
      beta.post '/tickets/export'

      granted, denied = audit_log.entries

      expect(granted.status).to eq(:granted)
      expect(granted.tenant).to eq('alpha')
      expect(granted.provider).to eq('alpha_directory')
      expect(granted.layer).to eq(:extra)
      expect(granted.key).to eq('role')
      expect(granted.actual).to eq('ticket_exporter')

      expect(denied.status).to eq(:unavailable_no_policy)
      expect(denied.tenant).to eq('beta')
      expect(denied.provider).to eq('beta_directory')
      expect(denied.layer).to be_nil
    end
  end

  describe 'optional permission view' do
    it 'distinguishes anonymous, permitted, and permit-less logins' do
      anonymous = new_session
      anonymous.get '/permits/export'
      expect(json_body(anonymous)).to eq('authenticated' => false, 'permit' => nil)

      beta = new_session
      login(beta, 'beta_directory')
      beta.get '/permits/export'
      beta_permit = json_body(beta)
      expect(beta_permit['authenticated']).to be(true)
      expect(beta_permit.dig('permit', 'granted')).to be(false)
      expect(beta_permit.dig('permit', 'status')).to eq('unavailable_no_policy')

      alpha = new_session
      login(alpha, 'alpha_directory')
      alpha.get '/permits/export'
      alpha_permit = json_body(alpha)
      expect(alpha_permit['authenticated']).to be(true)
      expect(alpha_permit.dig('permit', 'granted')).to be(true)
      expect(alpha_permit.dig('permit', 'status')).to eq('granted')
      expect(alpha_permit.dig('permit', 'layer')).to eq('extra')
      expect(alpha_permit.dig('permit', 'tenant')).to eq('alpha')
    end
  end

  describe TicketService::PermissionView do
    let(:registry) do
      TicketService::PolicyRegistry.new.register(
        tenant: 'alpha', operation: :export_tickets,
        layer: :extra, key: 'role', value: 'ticket_exporter'
      )
    end

    def decision_for(auth, tenant: 'alpha')
      described_class.new(auth, tenant: tenant, registry: registry).decision(:export_tickets)
    end

    it 'reads only the approved layer even when the merged profile would satisfy the check' do
      # The placeholder sits in the profile layer only; merging info+extra
      # would surface it, but the approved source is the extra layer.
      auth = { 'info' => { 'role' => 'ticket_exporter' }, 'extra' => {} }

      decision = decision_for(auth)

      expect(decision.status).to eq(:denied_claim_missing)
      expect(decision).not_to be_granted
    end

    it 'ignores a conflicting value in the unauthenticated layer' do
      auth = {
        'info' => { 'role' => 'ticket_viewer' },
        'extra' => { 'role' => 'ticket_exporter' }
      }

      expect(decision_for(auth)).to be_granted
    end

    it 'reports a mismatch when the approved layer holds another value' do
      auth = { 'info' => {}, 'extra' => { 'role' => 'ticket_viewer' } }

      decision = decision_for(auth)

      expect(decision.status).to eq(:denied_claim_mismatch)
      expect(decision.actual).to eq('ticket_viewer')
    end

    it 'reports unavailable when the tenant has no registered policy' do
      auth = { 'info' => {}, 'extra' => { 'role' => 'ticket_exporter' } }

      expect(decision_for(auth, tenant: 'beta').status).to eq(:unavailable_no_policy)
    end
  end

  describe TicketService::PolicyRegistry do
    it 'rejects claim sources outside the auth hash layers' do
      expect do
        described_class.new.register(
          tenant: 'alpha', operation: :export_tickets,
          layer: :params, key: 'role', value: 'ticket_exporter'
        )
      end.to raise_error(ArgumentError, /layer/)
    end
  end
end
