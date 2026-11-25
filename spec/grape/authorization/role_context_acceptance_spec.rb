# frozen_string_literal: true

require 'grape'

# End-to-end acceptance for FB-20261120-SEC-JW-123:
#
# Two approved identity sources authenticate the same user name. Only the
# registered management source can compose the +:admin+ role, and even then
# only for the API version whose map elevates the attested role and only on a
# mount declaration that does not ceiling it away. Parent and child Grape APIs
# are mounted minimally; the same child is mounted three times to prove local
# overrides never cross into a sibling mount. Every authentication call and
# every business block leaves a record in the shared audit log.

RSpec.describe Grape::Authorization, 'composite identity role context' do
  let(:audit) { [] }

  let(:bearer_strategy) do
    Class.new do
      def initialize(app, &verifier)
        @app = app
        @verifier = verifier
      end

      def call(env)
        token = env['HTTP_AUTHORIZATION'].to_s[/\ABearer (.+)\z/, 1]
        return @app.call(env) if @verifier.call(token)

        [401, { 'content-type' => 'text/plain', 'www-authenticate' => 'Bearer realm="feedback"' }, ['Unauthorized']]
      end
    end
  end

  let(:ledger) do
    Class.new do
      def identity_for(token)
        return unless token.to_s.start_with?('ledger-')

        Grape::Authorization::Identity.new(
          name: token.split('-', 2).last, source: :ledger, roles: %i[reader steward]
        )
      end
    end.new
  end

  let(:desk) do
    Class.new do
      def identity_for(token)
        return unless token.to_s.start_with?('desk-')

        Grape::Authorization::Identity.new(
          name: token.split('-', 2).last, source: :desk, roles: %i[reader steward]
        )
      end
    end.new
  end

  let(:child_api) do
    events = audit
    Class.new(Grape::API) do
      version %w[v1 v2], using: :header, vendor: 'feedback', cascade: false
      format :json

      get :widgets, roles: :reader do
        events << [:business, :read, authorization_context.to_h]
        { widget: true, source: authorization_context.source }
      end

      post :publish, roles: :admin do
        events << [:business, :publish, authorization_context.to_h]
        { published: true, by: authorization_context.name }
      end

      get :audit, roles: :auditor do
        events << [:business, :audit, authorization_context.to_h]
        { audited: true, mount: authorization_context.mount_label }
      end
    end
  end

  let(:app) do
    events = audit
    ledger_authenticator = ledger
    desk_authenticator = desk
    child = child_api

    Class.new(Grape::API) do
      format :json

      identity_source :ledger, management: true
      identity_source :desk
      version_role_map 'v1' => { steward: :admin }, 'v2' => { steward: :auditor }

      auth :role_context_bearer do |token|
        if token.nil?
          events << [:authentication, nil, nil, :missing]
          next false
        end

        identity = ledger_authenticator.identity_for(token)
        events << [:authentication, :ledger, identity&.name, identity ? :approved : :rejected]

        unless identity
          identity = desk_authenticator.identity_for(token)
          events << [:authentication, :desk, identity&.name, identity ? :approved : :rejected]
        end

        if identity
          authenticate_identity(identity)
          true
        else
          events << [:authentication, nil, nil, :denied]
          false
        end
      end

      mount({ child => '/console' })
      mount({ child => '/floor' }, authorization: { ceiling: :reader, label: 'floor-kiosk' })
      mount({ child => '/booth' }, authorization: { grant: :auditor, label: 'audit-booth' })
    end
  end

  before do
    Grape::Middleware::Auth::Strategies.add(:role_context_bearer, bearer_strategy)
  end

  def authorization_for(user)
    { 'HTTP_AUTHORIZATION' => "Bearer #{user}" }
  end

  let(:v1) { { 'HTTP_ACCEPT' => 'application/vnd.feedback-v1+json' } }
  let(:v2) { { 'HTTP_ACCEPT' => 'application/vnd.feedback-v2+json' } }

  describe 'ordinary reads' do
    it 'allow the identity from the registered management source' do
      get '/console/widgets', {}, authorization_for('ledger-ada').merge(v1)
      expect(last_response).to be_successful
      expect(JSON.parse(last_response.body)['source']).to eq('ledger')
    end

    it 'allow the identity from the other approved source' do
      get '/console/widgets', {}, authorization_for('desk-ada').merge(v1)
      expect(last_response).to be_successful
      expect(JSON.parse(last_response.body)['source']).to eq('desk')
    end

    it 'rejects requests with no credentials before any business block' do
      get '/console/widgets', {}, v1
      expect(last_response.status).to eq(401)
      expect(audit.map(&:first)).to eq([:authentication])
      expect(audit.first).to eq([:authentication, nil, nil, :missing])
    end
  end

  describe 'management actions' do
    it 'allow the registered source on the elevating version and unrestricted mount' do
      post '/console/publish', {}, authorization_for('ledger-ada').merge(v1)
      expect(last_response.status).to eq(201)
    end

    it 'deny the other approved source even with the same user name and asserted role' do
      post '/console/publish', {}, authorization_for('desk-ada').merge(v1)
      expect(last_response.status).to eq(403)
    end

    it 'deny the registered source on a version whose map does not elevate to admin' do
      post '/console/publish', {}, authorization_for('ledger-ada').merge(v2)
      expect(last_response.status).to eq(403)
    end

    it 'deny the registered source when the mount declaration ceilings roles to reader' do
      post '/floor/publish', {}, authorization_for('ledger-ada').merge(v1)
      expect(last_response.status).to eq(403)
    end

    it 'does not let a ceiling on one mount touch the sibling console mount' do
      post '/floor/publish', {}, authorization_for('ledger-ada').merge(v1)
      post '/console/publish', {}, authorization_for('ledger-ada').merge(v1)
      expect(audit.select { |entry| entry[0] == :business }.map { |entry| entry[1] }).to eq([:publish])
      expect(last_response.status).to eq(201)
    end
  end

  describe 'mount-local grants and sibling isolation' do
    it 'withhold the granted role from the sibling console mount' do
      get '/console/audit', {}, authorization_for('ledger-ada').merge(v1)
      expect(last_response.status).to eq(403)
    end

    it 'apply the grant on the mount that declares it' do
      get '/booth/audit', {}, authorization_for('ledger-ada').merge(v1)
      expect(last_response.status).to eq(200)
      expect(JSON.parse(last_response.body)['mount']).to eq('audit-booth')
    end

    it 'keep the grant on its own mount when sibling mounts are hit interleaved' do
      get '/booth/audit', {}, authorization_for('ledger-ada').merge(v1)
      expect(last_response.status).to eq(200)
      get '/console/audit', {}, authorization_for('ledger-ada').merge(v1)
      expect(last_response.status).to eq(403)
      get '/booth/audit', {}, authorization_for('ledger-ada').merge(v1)
      expect(last_response.status).to eq(200)

      business_mounts = audit.select { |entry| entry[0] == :business }.map { |entry| entry[2][:mount_label] }
      expect(business_mounts).to eq(['audit-booth', 'audit-booth'])
    end
  end

  describe 'same user name across sources' do
    it 'never shares an effective role globally by name' do
      post '/console/publish', {}, authorization_for('ledger-ada').merge(v1)
      expect(last_response.status).to eq(201)
      post '/console/publish', {}, authorization_for('desk-ada').merge(v1)
      expect(last_response.status).to eq(403)
      post '/console/publish', {}, authorization_for('ledger-ada').merge(v1)
      expect(last_response.status).to eq(201)

      publish_contexts = audit.select { |entry| entry[0] == :business && entry[1] == :publish }
      expect(publish_contexts.size).to eq(2)
      expect(publish_contexts.map { |entry| entry[2][:source] }).to eq(%i[ledger ledger])
    end
  end

  describe 'audit trail' do
    it 'records every authentication and the one business block that ran' do
      post '/console/publish', {}, authorization_for('ledger-ada').merge(v1)
      expect(last_response.status).to eq(201)

      expect(audit.first(2)).to eq([
        [:authentication, :ledger, 'ada', :approved],
        [:business, :publish, {
          name: 'ada',
          source: :ledger,
          version: 'v1',
          mount_path: '/console',
          mount_label: nil,
          effective_roles: %i[admin reader steward]
        }]
      ])
    end

    it 'records the rejected source call and no business block on denial' do
      post '/console/publish', {}, authorization_for('desk-ada').merge(v1)
      expect(last_response.status).to eq(403)

      expect(audit).to eq([
        [:authentication, :ledger, nil, :rejected],
        [:authentication, :desk, 'ada', :approved]
      ])
    end
  end
end
