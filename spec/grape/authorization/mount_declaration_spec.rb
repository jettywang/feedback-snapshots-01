# frozen_string_literal: true

require 'grape'

RSpec.describe Grape::DSL::Mounting, 'mount declarations and local role overrides' do
  let(:child) do
    Class.new(Grape::API) do
      format :json
      get('/manage', roles: :admin) { { allowed: true } }
      get('/read', roles: :reader) { { allowed: true } }
    end
  end

  let(:headers) do
    { 'HTTP_AUTHORIZATION' => "Basic #{['ada:secret'].pack('m0')}" }
  end

  def parent_app(&)
    Class.new(Grape::API) do
      format :json
      http_basic(realm: 'test') do |name, _password|
        authenticate_identity(
          Grape::Authorization::Identity.new(name:, source: :ledger, roles: %i[admin reader])
        )
        true
      end
      identity_source :ledger, management: true
      instance_eval(&)
    end
  end

  it 'applies an explicit two-Hash mount ceiling only to that mount' do
    api_child = child
    app = parent_app do
      mount({ api_child => '/capped' }, authorization: { ceiling: :reader })
      mount({ api_child => '/open' })
    end
    rack = Rack::Test::Session.new(Rack::MockSession.new(app))

    rack.get('/capped/manage', {}, headers)
    expect(rack.last_response).to be_forbidden
    rack.get('/open/manage', {}, headers)
    expect(rack.last_response).to be_successful
  end

  it 'accepts the paren-less rocket form and folds authorization out of the mounts Hash' do
    api_child = child
    app = parent_app do
      mount api_child => '/capped', authorization: { ceiling: :reader }
    end
    rack = Rack::Test::Session.new(Rack::MockSession.new(app))

    rack.get('/capped/read', {}, headers)
    expect(rack.last_response).to be_successful
    rack.get('/capped/manage', {}, headers)
    expect(rack.last_response).to be_forbidden
  end

  it 'applies a namespace role ceiling around a mount without touching siblings' do
    api_child = child
    app = parent_app do
      namespace '/locked' do
        role_ceiling :reader
        mount api_child
      end
      mount({ api_child => '/open' })
    end
    rack = Rack::Test::Session.new(Rack::MockSession.new(app))

    rack.get('/locked/manage', {}, headers)
    expect(rack.last_response).to be_forbidden
    rack.get('/open/manage', {}, headers)
    expect(rack.last_response).to be_successful
  end

  it 'adds a mount-scoped grant that the sibling mount does not receive' do
    grant_child = Class.new(Grape::API) do
      format :json
      get('/audit', roles: :auditor) { { audited: true } }
    end
    app_child = grant_child
    app = parent_app do
      mount({ app_child => '/booth' }, authorization: { grant: :auditor })
      mount({ app_child => '/plain' })
    end
    rack = Rack::Test::Session.new(Rack::MockSession.new(app))

    rack.get('/booth/audit', {}, headers)
    expect(rack.last_response).to be_successful
    rack.get('/plain/audit', {}, headers)
    expect(rack.last_response).to be_forbidden
  end
end
