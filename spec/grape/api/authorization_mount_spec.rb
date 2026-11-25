# frozen_string_literal: true

# Fine-grained authorization across Grape APIs that share one visible path in
# the same Rack app. The router settles which handler actually serves a
# request (a version, or an X-Cascade candidate that let the request pass),
# and only that handler's permission set may run.
describe 'authorization across mounted Grape APIs' do
  include Rack::Test::Methods

  # Records every business block that actually executed and the permission set
  # it ran with, so an example can assert the handler rather than the path.
  let(:audit) { @audit }

  around do |example|
    @audit = []
    example.run
  end

  let(:v1_api) do
    audit = @audit
    Class.new(Grape::API) do
      format :json
      version 'v1', using: :header, vendor: 'acme', cascade: true

      # Existing authentication strategy stays in front of authorization.
      http_basic { |user, password| [user, password] == ['alice', 'secret'] }

      namespace :accounts do
        scope :read do
          authorize :v1_read do
            audit << [:v1, :v1_read, authorization_name]
            error!('Forbidden', 403) unless headers['X-Permission'] == 'v1:read'
          end
          get do
            audit << [:v1, :handler]
            { handler: 'v1', permissions: authorization_names.map(&:to_s) }
          end
        end

        scope :write do
          authorize :v1_write do
            audit << [:v1, :v1_write, authorization_name]
            error!('Forbidden', 403) unless headers['X-Permission'] == 'v1:write'
          end
          post do
            audit << [:v1, :post_handler]
            status 201
            { handler: 'v1-post', permissions: authorization_names.map(&:to_s) }
          end
        end
      end
    end
  end

  let(:v2_api) do
    audit = @audit
    Class.new(Grape::API) do
      format :json
      version 'v2', using: :header, vendor: 'acme', cascade: true

      http_basic { |user, password| [user, password] == ['alice', 'secret'] }

      # Same visible path, different allowed operations: each verb gets its own
      # forked scope so its permission set never stacks onto the other route.
      namespace :accounts do
        scope :read do
          authorize :v2_read do
            audit << [:v2, :v2_read, authorization_name]
            error!('Forbidden', 403) unless headers['X-Permission'] == 'v2:read'
          end
          get do
            audit << [:v2, :get_handler]
            { handler: 'v2-get', permissions: authorization_names.map(&:to_s) }
          end
        end

        scope :write do
          authorize :v2_write do
            audit << [:v2, :v2_write, authorization_name]
            error!('Forbidden', 403) unless headers['X-Permission'] == 'v2:write'
          end
          post do
            audit << [:v2, :post_handler]
            status 201
            { handler: 'v2-post', permissions: authorization_names.map(&:to_s) }
          end
        end
      end
    end
  end

  let(:fallback_api) do
    audit = @audit
    Class.new(Grape::API) do
      format :json

      # Unversioned: it only answers once every versioned candidate has let
      # the request cascade through (an unknown version under header
      # versioning).
      authorize :fallback_read do
        audit << [:fallback, :fallback_read, authorization_name]
        error!('Forbidden', 403) unless headers['X-Permission'] == 'fallback:read'
      end

      get '/accounts' do
        audit << [:fallback, :handler]
        { handler: 'fallback', permissions: authorization_names.map(&:to_s) }
      end
    end
  end

  let(:app) do
    v1 = v1_api
    v2 = v2_api
    fallback = fallback_api
    Rack::Builder.app do
      run Rack::Cascade.new([v2, v1, fallback])
    end
  end

  let(:basic_auth) { encode_basic_auth('alice', 'secret') }

  def get_accounts(version:, permission:)
    get '/accounts', {},
        'HTTP_AUTHORIZATION' => basic_auth,
        'HTTP_ACCEPT' => "application/vnd.acme-#{version}+json",
        'HTTP_X_PERMISSION' => permission
  end

  it 'authenticates with the existing strategy and authorizes the v1 handler' do
    get_accounts(version: 'v1', permission: 'v1:read')

    expect(last_response).to be_successful
    expect(JSON.parse(last_response.body)).to eq(
      'handler' => 'v1',
      'permissions' => ['v1_read']
    )
    expect(audit).to eq([[:v1, :v1_read, :v1_read], [:v1, :handler]])
  end

  it 'runs the v2 permission set, not v1, when the v2 version is negotiated' do
    get_accounts(version: 'v2', permission: 'v2:read')

    expect(last_response).to be_successful
    expect(JSON.parse(last_response.body)).to eq(
      'handler' => 'v2-get',
      'permissions' => ['v2_read']
    )
    expect(audit.map(&:first).uniq).to eq([:v2])
  end

  it 'keeps the authorizers of the same visible path from crossing over' do
    # A v1 permission presented to the v2 handler must not satisfy it.
    get_accounts(version: 'v2', permission: 'v1:read')

    expect(last_response.status).to eq(403)
    expect(audit).to eq([[:v2, :v2_read, :v2_read]])
  end

  it 'denies before the business block executes' do
    get_accounts(version: 'v1', permission: 'v2:read')

    expect(last_response.status).to eq(403)
    expect(audit).to eq([[:v1, :v1_read, :v1_read]])
  end

  it 'rejects an unauthenticated request before authorization is consulted' do
    get '/accounts', {}, 'HTTP_ACCEPT' => 'application/vnd.acme-v1+json'

    expect(last_response).to be_unauthorized
    expect(audit).to be_empty
  end

  it 'checks the operation-specific permission set for POST' do
    post '/accounts', {},
         'HTTP_AUTHORIZATION' => basic_auth,
         'HTTP_ACCEPT' => 'application/vnd.acme-v2+json',
         'HTTP_X_PERMISSION' => 'v2:write'

    expect(last_response.status).to eq(201)
    expect(JSON.parse(last_response.body)).to eq(
      'handler' => 'v2-post',
      'permissions' => ['v2_write']
    )
    expect(audit).to eq(
      [
        [:v2, :v2_write, :v2_write],
        [:v2, :post_handler]
      ]
    )
  end

  it 'routes a POST to the handler of the negotiated version and its write permission' do
    post '/accounts', {},
         'HTTP_AUTHORIZATION' => basic_auth,
         'HTTP_ACCEPT' => 'application/vnd.acme-v1+json',
         'HTTP_X_PERMISSION' => 'v1:write'

    expect(last_response.status).to eq(201)
    expect(JSON.parse(last_response.body)).to eq(
      'handler' => 'v1-post',
      'permissions' => ['v1_write']
    )
    expect(audit).to eq(
      [
        [:v1, :v1_write, :v1_write],
        [:v1, :post_handler]
      ]
    )
  end

  it 'rejects a v1 write token presented to the v2 handler' do
    post '/accounts', {},
         'HTTP_AUTHORIZATION' => basic_auth,
         'HTTP_ACCEPT' => 'application/vnd.acme-v2+json',
         'HTTP_X_PERMISSION' => 'v1:write'

    expect(last_response.status).to eq(403)
    expect(audit).to eq([[:v2, :v2_write, :v2_write]])
  end

  context 'when every versioned candidate lets the request pass' do
    # v3 is declared by no API: the header versioner answers 406 with
    # X-Cascade, so both versioned apps decline and the fallback handles it.
    it 'authorizes the fallback handler with its own permission set' do
      get_accounts(version: 'v3', permission: 'fallback:read')

      expect(last_response).to be_successful
      expect(JSON.parse(last_response.body)).to eq(
        'handler' => 'fallback',
        'permissions' => ['fallback_read']
      )
      expect(audit).to eq([[:fallback, :fallback_read, :fallback_read], [:fallback, :handler]])
    end

    it 'denies on the fallback permission rather than a versioned one' do
      get_accounts(version: 'v3', permission: 'v1:read')

      expect(last_response.status).to eq(403)
      expect(audit).to eq([[:fallback, :fallback_read, :fallback_read]])
    end

    it 'runs no versioned authorizer while the candidates decline' do
      get_accounts(version: 'v3', permission: 'fallback:read')

      expect(audit.map { |entry| entry.first }.uniq).to eq([:fallback])
    end
  end
end
