# frozen_string_literal: true

require 'grape'

RSpec.describe Grape::DSL::Roles do
  def basic_app(&)
    Class.new(Grape::API) do
      format :json
      http_basic(realm: 'test') do |name, _password|
        authenticate_identity(
          Grape::Authorization::Identity.new(name:, source: :legacy, roles: name == 'boss' ? %i[admin] : %i[reader])
        )
        true
      end
      instance_eval(&)
    end
  end

  def auth_header(name)
    { 'HTTP_AUTHORIZATION' => "Basic #{["#{name}:x"].pack('m0')}" }
  end

  let(:app) { api }

  context 'standalone role conditions' do
    let(:api) do
      basic_app do
        require_role :admin
        get('/secret') { { ok: true } }
      end
    end

    it 'passes when the identity carries the role without any source policy' do
      get '/secret', {}, auth_header('boss')
      expect(last_response).to be_successful
    end

    it 'denies an authenticated identity missing the role with 403' do
      get '/secret', {}, auth_header('erin')
      expect(last_response).to be_forbidden
    end
  end

  context 'when no authentication produced an identity' do
    let(:api) do
      Class.new(Grape::API) do
        format :json
        require_role :admin
        get('/secret') { { ok: true } }
      end
    end

    it 'answers 401 rather than treating the missing identity as authorized' do
      get '/secret'
      expect(last_response).to be_unauthorized
    end
  end

  context 'inline route roles' do
    let(:api) do
      basic_app do
        get('/read', roles: :reader) { { ok: true } }
        get('/manage', roles: %i[admin superuser]) { { ok: true } }
      end
    end

    it 'accepts a single role' do
      get '/read', {}, auth_header('erin')
      expect(last_response).to be_successful
    end

    it 'treats an array as ANY match' do
      get '/manage', {}, auth_header('boss')
      expect(last_response).to be_successful
    end

    it 'rejects when none of the roles match' do
      get '/manage', {}, auth_header('erin')
      expect(last_response).to be_forbidden
    end
  end

  context 'context predicates and helpers' do
    let(:api) do
      basic_app do
        require_role { |context| context.name == 'root' || context.role?(:admin) }
        get('/rootish') { { roles: effective_roles, can: has_role?(:admin) } }
      end
    end

    it 'yields the request context to the predicate and helpers' do
      get '/rootish', {}, auth_header('boss')
      expect(last_response).to be_successful
      body = JSON.parse(last_response.body)
      expect(body['can']).to be(true)
      expect(body['roles']).to include('admin')
    end
  end

  context 'namespace scope isolation' do
    let(:api) do
      Class.new(Grape::API) do
        format :json
        http_basic(realm: 'test') do |name, _|
          authenticate_identity(Grape::Authorization::Identity.new(name:, source: :legacy, roles: %i[reader]))
          true
        end

        namespace :open do
          get('/thing') { { open: true } }
        end

        namespace :guarded do
          require_role :admin
          get('/thing') { { guarded: true } }
        end
      end
    end

    it 'enforces the namespace condition only inside that namespace' do
      get '/open/thing', {}, auth_header('erin')
      expect(last_response).to be_successful

      get '/guarded/thing', {}, auth_header('erin')
      expect(last_response).to be_forbidden
    end
  end
end
