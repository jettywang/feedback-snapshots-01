# frozen_string_literal: true

describe Grape::DSL::Authorization do
  subject(:app) { Class.new(Grape::API) }

  describe '.authorize' do
    it 'requires a block' do
      expect { app.authorize(:read) }.to raise_error(ArgumentError, 'authorize requires a block')
    end

    it 'registers a named authorizer on the scope settings' do
      block = proc {}
      app.authorize(:read, &block)

      expect(app.inheritable_setting.authorizers).to eq([[:read, block]])
    end
  end

  describe 'running an endpoint' do
    it 'runs each authorizer outermost scope first' do
      order = []
      app.authorize(:outer) { order << "outer:#{authorization_name}" }
      app.namespace :accounts do
        authorize(:inner) { order << "inner:#{authorization_name}" }
        get { status 200 }
      end

      get '/accounts'

      expect(last_response).to be_successful
      expect(order).to eq(['outer:outer', 'inner:inner'])
    end

    it 'denies with error! before the route block runs' do
      executed = []
      app.authorize { error!('Forbidden', 403) }
      app.get('/accounts') { executed << :route; 'ok' }

      get '/accounts'

      expect(last_response.status).to eq(403)
      expect(last_response.body).to eq('Forbidden')
      expect(executed).to be_empty
    end

    it 'denies before before-filters and validations run' do
      ran = []
      app.authorize { error!('Forbidden', 403) }
      app.before { ran << :before }
      app.params { requires :name, type: String }
      app.post('/accounts') { ran << :route }

      post '/accounts'

      expect(last_response.status).to eq(403)
      expect(ran).to be_empty
    end

    it 'lets a raised exception flow through the usual error middleware' do
      app.authorize { raise 'boom' }
      app.get('/accounts') { 'ok' }

      expect { get '/accounts' }.to raise_error(RuntimeError, 'boom')
    end

    it 'exposes the guarding permission names on the endpoint' do
      app.authorize(:list_accounts) {}
      app.get('/accounts') { authorization_names.map(&:to_s) }

      get '/accounts'

      expect(JSON.parse(last_response.body)).to eq(['list_accounts'])
    end

    it 'resets authorization_name once the block returns' do
      seen_after = nil
      app.authorize(:scoped) {}
      app.get('/accounts') do
        seen_after = authorization_name
        'ok'
      end

      get '/accounts'

      expect(seen_after).to be_nil
    end

    it 'does not run an authorizer declared on a sibling route' do
      app.namespace :accounts do
        authorize { error!('Forbidden', 403) }
        get {}
      end
      app.namespace :billing do
        get { 'billing' }
      end

      get '/billing'

      expect(last_response).to be_successful
      expect(last_response.body).to eq('billing')
    end

    it 'stacks authorizers from every enclosing scope, outermost first' do
      order = []
      app.authorize(:api) { order << :api }
      app.namespace :accounts do
        authorize(:namespace) { order << :namespace }
        scope :read do
          authorize(:route) { order << :route }
          get { status 200 }
        end
      end

      get '/accounts'

      expect(last_response).to be_successful
      expect(order).to eq(%i[api namespace route])
    end

    it 'stops at the first denying block but still runs finally filters' do
      order = []
      app.authorize { order << :first }
      app.authorize { error!('Forbidden', 403) }
      app.authorize { order << :third }
      app.before { order << :before }
      app.finally { order << :finally }
      app.get('/accounts') { order << :route }

      get '/accounts'

      expect(last_response.status).to eq(403)
      expect(order).to eq(%i[first finally])
    end
  end
end
