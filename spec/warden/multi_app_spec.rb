# encoding: utf-8
# frozen_string_literal: true
RSpec.describe "multiple mounted Warden applications" do
  before(:all) do
    load_strategies
  end

  # Two independent Rack applications, each fronted by its own Warden::Manager
  # and mounted at a distinct path. They share one process and one global
  # Warden::Manager callback registry but keep their own local registries.
  let(:employee_app) { build_application(:employee) }
  let(:external_app) { build_application(:external) }

  let(:trace) { [] }

  def build_application(name)
    registry_trace = trace

    inner = lambda do |env|
      warden = env['warden']
      case env['PATH_INFO']
      when '/login'
        warden.authenticate!(:pass, :scope => name)
      when '/logout'
        warden.logout(name)
      end
      [200, {"Content-Type" => "text/plain"}, [name.to_s]]
    end

    failure_app = lambda { |env| [401, {"Content-Type" => "text/plain"}, ["failure"]] }

    Warden::Manager.new(inner, :failure_app => failure_app) do |config|
      config.on_request { |proxy| registry_trace << [name, :local, :on_request] }
      config.after_set_user { |user, auth, opts| registry_trace << [name, :local, :after_set_user, opts[:scope]] }
      config.before_failure { |env, opts| registry_trace << [name, :local, :before_failure] }
      config.before_logout { |user, auth, opts| registry_trace << [name, :local, :before_logout, opts[:scope]] }
      config.after_failed_fetch { |user, auth, opts| registry_trace << [name, :local, :after_failed_fetch, opts[:scope]] }
    end
  end

  def call(manager, path = "/", extra = {})
    env = env_with_params(path).merge('rack.session' => {}).merge(extra)
    manager.call(env)
    env
  end

  before(:each) do
    @globals = {}
    Warden::Manager::CALLBACK_KINDS.each do |kind|
      @globals[kind] = Warden::Manager.public_send("_#{kind}").dup
      Warden::Manager.public_send("_#{kind}").clear
    end
  end

  after(:each) do
    Warden::Manager::CALLBACK_KINDS.each do |kind|
      Warden::Manager.public_send("_#{kind}").replace(@globals[kind])
    end
  end

  describe "registration isolation" do
    it "keeps an application's local callbacks out of the other application" do
      call(external_app)
      employee_names = trace.map(&:first).uniq
      expect(employee_names).to contain_exactly(:external)
      expect(trace).to include([:external, :local, :on_request])
    end

    it "runs the global, operations approved callback for both applications" do
      Warden::Manager.on_request { |proxy| trace << [:shared, :global, :on_request] }

      call(employee_app)
      call(external_app)

      expect(trace.count { |entry| entry == [:shared, :global, :on_request] }).to eq(2)
    end

    it "does not leak a callback added through one config into the other manager" do
      config_a = employee_app.config
      config_a.on_request { |proxy| trace << [:employee_only] }

      call(employee_app)
      call(external_app)

      expect(trace.count { |entry| entry == [:employee_only] }).to eq(1)
    end
  end

  describe "execution order when global, local and scoped callbacks combine" do
    it "runs global callbacks before the application's local callbacks" do
      Warden::Manager.on_request { |proxy| trace << :global_on_request }

      call(employee_app)

      expect(trace).to include(:global_on_request)
      expect(trace.index(:global_on_request)).to be < trace.index([:employee, :local, :on_request])
    end

    it "keeps declaration order within each layer and applies scope conditions" do
      order = []
      Warden::Manager.after_set_user { |u, a, o| order << :global_any }
      Warden::Manager.after_set_user(:scope => :employee) { |u, a, o| order << :global_employee_scope }
      employee_app.callbacks.after_set_user { |u, a, o| order << :local_any }
      employee_app.callbacks.after_set_user(:scope => :employee) { |u, a, o| order << :local_employee_scope }

      call(employee_app, "/login")

      expect(order).to eq([:global_any, :global_employee_scope, :local_any, :local_employee_scope])
    end

    it "honours prepend only inside the local layer, never ahead of globals" do
      order = []
      Warden::Manager.after_set_user { |u, a, o| order << :global }
      employee_app.callbacks.after_set_user { |u, a, o| order << :local_push }
      employee_app.callbacks.prepend_after_set_user { |u, a, o| order << :local_prepend }

      call(employee_app, "/login")

      expect(order).to eq([:global, :local_prepend, :local_push])
    end

    it "preserves the original call order for a single application with no globals" do
      order = []
      app = Warden::Manager.new(lambda { |env| env['warden'].authenticate(:pass); [200, {}, ['ok']] }) do |config|
        config.after_set_user { |u, a, o| order << :two }
        config.after_set_user { |u, a, o| order << :three }
        config.prepend_after_set_user { |u, a, o| order << :one }
      end

      call(app)

      expect(order).to eq([:one, :two, :three])
    end
  end

  describe "in-flight stability" do
    it "keeps the flow selected at request start when a local callback is removed mid request" do
      seen = []
      gate = Queue.new
      proceed = Queue.new

      employee_app.callbacks.on_request do |proxy|
        seen << :local_on_request
        gate << :ready
        proceed.pop
      end

      env = env_with_params("/").merge(
        'rack.session' => {}, 'warden.spec.gate' => gate, 'warden.spec.proceed' => proceed
      )
      thread = Thread.new { employee_app.call(env) }
      expect(gate.pop).to eq(:ready)

      # Another application/request removes the employee registration while
      # the first request is parked inside its callback.
      employee_app.callbacks._on_request.clear
      proceed << :go
      thread.join

      expect(seen).to eq([:local_on_request])
    end

    it "does not run a removed local callback on the next request" do
      employee_app.callbacks._on_request.clear
      call(employee_app)
      expect(trace.map(&:last)).not_to include(:on_request)
    end

    it "captures an immutable config and strategy list for the request" do
      captured = nil
      app = Warden::Manager.new(lambda do |env|
        captured = env['warden']
        captured.authenticate
        [200, {}, ['ok']]
      end) do |config|
        config.default_strategies(:pass)
      end

      app.call(env_with_params("/").merge('rack.session' => {}))

      expect(captured.config).to be_frozen
      expect(captured.callback_chain(:on_request)).to be_frozen
      expect(captured.config.default_strategies).to eq([:pass])
    end

    it "keeps the strategies selected when the request started despite a later default change" do
      gate = Queue.new
      proceed = Queue.new
      scanned = []

      app = Warden::Manager.new(lambda do |env|
        proxy = env['warden']
        # Park after the proxy exists but before strategies are evaluated, so
        # the manager's default can be changed by another request meanwhile.
        env['warden.spec.gate'] << :ready
        env['warden.spec.proceed'].pop
        proxy.authenticate
        scanned.concat(env['warden.spec.strategies'] || [])
        [200, {}, ['ok']]
      end) do |config|
        config.default_strategies(:pass)
      end

      parked_env = env_with_params("/").merge(
        'rack.session' => {},
        'warden.spec.gate' => gate,
        'warden.spec.proceed' => proceed
      )
      thread = Thread.new { app.call(parked_env) }
      expect(gate.pop).to eq(:ready)

      # A second application changes the shared manager default while the
      # first request is parked.
      app.config.default_strategies(:failz)
      proceed << :go
      thread.join

      expect(scanned).to eq([:pass])
    end
  end

  describe "nested Rack mounting" do
    it "attributes the request to the outermost warden manager and runs its chain once" do
      hits = []
      employee_app.callbacks.on_request { |proxy| hits << proxy.manager.object_id }

      nested = Warden::Spec::Helpers::Session.new(employee_app)
      env = env_with_params("/").merge('rack.session' => {})
      nested.call(env)

      expect(hits).to eq([employee_app.object_id])
    end

    it "does not let an inner warden manager re-run or hijack an already owned request" do
      owners = []
      inner = Warden::Manager.new(lambda do |env|
        owners << env['warden'].manager
        [200, {}, ['inner']]
      end)
      inner.callbacks.on_request { |proxy| owners << :inner_on_request }

      outer = Warden::Manager.new(inner)
      outer.callbacks.on_request { |proxy| owners << :outer_on_request }

      stack = Warden::Spec::Helpers::Session.new(outer)
      env = env_with_params("/").merge('rack.session' => {})
      stack.call(env)

      # The outer manager owns the env['warden'] proxy for the whole request;
      # the nested manager defers and neither its proxy nor its on_request
      # callback is invoked.
      expect(owners).to eq([:outer_on_request, outer])
    end

    it "lets each separately mounted manager own its own request" do
      inner_env_owner = nil
      inner = Warden::Manager.new(lambda do |env|
        inner_env_owner = env['warden'].manager
        [200, {}, ['inner']]
      end)

      inner.call(env_with_params("/").merge('rack.session' => {}))
      expect(inner_env_owner).to eq(inner)
    end
  end

  describe "employee and external entry points" do
    def entry_point(name, scope_default)
      local_trace = trace
      Warden::Manager.new(lambda do |env|
        env['warden'].authenticate!(:scope => name)
        [200, {}, [name.to_s]]
      end, :failure_app => lambda { |env| [401, {}, ['fail']] }) do |config|
        config.scope_defaults(name, :strategies => [scope_default])
        config.on_request { |proxy| local_trace << [name, :local] }
      end
    end

    it "registers per-scope default strategies independently for each entry" do
      employee = entry_point(:employee, :pass)
      external = entry_point(:external, :failz)

      employee_env = call(employee, "/")
      external_env = call(external, "/")

      expect(employee_env['warden.spec.strategies']).to eq([:pass])
      expect(external_env['warden.spec.strategies']).to eq([:failz])
    end

    it "keeps an operations approved shared callback after the employee local registration is removed" do
      Warden::Manager.on_request { |proxy| trace << [:shared] }
      employee = entry_point(:employee, :pass)

      # Withdraw the employee entry's own registration.
      employee.callbacks._on_request.clear

      env = call(employee, "/")

      # Local callbacks are gone...
      expect(trace.map(&:first)).not_to include(:employee)
      # ...but the explicitly shared global callback still runs for it.
      expect(trace).to include([:shared])
    end
  end
end
