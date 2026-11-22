# encoding: utf-8
# frozen_string_literal: true

RSpec.describe "scope inheritance" do
  before(:all) do
    load_strategies
  end

  before(:each) do
    @env = env_with_params("/")
    @env['rack.session'] = {}
  end

  def build_rack(app, rules, &block)
    configurator = proc do |config|
      rules.each { |child, parent| config.inherit_scope(child, parent) }
      block.call(config) if block
    end
    setup_rack(app, :configurator => configurator)
  end

  describe "reusing an existing session" do
    it "reuses the source scope identity without running its own strategies" do
      @env['rack.session']['warden.user.default.key'] = "an employee"
      app = lambda do |e|
        w = e['warden']
        expect(w.authenticate(:pass, :scope => :support)).to eq("an employee")
        expect(e['warden.spec.strategies']).to be_nil
        valid_response
      end
      build_rack(app, :support => :default).call(@env)
    end

    it "reports the scope as authenticated and exposes the inherited user" do
      @env['rack.session']['warden.user.default.key'] = "an employee"
      app = lambda do |e|
        w = e['warden']
        expect(w).to be_authenticated(:support)
        expect(w.user(:support)).to eq("an employee")
        valid_response
      end
      build_rack(app, :support => :default).call(@env)
    end

    it "does not write the inherited identity into the inheriting scope session" do
      @env['rack.session']['warden.user.default.key'] = "an employee"
      app = lambda do |e|
        e['warden'].user(:support)
        valid_response
      end
      build_rack(app, :support => :default).call(@env)
      expect(@env['rack.session'].key?('warden.user.support.key')).to eq(false)
      expect(@env['rack.session']['warden.user.default.key']).to eq("an employee")
    end

    it "prefers its own session over the inherited identity" do
      @env['rack.session']['warden.user.support.key'] = "the real support agent"
      @env['rack.session']['warden.user.default.key'] = "an employee"
      app = lambda do |e|
        expect(e['warden'].user(:support)).to eq("the real support agent")
        valid_response
      end
      build_rack(app, :support => :default).call(@env)
    end

    it "follows a chain, consulting each source scope's own session" do
      @env['rack.session']['warden.user.default.key'] = "an employee"
      app = lambda do |e|
        expect(e['warden'].user(:support)).to eq("an employee")
        valid_response
      end
      build_rack(app, :support => :employee, :employee => :default).call(@env)
    end

    it "returns nil when neither the scope nor any source has a session" do
      app = lambda do |e|
        expect(e['warden'].user(:support)).to be_nil
        expect(e['warden']).not_to be_authenticated(:support)
        valid_response
      end
      build_rack(app, :support => :default).call(@env)
    end

    it "does not let identity flow in the reverse direction" do
      @env['rack.session']['warden.user.support.key'] = "a support agent"
      app = lambda do |e|
        expect(e['warden'].user(:default)).to be_nil
        valid_response
      end
      build_rack(app, :support => :default).call(@env)
    end

    it "leaves unrelated scopes without inheritance completely untouched" do
      @env['rack.session']['warden.user.default.key'] = "an employee"
      app = lambda do |e|
        w = e['warden']
        expect(w.user(:support)).to eq("an employee")
        expect(w.user(:admin)).to be_nil
        valid_response
      end
      build_rack(app, :support => :default).call(@env)
    end
  end

  describe "falling back to a fresh authentication" do
    it "runs the requested scope's own strategies when no session can be reused" do
      app = lambda do |e|
        w = e['warden']
        expect(w.authenticate(:pass, :scope => :support)).to eq("Valid User")
        expect(e['warden.spec.strategies']).to eq([:pass])
        valid_response
      end
      build_rack(app, :support => :default).call(@env)
    end

    it "authenticates independently even when a source scope could later be used" do
      app = lambda do |e|
        w = e['warden']
        w.authenticate(:pass, :scope => :default)
        expect(e['warden.spec.strategies']).to eq([:pass])
        e['warden.spec.strategies'].clear
        expect(w.authenticate(:pass, :scope => :admin)).to eq("Valid User")
        expect(e['warden.spec.strategies']).to eq([:pass])
        valid_response
      end
      build_rack(app, :support => :default).call(@env)
    end

    it "stores the freshly authenticated user in its own scope session" do
      app = lambda do |e|
        e['warden'].authenticate(:pass, :scope => :support)
        valid_response
      end
      build_rack(app, :support => :default).call(@env)
      expect(@env['rack.session']['warden.user.support.key']).to eq("Valid User")
    end

    it "runs the scope's own default strategies with no explicit strategy" do
      env = env_with_params("/", :username => "fred", :password => "sekrit")
      env['rack.session'] = {}
      app = lambda do |e|
        expect(e['warden'].authenticate(:scope => :support)).to eq("Authenticated User")
        expect(e['warden.spec.strategies']).to eq([:password])
        valid_response
      end
      build_rack(app, :support => :default) do |config|
        config.default_strategies :password, :scope => :support
      end.call(env)
    end
  end

  describe "callbacks" do
    after(:each) do
      Warden::Manager._after_set_user.clear
      Warden::Manager._after_failed_fetch.clear
    end

    it "runs each scope's own fetch callback while resolving the chain" do
      events = []
      Warden::Manager.after_set_user { |_user, _auth, opts| events << [:set, opts[:scope], opts[:event]] }
      Warden::Manager.after_failed_fetch { |_user, _auth, opts| events << [:failed, opts[:scope]] }
      @env['rack.session']['warden.user.default.key'] = "an employee"
      app = lambda { |e| e['warden'].user(:support); valid_response }
      build_rack(app, :support => :default).call(@env)
      expect(events).to eq([[:set, :default, :fetch], [:set, :support, :fetch]])
    end

    it "reports failed fetches for every consulted scope when nothing resolves" do
      events = []
      Warden::Manager.after_set_user { |_user, _auth, opts| events << [:set, opts[:scope]] }
      Warden::Manager.after_failed_fetch { |_user, _auth, opts| events << [:failed, opts[:scope]] }
      app = lambda { |e| e['warden'].user(:support); valid_response }
      build_rack(app, :support => :default).call(@env)
      expect(events).to eq([[:failed, :default], [:failed, :support]])
    end

    it "honors run_callbacks => false along the inherited lookup" do
      events = []
      Warden::Manager.after_set_user { |_user, _auth, opts| events << opts[:scope] }
      @env['rack.session']['warden.user.default.key'] = "an employee"
      app = lambda { |e| e['warden'].user(:scope => :support, :run_callbacks => false); valid_response }
      build_rack(app, :support => :default).call(@env)
      expect(events).to eq([])
    end
  end

  describe "configuration time validation" do
    let(:noop_app) { lambda { |_e| [200, {}, []] } }

    it "raises while building the manager when the inheritance graph has a cycle" do
      expect {
        Warden::Manager.new(noop_app) do |config|
          config.inherit_scope :a, :b
          config.inherit_scope :b, :a
        end
      }.to raise_error(Warden::InvalidScopeInheritance, /cycle detected/)
    end

    it "raises while building the manager when a rule references an unknown scope" do
      expect {
        Warden::Manager.new(noop_app) do |config|
          config.inherit_scope :support, Object.new
        end
      }.to raise_error(Warden::InvalidScopeInheritance, /scope inherited from/)
    end

    it "accepts an acyclic graph when the manager is built" do
      expect {
        Warden::Manager.new(noop_app) do |config|
          config.inherit_scope :support => :employee, :employee => :default
        end
      }.not_to raise_error
    end
  end
end
