# encoding: utf-8
# frozen_string_literal: true

require 'rack/mock'

RSpec.describe "restricted delegation contexts" do
  # A plain Rack stand-in that plays the plugin layer. It receives the same
  # env as the main app; the only thing that changes is the delegated handle.
  def plugin(&block)
    lambda { |env| block.call(env) }
  end

  def session_app(&block)
    Rack::Builder.new do
      use Warden::Spec::Helpers::Session
      use Warden::Manager, :failure_app => Warden::Spec::Helpers::FAILURE_APP
      run lambda { |env| block.call(env) }
    end
  end

  def stored_session(env, scope)
    env['rack.session']["warden.user.#{scope}.key"]
  end

  before(:all) do
    load_strategies
  end

  before(:each) do
    @saved_hooks = {
      :after_set_user => Warden::Manager._after_set_user.dup,
      :before_logout => Warden::Manager._before_logout.dup
    }
    Warden::Manager._after_set_user.clear
    Warden::Manager._before_logout.clear
    @env = env_with_params("/")
    @env['rack.session'] = {
      "warden.user.default.key" => "Default User",
      "warden.user.reports.key" => "Reports User",
      "warden.user.reports.session" => { :filters => { :region => "eu" } }
    }
    @env['warden.spec.strategies'] = []
  end

  after(:each) do
    Warden::Manager._after_set_user.replace(@saved_hooks[:after_set_user])
    Warden::Manager._before_logout.replace(@saved_hooks[:before_logout])
  end

  describe "reading the current principal" do
    it "reads an already resolved identity without running any strategy" do
      outer = session_app do |env|
        env['warden'].delegate(:scopes => [:reports]) do |ctx|
          expect(ctx.user(:reports)).to eq("Reports User")
          expect(ctx.principal(:reports)).to eq("Reports User")
          expect(ctx.authenticated?(:reports)).to be(true)
        end
        [200, {}, ["ok"]]
      end

      outer.call(@env)
      expect(@env['warden.spec.strategies']).to eq([])
      expect(@env['rack.session']['warden.user.reports.key']).to eq("Reports User")
    end

    it "refuses identities from a scope that was not granted" do
      outer = session_app do |env|
        env['warden'].delegate(:scopes => [:reports]) do |ctx|
          expect { ctx.user(:default) }.to raise_error(Warden::ScopeNotGranted, /default/)
        end
        [200, {}, ["ok"]]
      end

      outer.call(@env)
      expect(@env['rack.session']['warden.user.default.key']).to eq("Default User")
    end

    it "defaults reads to the configured default scope" do
      outer = session_app do |env|
        env['warden'].delegate do |ctx|
          expect(ctx.scopes).to eq([:default])
          expect(ctx.user).to eq("Default User")
          expect(ctx.session).to be_a(Warden::ReadOnlySession)
        end
        [200, {}, ["ok"]]
      end

      outer.call(@env)
      expect(@env['warden.spec.strategies']).to eq([])
    end

    it "does not delete a stale key just by reading" do
      @env['rack.session']['warden.user.stale.key'] = "gone"
      allow_any_instance_of(Warden::SessionSerializer).to receive(:deserialize).and_return(nil)

      outer = session_app do |env|
        env['warden'].delegate(:scopes => [:stale]) do |ctx|
          expect(ctx.user(:stale)).to be_nil
        end
        [200, {}, ["ok"]]
      end

      outer.call(@env)
      expect(@env['rack.session']['warden.user.stale.key']).to eq("gone")
    end

    it "returns nil, not a strategy run, for an unresolved granted scope" do
      outer = session_app do |env|
        env['warden'].delegate(:scopes => [:missing]) do |ctx|
          expect(ctx.user(:missing)).to be_nil
        end
        [200, {}, ["ok"]]
      end

      outer.call(@env)
      expect(@env['warden.spec.strategies']).to eq([])
    end
  end

  describe "read-only session access" do
    it "reads scoped session data but cannot mutate it" do
      outer = session_app do |env|
        env['warden'].delegate(:scopes => [:reports]) do |ctx|
          view = ctx.session(:reports)
          expect(view[:filters]).to eq(:region => "eu")
          expect { view[:filters] = {} }.to raise_error(Warden::WritableSessionNotGranted)
          expect { view.delete(:filters) }.to raise_error(Warden::WritableSessionNotGranted)
          expect { view[:new] = 1 }.to raise_error(Warden::WritableSessionNotGranted)
        end
        [200, {}, ["ok"]]
      end

      outer.call(@env)
      expect(@env['rack.session']['warden.user.reports.session']).to eq(:filters => { :region => "eu" })
    end

    it "does not leak the backing session through a nested value" do
      outer = session_app do |env|
        env['warden'].delegate(:scopes => [:reports]) do |ctx|
          nested = ctx.session(:reports)[:filters]
          expect(nested).to eq(:region => "eu")
          expect { nested[:region] = "us" }.to raise_error(FrozenError)
        end
        [200, {}, ["ok"]]
      end

      outer.call(@env)
      expect(@env['rack.session']['warden.user.reports.session']).to eq(:filters => { :region => "eu" })
    end

    it "copies values yielded by enumerators" do
      outer = session_app do |env|
        env['warden'].delegate(:scopes => [:reports]) do |ctx|
          view = ctx.session(:reports)
          yielded = []
          view.each_value { |value| yielded << value }
          view.each { |_key, value| yielded << value }
          expect(yielded.flatten).to include(:region => "eu")
          expect(yielded).to all(satisfy(&:frozen?))
          expect { yielded.first[:region] = "us" }.to raise_error(FrozenError)
        end
        [200, {}, ["ok"]]
      end

      outer.call(@env)
      expect(@env['rack.session']['warden.user.reports.session']).to eq(:filters => { :region => "eu" })
    end

    it "does not hand out the raw session" do
      outer = session_app do |env|
        env['warden'].delegate(:scopes => [:reports]) do |ctx|
          expect { ctx.raw_session }.to raise_error(Warden::CapabilityNotGranted)
          expect { env['warden'].raw_session }.to raise_error(Warden::CapabilityNotGranted)
        end
        [200, {}, ["ok"]]
      end

      outer.call(@env)
    end

    it "hides the writable serializer behind a read-only facade" do
      outer = session_app do |env|
        env['warden'].delegate(:scopes => [:reports]) do |ctx|
          expect(env['warden'].session_serializer.fetch(:reports)).to eq("Reports User")
          expect { env['warden'].session_serializer.store("x", :reports) }.
            to raise_error(Warden::WritableSessionNotGranted)
        end
        [200, {}, ["ok"]]
      end

      outer.call(@env)
      expect(@env['rack.session']['warden.user.reports.key']).to eq("Reports User")
    end
  end

  describe "explicitly delegated writes" do
    it "allows set_user only when delegated and only for a granted scope" do
      outer = session_app do |env|
        env['warden'].delegate(:scopes => [:reports], :capabilities => [:set_user]) do |ctx|
          ctx.set_user("Delegated User", :scope => :reports)
          expect(ctx.user(:reports)).to eq("Delegated User")
        end
        [200, {}, ["ok"]]
      end

      outer.call(@env)
      expect(@env['rack.session']['warden.user.reports.key']).to eq("Delegated User")
      expect(@env['rack.session']['warden.user.default.key']).to eq("Default User")
    end

    it "refuses set_user without the capability" do
      outer = session_app do |env|
        env['warden'].delegate(:scopes => [:reports]) do |ctx|
          expect { ctx.set_user("Nope", :scope => :reports) }.
            to raise_error(Warden::CapabilityNotGranted, /set_user/)
        end
        [200, {}, ["ok"]]
      end

      outer.call(@env)
      expect(@env['rack.session']['warden.user.reports.key']).to eq("Reports User")
    end

    it "refuses a delegated write to an ungranted scope" do
      outer = session_app do |env|
        env['warden'].delegate(:scopes => [:reports], :capabilities => [:set_user]) do |ctx|
          expect { ctx.set_user("Escalate", :scope => :default) }.
            to raise_error(Warden::ScopeNotGranted, /default/)
        end
        [200, {}, ["ok"]]
      end

      outer.call(@env)
      expect(@env['rack.session']['warden.user.default.key']).to eq("Default User")
    end

    it "allows an explicitly delegated logout for a granted scope" do
      outer = session_app do |env|
        env['warden'].delegate(:scopes => [:reports], :capabilities => [:logout]) do |ctx|
          ctx.logout(:reports)
        end
        [200, {}, ["ok"]]
      end

      outer.call(@env)
      expect(@env['rack.session']['warden.user.reports.key']).to be_nil
      expect(@env['rack.session']['warden.user.default.key']).to eq("Default User")
    end

    it "requires an explicit scope to log out while delegated" do
      outer = session_app do |env|
        env['warden'].delegate(:scopes => [:reports, :default], :capabilities => [:logout]) do |ctx|
          expect { ctx.logout }.to raise_error(Warden::ScopeNotGranted, /explicit scope/)
        end
        [200, {}, ["ok"]]
      end

      outer.call(@env)
      expect(@env['rack.session']['warden.user.reports.key']).to eq("Reports User")
      expect(@env['rack.session']['warden.user.default.key']).to eq("Default User")
    end

    it "refuses logout without the capability" do
      outer = session_app do |env|
        env['warden'].delegate(:scopes => [:reports]) do |ctx|
          expect { ctx.logout(:reports) }.to raise_error(Warden::CapabilityNotGranted, /logout/)
        end
        [200, {}, ["ok"]]
      end

      outer.call(@env)
      expect(@env['rack.session']['warden.user.reports.key']).to eq("Reports User")
    end
  end

  describe "strategy execution" do
    it "does not run a strategy for an identity read" do
      outer = session_app do |env|
        env['warden'].delegate(:scopes => [:default]) do |ctx|
          ctx.user(:default)
        end
        [200, {}, ["ok"]]
      end

      outer.call(@env)
      expect(@env['warden.spec.strategies']).to eq([])
    end

    it "runs a strategy only when authenticate is delegated" do
      @env['rack.session'].delete("warden.user.default.key")
      outer = session_app do |env|
        env['warden'].delegate(:scopes => [:default], :capabilities => [:authenticate]) do |ctx|
          expect(ctx.authenticate(:pass)).to eq("Valid User")
        end
        [200, {}, ["ok"]]
      end

      outer.call(@env)
      expect(@env['warden.spec.strategies']).to eq([:pass])
    end

    it "supports the predicate form when authenticate is delegated" do
      @env['rack.session'].delete("warden.user.default.key")
      outer = session_app do |env|
        env['warden'].delegate(:scopes => [:default], :capabilities => [:authenticate]) do |ctx|
          yielded = false
          expect(ctx.authenticate?(:pass) { yielded = true }).to be(true)
          expect(yielded).to be(true)
        end
        [200, {}, ["ok"]]
      end

      outer.call(@env)
      expect(@env['warden.spec.strategies']).to eq([:pass])
    end

    it "refuses to run a strategy without the authenticate capability" do
      @env['rack.session'].delete("warden.user.default.key")
      outer = session_app do |env|
        env['warden'].delegate(:scopes => [:default]) do |ctx|
          expect { ctx.authenticate(:pass) }.to raise_error(Warden::CapabilityNotGranted, /authenticate/)
          expect { env['warden'].authenticate(:pass) }.to raise_error(Warden::CapabilityNotGranted)
        end
        [200, {}, ["ok"]]
      end

      outer.call(@env)
      expect(@env['warden.spec.strategies']).to eq([])
    end

    it "refuses to mutate caches or lock the proxy while delegated" do
      outer = session_app do |env|
        env['warden'].delegate(:scopes => [:default]) do |ctx|
          expect { env['warden'].lock! }.to raise_error(Warden::CapabilityNotGranted)
          expect { env['warden'].clear_strategies_cache! }.to raise_error(Warden::CapabilityNotGranted)
        end
        [200, {}, ["ok"]]
      end

      outer.call(@env)
    end
  end

  describe "nested contexts" do
    it "keeps an inner context inside the outer grant" do
      outer = session_app do |env|
        env['warden'].delegate(:scopes => [:reports], :capabilities => [:set_user]) do |outer_ctx|
          env['warden'].delegate(:scopes => [:reports]) do |inner_ctx|
            expect(inner_ctx.user(:reports)).to eq("Reports User")
            expect { inner_ctx.set_user("x", :scope => :reports) }.
              to raise_error(Warden::CapabilityNotGranted)
          end
          outer_ctx.set_user("Outer Write", :scope => :reports)
        end
        [200, {}, ["ok"]]
      end

      outer.call(@env)
      expect(@env['rack.session']['warden.user.reports.key']).to eq("Outer Write")
    end

    it "rejects a nested context that asks for a wider scope" do
      outer = session_app do |env|
        env['warden'].delegate(:scopes => [:reports]) do |_outer_ctx|
          expect {
            env['warden'].delegate(:scopes => [:reports, :default]) { |_inner| }
          }.to raise_error(Warden::DelegationEscalation, /default/)
        end
        [200, {}, ["ok"]]
      end

      outer.call(@env)
    end

    it "rejects a nested context that asks for a capability the outer lacks" do
      outer = session_app do |env|
        env['warden'].delegate(:scopes => [:reports]) do |_outer_ctx|
          expect {
            env['warden'].delegate(:scopes => [:reports], :capabilities => [:logout]) { |_inner| }
          }.to raise_error(Warden::DelegationEscalation, /logout/)
        end
        [200, {}, ["ok"]]
      end

      outer.call(@env)
    end

    it "does not let an inner exception leak the inner grant into the outer frame" do
      outer = session_app do |env|
        env['warden'].delegate(:scopes => [:reports], :capabilities => [:set_user]) do |outer_ctx|
          begin
            env['warden'].delegate(:scopes => [:reports]) do |_inner_ctx|
              raise "inner boom"
            end
          rescue RuntimeError => e
            expect(e.message).to eq("inner boom")
          end

          # The outer frame still has exactly the grant it declared.
          outer_ctx.set_user("Still Delegated", :scope => :reports)
        end
        [200, {}, ["ok"]]
      end

      outer.call(@env)
      expect(@env['rack.session']['warden.user.reports.key']).to eq("Still Delegated")
    end

    it "revokes the inner handle after an inner exception" do
      inner_captured = nil
      outer = session_app do |env|
        env['warden'].delegate(:scopes => [:reports], :capabilities => [:set_user]) do |_outer_ctx|
          begin
            env['warden'].delegate(:scopes => [:reports], :capabilities => [:set_user]) do |inner_ctx|
              inner_captured = inner_ctx
              raise "inner boom"
            end
          rescue RuntimeError
            # swallow
          end
        end
        [200, {}, ["ok"]]
      end

      outer.call(@env)
      expect(inner_captured).to be_expired
      expect { inner_captured.set_user("x", :scope => :reports) }.
        to raise_error(Warden::DelegationExpired)
    end

    it "refuses to use an outer handle while a narrower inner context is active" do
      captured = nil
      outer = session_app do |env|
        env['warden'].delegate(:scopes => [:reports]) do |outer_ctx|
          captured = outer_ctx
          env['warden'].delegate(:scopes => [:reports]) do |_inner_ctx|
            expect { captured.user(:reports) }.to raise_error(Warden::DelegationNotActive)
          end
        end
        [200, {}, ["ok"]]
      end

      outer.call(@env)
    end
  end

  describe "expiry and callbacks that try to retain the context" do
    it "revokes the handle when the delegated call finishes" do
      captured = nil
      outer = session_app do |env|
        env['warden'].delegate(:scopes => [:reports]) do |ctx|
          captured = ctx
          ctx.user(:reports)
        end
        [200, {}, ["ok"]]
      end

      outer.call(@env)
      expect(captured).to be_expired
      expect { captured.user(:reports) }.to raise_error(Warden::DelegationExpired)
    end

    it "revokes the handle when the delegated call raises" do
      captured = nil
      outer = session_app do |env|
        begin
          env['warden'].delegate(:scopes => [:reports]) do |ctx|
            captured = ctx
            raise "plugin boom"
          end
        rescue RuntimeError => e
          expect(e.message).to eq("plugin boom")
        end
        [200, {}, ["ok"]]
      end

      outer.call(@env)
      expect(captured).to be_expired
      expect { captured.user(:reports) }.to raise_error(Warden::DelegationExpired)
    end

    it "does not let an after_set_user callback retain the context" do
      captured = nil
      Warden::Manager.after_set_user do |_user, _auth, _opts|
        captured = Thread.current[:plugin_ctx]
      end

      outer = session_app do |env|
        env['warden'].delegate(:scopes => [:reports], :capabilities => [:set_user]) do |ctx|
          Thread.current[:plugin_ctx] = ctx
          ctx.set_user("Callback User", :scope => :reports)
        end
        [200, {}, ["ok"]]
      end

      outer.call(@env)
      expect(captured).to be_expired
      expect { captured.set_user("x", :scope => :reports) }.to raise_error(Warden::DelegationExpired)
    ensure
      Thread.current[:plugin_ctx] = nil
    end

    it "does not let a before_logout callback retain the context" do
      captured = nil
      Warden::Manager.before_logout do |_user, _auth, _opts|
        captured = Thread.current[:plugin_ctx]
      end

      outer = session_app do |env|
        env['warden'].delegate(:scopes => [:reports], :capabilities => [:logout]) do |ctx|
          Thread.current[:plugin_ctx] = ctx
          ctx.logout(:reports)
        end
        [200, {}, ["ok"]]
      end

      outer.call(@env)
      expect(captured).to be_expired
      expect { captured.logout(:reports) }.to raise_error(Warden::DelegationExpired)
    ensure
      Thread.current[:plugin_ctx] = nil
    end

    it "refuses to copy a handle into a retained reference" do
      outer = session_app do |env|
        env['warden'].delegate(:scopes => [:reports]) do |ctx|
          expect { ctx.dup }.to raise_error(Warden::DelegationError)
        end
        [200, {}, ["ok"]]
      end

      outer.call(@env)
    end
  end

  describe "restoring the main request" do
    it "restores the normal session entry points after delegation" do
      outer = session_app do |env|
        env['warden'].delegate(:scopes => [:reports], :capabilities => [:set_user]) do |ctx|
          ctx.set_user("Delegated", :scope => :reports)
        end

        # Back in the main request: ordinary Warden API is writable again.
        env['warden'].session(:default)[:note] = "main"
        expect(env['warden'].session(:default)[:note]).to eq("main")
        expect(env['warden']).not_to be_delegating
        [200, {}, ["ok"]]
      end

      outer.call(@env)
      expect(@env['rack.session']['warden.user.default.session']).to eq(:note => "main")
      expect(@env['rack.session']['warden.user.reports.key']).to eq("Delegated")
    end

    it "still runs a normal login after delegation" do
      @env['rack.session'].delete("warden.user.default.key")
      @env['rack.session'].delete("warden.user.reports.key")
      outer = session_app do |env|
        env['warden'].delegate(:scopes => [:reports]) do |ctx|
          expect(ctx.user(:reports)).to be_nil
        end

        expect(env['warden'].authenticate(:pass)).to eq("Valid User")
        [200, {}, ["ok"]]
      end

      outer.call(@env)
      expect(@env['warden.spec.strategies']).to eq([:pass])
      expect(@env['rack.session']['warden.user.default.key']).to eq("Valid User")
    end

    it "keeps the two scoped persistent sessions intact across the call" do
      outer = session_app do |env|
        env['warden'].delegate(:scopes => [:reports]) do |ctx|
          ctx.user(:reports)
        end
        env['warden'].session(:reports)[:visited] = true
        [200, {}, ["ok"]]
      end

      outer.call(@env)
      expect(@env['rack.session']['warden.user.default.key']).to eq("Default User")
      expect(@env['rack.session']['warden.user.reports.key']).to eq("Reports User")
      expect(@env['rack.session']['warden.user.reports.session']).to eq(
        :filters => { :region => "eu" }, :visited => true
      )
    end
  end

  describe "argument validation" do
    it "requires a block" do
      outer = session_app do |env|
        expect { env['warden'].delegate(:scopes => [:reports]) }.to raise_error(ArgumentError, /block/)
        [200, {}, ["ok"]]
      end

      outer.call(@env)
    end

    it "rejects unknown capabilities at construction" do
      outer = session_app do |env|
        expect {
          env['warden'].delegate(:scopes => [:reports], :capabilities => [:read, :delete_all]) { |_ctx| }
        }.to raise_error(ArgumentError, /delete_all/)
        [200, {}, ["ok"]]
      end

      outer.call(@env)
    end

    it "accepts positional scopes for convenience" do
      outer = session_app do |env|
        result = env['warden'].delegate([:reports]) do |ctx|
          ctx.user(:reports)
        end
        expect(result).to eq("Reports User")
        [200, {}, ["ok"]]
      end

      outer.call(@env)
    end
  end
end
