# encoding: utf-8
# frozen_string_literal: true
require 'rack/session'

RSpec.describe "authentication levels" do
  before(:all) do
    load_strategies
  end

  before(:each) do
    @env = env_with_params("/")
  end

  # Runs the app once against @env and returns the response. A proxy from a
  # previous request is dropped so each call behaves like a fresh request
  # while the rack session is carried over.
  def call_app(app, opts = {})
    @env.delete('warden')
    setup_rack(app, opts).call(@env)
  end

  describe "a strategy declaring its verification level" do
    it "exposes the declared level on the strategy class" do
      expect(Warden::Strategies[:level_two].authentication_level).to eq(2)
    end

    it "reports an ordinary strategy as the default level" do
      expect(Warden::Strategies[:pass].authentication_level).to eq(Warden::DEFAULT_AUTHENTICATION_LEVEL)
    end

    it "lets success! override the declared level for one attempt" do
      Warden::Strategies.add(:one_off_level) do
        authentication_level 1
        def authenticate!
          success!("One Off", nil, :level => 3)
        end
      end
      strategy = Warden::Strategies[:one_off_level].new(env_with_params)
      strategy._run!
      expect(strategy.level).to eq(3)
    end

    it "inherits the declared level in a subclass" do
      base = Class.new(Warden::Strategies::Base)
      base.authentication_level 3
      expect(base.authentication_level).to eq(3)
      expect(Class.new(base).authentication_level).to eq(3)
    end

    it "accepts a level hash as the second argument of success!" do
      Warden::Strategies.add(:hash_level) do
        def authenticate!
          success!("Hash User", :level => 2)
        end
      end
      strategy = Warden::Strategies[:hash_level].new(env_with_params)
      strategy._run!
      expect(strategy.level).to eq(2)
      expect(strategy.message).to be_nil
    end

    it "rejects a negative or non-integer declared level with an actionable error" do
      expect {
        Warden::Strategies.add(:bad_level) do
          authentication_level(-1)
        end
      }.to raise_error(ArgumentError, /non-negative integer/)

      expect {
        Warden::Strategies.add(:bad_level_string) do
          authentication_level("high")
        end
      }.to raise_error(ArgumentError, /non-negative integer/)
    end
  end

  describe "logging in normally and then requiring a higher level" do
    it "stores the default level for a strategy that does not declare one" do
      call_app(lambda do |e|
        expect(e['warden'].authenticate(:pass)).to eq("Valid User")
        valid_response
      end)
      expect(@env['rack.session']['warden.user.default.level']).to eq(Warden::DEFAULT_AUTHENTICATION_LEVEL)
    end

    it "accepts a fresh login that directly satisfies the required level" do
      app = lambda do |e|
        e['warden.spec.outcome'] = e['warden'].authenticate(:level_two, :min_level => 2)
        valid_response
      end
      call_app(app)

      expect(@env['warden.spec.outcome']).to eq("Level Two User")
      expect(@env['rack.session']['warden.user.default.level']).to eq(2)
    end

    it "records the ordinary level in the session" do
      app = lambda do |e|
        e['warden'].authenticate(:level_one)
        valid_response
      end
      call_app(app)
      expect(@env['rack.session']['warden.user.default.key']).to eq("Level One User")
      expect(@env['rack.session']['warden.user.default.level']).to eq(1)
    end

    it "elevates an existing lower-level session with the declared strategy" do
      call_app(lambda do |e|
        e['warden'].authenticate(:level_one)
        valid_response
      end)

      app = lambda do |e|
        user = e['warden'].authenticate(:level_two, :min_level => 2)
        e['warden.spec.outcome'] = user
        valid_response
      end
      call_app(app)

      expect(@env['warden.spec.outcome']).to eq("Level Two User")
      expect(@env['rack.session']['warden.user.default.key']).to eq("Level Two User")
      expect(@env['rack.session']['warden.user.default.level']).to eq(2)
      expect(@env['warden.spec.strategies']).to include(:level_two)
    end

    it "does not re-run strategies when the session already meets the requirement" do
      call_app(lambda do |e|
        e['warden'].authenticate(:level_two, :min_level => 2)
        valid_response
      end)
      @env['warden.spec.strategies'] = []

      call_app(lambda do |e|
        expect(e['warden'].authenticate(:level_two, :min_level => 2)).to eq("Level Two User")
        valid_response
      end)
      expect(@env['warden.spec.strategies']).to eq([])
    end

    it "elevates within the same request after an ordinary authenticate" do
      app = lambda do |e|
        expect(e['warden'].authenticate(:level_one)).to eq("Level One User")
        outcome = e['warden'].authenticate(:level_two, :min_level => 2)
        e['warden.spec.outcome'] = outcome
        e['warden.spec.level'] = e['warden'].authentication_level
        valid_response
      end
      call_app(app)

      expect(@env['warden.spec.outcome']).to eq("Level Two User")
      expect(@env['warden.spec.level']).to eq(2)
      expect(@env['warden.spec.strategies']).to eq([:level_one, :level_two])
    end
  end

  describe "when elevation does not reach the required level" do
    before(:each) do
      call_app(lambda do |e|
        e['warden'].authenticate(:level_one)
        valid_response
      end)
      @env['warden.spec.strategies'] = []
    end

    it "reports failure and keeps the original lower-level session intact" do
      app = lambda do |e|
        result = e['warden'].authenticate(:weak_step_up, :min_level => 2)
        e['warden.spec.outcome'] = result
        e['warden.spec.level'] = e['warden'].authentication_level
        valid_response
      end
      call_app(app)

      expect(@env['warden.spec.outcome']).to be_nil
      expect(@env['warden.spec.level']).to eq(1)
      expect(@env['rack.session']['warden.user.default.key']).to eq("Level One User")
      expect(@env['rack.session']['warden.user.default.level']).to eq(1)
    end

    it "explains the shortfall through #message" do
      app = lambda do |e|
        e['warden'].authenticate(:weak_step_up, :min_level => 2)
        e['warden.spec.message'] = e['warden'].message
        valid_response
      end
      call_app(app)
      expect(@env['warden.spec.message']).to match(/below the required level 2/)
    end

    it "reports failure when the step-up strategy rejects the attempt" do
      app = lambda do |e|
        result = e['warden'].authenticate(:failed_step_up, :min_level => 2)
        e['warden.spec.outcome'] = result
        valid_response
      end
      call_app(app)

      expect(@env['warden.spec.outcome']).to be_nil
      expect(@env['rack.session']['warden.user.default.level']).to eq(1)
      expect(@env['rack.session']['warden.user.default.key']).to eq("Level One User")
    end

    it "throws to the failure app for authenticate! with an unmet level" do
      app = lambda do |e|
        e['warden'].authenticate!(:weak_step_up, :min_level => 2)
        e['warden.spec.after_bang'] = true
        valid_response
      end
      response = call_app(app)
      expect(response.first).to eq(401)
      expect(@env['warden.spec.after_bang']).to be_nil
      expect(@env['warden.options'][:message]).to match(/below the required level 2/)
    end

    it "keeps the strategy's own rejection message when one is given" do
      app = lambda do |e|
        e['warden'].authenticate(:failed_step_up, :min_level => 2)
        e['warden.spec.message'] = e['warden'].message
        valid_response
      end
      call_app(app)
      expect(@env['warden.spec.message']).to eq("Second factor rejected")
    end
  end

  describe "sessions written before levels existed" do
    before(:each) do
      @env['rack.session'] = { 'warden.user.default.key' => 'Legacy User' }
    end

    it "treats the missing level as unknown (0)" do
      app = lambda do |e|
        e['warden.spec.level'] = e['warden'].authentication_level
        valid_response
      end
      call_app(app)
      expect(@env['warden.spec.level']).to eq(Warden::UNKNOWN_AUTHENTICATION_LEVEL)
    end

    it "still allows ordinary level-less authentication" do
      app = lambda do |e|
        expect(e['warden']).to be_authenticated
        expect(e['warden'].authenticate(:pass)).to eq("Legacy User")
        valid_response
      end
      call_app(app)
    end

    it "does not satisfy a positive minimum requirement" do
      app = lambda do |e|
        expect(e['warden'].authenticated?(:default, :min_level => 1)).to eq(false)
        expect(e['warden'].user(:min_level => 1)).to be_nil
        valid_response
      end
      call_app(app)
    end

    it "can be elevated by a step-up strategy and then reports the new level" do
      app = lambda do |e|
        user = e['warden'].authenticate(:level_two, :min_level => 2)
        e['warden.spec.outcome'] = user
        e['warden.spec.level'] = e['warden'].authentication_level
        valid_response
      end
      call_app(app)

      expect(@env['warden.spec.outcome']).to eq("Level Two User")
      expect(@env['warden.spec.level']).to eq(2)
      expect(@env['rack.session']['warden.user.default.level']).to eq(2)
    end

    it "survives an elevation failure without creating a level entry" do
      app = lambda do |e|
        e['warden.spec.outcome'] = e['warden'].authenticate(:weak_step_up, :min_level => 2)
        valid_response
      end
      call_app(app)

      expect(@env['warden.spec.outcome']).to be_nil
      expect(@env['rack.session']['warden.user.default.key']).to eq("Legacy User")
      expect(@env['rack.session']).not_to have_key('warden.user.default.level')
    end
  end

  describe "reading the level on subsequent requests" do
    it "restores the stored level for a new request" do
      call_app(lambda do |e|
        e['warden'].authenticate(:level_two, :min_level => 2)
        valid_response
      end)

      next_env = env_with_params("/", {}, 'rack.session' => @env['rack.session'])
      next_app = setup_rack(lambda do |e|
        e['warden.spec.level'] = e['warden'].authentication_level
        e['warden.spec.authenticated'] = e['warden'].authenticated?(:default, :min_level => 2)
        valid_response
      end)
      next_app.call(next_env)

      expect(next_env['warden.spec.level']).to eq(2)
      expect(next_env['warden.spec.authenticated']).to eq(true)
    end

    it "does not let an elevated session satisfy a higher level for another scope" do
      @env = env_with_params("/")
      call_app(lambda do |e|
        e['warden'].authenticate(:level_two, :min_level => 2)
        e['warden'].authenticate(:level_one, :scope => :admin)
        valid_response
      end)

      app = lambda do |e|
        e['warden.spec.admin'] = e['warden'].authenticated?(:admin, :min_level => 2)
        e['warden.spec.default'] = e['warden'].authenticated?(:default, :min_level => 2)
        valid_response
      end
      call_app(app)

      expect(@env['warden.spec.admin']).to eq(false)
      expect(@env['warden.spec.default']).to eq(true)
    end

    it "keeps scopes independent when one is elevated" do
      @env = env_with_params("/")
      call_app(lambda do |e|
        e['warden'].authenticate(:level_one)
        e['warden'].authenticate(:level_one, :scope => :admin)
        valid_response
      end)

      call_app(lambda do |e|
        e['warden'].authenticate(:level_two, :min_level => 2)
        valid_response
      end)

      expect(@env['rack.session']['warden.user.default.level']).to eq(2)
      expect(@env['rack.session']['warden.user.admin.level']).to eq(1)
      expect(@env['rack.session']['warden.user.admin.key']).to eq("Level One User")
    end
  end

  describe "logout" do
    it "removes the stored level along with the user" do
      call_app(lambda do |e|
        e['warden'].authenticate(:level_two, :min_level => 2)
        valid_response
      end)
      expect(@env['rack.session']['warden.user.default.level']).to eq(2)

      call_app(lambda do |e|
        e['warden'].logout(:default)
        valid_response
      end)

      expect(@env['rack.session']).not_to have_key('warden.user.default.key')
      expect(@env['rack.session']).not_to have_key('warden.user.default.level')
    end
  end

  describe Warden::SessionSerializer do
    before(:each) do
      @env = env_with_params
      @env['rack.session'] ||= {}
      @serializer = Warden::SessionSerializer.new(@env)
    end

    it "stores and fetches a level" do
      @serializer.store("user", :default)
      @serializer.store_level(:default, 2)
      expect(@serializer.fetch_level(:default)).to eq(2)
    end

    it "reports nil for a scope with no stored user" do
      expect(@serializer.fetch_level(:default)).to be_nil
    end

    it "falls back to the unknown level for a session without one" do
      @env['rack.session']['warden.user.default.key'] = "user"
      expect(@serializer.fetch_level(:default)).to eq(Warden::UNKNOWN_AUTHENTICATION_LEVEL)
    end

    it "treats an unreadable stored level as unknown rather than raising" do
      @env['rack.session']['warden.user.default.key'] = "user"
      @env['rack.session']['warden.user.default.level'] = "not-a-level"
      expect(@serializer.fetch_level(:default)).to eq(Warden::UNKNOWN_AUTHENTICATION_LEVEL)
    end

    it "clears the level when the user is deleted" do
      @serializer.store("user", :default)
      @serializer.store_level(:default, 2)
      @serializer.delete(:default)
      expect(@env['rack.session']).not_to have_key('warden.user.default.level')
    end
  end
end
