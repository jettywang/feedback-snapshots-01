# encoding: utf-8
# frozen_string_literal: true

RSpec.describe Warden::LoginEvent do
  before(:all) do
    load_strategies
  end

  before(:each) do
    RAM = Warden::Manager unless defined?(RAM)
    RAM._after_set_user.clear
  end

  after(:each) do
    RAM._after_set_user.clear
  end

  describe "password authentication" do
    it "records a fresh credentials event with the scoped identity" do
      app = lambda do |e|
        e['warden'].authenticate!(:password)
        valid_response
      end
      env = env_with_params("/", :username => "fred", :password => "sekrit")
      setup_rack(app).call(env)

      events = env['warden'].login_events
      expect(events.size).to eq(1)

      event = events.first
      expect(event.event).to eq(:authentication)
      expect(event.user).to eq("Authenticated User")
      expect(event.scope).to eq(:default)
      expect(event.strategy).to eq(:password)
      expect(event.at).to be_a(Time)
      expect(event).to be_fresh_credentials
      expect(event).to be_stored
      expect(event).not_to be_fetched
      expect(event).not_to be_failure
      expect(env['warden'].fresh_authentication?).to be(true)
    end

    it "scopes the evidence to the authenticated scope" do
      app = lambda do |e|
        e['warden'].authenticate!(:password, :scope => :admin)
        valid_response
      end
      env = env_with_params("/", :username => "fred", :password => "sekrit")
      setup_rack(app).call(env)

      event = env['warden'].login_events.first
      expect(event.event).to eq(:authentication)
      expect(event.scope).to eq(:admin)
      expect(env['warden'].fresh_authentication?(:admin)).to be(true)
      expect(env['warden'].fresh_authentication?).to be(false)
    end
  end

  describe "session restore" do
    it "records a fetch event that is not a fresh authentication" do
      app = lambda do |e|
        e['warden'].user
        valid_response
      end
      env = env_with_params("/", {}, 'rack.session' => { 'warden.user.default.key' => 'Persisted User' })
      setup_rack(app).call(env)

      events = env['warden'].login_events
      expect(events.size).to eq(1)

      event = events.first
      expect(event.event).to eq(:fetch)
      expect(event.user).to eq("Persisted User")
      expect(event.scope).to eq(:default)
      expect(event.strategy).to be_nil
      expect(event).to be_fetched
      expect(event).not_to be_fresh_credentials
      expect(event).not_to be_stored
      expect(env['warden'].fresh_authentication?).to be(false)
    end
  end

  describe "manual set_user" do
    it "records a set_user event that is not a fresh authentication" do
      app = lambda do |e|
        e['warden'].set_user("Manual User")
        valid_response
      end
      env = env_with_params
      setup_rack(app).call(env)

      event = env['warden'].login_events.first
      expect(event.event).to eq(:set_user)
      expect(event.user).to eq("Manual User")
      expect(event.scope).to eq(:default)
      expect(event.strategy).to be_nil
      expect(event).not_to be_fresh_credentials
      expect(event).to be_stored
      expect(env['warden'].fresh_authentication?).to be(false)
    end
  end

  describe "failed authentication" do
    it "records a failure event with the scope and a nil identity" do
      app = lambda do |e|
        e['warden'].authenticate!(:password)
        valid_response
      end
      env = env_with_params("/", :username => "fred", :password => "wrong")
      status, = setup_rack(app).call(env)
      expect(status).to eq(401)

      events = env['warden'].login_events
      expect(events.size).to eq(1)

      event = events.first
      expect(event.event).to eq(:failure)
      expect(event.user).to be_nil
      expect(event.scope).to eq(:default)
      expect(event.strategy).to eq(:password)
      expect(event).to be_failure
      expect(event).not_to be_fresh_credentials
      expect(env['warden'].user).to be_nil
      expect(env['warden'].fresh_authentication?).to be(false)
    end

    it "records a failure event when a strategy throws :warden" do
      app = lambda do |e|
        e['warden'].authenticate!(:failz)
        valid_response
      end
      env = env_with_params
      status, = setup_rack(app).call(env)
      expect(status).to eq(401)

      event = env['warden'].login_events.first
      expect(event.event).to eq(:failure)
      expect(event.strategy).to eq(:failz)
    end

    it "records a single failure when authenticate and authenticate! both run" do
      app = lambda do |e|
        e['warden'].authenticate(:password)
        e['warden'].authenticate!(:password)
        valid_response
      end
      env = env_with_params("/", :username => "fred", :password => "wrong")
      setup_rack(app).call(env)

      failures = env['warden'].login_events.select(&:failure?)
      expect(failures.size).to eq(1)
    end
  end

  describe "hook compatibility" do
    it "still runs after_set_user callbacks for each event kind" do
      seen = []
      RAM.after_set_user { |user, auth, opts| seen << [user, opts[:event]] }
      app = lambda do |e|
        e['warden'].authenticate!(:password)
        valid_response
      end
      env = env_with_params("/", :username => "fred", :password => "sekrit")
      setup_rack(app).call(env)

      expect(seen).to eq([["Authenticated User", :authentication]])
      expect(env['warden'].login_events.map(&:event)).to eq([:authentication])
    end

    it "keeps the recorded event when an after_set_user hook fails" do
      RAM.after_set_user { |user, auth, opts| raise "hook boom" }
      app = lambda do |e|
        e['warden'].set_user("foo")
        valid_response
      end
      env = env_with_params
      expect { setup_rack(app).call(env) }.to raise_error("hook boom")

      event = env['warden'].login_events.first
      expect(event.event).to eq(:set_user)
      expect(event.user).to eq("foo")
      expect(event).to be_hook_failed
      expect(event.hook_error).to be_a(RuntimeError)
      expect(event.hook_error.message).to eq("hook boom")
    end
  end

  describe "evidence hash" do
    it "exposes a reconcilable description of the event" do
      app = lambda do |e|
        e['warden'].authenticate!(:password)
        valid_response
      end
      env = env_with_params("/", :username => "fred", :password => "sekrit")
      setup_rack(app).call(env)

      evidence = env['warden'].login_events.first.to_h
      expect(evidence[:event]).to eq(:authentication)
      expect(evidence[:scope]).to eq(:default)
      expect(evidence[:user]).to eq("Authenticated User")
      expect(evidence[:strategy]).to eq(:password)
      expect(evidence[:stored]).to be(true)
      expect(evidence[:at]).to be_a(Time)
      expect(evidence[:hook_error]).to be_nil
    end
  end
end
