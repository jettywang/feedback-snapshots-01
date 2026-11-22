# encoding: utf-8
# frozen_string_literal: true

class FakeAccountStore
  class Unavailable < StandardError; end

  attr_reader :accounts

  def initialize
    @accounts = {}
    @pending_failures = 0
  end

  def add(id, user)
    @accounts[id] = user
  end

  def disable!(id)
    @accounts.fetch(id)[:status] = :disabled
  end

  def fail_next_read!
    @pending_failures += 1
  end

  def find(id)
    if @pending_failures > 0
      @pending_failures -= 1
      raise Unavailable, "temporary read failure for #{id.inspect}"
    end

    user = @accounts.fetch(id)
    return Warden::SessionSerializer::SessionResult.denied("account disabled") if user[:status] == :disabled

    Warden::SessionSerializer::SessionResult.ok(user)
  end
end

class AccountSerializer < Warden::SessionSerializer
  class << self
    attr_accessor :account_store
  end

  def deserialize(id)
    self.class.account_store.find(id)
  rescue FakeAccountStore::Unavailable => error
    Warden::SessionSerializer::SessionResult.unconfirmed(error.message)
  end
end

RSpec.describe Warden::SessionSerializer::SessionResult do
  it "builds an ok result carrying the reconstituted user" do
    user = { :id => 1 }
    result = described_class.ok(user)

    expect(result.status).to eq(:ok)
    expect(result.user).to equal(user)
    expect(result).to be_ok
    expect(result).not_to be_denied
    expect(result).not_to be_unconfirmed
  end

  it "builds a denied result with an optional reason" do
    result = described_class.denied("account disabled")

    expect(result.status).to eq(:denied)
    expect(result.user).to be_nil
    expect(result.reason).to eq("account disabled")
    expect(result).to be_denied
  end

  it "builds an unconfirmed result with an optional reason" do
    result = described_class.unconfirmed("store unavailable")

    expect(result.status).to eq(:unconfirmed)
    expect(result.user).to be_nil
    expect(result.reason).to eq("store unavailable")
    expect(result).to be_unconfirmed
  end

  it "rejects an unknown status" do
    expect { described_class.new(:bogus) }.to raise_error(ArgumentError, /unknown session result status/)
  end
end

RSpec.describe "Warden session fetch result contract" do
  let(:alice) { { :id => 1, :name => "Alice", :status => :active } }
  let(:bob)   { { :id => 2, :name => "Bob",   :status => :active } }
  let(:store) { FakeAccountStore.new }
  let(:env) do
    environment = env_with_params
    environment['rack.session'] = {}
    environment
  end

  before do
    AccountSerializer.account_store = store
    store.add(1, alice)
    store.add(2, bob)
  end

  def build_serializer(config = nil)
    AccountSerializer.new(env, config)
  end

  describe "available user" do
    2.times do |attempt|
      it "reconstitutes the user and keeps the stored session (verification #{attempt + 1})" do
        serializer = build_serializer
        serializer.store(1, :default)

        first_user = serializer.fetch(:default)
        second_user = serializer.fetch(:default)

        expect(first_user).to eq(alice)
        expect(second_user).to eq(alice)
        expect(serializer).to be_stored(:default)
      end
    end
  end

  describe "disabled account" do
    2.times do |attempt|
      it "permanently denies the old principal and removes the session (verification #{attempt + 1})" do
        serializer = build_serializer
        serializer.store(1, :default)
        store.disable!(1)

        expect(serializer.fetch(:default)).to be_nil
        expect(serializer).not_to be_stored(:default)

        # The disabled principal must not recover on a following request.
        expect(serializer.fetch(:default)).to be_nil
        expect(serializer).not_to be_stored(:default)
      end
    end
  end

  describe "temporary read failure with the default policy" do
    2.times do |attempt|
      it "keeps the stored session so it can be confirmed later (verification #{attempt + 1})" do
        serializer = build_serializer
        serializer.store(1, :default)
        store.fail_next_read!

        expect(serializer.fetch(:default)).to be_nil
        expect(serializer).to be_stored(:default)

        # Once the transient problem clears, the existing session works again.
        expect(serializer.fetch(:default)).to eq(alice)
        expect(serializer).to be_stored(:default)
      end
    end
  end

  describe "temporary read failure with a strict policy" do
    2.times do |attempt|
      it "removes the stored session when configured to do so (verification #{attempt + 1})" do
        config = Warden::Config.new
        config.clear_stored_session_on_unconfirmed!
        serializer = build_serializer(config)
        serializer.store(1, :default)
        store.fail_next_read!

        expect(serializer.fetch(:default)).to be_nil
        expect(serializer).not_to be_stored(:default)

        # A later successful read cannot bring the removed session back.
        expect(serializer.fetch(:default)).to be_nil
      end
    end
  end

  describe "other scopes" do
    it "keeps an existing session in another scope when one scope is denied" do
      serializer = build_serializer
      serializer.store(1, :default)
      serializer.store(2, :admin)
      store.disable!(1)

      expect(serializer.fetch(:default)).to be_nil
      expect(serializer).not_to be_stored(:default)
      expect(serializer).to be_stored(:admin)
      expect(serializer.fetch(:admin)).to eq(bob)
    end

    it "keeps an existing session in another scope when one scope is unconfirmed" do
      serializer = build_serializer
      serializer.store(1, :default)
      serializer.store(2, :admin)
      store.fail_next_read!

      expect(serializer.fetch(:default)).to be_nil
      expect(serializer).to be_stored(:default)
      expect(serializer).to be_stored(:admin)
      expect(serializer.fetch(:admin)).to eq(bob)
    end
  end

  describe "legacy return values" do
    it "still treats a bare user object as a successful fetch" do
      serializer = Warden::SessionSerializer.new(env)
      serializer.store("user", :default)

      expect(serializer.fetch(:default)).to eq("user")
      expect(serializer).to be_stored(:default)
    end

    it "still removes the stored session when nil is returned" do
      serializer = Warden::SessionSerializer.new(env)
      serializer.store("user", :default)
      allow(serializer).to receive(:deserialize).and_return(nil)

      expect(serializer.fetch(:default)).to be_nil
      expect(serializer).not_to be_stored(:default)
    end
  end

  describe "through Warden::Proxy" do
    after do
      Warden::Manager.serialize_from_session { |key| key }
      Warden::Manager.serialize_into_session { |user| user }
    end

    def build_stack(configurator = nil)
      app = lambda do |environment|
        environment['warden'].user
        valid_response
      end
      setup_rack(app, :configurator => configurator || proc {})
    end

    def request_with_stored_key(store_id, stack = build_stack)
      environment = env_with_params
      environment['rack.session'] = { "warden.user.default.key" => store_id }
      stack.call(environment)
      environment
    end

    before do
      current_store = store
      Warden::Manager.serialize_into_session { |user| user[:id] }
      Warden::Manager.serialize_from_session do |id|
        current_store.find(id)
      rescue FakeAccountStore::Unavailable => error
        Warden::SessionSerializer::SessionResult.unconfirmed(error.message)
      end
    end

    it "removes a denied session and never restores it on later requests" do
      store.disable!(1)

      environment = request_with_stored_key(1)
      expect(environment['warden'].user).to be_nil
      expect(environment['rack.session']).not_to have_key("warden.user.default.key")

      second_environment = request_with_stored_key(1)
      expect(second_environment['warden'].user).to be_nil
    end

    it "retains an unconfirmed session by default and restores it once the store recovers" do
      store.fail_next_read!

      environment = request_with_stored_key(1)
      expect(environment['warden'].user).to be_nil
      expect(environment['rack.session']).to have_key("warden.user.default.key")

      recovered_environment = request_with_stored_key(1)
      expect(recovered_environment['warden'].user).to eq(alice)
    end

    it "clears an unconfirmed session when the strict configuration is enabled" do
      store.fail_next_read!
      configurator = proc { |config| config.clear_stored_session_on_unconfirmed! }

      environment = request_with_stored_key(1, build_stack(configurator))
      expect(environment['warden'].user).to be_nil
      expect(environment['rack.session']).not_to have_key("warden.user.default.key")
    end
  end
end
