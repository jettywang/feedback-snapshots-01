# encoding: utf-8
# frozen_string_literal: true
require 'spec_helper'

RSpec.describe "single sign-on result contract" do
  before(:all) do
    load_strategies
  end

  # SSO is consulted first; the legacy password strategy only backs it up.
  let(:ordered_strategies) { [:single_sign_on, :legacy_password] }

  def run_strategy(label, params = {})
    Warden::Strategies[label].new(env_with_params("/", params)).tap(&:_run!)
  end

  describe "Warden::Strategies::Base result contract" do
    context "missing credentials" do
      it "passes without a failure and keeps cascading" do
        strategy = run_strategy(:single_sign_on)
        expect(strategy.result).to be_nil
        expect(strategy).not_to be_halted
        expect(strategy).not_to be_failed
        expect(strategy).not_to be_successful
        expect(strategy.user).to be_nil
      end
    end

    context "verification failure" do
      it "soft-fails, records the message and keeps cascading" do
        strategy = run_strategy(:single_sign_on, :sso_token => "bad")
        expect(strategy.result).to be(:failure)
        expect(strategy).to be_failed
        expect(strategy).not_to be_halted
        expect(strategy.message).to eq("Single sign-on token could not be verified")
      end
    end

    context "explicit rejection" do
      it "hard-fails with the upstream message and terminates the cascade" do
        strategy = run_strategy(:single_sign_on, :sso_token => "deactivated")
        expect(strategy.result).to be(:failure)
        expect(strategy).to be_failed
        expect(strategy).to be_halted
        expect(strategy).not_to be_successful
        expect(strategy.message).to eq("Account deactivated by the identity provider")
      end
    end

    context "short-circuit success" do
      it "succeeds, assigns the user and terminates the cascade" do
        strategy = run_strategy(:single_sign_on, :sso_token => "good")
        expect(strategy.result).to be(:success)
        expect(strategy).to be_successful
        expect(strategy).to be_halted
        expect(strategy).not_to be_failed
        expect(strategy.user).to eq("SSO User")
        expect(strategy.message).to eq("Single sign-on accepted")
      end
    end
  end

  describe "legacy password strategy" do
    it "passes and keeps cascading when it has no credentials" do
      strategy = run_strategy(:legacy_password)
      expect(strategy.result).to be_nil
      expect(strategy).not_to be_halted
      expect(strategy).not_to be_failed
    end

    it "hard-fails on bad credentials" do
      strategy = run_strategy(:legacy_password, :username => "fred", :password => "wrong")
      expect(strategy).to be_failed
      expect(strategy).to be_halted
      expect(strategy.message).to eq("Username or password is incorrect")
    end

    it "succeeds on valid legacy credentials" do
      strategy = run_strategy(:legacy_password, :username => "fred", :password => "sekrit")
      expect(strategy).to be_successful
      expect(strategy.user).to eq("Legacy User")
    end
  end

  describe "end to end strategy cascade" do
    def authenticate_with(params)
      env = env_with_params("/", params)
      app = lambda do |rack_env|
        rack_env['warden'].authenticate(*ordered_strategies)
        if rack_env['warden'].authenticated?
          valid_response
        else
          [401, {"Content-Type" => "text/plain"}, [rack_env['warden'].message.to_s]]
        end
      end
      setup_rack(app, :default_strategies => ordered_strategies).call(env)
      env
    end

    it "falls through SSO to the legacy client when no SSO credential is present" do
      env = authenticate_with(:username => "fred", :password => "sekrit")
      expect(env['warden.spec.strategies']).to eq([:single_sign_on, :legacy_password])
      expect(env['warden']).to be_authenticated
      expect(env['warden'].user).to eq("Legacy User")
    end

    it "cascades past a soft SSO failure and keeps the password fallback usable" do
      env = authenticate_with(:sso_token => "bad", :username => "fred", :password => "sekrit")
      expect(env['warden.spec.strategies']).to eq([:single_sign_on, :legacy_password])
      expect(env['warden']).to be_authenticated
    end

    it "returns 401 and stops cascading when the upstream confirms deactivation" do
      env = authenticate_with(:sso_token => "deactivated", :username => "fred", :password => "sekrit")
      expect(env['warden.spec.strategies']).to eq([:single_sign_on])
      expect(env['warden']).not_to be_authenticated
      expect(env['warden'].winning_strategy).to be_halted
      expect(env['warden'].message).to eq("Account deactivated by the identity provider")
    end

    it "short-circuits on a valid SSO session without touching the legacy strategy" do
      env = authenticate_with(:sso_token => "good", :username => "fred", :password => "sekrit")
      expect(env['warden.spec.strategies']).to eq([:single_sign_on])
      expect(env['warden']).to be_authenticated
      expect(env['warden'].user).to eq("SSO User")
    end

    it "ends unauthenticated with the soft-failure message when nothing authenticates" do
      env = authenticate_with(:sso_token => "bad")
      expect(env['warden.spec.strategies']).to eq([:single_sign_on, :legacy_password])
      expect(env['warden']).not_to be_authenticated
    end
  end
end
