# encoding: utf-8
# frozen_string_literal: true

require 'rack/session/pool'

module WardenLogoutContract
  BACKEND_KEY = "warden.user.backend.key".freeze
  BACKEND_SESSION_KEY = "warden.user.backend.session".freeze
  PORTAL_KEY = "warden.user.portal.key".freeze
  PORTAL_SESSION_KEY = "warden.user.portal.session".freeze
  APPLICATION_MARKER_KEY = "application_marker".freeze

  class User
    attr_reader :id

    def initialize(id)
      @id = id
    end

    def ==(other)
      other.is_a?(self.class) && other.id == id
    end
  end

  class BackendUser < User; end
  class PortalUser < User; end

  class Client
    def initialize(app)
      @app = app
      @cookie = nil
    end

    def request(path)
      env = Rack::MockRequest.env_for(path)
      env['HTTP_COOKIE'] = @cookie if @cookie
      _status, headers, _body = @app.call(env)
      cookie = extract_session_cookie(headers)
      @cookie = cookie if cookie
      env
    end

    private

    def extract_session_cookie(headers)
      value = headers['set-cookie'] || headers['Set-Cookie']
      value = value.join("\n") if value.is_a?(Array)
      return nil unless value

      match = value.match(/rack\.session=[^;\n]+/)
      match && match[0]
    end
  end
end

RSpec.describe "Warden logout contract" do
  before(:all) do
    Warden::Manager.serialize_into_session(:backend) do |user|
      "backend-serialized:#{user.id}"
    end
    Warden::Manager.serialize_from_session(:backend) do |serialized|
      WardenLogoutContract::BackendUser.new(serialized.sub("backend-serialized:", ""))
    end
    Warden::Manager.serialize_into_session(:portal) do |user|
      "portal-serialized:#{user.id}"
    end
    Warden::Manager.serialize_from_session(:portal) do |serialized|
      WardenLogoutContract::PortalUser.new(serialized.sub("portal-serialized:", ""))
    end
  end

  after(:all) do
    [:backend_serialize, :backend_deserialize, :portal_serialize, :portal_deserialize].each do |method|
      if Warden::SessionSerializer.method_defined?(method)
        Warden::SessionSerializer.send(:remove_method, method)
      end
    end
  end

  before(:each) do
    @previous_logout_hooks = Warden::Manager._before_logout.dup
    Warden::Manager._before_logout.clear
    @logout_hook_records = []
    Warden::Manager.before_logout do |user, auth, opts|
      @logout_hook_records << {
        :scope => opts[:scope],
        :user => user,
        :session => session_snapshot(auth.raw_session)
      }
    end
  end

  after(:each) do
    Warden::Manager._before_logout.clear
    Warden::Manager._before_logout.concat(@previous_logout_hooks)
  end

  def session_snapshot(session)
    session.to_hash.dup
  end

  def build_client
    handler = method(:handle_request)
    app = Rack::Builder.new do
      use Rack::Session::Pool
      use Warden::Manager do |config|
        config.failure_app = lambda { |_env| [401, { 'Content-Type' => 'text/plain' }, ['Unauthenticated']] }
      end
      run lambda { |env| handler.call(env) }
    end.to_app
    WardenLogoutContract::Client.new(app)
  end

  def handle_request(env)
    warden = env['warden']
    request = Rack::Request.new(env)

    case request.path_info
    when "/login"
      login(env, warden)
    when "/logout/backend"
      warden.user(:backend) if request.params["load"] == "backend"
      warden.logout(:backend)
      record_logout(env, warden)
    when "/logout/all"
      warden.user(:backend) if request.params["load"] == "backend"
      warden.logout
      record_logout(env, warden)
    when "/probe"
      probe(env, warden)
    end

    [200, { 'Content-Type' => 'text/plain' }, ['OK']]
  end

  def login(env, warden)
    warden.set_user(WardenLogoutContract::BackendUser.new("backend-1"), :scope => :backend)
    warden.set_user(WardenLogoutContract::PortalUser.new("portal-1"), :scope => :portal)
    warden.session(:backend)[:authorization] = "backend-authorization"
    warden.session(:portal)[:authorization] = "portal-authorization"
    warden.raw_session[WardenLogoutContract::APPLICATION_MARKER_KEY] = "shared-session"

    session = warden.raw_session.to_hash
    env["contract.login"] = {
      :backend_user => warden.user(:backend),
      :portal_user => warden.user(:portal),
      :backend_authenticated => warden.authenticated?(:backend),
      :portal_authenticated => warden.authenticated?(:portal),
      :backend_serialized => session[WardenLogoutContract::BACKEND_KEY],
      :portal_serialized => session[WardenLogoutContract::PORTAL_KEY],
      :backend_authorization => session[WardenLogoutContract::BACKEND_SESSION_KEY],
      :portal_authorization => session[WardenLogoutContract::PORTAL_SESSION_KEY],
      :application_marker => session[WardenLogoutContract::APPLICATION_MARKER_KEY]
    }
  end

  def record_logout(env, warden)
    env["contract.logout"] = {
      :session => warden.raw_session.to_hash.dup,
      :backend_user => warden.user(:backend),
      :portal_user => warden.user(:portal),
      :backend_authenticated => warden.authenticated?(:backend),
      :portal_authenticated => warden.authenticated?(:portal)
    }
  end

  def probe(env, warden)
    env["contract.probe"] = {
      :backend_user => warden.user(:backend),
      :portal_user => warden.user(:portal),
      :backend_authenticated => warden.authenticated?(:backend),
      :portal_authenticated => warden.authenticated?(:portal),
      :session => warden.raw_session.to_hash.dup
    }
  end

  it "logs both scopes in through the initial request with distinguishable serialization" do
    client = build_client
    login = client.request("/login")

    expect(login["contract.login"][:backend_user]).to eq(WardenLogoutContract::BackendUser.new("backend-1"))
    expect(login["contract.login"][:portal_user]).to eq(WardenLogoutContract::PortalUser.new("portal-1"))
    expect(login["contract.login"][:backend_authenticated]).to be(true)
    expect(login["contract.login"][:portal_authenticated]).to be(true)
    expect(login["contract.login"][:backend_serialized]).to eq("backend-serialized:backend-1")
    expect(login["contract.login"][:portal_serialized]).to eq("portal-serialized:portal-1")
    expect(login["contract.login"][:backend_serialized]).not_to eq(login["contract.login"][:portal_serialized])
    expect(login["contract.login"][:backend_authorization]).to eq(:authorization => "backend-authorization")
    expect(login["contract.login"][:portal_authorization]).to eq(:authorization => "portal-authorization")
  end

  it "revokes a loaded scope without touching the other user or its authorization data" do
    client = build_client
    client.request("/login")

    logout = client.request("/logout/backend?load=backend")
    raw_session = logout["contract.logout"][:session]

    aggregate_failures "before_logout sees the still-visible session" do
      expect(@logout_hook_records.length).to eq(1)
      record = @logout_hook_records.first
      expect(record[:scope]).to eq(:backend)
      expect(record[:user]).to eq(WardenLogoutContract::BackendUser.new("backend-1"))
      expect(record[:session]).to include(
        WardenLogoutContract::BACKEND_KEY => "backend-serialized:backend-1",
        WardenLogoutContract::BACKEND_SESSION_KEY => { :authorization => "backend-authorization" },
        WardenLogoutContract::PORTAL_KEY => "portal-serialized:portal-1",
        WardenLogoutContract::PORTAL_SESSION_KEY => { :authorization => "portal-authorization" },
        "application_marker" => "shared-session"
      )
    end

    aggregate_failures "backend revoked without collateral damage" do
      expect(raw_session).not_to have_key(WardenLogoutContract::BACKEND_KEY),
        "proxy-only logout would leave the backend user in the persistent session"
      expect(raw_session).not_to have_key(WardenLogoutContract::BACKEND_SESSION_KEY),
        "clearing the persisted user without clearing its authorization data would leave the scoped session"
      expect(logout["contract.logout"][:backend_user]).to be_nil
      expect(logout["contract.logout"][:backend_authenticated]).to be(false)
      expect(logout["contract.logout"][:portal_user]).to eq(WardenLogoutContract::PortalUser.new("portal-1"))
      expect(logout["contract.logout"][:portal_authenticated]).to be(true)
      expect(raw_session[WardenLogoutContract::PORTAL_KEY]).to eq("portal-serialized:portal-1")
      expect(raw_session[WardenLogoutContract::PORTAL_SESSION_KEY]).to eq(:authorization => "portal-authorization")
      expect(raw_session[WardenLogoutContract::APPLICATION_MARKER_KEY]).to eq("shared-session")
    end

    probe = client.request("/probe")
    aggregate_failures "next request in the same client" do
      expect(probe["contract.probe"][:backend_user]).to be_nil
      expect(probe["contract.probe"][:backend_authenticated]).to be(false)
      expect(probe["contract.probe"][:portal_user]).to eq(WardenLogoutContract::PortalUser.new("portal-1"))
      expect(probe["contract.probe"][:portal_authenticated]).to be(true)
      expect(probe["contract.probe"][:session]).not_to have_key(WardenLogoutContract::BACKEND_KEY)
      expect(probe["contract.probe"][:session]).not_to have_key(WardenLogoutContract::BACKEND_SESSION_KEY)
      expect(probe["contract.probe"][:session][WardenLogoutContract::PORTAL_SESSION_KEY]).to eq(:authorization => "portal-authorization")
      expect(probe["contract.probe"][:session][WardenLogoutContract::APPLICATION_MARKER_KEY]).to eq("shared-session")
    end
  end

  it "revokes a scope that exists only in the persistent session" do
    client = build_client
    client.request("/login")

    logout = client.request("/logout/backend")
    raw_session = logout["contract.logout"][:session]

    aggregate_failures "before_logout sees the still-visible session" do
      expect(@logout_hook_records.length).to eq(1)
      record = @logout_hook_records.first
      expect(record[:scope]).to eq(:backend)
      expect(record[:user]).to be_nil
      expect(record[:session]).to include(
        WardenLogoutContract::BACKEND_KEY => "backend-serialized:backend-1",
        WardenLogoutContract::BACKEND_SESSION_KEY => { :authorization => "backend-authorization" },
        WardenLogoutContract::PORTAL_KEY => "portal-serialized:portal-1",
        WardenLogoutContract::PORTAL_SESSION_KEY => { :authorization => "portal-authorization" }
      )
    end

    aggregate_failures "backend revoked from persistent session only" do
      expect(raw_session).not_to have_key(WardenLogoutContract::BACKEND_KEY),
        "a logout that only clears the proxy cannot reach a user that was never loaded"
      expect(raw_session).not_to have_key(WardenLogoutContract::BACKEND_SESSION_KEY),
        "clearing only the persisted user would leave backend authorization data behind"
      expect(logout["contract.logout"][:backend_user]).to be_nil
      expect(logout["contract.logout"][:backend_authenticated]).to be(false)
      expect(logout["contract.logout"][:portal_user]).to eq(WardenLogoutContract::PortalUser.new("portal-1"))
      expect(logout["contract.logout"][:portal_authenticated]).to be(true)
      expect(raw_session[WardenLogoutContract::PORTAL_KEY]).to eq("portal-serialized:portal-1")
      expect(raw_session[WardenLogoutContract::PORTAL_SESSION_KEY]).to eq(:authorization => "portal-authorization")
      expect(raw_session[WardenLogoutContract::APPLICATION_MARKER_KEY]).to eq("shared-session")
    end

    probe = client.request("/probe")
    aggregate_failures "next request in the same client" do
      expect(probe["contract.probe"][:backend_user]).to be_nil
      expect(probe["contract.probe"][:backend_authenticated]).to be(false)
      expect(probe["contract.probe"][:portal_user]).to eq(WardenLogoutContract::PortalUser.new("portal-1"))
      expect(probe["contract.probe"][:portal_authenticated]).to be(true)
      expect(probe["contract.probe"][:session]).not_to have_key(WardenLogoutContract::BACKEND_KEY)
      expect(probe["contract.probe"][:session]).not_to have_key(WardenLogoutContract::BACKEND_SESSION_KEY)
      expect(probe["contract.probe"][:session][WardenLogoutContract::PORTAL_KEY]).to eq("portal-serialized:portal-1")
      expect(probe["contract.probe"][:session][WardenLogoutContract::PORTAL_SESSION_KEY]).to eq(:authorization => "portal-authorization")
      expect(probe["contract.probe"][:session][WardenLogoutContract::APPLICATION_MARKER_KEY]).to eq("shared-session")
    end
  end

  it "empties the shared application session when a scope was never read into the proxy" do
    client = build_client
    client.request("/login")

    logout = client.request("/logout/all?load=backend")
    raw_session = logout["contract.logout"][:session]

    aggregate_failures "before_logout runs only for users instantiated in this request" do
      expect(@logout_hook_records.length).to eq(1)
      record = @logout_hook_records.first
      expect(record[:scope]).to eq(:backend)
      expect(record[:user]).to eq(WardenLogoutContract::BackendUser.new("backend-1"))
      expect(record[:session]).to include(
        WardenLogoutContract::BACKEND_KEY => "backend-serialized:backend-1",
        WardenLogoutContract::BACKEND_SESSION_KEY => { :authorization => "backend-authorization" },
        WardenLogoutContract::PORTAL_KEY => "portal-serialized:portal-1",
        WardenLogoutContract::PORTAL_SESSION_KEY => { :authorization => "portal-authorization" },
        "application_marker" => "shared-session"
      )
      expect(@logout_hook_records.map { |hook| hook[:scope] }).not_to include(:portal),
        "portal was never read into this proxy and must not receive a logout callback"
    end

    aggregate_failures "whole-site logout" do
      expect(raw_session).to be_empty
      expect(logout["contract.logout"][:backend_user]).to be_nil
      expect(logout["contract.logout"][:backend_authenticated]).to be(false)
      expect(logout["contract.logout"][:portal_user]).to be_nil
      expect(logout["contract.logout"][:portal_authenticated]).to be(false)
    end

    probe = client.request("/probe")
    aggregate_failures "next request in the same client" do
      expect(probe["contract.probe"][:backend_user]).to be_nil
      expect(probe["contract.probe"][:backend_authenticated]).to be(false)
      expect(probe["contract.probe"][:portal_user]).to be_nil
      expect(probe["contract.probe"][:portal_authenticated]).to be(false)
      expect(probe["contract.probe"][:session]).to be_empty
    end
  end

  it "empties the shared application session when no user was read into the proxy" do
    client = build_client
    client.request("/login")

    logout = client.request("/logout/all")
    raw_session = logout["contract.logout"][:session]

    aggregate_failures "logout callbacks with an empty proxy user cache" do
      expect(@logout_hook_records).to be_empty,
        "logout must not invent callbacks for users it never instantiated"
      expect(raw_session).to be_empty
      expect(logout["contract.logout"][:backend_user]).to be_nil
      expect(logout["contract.logout"][:backend_authenticated]).to be(false)
      expect(logout["contract.logout"][:portal_user]).to be_nil
      expect(logout["contract.logout"][:portal_authenticated]).to be(false)
    end

    probe = client.request("/probe")
    aggregate_failures "next request in the same client" do
      expect(probe["contract.probe"][:backend_user]).to be_nil
      expect(probe["contract.probe"][:backend_authenticated]).to be(false)
      expect(probe["contract.probe"][:portal_user]).to be_nil
      expect(probe["contract.probe"][:portal_authenticated]).to be(false)
      expect(probe["contract.probe"][:session]).to be_empty
    end
  end
end
