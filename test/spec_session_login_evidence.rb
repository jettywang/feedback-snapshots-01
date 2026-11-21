# frozen_string_literal: true

require_relative 'helper'

require 'json'
require 'stringio'
require 'uri'
require 'rack/mock'
require 'rack/lint'
require 'rack/response'

require_relative '../lib/rack/session/cookie'
require_relative '../lib/rack/session/pool'

# Evidence for the incident review: "seeing Set-Cookie" is not proof that a
# login landed. These specs exercise both rack-session backends (Cookie and
# Pool) through a minimal RFC 6265-flavoured client jar, and check whether
# the *next* visit recovers the real session.

# A minimal client-side cookie jar enforcing the acceptance/return rules a
# browser applies: Domain match on store, Secure/Path/Domain match on send.
class EvidenceJar
  Entry = Struct.new(:name, :value, :domain, :path, :secure)

  attr_reader :stored, :rejections

  def initialize
    @stored = []
    @rejections = []
  end

  # Returns true if a Set-Cookie header was present at all.
  def absorb(response, uri)
    header = response["Set-Cookie"]
    return false unless header

    header.split("\n").each do |line|
      name, rest = line.split("=", 2)
      value, *attributes = rest.split(";").map(&:strip)
      entry = Entry.new(name, value, nil, "/", false)
      attributes.each do |attribute|
        key, val = attribute.split("=", 2)
        case key.downcase
        when "domain" then entry.domain = val
        when "path" then entry.path = val || "/"
        when "secure" then entry.secure = true
        end
      end

      if entry.domain && !domain_match?(uri.host, entry.domain)
        @rejections << "Domain=#{entry.domain} does not match host #{uri.host}"
      else
        @stored << entry
      end
    end
    true
  end

  def cookie_header_for(uri)
    pairs = @stored.select do |entry|
      (!entry.secure || uri.scheme == "https") &&
        uri.path.start_with?(entry.path || "/") &&
        (entry.domain.nil? || domain_match?(uri.host, entry.domain))
    end.map {|entry| "#{entry.name}=#{entry.value}"}
    pairs.empty? ? nil : pairs.join("; ")
  end

  private

  def domain_match?(host, domain)
    host == domain || host.end_with?(".#{domain}")
  end
end

describe "login landing evidence (Set-Cookie is not proof of login)" do
  secret = "s" * 64

  login_app = lambda do |env|
    request = Rack::Request.new(env)
    session = env["rack.session"]
    session["user_id"] = 4242 if request.path == "/login"
    Rack::Response.new(JSON.dump(
      "user_id" => session["user_id"],
      "session_id" => session["session_id"]
    ), 200, {"content-type" => "application/json"}).to_a
  end

  build_app = lambda do |backend, **options|
    app = Rack::Lint.new(login_app)
    case backend
    when :cookie then Rack::Session::Cookie.new(app, secrets: secret, **options)
    when :pool then Rack::Session::Pool.new(app, **options)
    end
  end

  fetch = lambda do |app, url, jar, errors: nil|
    uri = URI(url)
    env = {}
    if header = jar.cookie_header_for(uri)
      env["HTTP_COOKIE"] = header
    end
    env["rack.errors"] = errors if errors
    response = Rack::MockRequest.new(app).get(url, env)
    jar.absorb(response, uri)
    response
  end

  evidence = lambda do |fields|
    puts "[evidence] " + fields.map {|key, value| "#{key}=#{value.inspect}"}.join(" ")
  end

  [:cookie, :pool].each do |backend|
    it "recovers the real session on the next visit after a full round trip (#{backend} backend)" do
      jar = EvidenceJar.new
      app = build_app.call(backend)

      login = fetch.call(app, "http://example.org/login", jar)
      login_sid = JSON.parse(login.body)["session_id"]

      followup = fetch.call(app, "http://example.org/", jar)
      body = JSON.parse(followup.body)

      evidence.call(
        backend: backend, scenario: :full_round_trip,
        set_cookie: !login["Set-Cookie"].nil?,
        cookie_returned: !jar.cookie_header_for(URI("http://example.org/")).nil?,
        recovered_user_id: body["user_id"], sid_stable: body["session_id"] == login_sid
      )

      login["Set-Cookie"].wont_be_nil
      body["user_id"].must_equal 4242
      body["session_id"].must_equal login_sid
    end

    it "loses the session when the client refuses to return the cookie (#{backend} backend)" do
      jar = EvidenceJar.new
      app = build_app.call(backend, secure: true)

      # Login over HTTPS: the server emits a Secure cookie and the jar stores it.
      login = fetch.call(app, "https://example.org/login", jar)
      login["Set-Cookie"].must_match(/secure/i)
      jar.stored.size.must_equal 1

      # The next visit is plain HTTP: the jar (like a browser) withholds the
      # Secure cookie, so the server sees no cookie and starts a fresh session.
      jar.cookie_header_for(URI("http://example.org/")).must_be_nil
      followup = fetch.call(app, "http://example.org/", jar)
      body = JSON.parse(followup.body)

      evidence.call(
        backend: backend, scenario: :client_reject_secure_over_http,
        set_cookie: true, cookie_returned: false,
        recovered_user_id: body["user_id"]
      )

      body["user_id"].must_be_nil
    end

    it "loses the session when the client rejects a mismatched Domain (#{backend} backend)" do
      jar = EvidenceJar.new
      app = build_app.call(backend, domain: "example.com")

      login = fetch.call(app, "http://example.org/login", jar)
      login["Set-Cookie"].wont_be_nil
      jar.stored.must_be_empty
      jar.rejections.wont_be_empty

      followup = fetch.call(app, "http://example.org/", jar)
      body = JSON.parse(followup.body)

      evidence.call(
        backend: backend, scenario: :client_reject_domain_mismatch,
        set_cookie: true, jar_rejections: jar.rejections,
        recovered_user_id: body["user_id"]
      )

      body["user_id"].must_be_nil
    end
  end

  it "emits no Set-Cookie at all when the cookie backend cannot fit the session in 4K" do
    jar = EvidenceJar.new
    errors = StringIO.new
    app = build_app.call(:cookie)

    big_app = Rack::Session::Cookie.new(Rack::Lint.new(lambda do |env|
      env["rack.session"]["user_id"] = 4242
      env["rack.session"]["blob"] = "x" * 5000
      Rack::Response.new("ok").to_a
    end), secrets: secret)

    response = fetch.call(big_app, "http://example.org/login", jar, errors: errors)

    evidence.call(
      backend: :cookie, scenario: :server_write_failure_oversize,
      set_cookie: !response["Set-Cookie"].nil?, rack_errors: errors.string.strip
    )

    response["Set-Cookie"].must_be_nil
    errors.string.must_match(/exceeds 4K/)
    errors.string.must_match(/failed to save session/)

    # Even if the client had kept an earlier cookie, this login never landed.
    followup = fetch.call(app, "http://example.org/", jar)
    JSON.parse(followup.body)["user_id"].must_be_nil
  end

  it "emits no Set-Cookie when the pool backend store write fails" do
    outage_pool = Class.new(Rack::Session::Pool) do
      def write_session(req, sid, session, options)
        false # emulates a backing store outage (e.g. Redis down)
      end
    end
    def outage_pool.name; "OutagePool"; end

    jar = EvidenceJar.new
    errors = StringIO.new
    app = outage_pool.new(Rack::Lint.new(login_app))

    response = fetch.call(app, "http://example.org/login", jar, errors: errors)

    evidence.call(
      backend: :pool, scenario: :server_write_failure_store_outage,
      set_cookie: !response["Set-Cookie"].nil?, rack_errors: errors.string.strip
    )

    response["Set-Cookie"].must_be_nil
    errors.string.must_match(/failed to save session/)

    followup = fetch.call(app, "http://example.org/", jar)
    JSON.parse(followup.body)["user_id"].must_be_nil
  end

  it "cannot recover the session after a pool restart even though the client returns the cookie" do
    jar = EvidenceJar.new
    first = Rack::Session::Pool.new(Rack::Lint.new(login_app))

    login = fetch.call(first, "http://example.org/login", jar)
    login["Set-Cookie"].wont_be_nil
    login_sid = JSON.parse(login.body)["session_id"]

    # Server restarts (or a second process): the in-memory pool is gone.
    restarted = Rack::Session::Pool.new(Rack::Lint.new(login_app))
    followup = fetch.call(restarted, "http://example.org/", jar)
    body = JSON.parse(followup.body)

    evidence.call(
      backend: :pool, scenario: :pool_restart,
      set_cookie: true, cookie_returned: true,
      recovered_user_id: body["user_id"],
      new_set_cookie: !followup["Set-Cookie"].nil?,
      sid_stable: body["session_id"] == login_sid
    )

    body["user_id"].must_be_nil
    body["session_id"].wont_equal login_sid
    followup["Set-Cookie"].wont_be_nil
  end
end
