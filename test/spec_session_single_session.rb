# frozen_string_literal: true

# Released under the MIT License.
# Copyright, 2024, by Samuel Williams.

require_relative 'helper'

require 'rack/response'
require 'rack/mock'
require 'json'

require_relative '../lib/rack/session/single_session'

describe Rack::Session::SingleSession do
  session_key = Rack::Session::SingleSession::DEFAULT_OPTIONS[:key]
  preference_key = Rack::Session::SingleSession::DEFAULT_OPTIONS[:preference_key]

  # A controllable stand-in for a real server-side store. It can be told to
  # reject the next write (partial failure) and to drop every record
  # (server-side eviction) while the client keeps its cookies.
  class FakeBackend
    attr_accessor :fail_next_write

    def initialize
      @records = {}
      @fail_next_write = false
    end

    def create_record(session_id)
      @records[session_id] ||= {}
    end

    def read_record(session_id)
      record = @records[session_id]
      record && record.dup
    end

    def write_record(session_id, record)
      if @fail_next_write
        @fail_next_write = false
        return false
      end

      @records[session_id] = record
      true
    end

    def destroy_record(session_id)
      @records.delete(session_id)
    end

    def evict!
      @records.clear
    end

    def [](session_id)
      @records[session_id]
    end

    def size
      @records.size
    end
  end

  # One application exercising the unified interface through every path the
  # tests need.
  APP = lambda do |env|
    session = env[Rack::Session::RACK_SESSION]

    case env["PATH_INFO"]
    when "/setup"
      session[:theme] = "dark"            # ordinary preference -> cookie
      session.grant!("admin")             # authorization   -> server only
    when "/grant-billing"
      session.grant!("billing")
    when "/check"
      body = {
        "theme" => session[:theme],
        "admin" => session.permitted?(:admin),
        "billing" => session.permitted?(:billing),
      }
      return Rack::Response.new(JSON.generate(body)).to_a
    when "/forged-read"
      # The app must not be able to read authorization straight off the client.
      body = { "permissions" => session["permissions"] }
      return Rack::Response.new(JSON.generate(body)).to_a
    end

    Rack::Response.new(session.to_hash.inspect).to_a
  end

  def build_request(backend)
    middleware = Rack::Session::SingleSession.new(APP, backend: backend)
    [middleware, Rack::MockRequest.new(middleware)]
  end

  # Rack 3 exposes Set-Cookie as an array; collapse it back into a single
  # Cookie request header worth of name=value pairs.
  def cookie_header(response)
    response.cookies.map { |name, cookie| "#{name}=#{cookie_value(cookie)}" }.join("; ")
  end

  # Rack 3 stores each parsed cookie's value in an array.
  def cookie_value(cookie)
    value = cookie.value
    value.is_a?(Array) ? value.first : value
  end

  def decoded_preferences(response)
    name = Rack::Session::SingleSession::DEFAULT_OPTIONS[:preference_key]
    JSON.parse(Rack::Utils.unescape(cookie_value(response.cookies[name])))
  end

  # Merge a response's Set-Cookie values over an existing request cookie jar,
  # the way a browser keeps an unchanged cookie it was not re-sent.
  def merge_cookies(jar, response)
    incoming = jar.split("; ").each_with_object({}) do |pair, hash|
      name, value = pair.split("=", 2)
      hash[name] = value
    end

    response.cookies.each do |name, cookie|
      incoming[name] = cookie_value(cookie)
    end

    incoming.map { |name, value| "#{name}=#{value}" }.join("; ")
  end

  it "stores preferences in the cookie but authorization only on the server" do
    backend = FakeBackend.new
    _, request = build_request(backend)

    response = request.get("/setup")

    # Both cookies are issued, but neither carries authorization data.
    cookies = response.cookies
    session_cookie = cookie_value(cookies[session_key])
    preference_cookie = cookie_value(cookies[preference_key])

    decoded_preferences = decoded_preferences(response)
    _(decoded_preferences).must_equal("theme" => "dark")
    _(decoded_preferences.keys).must_equal(%w[theme])

    # The opaque session id is not the payload; no permission leaks into either.
    _(session_cookie).wont_include "admin"
    _(preference_cookie).wont_include "admin"
    _(preference_cookie).wont_include "permissions"
    # The permission lives exclusively in the backend record.
    record = backend[session_cookie]
    _(record["permissions"]).must_equal(["admin"])
    _(backend.size).must_equal 1
  end

  it "keeps an established permission across requests carrying the cookie" do
    backend = FakeBackend.new
    _, request = build_request(backend)

    setup = request.get("/setup")
    jar = cookie_header(setup)

    check = request.get("/check", "HTTP_COOKIE" => jar)
    body = JSON.parse(check.body)

    _(body["theme"]).must_equal("dark")
    _(body["admin"]).must_equal(true)
    _(body["billing"]).must_equal(false)
  end

  it "does not persist authorization when the backend rejects a write" do
    backend = FakeBackend.new
    _, request = build_request(backend)

    setup = request.get("/setup")
    jar = cookie_header(setup)

    # Request two: a backend write fails halfway through.
    errors = StringIO.new
    backend.fail_next_write = true
    failed = request.get("/grant-billing", "HTTP_COOKIE" => jar, "rack.errors" => errors)
    _(errors.string).must_match(/rejected the session update/)

    # The preference cookie is still refreshed, but the rejected permission
    # never reaches the backend.
    _(failed.cookies[preference_key]).wont_be_nil
    _(backend.size).must_equal 1

    # Request three: a fresh request still only knows the previously saved grant.
    check = request.get("/check", "HTTP_COOKIE" => merge_cookies(jar, failed))
    body = JSON.parse(check.body)

    _(body["admin"]).must_equal(true)
    _(body["billing"]).must_equal(false)
  end

  it "treats an evicted server record as a new, unauthorized session" do
    backend = FakeBackend.new
    _, request = build_request(backend)

    setup = request.get("/setup")
    original_jar = cookie_header(setup)
    original_sid = original_jar[/#{session_key}=([^;]+)/, 1]

    # The server-side record is reclaimed while the client retains its cookies.
    backend.evict!
    _(backend.size).must_equal 0

    response = request.get("/check", "HTTP_COOKIE" => original_jar)
    body = JSON.parse(response.body)

    # Authorization cannot be reconstructed from the cookie.
    _(body["admin"]).must_equal(false)
    _(body["billing"]).must_equal(false)

    # Ordinary client-side preferences survive independently.
    _(body["theme"]).must_equal("dark")

    # A brand new server record and session id are established.
    new_sid = cookie_value(response.cookies[session_key])
    _(new_sid).wont_equal(original_sid)
    _(backend[new_sid]).must_equal({})
    _(backend.size).must_equal 1
  end

  it "ignores non-preference keys forged into the preference cookie" do
    backend = FakeBackend.new
    _, request = build_request(backend)

    forged = {
      preference_key => JSON.generate(
        "theme" => "dark",
        "permissions" => ["admin"],
        "admin" => true,
      ),
    }.map { |name, value| "#{name}=#{Rack::Utils.escape(value)}" }.join("; ")

    response = request.get("/forged-read", "HTTP_COOKIE" => forged)
    body = JSON.parse(response.body)

    # Forged fields are filtered at the boundary; they grant nothing.
    _(body["permissions"]).must_be_nil

    check = request.get("/check", "HTTP_COOKIE" => cookie_header(response))
    _(JSON.parse(check.body)["admin"]).must_equal(false)

    # The re-issued preference cookie only contains approved fields.
    _(decoded_preferences(response)).must_equal("theme" => "dark")
  end

  it "survives a malformed preference cookie without raising" do
    backend = FakeBackend.new
    _, request = build_request(backend)

    response = request.get(
      "/check",
      "HTTP_COOKIE" => "#{preference_key}=not-valid-json",
    )

    _(response.status).must_equal 200
    _(JSON.parse(response.body)["theme"]).must_be_nil
  end

  it "starts a first-time visitor with an empty record and no permissions" do
    backend = FakeBackend.new
    _, request = build_request(backend)

    response = request.get("/check")
    body = JSON.parse(response.body)

    _(body["admin"]).must_equal(false)
    _(body["theme"]).must_be_nil
    _(backend.size).must_equal 1
  end
end
