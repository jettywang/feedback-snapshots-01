# frozen_string_literal: true

require_relative 'helper'
require 'rack/request'
require 'rack/response'
require 'rack/mock'
require 'securerandom'

require_relative '../lib/rack/session/cookie'
require_relative '../lib/rack/session/pool'
require_relative '../lib/rack/session/observation'

describe Rack::Session::Observation do
  # A session store which records the calls made to it, so tests can
  # verify that observing a request does not force the session to load.
  class RecordingStore
    attr_reader :calls

    def initialize(session = {}, exists: true, presented: false)
      @session = session
      @exists = exists
      @presented = presented
      @calls = []
    end

    def load_session(request)
      @calls << :load_session
      ["id", @session]
    end

    def session_exists?(request)
      @calls << :session_exists?
      @exists
    end

    def session_presented?(request)
      @calls << :session_presented?
      @presented
    end
  end

  def request_with_session(store, options: {}, env: {})
    request = Rack::Request.new({'rack.url_scheme' => 'http'}.merge(env))
    session = Rack::Session::Abstract::SessionHash.new(store, request)
    request.set_header(Rack::Session::RACK_SESSION, session)
    request.set_header(Rack::Session::RACK_SESSION_OPTIONS, {secure: false}.merge(options))
    [request, session]
  end

  it "reports :unloaded when the session has not been loaded" do
    store = RecordingStore.new({"user_id" => 42})
    request, session = request_with_session(store)

    observation = Rack::Session::Observation.new(request, allow: [:user_id])

    observation.status.must_equal :unloaded
    session.loaded?.must_equal false
    observation.to_h.must_equal(status: :unloaded, keys: [], classification: {})
  end

  it "does not force the session to load when collecting the status" do
    store = RecordingStore.new({"user_id" => 42})
    request, session = request_with_session(store)

    Rack::Session::Observation.observe(request, allow: [:user_id]).to_h

    store.calls.wont_include :load_session
    session.loaded?.must_equal false
  end

  it "reports :prepared with only approved keys and their classification" do
    store = RecordingStore.new({"user_id" => 42, "token" => "secret-value"})
    request, session = request_with_session(store)
    session["user_id"]

    observation = Rack::Session::Observation.new(request, allow: [:user_id, :missing])

    observation.status.must_equal :prepared
    observation.to_h.must_equal(
      status: :prepared,
      keys: ["user_id"],
      classification: {"user_id" => "Integer"},
    )
    observation.to_h.inspect.wont_include "token"
    observation.to_h.inspect.wont_include "secret-value"
  end

  it "reports :invalid when presented credentials cannot be resolved" do
    store = RecordingStore.new(exists: false, presented: true)
    request, session = request_with_session(store)

    observation = Rack::Session::Observation.new(request, allow: [:user_id])

    observation.status.must_equal :invalid
    observation.to_h.must_equal(status: :invalid, keys: [], classification: {})
    store.calls.wont_include :load_session
  end

  it "reports :rejected when security requirements are not met" do
    store = RecordingStore.new
    request, = request_with_session(store, options: {secure: true})

    Rack::Session::Observation.new(request).status.must_equal :rejected
  end

  it "does not report :rejected for a secure session over a secure request" do
    store = RecordingStore.new
    request, = request_with_session(store, options: {secure: true}, env: {'rack.url_scheme' => 'https'})

    Rack::Session::Observation.new(request).status.must_equal :unloaded
  end

  it "reports :unloaded when the request has no session" do
    observation = Rack::Session::Observation.new(Rack::Request.new({}))

    observation.status.must_equal :unloaded
    observation.keys.must_equal []
    observation.classification.must_equal({})
  end

  it "treats credentials as not presented when the store does not report them" do
    store = Class.new do
      def load_session(request)
        ["id", {}]
      end

      def session_exists?(request)
        false
      end
    end.new
    request, = request_with_session(store)

    Rack::Session::Observation.new(request).status.must_equal :unloaded
  end

  describe "backends" do
    observer = lambda do |env|
      observation = Rack::Session::Observation.new(Rack::Request.new(env), allow: [:user_id])
      Rack::Response.new(observation.to_h.inspect).to_a
    end

    app = lambda do |env|
      request = Rack::Request.new(env)

      if request.path == "/write"
        env['rack.session']['user_id'] = 42
        env['rack.session']['private'] = 'top-secret'
        Rack::Response.new('OK').to_a
      else
        # Force the session to load, as an application reading it would:
        env['rack.session']['user_id']
        observation = Rack::Session::Observation.new(request, allow: [:user_id])
        Rack::Response.new(observation.to_h.inspect).to_a
      end
    end

    it "reports :unloaded for a valid cookie the request never read" do
      secret = SecureRandom.random_bytes(64)
      request = Rack::MockRequest.new(Rack::Session::Cookie.new(app, secrets: secret))

      cookie = request.get('/write')['Set-Cookie']
      response = Rack::MockRequest.new(
        Rack::Session::Cookie.new(observer, secrets: secret)
      ).get('/', 'HTTP_COOKIE' => cookie)

      response.body.must_include ':unloaded'
      response.body.wont_include 'top-secret'
    end

    it "does not expose private values for a tampered cookie" do
      secret = SecureRandom.random_bytes(64)
      sessioned = Rack::Session::Cookie.new(app, secrets: secret)
      request = Rack::MockRequest.new(sessioned)

      cookie = request.get('/write')['Set-Cookie']
      name, value = cookie.split('=', 2)
      tampered = "#{name}=#{value.split(';').first.reverse}"

      response = Rack::MockRequest.new(
        Rack::Session::Cookie.new(observer, secrets: secret)
      ).get('/', 'HTTP_COOKIE' => tampered)

      response.body.must_include ':invalid'
      response.body.wont_include 'user_id'
      response.body.wont_include 'top-secret'
    end

    it "reports only approved keys for a valid pool session" do
      request = Rack::MockRequest.new(Rack::Session::Pool.new(app))

      cookie = request.get('/write')['Set-Cookie']
      response = request.get('/observe', 'HTTP_COOKIE' => cookie)

      response.body.must_include ':prepared'
      response.body.must_include 'user_id'
      response.body.wont_include 'private'
      response.body.wont_include 'top-secret'
    end

    it "does not expose private values for an unknown pool session cookie" do
      request = Rack::MockRequest.new(Rack::Session::Pool.new(app))
      request.get('/write')

      response = request.get('/observe', 'HTTP_COOKIE' => "rack.session=#{'f' * 128}")

      response.body.wont_include 'user_id'
      response.body.wont_include 'private'
      response.body.wont_include 'top-secret'
    end
  end
end
