# frozen_string_literal: true

# Released under the MIT License.
# Copyright, 2026.

require_relative 'helper'
require 'rack/mock'
require 'rack/lint'
require 'rack/utils'

require_relative '../lib/rack/session/pool'
require_relative '../lib/rack/session/cookie'
require_relative '../lib/rack/session/commit_policy'

describe Rack::Session::CommitPolicy do
  describe ".family_for" do
    it "maps status codes to response families" do
      [
        [100, :informational],
        [204, :success],
        [302, :redirect],
        [404, :client_error],
        [503, :server_error],
        [700, :unknown]
      ].each do |status, family|
        Rack::Session::CommitPolicy.family_for(status).must_equal family
      end
    end
  end

  describe "selections" do
    def context(status, env = {})
      Rack::Session::CommitContext.new(env: env, status: status)
    end

    it "accepts response family symbols" do
      policy = Rack::Session::CommitPolicy.new(:success, :redirect)
      policy.decide(context(200)).must_equal true
      policy.decide(context(302)).must_equal true
      policy.decide(context(422)).must_equal false
    end

    it "accepts explicit status codes and ranges" do
      policy = Rack::Session::CommitPolicy.new(201, 400..404)
      policy.decide(context(201)).must_equal true
      policy.decide(context(403)).must_equal true
      policy.decide(context(200)).must_equal false
    end

    it "accepts :all, :none and :error" do
      Rack::Session::CommitPolicy.new(:all).decide(context(500)).must_equal true
      Rack::Session::CommitPolicy.new(:none).decide(context(200)).must_equal false
      policy = Rack::Session::CommitPolicy.new(:error)
      policy.decide(context(422)).must_equal true
      policy.decide(context(503)).must_equal true
      policy.decide(context(200)).must_equal false
    end

    it "defaults to committing successful and redirect responses" do
      policy = Rack::Session::CommitPolicy.new
      policy.decide(context(204)).must_equal true
      policy.decide(context(304)).must_equal true
      policy.decide(context(422)).must_equal false
    end
  end

  describe "business markers" do
    def context(status, env = {})
      Rack::Session::CommitContext.new(env: env, status: status)
    end

    it "uses the response status when no marker is present" do
      context(200).business_success?.must_equal true
      context(500).business_success?.must_equal false
    end

    it "honours the explicit success marker" do
      env = { Rack::Session::RACK_SESSION_BUSINESS_SUCCESS => true }
      context(422, env).business_success?.must_equal true
    end

    it "honours the explicit failure marker" do
      env = { Rack::Session::RACK_SESSION_BUSINESS_FAILURE => true }
      context(200, env).business_success?.must_equal false
    end

    it "honours a response header marker" do
      headers = {Rack::Session::RACK_SESSION_BUSINESS_SUCCESS_HEADER => "false"}
      context = Rack::Session::CommitContext.new(env: {}, status: 200, headers: headers)
      context.business_success?.must_equal false
    end

    it "requires a marker when require_business is set" do
      policy = Rack::Session::CommitPolicy.new(:success, require_business: true)
      policy.decide(context(200)).must_equal false
      policy.decide(context(200, Rack::Session::RACK_SESSION_BUSINESS_SUCCESS => true)).must_equal true
    end
  end

  describe ".resolve" do
    def context(status, env = {})
      Rack::Session::CommitContext.new(env: env, status: status)
    end

    it "supports callables" do
      policy = ->(context) { context.status == 201 }
      Rack::Session::CommitPolicy.resolve(policy, context(201)).must_equal true
      Rack::Session::CommitPolicy.resolve(policy, context(200)).must_equal false
    end

    it "supports callables which take the env and status" do
      policy = ->(env, status) { env["allowed"] && status == 200 }
      Rack::Session::CommitPolicy.resolve(policy, context(200, "allowed" => true)).must_equal true
      Rack::Session::CommitPolicy.resolve(policy, context(200)).must_equal false
    end

    it "supports true, false and nil" do
      Rack::Session::CommitPolicy.resolve(true, context(500)).must_equal true
      Rack::Session::CommitPolicy.resolve(false, context(200)).must_equal false
      Rack::Session::CommitPolicy.resolve(nil, context(200)).must_equal true
    end

    it "lets an explicit env decision win" do
      env = { Rack::Session::RACK_SESSION_COMMIT => false }
      Rack::Session::CommitPolicy.resolve(:all, context(200, env)).must_equal false
    end
  end
end

describe "Rack::Session commit policy integration" do
  class CommitPolicyStreamingBody
    def initialize(chunks: [], each_error: nil, close_error: nil)
      @chunks = chunks
      @each_error = each_error
      @close_error = close_error
      @closed = false
    end

    def each
      @chunks.each { |chunk| yield chunk }
      raise @each_error if @each_error
    end

    def close
      @closed = true
      raise @close_error if @close_error
    end

    def closed?
      @closed
    end
  end

  class CommitPolicyFailingPool < Rack::Session::Pool
    def write_session(*)
      raise IOError, "pool write failed"
    end
  end

  def perform(app, path = "/", opts = {})
    env = Rack::MockRequest.env_for(path, opts)
    status, headers, body = app.call(env)

    chunks = []
    error = nil

    begin
      body.each { |chunk| chunks << chunk } if body.respond_to?(:each)
    rescue => exception
      error = exception
    ensure
      begin
        body.close if body.respond_to?(:close)
      rescue => exception
        error ||= exception
      end
    end

    [status, headers, chunks, env, error]
  end

  def app_for(&block)
    lambda do |env|
      block.call(env["rack.session"], env)
    end
  end

  # Wraps a lambda so it can be used with Rack::Utils::Context.
  class CommitPolicyLambda
    def initialize(&block)
      @block = block
    end

    def context(env, app = self)
      @block.call(env)
    end

    def call(env)
      context(env)
    end
  end

  it "commits staged data on a successful update" do
    app = app_for do |session, _env|
      session["sensitive"] = "updated"
      [200, {"content-type" => "text/plain"}, ["ok"]]
    end

    pool = Rack::Session::Pool.new(Rack::Lint.new(app), commit_policy: :success)

    status, headers, _chunks, env, error = perform(pool)

    error.must_be_nil
    status.must_equal 200
    headers["set-cookie"].wont_be_nil
    env["rack.session.commit_result"].persisted?.must_equal true
    env["rack.session.persisted"].must_equal true
    pool.pool.size.must_equal 1
    pool.pool.values.first["sensitive"].must_equal "updated"
  end

  it "does not commit staged data on a business error" do
    app = app_for do |session, env|
      session["sensitive"] = "staged"

      if env["PATH_INFO"] == "/error"
        [422, {"content-type" => "text/plain"}, ["invalid"]]
      else
        [200, {"content-type" => "text/plain"}, ["ok"]]
      end
    end

    pool = Rack::Session::Pool.new(app, commit_policy: :success)

    status, headers, _chunks, env, _error = perform(pool, "/error")

    status.must_equal 422
    headers["set-cookie"].must_be_nil
    env["rack.session.commit_result"].business_success?.must_equal false
    env["rack.session.commit_result"].committed?.must_equal false
    env["rack.session.commit_result"].persisted?.must_equal false
    pool.pool.values.first.wont_be :key?, "sensitive"
  end

  it "does not commit staged data when streaming raises" do
    body = CommitPolicyStreamingBody.new(
      chunks: ["partial"],
      each_error: RuntimeError.new("stream failed")
    )

    app = app_for do |session, _env|
      session["sensitive"] = "streamed"
      [200, {"content-type" => "text/plain"}, body]
    end

    pool = Rack::Session::Pool.new(app, commit_policy: :success)

    status, headers, _chunks, env, error = perform(pool)

    status.must_equal 200
    headers["set-cookie"].must_be_nil
    error.message.must_equal "stream failed"
    result = env["rack.session.commit_result"]
    result.business_success?.must_equal true
    result.persisted?.must_equal false
    result.reason.must_equal :stream_error
    pool.pool.values.first.wont_be :key?, "sensitive"
  end

  it "does not commit staged data when closing the stream raises" do
    body = CommitPolicyStreamingBody.new(
      chunks: ["complete"],
      close_error: RuntimeError.new("close failed")
    )

    app = app_for do |session, _env|
      session["sensitive"] = "streamed"
      [200, {"content-type" => "text/plain"}, body]
    end

    pool = Rack::Session::Pool.new(app, commit_policy: :success)

    _status, headers, _chunks, env, error = perform(pool)

    headers["set-cookie"].must_be_nil
    error.message.must_equal "close failed"
    result = env["rack.session.commit_result"]
    result.business_success?.must_equal true
    result.persisted?.must_equal false
    result.reason.must_equal :stream_error
    pool.pool.values.first.wont_be :key?, "sensitive"
  end

  it "commits a streaming response once the body is closed successfully" do
    body = CommitPolicyStreamingBody.new(chunks: ["a", "b"])

    app = app_for do |session, _env|
      session["sensitive"] = "streamed"
      [200, {"content-type" => "text/plain"}, body]
    end

    pool = Rack::Session::Pool.new(app, commit_policy: :success)

    status, headers, chunks, env, error = perform(pool)

    error.must_be_nil
    status.must_equal 200
    chunks.must_equal ["a", "b"]
    headers["set-cookie"].wont_be_nil
    env["rack.session.commit_result"].persisted?.must_equal true
    pool.pool.values.first["sensitive"].must_equal "streamed"
  end

  it "reports business success independently from a pool write failure" do
    app = app_for do |session, _env|
      session["sensitive"] = "updated"
      [200, {"content-type" => "text/plain"}, ["ok"]]
    end

    pool = CommitPolicyFailingPool.new(app, commit_policy: :success)

    status, headers, _chunks, env, error = perform(pool)

    error.must_be_nil
    status.must_equal 200
    headers["set-cookie"].must_be_nil
    result = env["rack.session.commit_result"]
    result.business_success?.must_equal true
    result.committed?.must_equal true
    result.persisted?.must_equal false
    result.reason.must_equal :write_error
    result.error.must_be_instance_of IOError
    env["rack.session.persisted"].must_equal false
  end

  it "allows the business marker to veto a successful status" do
    app = app_for do |session, env|
      session["sensitive"] = "staged"
      env[Rack::Session::RACK_SESSION_BUSINESS_SUCCESS] = false
      [200, {"content-type" => "text/plain"}, ["ok"]]
    end

    pool = Rack::Session::Pool.new(app, commit_policy: :success)

    _status, headers, _chunks, env, _error = perform(pool)

    headers["set-cookie"].must_be_nil
    env["rack.session.commit_result"].business_success?.must_equal false
    env["rack.session.commit_result"].persisted?.must_equal false
  end

  it "allows the business marker to commit a client error" do
    app = app_for do |session, env|
      session["sensitive"] = "staged"
      env[Rack::Session::RACK_SESSION_BUSINESS_SUCCESS] = true
      [422, {"content-type" => "text/plain"}, ["staged"]]
    end

    pool = Rack::Session::Pool.new(app, commit_policy: {on: :client_error, require_business: true})

    _status, headers, _chunks, env, _error = perform(pool)

    headers["set-cookie"].wont_be_nil
    env["rack.session.commit_result"].persisted?.must_equal true
    pool.pool.values.first["sensitive"].must_equal "staged"
  end

  it "reads a business marker from the session options" do
    app = app_for do |session, _env|
      session["sensitive"] = "staged"
      session.options[:business_success] = false
      [200, {"content-type" => "text/plain"}, ["ok"]]
    end

    pool = Rack::Session::Pool.new(app, commit_policy: :success)

    _status, headers, _chunks, env, _error = perform(pool)

    headers["set-cookie"].must_be_nil
    env["rack.session.commit_result"].business_success?.must_equal false
    env["rack.session.commit_result"].persisted?.must_equal false
  end

  it "supports a per-request policy override" do
    app = app_for do |session, _env|
      session["sensitive"] = "staged"
      [503, {"content-type" => "text/plain"}, ["unavailable"]]
    end

    pool = Rack::Session::Pool.new(app, commit_policy: :success)

    _status, headers, _chunks, env, _error = perform(
      pool, "/",
      Rack::Session::RACK_SESSION_COMMIT_POLICY => :server_error
    )

    headers["set-cookie"].wont_be_nil
    env["rack.session.commit_result"].persisted?.must_equal true
  end

  it "supports an explicit commit decision" do
    app = app_for do |session, _env|
      session["sensitive"] = "staged"
      [500, {"content-type" => "text/plain"}, ["error"]]
    end

    pool = Rack::Session::Pool.new(app, commit_policy: :success)

    _status, headers, _chunks, env, _error = perform(
      pool, "/",
      Rack::Session::RACK_SESSION_COMMIT => true
    )

    headers["set-cookie"].wont_be_nil
    env["rack.session.commit_result"].persisted?.must_equal true
  end

  it "works with the cookie store" do
    app = app_for do |session, env|
      session["sensitive"] = "staged"

      if env["PATH_INFO"] == "/error"
        [400, {"content-type" => "text/plain"}, ["bad request"]]
      else
        [200, {"content-type" => "text/plain"}, ["ok"]]
      end
    end

    cookie = Rack::Session::Cookie.new(app, secrets: "s" * 64, commit_policy: :success)

    _status, headers, _chunks, env, _error = perform(cookie, "/")
    headers["set-cookie"].wont_be_nil
    env["rack.session.commit_result"].persisted?.must_equal true

    _status, headers, _chunks, env, _error = perform(cookie, "/error")
    headers["set-cookie"].must_be_nil
    env["rack.session.commit_result"].persisted?.must_equal false
  end

  it "does not destroy an existing session when the policy denies the commit" do
    app = app_for do |session, env|
      if env["PATH_INFO"] == "/destroy"
        session.destroy
        [422, {"content-type" => "text/plain"}, ["invalid"]]
      else
        session["user"] = "alice"
        [200, {"content-type" => "text/plain"}, ["ok"]]
      end
    end

    pool = Rack::Session::Pool.new(app, commit_policy: :success)

    _status, headers, _chunks, _env, _error = perform(pool)
    cookie = headers["set-cookie"][/rack\.session=([^;]+)/, 1]

    context = Rack::Utils::Context.new(pool, CommitPolicyLambda.new(&app))
    status, headers, _chunks, env, _error = perform(
      context, "/destroy", "HTTP_COOKIE" => "rack.session=#{cookie}"
    )

    status.must_equal 422
    headers["set-cookie"].must_be_nil
    env["rack.session.commit_result"].persisted?.must_equal false
    pool.pool.values.first["user"].must_equal "alice"
  end

  it "destroys the session when the policy allows the commit" do
    app = app_for do |session, env|
      if env["PATH_INFO"] == "/destroy"
        session.destroy
        [200, {"content-type" => "text/plain"}, ["bye"]]
      else
        session["user"] = "alice"
        [200, {"content-type" => "text/plain"}, ["ok"]]
      end
    end

    pool = Rack::Session::Pool.new(app, commit_policy: :success)

    _status, headers, _chunks, _env, _error = perform(pool)
    cookie = headers["set-cookie"][/rack\.session=([^;]+)/, 1]

    context = Rack::Utils::Context.new(pool, CommitPolicyLambda.new(&app))
    _status, headers, _chunks, env, _error = perform(
      context, "/destroy", "HTTP_COOKIE" => "rack.session=#{cookie}"
    )

    headers["set-cookie"].wont_be_nil
    env["rack.session.commit_result"].persisted?.must_equal true
    pool.pool.values.first.wont_be :key?, "user"
  end

  it "does not renew an existing session when the policy denies the commit" do
    app = app_for do |session, env|
      session["user"] = "alice"

      if env["PATH_INFO"] == "/renew"
        session.options[:renew] = true
        [500, {"content-type" => "text/plain"}, ["error"]]
      else
        [200, {"content-type" => "text/plain"}, ["ok"]]
      end
    end

    pool = Rack::Session::Pool.new(app, commit_policy: :success)

    _status, headers, _chunks, _env, _error = perform(pool)
    cookie = headers["set-cookie"][/rack\.session=([^;]+)/, 1]

    context = Rack::Utils::Context.new(pool, CommitPolicyLambda.new(&app))
    _status, headers, _chunks, env, _error = perform(
      context, "/renew", "HTTP_COOKIE" => "rack.session=#{cookie}"
    )

    headers["set-cookie"].must_be_nil
    env["rack.session.commit_result"].persisted?.must_equal false
    pool.pool.size.must_equal 1
  end

  it "records an explicit skip without committing" do
    app = app_for do |session, _env|
      session.options[:skip] = true
      session["sensitive"] = "staged"
      [200, {"content-type" => "text/plain"}, ["ok"]]
    end

    pool = Rack::Session::Pool.new(app, commit_policy: :success)

    _status, headers, _chunks, env, _error = perform(pool)

    headers["set-cookie"].must_be_nil
    result = env["rack.session.commit_result"]
    result.skipped?.must_equal true
    result.reason.must_equal :skip
    result.business_success?.must_equal true
  end

  it "honours an explicit deny even when the policy would allow" do
    app = app_for do |session, _env|
      session["sensitive"] = "staged"
      [200, {"content-type" => "text/plain"}, ["ok"]]
    end

    pool = Rack::Session::Pool.new(app, commit_policy: :success)

    _status, headers, _chunks, env, _error = perform(
      pool, "/",
      Rack::Session::RACK_SESSION_COMMIT => false
    )

    headers["set-cookie"].must_be_nil
    result = env["rack.session.commit_result"]
    result.committed?.must_equal false
    result.persisted?.must_equal false
  end

  it "reports a deferred write as persisted" do
    app = app_for do |session, _env|
      session.options[:defer] = true
      session["sensitive"] = "staged"
      [200, {"content-type" => "text/plain"}, ["ok"]]
    end

    pool = Rack::Session::Pool.new(app, commit_policy: :success)

    _status, headers, _chunks, env, _error = perform(pool)

    headers["set-cookie"].must_be_nil
    result = env["rack.session.commit_result"]
    result.persisted?.must_equal true
    pool.pool.values.first["sensitive"].must_equal "staged"
  end

  it "does not load an otherwise untouched lazy session" do
    app = app_for do |_session, _env|
      [200, {"content-type" => "text/plain"}, ["nothing"]]
    end

    pool = Rack::Session::Pool.new(app, commit_policy: :success)

    _status, headers, _chunks, env, _error = perform(pool)

    headers["set-cookie"].must_be_nil
    env["rack.session.commit_result"].persisted?.must_equal false
    env["rack.session.commit_result"].reason.must_equal :not_loaded
  end

  it "distinguishes business success from a cookie store write failure" do
    app = app_for do |session, _env|
      session["big"] = "x" * 5000
      [200, {"content-type" => "text/plain"}, ["ok"]]
    end

    cookie = Rack::Session::Cookie.new(app, secrets: "s" * 64, commit_policy: :success)

    _status, headers, _chunks, env, _error = perform(cookie)

    headers["set-cookie"].must_be_nil
    result = env["rack.session.commit_result"]
    result.business_success?.must_equal true
    result.committed?.must_equal true
    result.persisted?.must_equal false
    result.reason.must_equal :write_error
  end

  describe "without a configured policy" do
    it "preserves the legacy commit behaviour for failures" do
      app = app_for do |session, _env|
        session["sensitive"] = "legacy"
        [422, {"content-type" => "text/plain"}, ["invalid"]]
      end

      pool = Rack::Session::Pool.new(app)

      _status, headers, _chunks, env, _error = perform(pool)

      headers["set-cookie"].wont_be_nil
      env.wont_include "rack.session.commit_result"
      env.wont_include "rack.session.persisted"
      pool.pool.values.first["sensitive"].must_equal "legacy"
    end

    it "preserves the legacy return value of commit_session" do
      pers = Rack::Session::Abstract::Persisted.new(nil)
      req = Rack::Request.new("rack.errors" => StringIO.new)

      store = Class.new do
        def load_session(req)
          ["id", {}]
        end

        def session_exists?(req)
          true
        end
      end

      session = req.env["rack.session"] = Rack::Session::Abstract::SessionHash.new(store.new, req)
      session["foo"] = "bar"

      def pers.write_session(*) end

      pers.commit_session(req, Rack::Response.new).must_be_nil
    end
  end
end
