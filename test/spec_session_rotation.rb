# frozen_string_literal: true

# Released under the MIT License.

require_relative 'helper'

require 'json'
require 'rack/lint'
require 'rack/mock'
require 'rack/response'

require_relative '../lib/rack/session/pool'
require_relative '../lib/rack/session/cookie'

# Exercises SessionHash#rotate! end-to-end against both persistent backends.
#
# The application models an ordinary user elevating to an administrative
# session after an extra confirmation. Elevation rotates the session, keeping
# only the explicitly declared non-sensitive keys (the locale).
describe "Rack::Session session rotation" do
  SESSION_MATCH = /rack\.session=([^;]+)/

  BACKENDS = {
    "Pool" => lambda { |app| Rack::Session::Pool.new(app) },
    "Cookie" => lambda { |app| Rack::Session::Cookie.new(app, secrets: "s" * 64) },
  }

  def cookie_value(response)
    return nil unless value = response["Set-Cookie"]
    value[SESSION_MATCH, 1]
  end

  def cookie_header(value)
    {"HTTP_COOKIE" => "rack.session=#{value}"}
  end

  def data(response)
    JSON.parse(response.body)
  end

  def build(backend)
    app = lambda do |env|
      session = env["rack.session"]

      body = case env["PATH_INFO"]
      when "/login"
        session["user_id"] = 1
        session["role"] = "user"
        session["locale"] = "zh-CN"
        session["timezone"] = "Asia/Shanghai"
        session.to_hash
      when "/elevate"
        if env["QUERY_STRING"] == "confirm=1"
          session.rotate!(keys: ["locale"])
          session["user_id"] = 1
          session["role"] = "admin"
          session.to_hash
        else
          {"error" => "denied"}
        end
      when "/stale_elevate"
        # A request that captured the session before rotation but commits
        # after it, trying to write the old, lower-privileged context.
        session.to_hash
        Fiber.yield if env["QUERY_STRING"] == "pause=1"
        session["role"] = "user"
        session["user_id"] = 1
        session.to_hash
      else
        session.to_hash
      end

      Rack::Response.new(JSON.dump(body)).to_a
    end

    Rack::MockRequest.new(Rack::Lint.new(backend.call(app)))
  end

  BACKENDS.each do |name, backend|
    describe name do
      it "rotates on successful elevation and migrates only the declared keys" do
        request = build(backend)

        login = request.get("/login")
        old_cookie = cookie_value(login)
        old_cookie.wont_be_nil

        elevated = request.get("/elevate?confirm=1", cookie_header(old_cookie))
        elevated.status.must_equal 200
        new_cookie = cookie_value(elevated)
        new_cookie.wont_be_nil
        new_cookie.wont_equal old_cookie

        # Only the declared locale migrated; the role was re-established by
        # the elevation flow, and the undeclared timezone is gone.
        elevated_data = data(elevated)
        elevated_data["locale"].must_equal "zh-CN"
        elevated_data["role"].must_equal "admin"
        elevated_data["user_id"].must_equal 1
        elevated_data.key?("timezone").must_equal false

        # The new cookie carries the elevated session.
        follow_up = data(request.get("/", cookie_header(new_cookie)))
        follow_up["role"].must_equal "admin"
        follow_up["locale"].must_equal "zh-CN"
        follow_up.key?("timezone").must_equal false
      end

      it "does not restore the old privileges when presenting the old cookie" do
        request = build(backend)

        login = request.get("/login")
        old_cookie = cookie_value(login)

        elevated = request.get("/elevate?confirm=1", cookie_header(old_cookie))
        new_cookie = cookie_value(elevated)
        new_cookie.wont_equal old_cookie

        # The retired cookie must not authenticate as either the old user or
        # the new administrator; it is simply an empty session.
        replay_data = data(request.get("/", cookie_header(old_cookie)))
        replay_data.key?("role").must_equal false
        replay_data.key?("user_id").must_equal false
        replay_data.key?("locale").must_equal false

        # Presenting the current cookie still works.
        data(request.get("/", cookie_header(new_cookie)))["role"].must_equal "admin"
      end

      it "leaves the session unchanged when elevation is refused" do
        request = build(backend)

        login = request.get("/login")
        cookie = cookie_value(login)

        denied = request.get("/elevate", cookie_header(cookie))
        denied.status.must_equal 200
        data(denied).must_equal({"error" => "denied"})

        # A refused elevation must not rotate or rewrite the session.
        denied["Set-Cookie"].must_be_nil

        after_data = data(request.get("/", cookie_header(cookie)))
        after_data["role"].must_equal "user"
        after_data["locale"].must_equal "zh-CN"
        after_data["timezone"].must_equal "Asia/Shanghai"
      end

      it "drops a commit from a request that loaded the old context before rotation" do
        request = build(backend)

        login = request.get("/login")
        old_cookie = cookie_value(login)

        # This request loads the old, lower-privileged session, then pauses
        # before committing, holding a stale request context.
        stale = Fiber.new do
          request.get("/stale_elevate?pause=1", cookie_header(old_cookie))
        end
        stale.resume

        # Meanwhile, the user elevates and rotates the session.
        elevated = request.get("/elevate?confirm=1", cookie_header(old_cookie))
        new_cookie = cookie_value(elevated)
        new_cookie.wont_equal old_cookie

        # The stale request now completes and tries to commit its old context.
        stale_response = stale.resume

        # It must not receive a session cookie, and it must not overwrite the
        # rotated session or resurrect the retired one.
        cookie_value(stale_response).must_be_nil

        current_data = data(request.get("/", cookie_header(new_cookie)))
        current_data["role"].must_equal "admin"
        current_data["locale"].must_equal "zh-CN"
        current_data.key?("timezone").must_equal false

        replay_data = data(request.get("/", cookie_header(old_cookie)))
        replay_data.key?("role").must_equal false
        replay_data.key?("locale").must_equal false
      end

      it "refuses to write a stale request context into the rotated session" do
        request = build(backend)

        login = request.get("/login")
        old_cookie = cookie_value(login)

        elevated = request.get("/elevate?confirm=1", cookie_header(old_cookie))
        new_cookie = cookie_value(elevated)

        # A late request still holding the old cookie tries to write the old
        # context. It must never write into the rotated (current) session.
        stale_cookie = cookie_value(request.get("/stale_elevate", cookie_header(old_cookie)))
        stale_cookie.wont_equal old_cookie

        current_data = data(request.get("/", cookie_header(new_cookie)))
        current_data["role"].must_equal "admin"
        current_data["locale"].must_equal "zh-CN"
        current_data.key?("timezone").must_equal false

        # The stale write must not be recoverable.
        data(request.get("/", cookie_header(stale_cookie)))["role"].must_equal "user"

        replay_data = data(request.get("/", cookie_header(old_cookie)))
        replay_data.key?("role").must_equal false
        replay_data.key?("locale").must_equal false
      end
    end
  end
end
