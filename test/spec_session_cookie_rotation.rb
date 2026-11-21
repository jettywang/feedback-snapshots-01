# frozen_string_literal: true

# Released under the MIT License.

require_relative 'helper'
require 'rack/lint'
require 'rack/mock'
require 'rack/response'

require_relative '../lib/rack/session/cookie'

describe Rack::Session::Cookie do
  # A small local Rack application exercising the read/write rotation
  # policy: GET / requires an authenticated session, POST /login starts one.
  # The app echoes env['rack.session.rotation'] back in a response header so
  # the handling of each cookie can be verified.
  def rotation_app(options)
    app = lambda do |env|
      session = env['rack.session']

      response = Rack::Response.new

      case env['PATH_INFO']
      when '/login'
        session['user'] = 'alice'
        response.write('logged in')
      else
        if user = session['user']
          response.write("authenticated as #{user}")
        else
          response.status = 401
          response.write('unauthorized')
        end
      end

      response['x-session-rotation'] = env['rack.session.rotation'].to_s
      response.finish
    end

    Rack::MockRequest.new(Rack::Lint.new(Rack::Session::Cookie.new(app, options)))
  end

  def legacy_cookie_value(data, secret)
    encoded = Rack::Session::Cookie::Base64::Marshal.new.encode(data)
    digest = OpenSSL::HMAC.hexdigest(OpenSSL::Digest::SHA1.new, secret, encoded)
    "#{encoded}--#{digest}"
  end

  def cookie_header(value)
    { 'HTTP_COOKIE' => "rack.session=#{Rack::Utils.escape(value)}" }
  end

  def set_cookie_value(response)
    return nil unless header = response['Set-Cookie']
    Rack::Utils.unescape(header[/rack\.session=([^;]+)/, 1])
  end

  before do
    @new_secret = SecureRandom.random_bytes(64)
    @old_secret = 'previous release secret'

    @middleware_options = {
      secrets: [@new_secret],
      legacy_hmac_secret: @old_secret,
      legacy_hmac_until: Time.now + 3600,
    }

    @old_cookie = legacy_cookie_value(
      { 'session_id' => 'old-session-id', 'user' => 'alice' }, @old_secret
    )
  end

  it 'accepts a valid old cookie, refreshes it to the new format, and authenticates the next request' do
    app = rotation_app(@middleware_options)

    response = app.get('/', cookie_header(@old_cookie))
    response.status.must_equal 200
    response.body.must_equal 'authenticated as alice'
    response['x-session-rotation'].must_equal 'legacy'

    # The session is re-issued in the new (encrypted) format:
    new_cookie = set_cookie_value(response)
    new_cookie.wont_be_nil
    new_cookie.wont_equal @old_cookie
    decrypted = Rack::Session::Encryptor.new(@new_secret).decrypt(new_cookie)
    decrypted['user'].must_equal 'alice'

    # The next request with the refreshed cookie is authenticated:
    follow_up = app.get('/', cookie_header(new_cookie))
    follow_up.status.must_equal 200
    follow_up.body.must_equal 'authenticated as alice'
    follow_up['x-session-rotation'].must_equal 'current'
  end

  it 'rejects an old cookie that fails verification and does not refresh it' do
    app = rotation_app(@middleware_options)

    forged = legacy_cookie_value(
      { 'session_id' => 'forged', 'user' => 'mallory' }, 'attacker secret'
    )

    response = app.get('/', cookie_header(forged))
    response.status.must_equal 401
    response.body.must_equal 'unauthorized'
    response['x-session-rotation'].must_equal 'invalid'
    response['Set-Cookie'].must_be_nil
  end

  it 'rejects a valid old cookie once the legacy format has expired, but still accepts the new format' do
    expired_app = rotation_app(@middleware_options.merge(legacy_hmac_until: Time.now - 60))

    response = expired_app.get('/', cookie_header(@old_cookie))
    response.status.must_equal 401
    response.body.must_equal 'unauthorized'
    response['x-session-rotation'].must_equal 'legacy_expired'
    response['Set-Cookie'].must_be_nil

    # Only the new authorization is accepted after the deadline:
    new_cookie = Rack::Session::Encryptor.new(@new_secret).encrypt(
      'session_id' => 'new-session-id', 'user' => 'alice'
    )
    follow_up = expired_app.get('/', cookie_header(new_cookie))
    follow_up.status.must_equal 200
    follow_up.body.must_equal 'authenticated as alice'
    follow_up['x-session-rotation'].must_equal 'current'
  end

  it 'issues a new-format cookie for a new session and authenticates the next request' do
    app = rotation_app(@middleware_options)

    response = app.get('/')
    response.status.must_equal 401
    response['x-session-rotation'].must_equal 'none'
    response['Set-Cookie'].must_be_nil

    login = app.post('/login')
    login.status.must_equal 200
    login['x-session-rotation'].must_equal 'none'

    new_cookie = set_cookie_value(login)
    new_cookie.wont_be_nil
    decrypted = Rack::Session::Encryptor.new(@new_secret).decrypt(new_cookie)
    decrypted['user'].must_equal 'alice'

    follow_up = app.get('/', cookie_header(new_cookie))
    follow_up.status.must_equal 200
    follow_up.body.must_equal 'authenticated as alice'
    follow_up['x-session-rotation'].must_equal 'current'
  end
end
