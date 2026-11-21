# frozen_string_literal: true

# Released under the MIT License.
# Copyright, 2026, by Samuel Williams.

require_relative 'helper'
require 'rack/response'
require 'rack/lint'
require 'rack/mock'

require_relative '../lib/rack/session/cookie'

describe 'Rack::Session::Cookie cross-service runtime compatibility' do
  # One application hosts two services: an employee portal and an operations
  # panel. Each service uses its own cookie key (which binds the encryption
  # purpose), its own encryption secret and its own legacy HMAC secret. Both
  # must keep reading their historical (legacy HMAC) session format, but the
  # legacy-to-encrypted migration on one service must never produce a session
  # for the other.

  session_echo = lambda do |env|
    hash = env["rack.session"].to_hash.dup
    hash.delete("session_id")
    Rack::Response.new(hash.inspect).to_a
  end

  employee_options = {
    key: 'employee.session',
    secrets: 'employee-portal-encryption-secret'.ljust(64, 'e'),
    legacy_hmac_secret: 'employee portal legacy secret',
  }

  ops_options = {
    key: 'ops.session',
    secrets: 'operations-panel-encryption-secret'.ljust(64, 'o'),
    legacy_hmac_secret: 'operations panel legacy secret',
  }

  before do
    @session_echo = session_echo
  end

  def response_for(app_options, cookie = nil)
    app = Rack::Session::Cookie.new(@session_echo, app_options)
    app = Rack::Lint.new(app)
    Rack::MockRequest.new(app).get("/", "HTTP_COOKIE" => cookie.to_s)
  end

  # Mint a pre-generated test session in the historical format:
  # base64-marshalled data with a legacy HMAC-SHA1 digest.
  def legacy_cookie(key, legacy_secret, data)
    session = Rack::Session::Cookie::Base64::Marshal.new.encode(data)
    digest = OpenSSL::HMAC.hexdigest(OpenSSL::Digest::SHA1.new, legacy_secret, session)
    "#{key}=#{session}--#{digest}"
  end

  # Replay a cookie pair under a different service's key.
  def rekey_cookie(cookie_pair, new_key)
    "#{new_key}=#{cookie_pair.split('=', 2).last}"
  end

  def cookie_pair(set_cookie)
    set_cookie.split(';').first
  end

  def unseal(set_cookie, options)
    value = Rack::Utils.unescape(cookie_pair(set_cookie).split('=', 2).last)
    encryptor = Rack::Session::Encryptor.new(options[:secrets], purpose: options[:key])
    encryptor.decrypt(value)
  end

  it 'employee portal unseals its own legacy session and re-issues it encrypted' do
    cookie = legacy_cookie(employee_options[:key], employee_options[:legacy_hmac_secret],
      'employee_id' => 42, 'session_id' => 'employee-sid')

    response = response_for(employee_options, cookie)
    response.body.must_equal({ 'employee_id' => 42 }.inspect)

    # The session is re-issued per policy: a new encrypted cookie, which no
    # longer carries the legacy `data--digest` format.
    set_cookie = response['Set-Cookie']
    set_cookie.wont_be_nil
    cookie_pair(set_cookie).must_match(/\Aemployee\.session=/)

    unsealed = unseal(set_cookie, employee_options)
    unsealed['employee_id'].must_equal 42

    # The re-issued cookie round-trips within the employee portal.
    follow_up = response_for(employee_options, set_cookie)
    follow_up.body.must_equal({ 'employee_id' => 42 }.inspect)
  end

  it 'operations panel unseals its own legacy session and re-issues it encrypted' do
    cookie = legacy_cookie(ops_options[:key], ops_options[:legacy_hmac_secret],
      'operator' => 'root', 'session_id' => 'ops-sid')

    response = response_for(ops_options, cookie)
    response.body.must_equal({ 'operator' => 'root' }.inspect)

    set_cookie = response['Set-Cookie']
    set_cookie.wont_be_nil
    cookie_pair(set_cookie).must_match(/\Aops\.session=/)

    unsealed = unseal(set_cookie, ops_options)
    unsealed['operator'].must_equal 'root'

    follow_up = response_for(ops_options, set_cookie)
    follow_up.body.must_equal({ 'operator' => 'root' }.inspect)
  end

  it 'does not unseal the other service\'s legacy session' do
    employee_cookie = legacy_cookie(employee_options[:key], employee_options[:legacy_hmac_secret],
      'employee_id' => 42, 'session_id' => 'employee-sid')
    ops_cookie = legacy_cookie(ops_options[:key], ops_options[:legacy_hmac_secret],
      'operator' => 'root', 'session_id' => 'ops-sid')

    # Replayed under the operations panel's key, the employee portal's legacy
    # cookie must not produce a session.
    response = response_for(ops_options, rekey_cookie(employee_cookie, ops_options[:key]))
    response.body.must_equal({}.inspect)

    # And vice versa.
    response = response_for(employee_options, rekey_cookie(ops_cookie, employee_options[:key]))
    response.body.must_equal({}.inspect)
  end

  it 'does not accept a migrated cookie from the other service' do
    # The employee portal migrates its legacy session to the encrypted format.
    employee_legacy = legacy_cookie(employee_options[:key], employee_options[:legacy_hmac_secret],
      'employee_id' => 42, 'session_id' => 'employee-sid')
    employee_migrated = response_for(employee_options, employee_legacy)['Set-Cookie']

    # The operations panel migrates its own legacy session too.
    ops_legacy = legacy_cookie(ops_options[:key], ops_options[:legacy_hmac_secret],
      'operator' => 'root', 'session_id' => 'ops-sid')
    ops_migrated = response_for(ops_options, ops_legacy)['Set-Cookie']

    # Replaying the migrated employee cookie under the operations panel's key
    # must not produce a session: the encryption purpose is bound to the
    # employee portal's cookie key.
    response = response_for(ops_options, rekey_cookie(cookie_pair(employee_migrated), ops_options[:key]))
    response.body.must_equal({}.inspect)

    # And vice versa.
    response = response_for(employee_options, rekey_cookie(cookie_pair(ops_migrated), employee_options[:key]))
    response.body.must_equal({}.inspect)
  end

  it 'rejects legacy cookies when the compatibility switch is disabled' do
    employee_no_legacy = employee_options.reject { |k, _| k == :legacy_hmac_secret }
    ops_no_legacy = ops_options.reject { |k, _| k == :legacy_hmac_secret }

    employee_cookie = legacy_cookie(employee_options[:key], employee_options[:legacy_hmac_secret],
      'employee_id' => 42, 'session_id' => 'employee-sid')
    response = response_for(employee_no_legacy, employee_cookie)
    response.body.must_equal({}.inspect)

    ops_cookie = legacy_cookie(ops_options[:key], ops_options[:legacy_hmac_secret],
      'operator' => 'root', 'session_id' => 'ops-sid')
    response = response_for(ops_no_legacy, ops_cookie)
    response.body.must_equal({}.inspect)
  end
end
