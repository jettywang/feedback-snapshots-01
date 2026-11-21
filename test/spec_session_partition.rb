# frozen_string_literal: true

# Released under the MIT License.
# Copyright, 2026, by Samuel Williams.

require_relative 'helper'

require 'json'
require 'time'

require 'rack/lint'
require 'rack/mock'
require 'rack/response'
require 'rack/urlmap'
require 'rack/utils'

require_relative '../lib/rack/session/cookie'
require_relative '../lib/rack/session/pool'
require_relative '../lib/rack/session/encryptor'

# A Cookie jar that distinguishes partitioned cookies from ordinary ones. A
# partitioned cookie is only presented to the embedded entry point, matching
# the browser rule that a partitioned cookie is scoped to its embedding
# context. Ordinary cookies are presented everywhere.
class PartitionAwareCookieJar
  Cookie = Struct.new(:value, :partitioned, :secure, :same_site, :path, keyword_init: true)

  attr_reader :cookies

  def initialize
    @cookies = {}
  end

  def update(response)
    Array(response.headers['set-cookie']).each do |header|
      store(header)
    end

    self
  end

  def store(header)
    name, rest = header.split('=', 2)
    value, *attributes = rest.to_s.split(';').map(&:strip)

    attributes = attributes.each_with_object({}) do |attribute, hash|
      key, attribute_value = attribute.split('=', 2)
      hash[key.downcase] = attribute_value || true
    end

    if deleted?(attributes)
      @cookies.delete(name)
    else
      @cookies[name] = Cookie.new(
        value: Rack::Utils.unescape(value),
        partitioned: !!attributes['partitioned'],
        secure: !!attributes['secure'],
        same_site: attributes['samesite'],
        path: attributes['path']
      )
    end
  end

  def deleted?(attributes)
    return true if attributes.key?('max-age') && attributes['max-age'].to_i.zero?

    if (expires = attributes['expires'])
      Time.httpdate(expires) <= Time.now
    else
      false
    end
  rescue ArgumentError
    false
  end

  def [](name)
    @cookies[name]
  end

  def names
    @cookies.keys
  end

  def header_for(context)
    @cookies.reject do |_name, cookie|
      cookie.partitioned && context != :embedded
    end.map do |name, cookie|
      "#{name}=#{Rack::Utils.escape(cookie.value)}"
    end.join('; ')
  end
end

describe 'Rack::Session partitioned sessions' do
  SECRET = 'p' * 64

  # Each entry point presents the same view of the session so the test can
  # compare them. The embedded entry point records that it was embedded; the
  # partition is selected by the configured strategy based on the mount path.
  def self.entry_app(entry)
    lambda do |env|
      session = env['rack.session']

      case env['PATH_INFO']
      when '/login'
        session['user'] = env['QUERY_STRING'] unless env['QUERY_STRING'].empty?
      when '/logout'
        session.expire!
      when '/logout_embedded'
        session.expire!(:embedded)
      end

      body = {
        'entry' => entry,
        'partition' => session.partition,
        'data' => session.to_hash.reject { |key, _value| key == 'session_id' }
      }

      Rack::Response.new(JSON.dump(body)).to_a
    end
  end

  def two_entry_app
    Rack::URLMap.new(
      '/' => self.class.entry_app(:direct),
      '/embed' => self.class.entry_app(:embedded)
    )
  end

  def build(backend, options = {})
    case backend
    when :cookie
      Rack::Session::Cookie.new(two_entry_app, options.merge(secrets: SECRET))
    when :pool
      Rack::Session::Pool.new(two_entry_app, options)
    end
  end

  def request(middleware, jar, context, path = '/', explicit_partition: nil)
    env = {
      'HTTPS' => 'on',
      'HTTP_COOKIE' => jar.header_for(context)
    }

    env[Rack::Session::RACK_SESSION_PARTITION] = explicit_partition if explicit_partition

    Rack::MockRequest.new(Rack::Lint.new(middleware)).get(path, env)
  end

  def body_of(response)
    JSON.parse(response.body)
  end

  def partition_options
    {
      partition: lambda do |req|
        req.path_info.start_with?('/embed') ? :embedded : nil
      end,
      partitions: {
        embedded: { partitioned: true, secure: true, same_site: :none }
      }
    }
  end

  # Read the persisted representation of a partition for the two backends.
  def persisted_partition(middleware, jar, cookie_name)
    cookie = jar[cookie_name]
    return nil unless cookie

    if middleware.is_a?(Rack::Session::Cookie)
      # The ordinary session keeps the upstream encryption purpose (the
      # explicit :key option, nil by default); named partitions use a
      # partition-qualified purpose.
      base = cookie_name == middleware.key ? nil : "#{middleware.key}.#{cookie_name.split('.').last}"
      encryptor = Rack::Session::Encryptor.new(SECRET, purpose: base)
      encryptor.decrypt(cookie.value)['session_partition']
    else
      session_id = Rack::Session::SessionId.new(cookie.value)
      record = middleware.pool[session_id.private_id] || middleware.pool[session_id.public_id]
      record && record['session_partition']
    end
  end

  [:cookie, :pool].each do |backend|
    describe backend.to_s do
      before do
        @middleware = build(backend, partition_options)
        @jar = PartitionAwareCookieJar.new
      end

      it 'issues an ordinary session without embedded permissions' do
        response = request(@middleware, @jar, :direct, '/login?dave')
        @jar.update(response)

        body = body_of(response)
        body['partition'].must_be_nil
        body['data']['user'].must_equal 'dave'

        set_cookie = Array(response.headers['set-cookie']).join("\n")
        set_cookie.wont_match(/partitioned/i)
        set_cookie.must_match(/rack\.session=/)

        @jar.names.must_equal ['rack.session']
        @jar['rack.session'].partitioned.must_equal false
        persisted_partition(@middleware, @jar, 'rack.session').must_be_nil
      end

      it 'issues an embedded session with partitioned cookie attributes and matching persistence' do
        response = request(@middleware, @jar, :embedded, '/embed/login?emma')
        @jar.update(response)

        body = body_of(response)
        body['partition'].must_equal 'embedded'
        body['data']['user'].must_equal 'emma'

        cookie = @jar['rack.session.embedded']
        cookie.wont_be_nil
        cookie.partitioned.must_equal true
        cookie.secure.must_equal true
        cookie.same_site.must_equal 'none'

        persisted_partition(@middleware, @jar, 'rack.session.embedded').must_equal 'embedded'
      end

      it 'keeps the two entry points separate when switching between them' do
        @jar.update(request(@middleware, @jar, :direct, '/login?dave'))
        @jar.update(request(@middleware, @jar, :embedded, '/embed/login?emma'))

        @jar.names.sort.must_equal ['rack.session', 'rack.session.embedded']

        direct_view = body_of(request(@middleware, @jar, :direct, '/'))
        direct_view['entry'].must_equal 'direct'
        direct_view['partition'].must_be_nil
        direct_view['data']['user'].must_equal 'dave'

        embedded_view = body_of(request(@middleware, @jar, :embedded, '/embed'))
        embedded_view['entry'].must_equal 'embedded'
        embedded_view['partition'].must_equal 'embedded'
        embedded_view['data']['user'].must_equal 'emma'

        # Coming back to the ordinary entry point after the embedded visit does
        # not inherit the embedded identity.
        back = body_of(request(@middleware, @jar, :direct, '/login'))
        back['data']['user'].must_equal 'dave'
      end

      it 'does not accept an embedded session presented to the ordinary entry' do
        @jar.update(request(@middleware, @jar, :embedded, '/embed/login?emma'))

        # Replay the embedded cookie under the ordinary cookie name: the
        # partition marker no longer matches, so it must not leak the user.
        renamed = PartitionAwareCookieJar.new
        renamed.store('rack.session=' + Rack::Utils.escape(@jar['rack.session.embedded'].value))

        body = body_of(request(@middleware, renamed, :direct, '/login'))
        body['partition'].must_be_nil
        body['data'].fetch('user', nil).must_be_nil
      end

      it 'does not let an ordinary cookie grant the embedded entry point' do
        @jar.update(request(@middleware, @jar, :direct, '/login?dave'))

        only_direct = PartitionAwareCookieJar.new
        only_direct.store('rack.session=' + Rack::Utils.escape(@jar['rack.session'].value))

        body = body_of(request(@middleware, only_direct, :embedded, '/embed'))
        body['partition'].must_equal 'embedded'
        body['data'].must_equal({})
      end

      it 'expires only the current partition on ordinary logout' do
        @jar.update(request(@middleware, @jar, :direct, '/login?dave'))
        @jar.update(request(@middleware, @jar, :embedded, '/embed/login?emma'))

        logout = request(@middleware, @jar, :direct, '/logout')
        @jar.update(logout)

        # The ordinary cookie is expired with ordinary attributes, and the
        # embedded session is untouched.
        set_cookie = Array(logout.headers['set-cookie']).join("\n")
        set_cookie.must_match(/rack\.session=;/)
        set_cookie.wont_match(/partitioned/i)
        @jar.names.must_equal ['rack.session.embedded']

        direct_view = body_of(request(@middleware, @jar, :direct, '/login'))
        direct_view['data'].fetch('user', nil).must_be_nil

        embedded_view = body_of(request(@middleware, @jar, :embedded, '/embed'))
        embedded_view['data']['user'].must_equal 'emma'
      end

      it 'expires an explicitly named embedded session from the ordinary entry' do
        @jar.update(request(@middleware, @jar, :direct, '/login?dave'))
        @jar.update(request(@middleware, @jar, :embedded, '/embed/login?emma'))

        logout = request(@middleware, @jar, :direct, '/logout_embedded')
        @jar.update(logout)

        # The embedded cookie is expired with the attributes it was issued
        # with, and the ordinary session survives.
        set_cookie = Array(logout.headers['set-cookie']).join("\n")
        set_cookie.must_match(/rack\.session\.embedded=;/)
        set_cookie.must_match(/partitioned/i)
        set_cookie.must_match(/secure/i)
        @jar.names.must_equal ['rack.session']

        embedded_view = body_of(request(@middleware, @jar, :embedded, '/embed'))
        embedded_view['data'].must_equal({})

        direct_view = body_of(request(@middleware, @jar, :direct, '/'))
        direct_view['data']['user'].must_equal 'dave'
      end

      it 'lets the application explicitly select the partition for a request' do
        response = request(@middleware, @jar, :direct, '/login?emma', explicit_partition: :embedded)
        @jar.update(response)

        body = body_of(response)
        body['partition'].must_equal 'embedded'

        cookie = @jar['rack.session.embedded']
        cookie.wont_be_nil
        cookie.partitioned.must_equal true
        @jar.names.wont_include 'rack.session'
      end
    end
  end

  it 'does not partition anything when no partition strategy is configured' do
    middleware = Rack::Session::Cookie.new(two_entry_app, secrets: SECRET)
    jar = PartitionAwareCookieJar.new

    direct = request(middleware, jar, :direct, '/login?dave')
    jar.update(direct)
    embedded = request(middleware, jar, :embedded, '/embed/login?emma')
    jar.update(embedded)

    # Both entry points share the ordinary, unpartitioned session, and no
    # Partitioned attribute is ever emitted.
    jar.names.must_equal ['rack.session']
    jar['rack.session'].partitioned.must_equal false
    body_of(embedded)['partition'].must_be_nil
    body_of(embedded)['data']['user'].must_equal 'emma'
    persisted_partition(middleware, jar, 'rack.session').must_be_nil
  end
end
