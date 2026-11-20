# frozen_string_literal: false
require 'test/unit'
require 'net/http'
require 'socket'
require 'stringio'

begin
  require 'net/https'
rescue LoadError
end

# Local samples for the share-safe phase debug view (Net::HTTP#set_debug_phases).
# Each sample runs over a local UNIX socketpair (no network, no listeners)
# and asserts that the debug output shows connection phases correlated with
# request ids, while never leaking credentials, header values, or bodies.
class TestHTTPDebugPhases < Test::Unit::TestCase
  AUTH_TOKEN   = 'test-secret-auth-token-9f8e7d'
  COOKIE_VALUE = 'session=test-secret-cookie-1a2b3c'
  REQUEST_BODY = 'test-secret-request-body-4d5e6f'
  RESPONSE_BODY = 'test-secret-response-body-7g8h9i'
  INVALID_MARKER = 'test-secret-invalid-payload-0z9y8x'
  PROXY_USER = 'test-secret-proxy-user'
  PROXY_PASS = 'test-secret-proxy-pass'
  PROXY_BASIC = ["#{PROXY_USER}:#{PROXY_PASS}"].pack('m0')

  ALL_SECRETS = [AUTH_TOKEN, COOKIE_VALUE, REQUEST_BODY, RESPONSE_BODY,
                 INVALID_MARKER, PROXY_USER, PROXY_PASS, PROXY_BASIC].freeze

  # Routes every TCP connect the http object attempts into a fresh local
  # socketpair; returns a queue of the server-side ends.
  def stub_connect(http)
    server_socks = Queue.new
    http.define_singleton_method(:timeouted_connect) do |*|
      client, server = Socket.pair(:UNIX, :STREAM, 0)
      client.define_singleton_method(:setsockopt) { |*| }
      server_socks << server
      client
    end
    server_socks
  end

  def run_server(server_socks, connections, &handler)
    Thread.new do
      connections.times do
        sock = server_socks.pop
        begin
          handler.call(sock)
        ensure
          sock.close
        end
      end
    end
  end

  def read_request(sock)
    request = sock.gets("\r\n\r\n") or return nil
    content_length = request[/^Content-Length: (\d+)/i, 1]
    sock.read(content_length.to_i) if content_length
    request
  end

  def assert_no_secrets(output)
    ALL_SECRETS.each do |secret|
      assert_not_include(output, secret)
    end
  end

  # Sample 1: normal success. The request carries Authorization/Cookie and
  # a body; the response carries a body. None of them may appear in the
  # debug output.
  def test_success_phases_are_logged_without_secrets
    http = Net::HTTP.new('example.internal', 80, nil)
    server_socks = stub_connect(http)
    server = run_server(server_socks, 1) do |sock|
      read_request(sock)
      sock.write "HTTP/1.1 200 OK\r\nContent-Length: #{RESPONSE_BODY.bytesize}\r\n\r\n#{RESPONSE_BODY}"
    end

    output = StringIO.new
    http.set_debug_phases(output)
    http.start
    req = Net::HTTP::Post.new('/submit')
    req['Authorization'] = "Bearer #{AUTH_TOKEN}"
    req['Cookie'] = COOKIE_VALUE
    req.body = REQUEST_BODY
    res = http.request(req)
    http.finish
    server.join

    assert_equal '200', res.code
    log = output.string
    assert_include log, '[net-http] phase=connect addr=example.internal port=80 via=direct'
    assert_include log, 'phase=tcp_open'
    assert_include log, 'phase=request req=1 method=POST path=/submit attempt=1'
    assert_include log, 'phase=response req=1 status=200'
    assert_no_secrets(log)
  end

  # Sample 2: disconnect. The peer drops each connection; the idempotent
  # GET is retried once and then fails. Retry and error phases must be
  # correlated with the same request id.
  def test_disconnect_phases_show_retry_without_secrets
    http = Net::HTTP.new('example.internal', 80, nil)
    server_socks = stub_connect(http)
    server = run_server(server_socks, 2) do |sock|
      # close immediately without responding
    end

    output = StringIO.new
    http.set_debug_phases(output)
    http.start
    req = Net::HTTP::Get.new('/flaky')
    req['Authorization'] = "Bearer #{AUTH_TOKEN}"
    req['Cookie'] = COOKIE_VALUE
    assert_raise(EOFError) { http.request(req) }
    http.finish
    server.join

    log = output.string
    assert_include log, 'phase=request req=1 method=GET path=/flaky attempt=1'
    assert_include log, 'phase=retry req=1 error=EOFError attempt=2'
    assert_include log, 'phase=connect req=1'
    assert_include log, 'phase=request req=1 method=GET path=/flaky attempt=2'
    assert_include log, 'phase=error req=1 error=EOFError'
    assert_no_secrets(log)
  end

  # Sample 3: invalid response. The peer replies with garbage; the error
  # phase must name only the exception class, never echo the offending
  # bytes.
  def test_invalid_response_phase_without_echoing_bytes
    http = Net::HTTP.new('example.internal', 80, nil)
    server_socks = stub_connect(http)
    server = run_server(server_socks, 1) do |sock|
      read_request(sock)
      sock.write "#{INVALID_MARKER}\r\n\r\n"
    end

    output = StringIO.new
    http.set_debug_phases(output)
    http.start
    req = Net::HTTP::Get.new('/broken')
    req['Authorization'] = "Bearer #{AUTH_TOKEN}"
    assert_raise(Net::HTTPBadResponse) { http.request(req) }
    http.finish
    server.join

    log = output.string
    assert_include log, 'phase=request req=1 method=GET path=/broken attempt=1'
    assert_include log, 'phase=error req=1 error=Net::HTTPBadResponse'
    assert_no_secrets(log)
  end

  # Proxy handoff: the CONNECT exchange must be visible as phases, with
  # only a boolean telling whether proxy auth was used -- never the
  # credentials themselves.
  def test_proxy_connect_handoff_without_credentials
    omit 'OpenSSL not available' unless defined?(OpenSSL::SSL)

    proxy = Net::HTTP.Proxy('proxy.internal', 8080, PROXY_USER, PROXY_PASS)
    http = proxy.new('example.internal', 443)
    http.use_ssl = true
    http.verify_mode = OpenSSL::SSL::VERIFY_NONE
    server_socks = stub_connect(http)
    server = run_server(server_socks, 1) do |sock|
      read_request(sock)
      sock.write "HTTP/1.1 200 Connection Established\r\n\r\n"
      # close the tunnel: the TLS handshake to the origin will fail
    end

    output = StringIO.new
    http.set_debug_phases(output)
    begin
      http.start
    rescue EOFError, SystemCallError, OpenSSL::SSL::SSLError
    end
    server.join

    log = output.string
    assert_include log, 'phase=connect addr=proxy.internal port=8080 via=proxy'
    assert_include log, 'phase=proxy_connect to=example.internal:443 auth=true'
    assert_include log, 'phase=proxy_established to=example.internal:443'
    assert_include log, 'phase=ssl_handshake'
    assert_include log, 'phase=connect_error'
    assert_no_secrets(log)
  end
end
