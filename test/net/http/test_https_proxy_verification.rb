# frozen_string_literal: false
require "test/unit"
require "stringio"
begin
  require 'net/https'
rescue LoadError
end

return unless defined?(OpenSSL::SSL)

# These tests run without opening any TCP port (the sandbox may forbid
# local port binding). Instead, connection doubles stand in for the TCP
# socket and the two TLS sockets, while real X509 certificates and stores
# drive the verification configuration of each layer independently.
class TestNetHTTPSProxyVerification < Test::Unit::TestCase
  PROXY_ENV_KEYS = %w[
    http_proxy HTTP_PROXY https_proxy HTTPS_PROXY
    all_proxy ALL_PROXY no_proxy NO_PROXY
  ].freeze

  PROXY_HOST = "proxy.example"
  TARGET_HOST = "target.example"

  def setup
    @saved_proxy_env = PROXY_ENV_KEYS.each_with_object({}) do |key, saved|
      saved[key] = ENV.delete(key)
    end
  end

  def teardown
    @saved_proxy_env.each do |key, value|
      ENV[key] = value
    end
  end

  class << self
    def make_ca(common_name)
      key = OpenSSL::PKey::RSA.new(2048)
      name = OpenSSL::X509::Name.new([["CN", common_name]])
      cert = OpenSSL::X509::Certificate.new
      cert.version = 2
      cert.serial = OpenSSL::Random.random_bytes(16).unpack1("n")
      cert.subject = name
      cert.issuer = name
      cert.public_key = key.public_key
      cert.not_before = Time.now - 60
      cert.not_after = Time.now + 600
      factory = OpenSSL::X509::ExtensionFactory.new(nil, cert)
      cert.add_extension(factory.create_extension("basicConstraints", "CA:TRUE", true))
      cert.add_extension(factory.create_extension("keyUsage", "keyCertSign,cRLSign", true))
      cert.sign(key, OpenSSL::Digest::SHA256.new)
      [key, cert]
    end

    def make_server(ca_key, ca_cert, common_name)
      key = OpenSSL::PKey::RSA.new(2048)
      cert = OpenSSL::X509::Certificate.new
      cert.version = 2
      cert.serial = OpenSSL::Random.random_bytes(16).unpack1("n")
      cert.subject = OpenSSL::X509::Name.new([["CN", common_name]])
      cert.issuer = ca_cert.subject
      cert.public_key = key.public_key
      cert.not_before = Time.now - 60
      cert.not_after = Time.now + 600
      factory = OpenSSL::X509::ExtensionFactory.new(ca_cert, cert)
      cert.add_extension(factory.create_extension("basicConstraints", "CA:FALSE"))
      cert.add_extension(factory.create_extension("subjectAltName", "DNS:#{common_name}"))
      cert.sign(ca_key, OpenSSL::Digest::SHA256.new)
      [key, cert]
    end
  end

  PROXY_CA_KEY, PROXY_CA = make_ca("Proxy Test CA")
  TARGET_CA_KEY, TARGET_CA = make_ca("Target Test CA")
  PROXY_KEY, PROXY_CERT = make_server(PROXY_CA_KEY, PROXY_CA, PROXY_HOST)
  TARGET_KEY, TARGET_CERT = make_server(TARGET_CA_KEY, TARGET_CA, TARGET_HOST)

  PROXY_STORE = OpenSSL::X509::Store.new.tap { |store| store.add_cert(PROXY_CA) }
  TARGET_STORE = OpenSSL::X509::Store.new.tap { |store| store.add_cert(TARGET_CA) }

  CONNECT_RESPONSE =
    "HTTP/1.1 200 Connection established\r\n" \
    "Proxy-Connection: Keep-Alive\r\n\r\n"

  TARGET_RESPONSE =
    "HTTP/1.1 200 OK\r\n" \
    "Content-Length: 2\r\n" \
    "Connection: close\r\n\r\n" \
    "ok"

  # Stands in for the raw TCP socket to the proxy. It records writes and
  # serves the canned CONNECT response once TLS has been negotiated.
  class FakeTCP
    attr_reader :written, :closed
    attr_accessor :auto_respond

    def initialize
      @written = "".b
      @closed = false
      @inbox = StringIO.new("".b)
      # When TLS sockets wrap this raw socket they inject the canned
      # responses themselves, so raw auto-response must be disabled.
      @auto_respond = true
    end

    def setsockopt(*); end

    def write(data)
      @written << data
      if @auto_respond
        if data.start_with?("CONNECT ")
          @inbox.string << CONNECT_RESPONSE
        elsif data.start_with?("GET ")
          @inbox.string << TARGET_RESPONSE
        end
      end
      data.bytesize
    end
    alias << write

    def write_nonblock(data, *_opts)
      write(data)
    end

    def read(length, dest = nil, *_args)
      chunk = @inbox.read(length)
      raise EOFError, "end of file reached" if chunk.nil? || chunk.empty?
      dest << chunk if dest
      chunk
    end

    def read_nonblock(length, dest = nil, *_opts)
      chunk = @inbox.read(length)
      return nil if chunk.nil? || chunk.empty?
      dest << chunk if dest
      chunk
    end

    def eof?
      @inbox.eof?
    end

    def close
      @closed = true
    end

    def closed?
      @closed
    end
  end

  # Stands in for an OpenSSL::SSL::SSLSocket for one layer (proxy or
  # destination). It performs the same trust decision as OpenSSL using the
  # real SSLContext the library built, so a misconfigured layer raises the
  # same OpenSSL::SSL::SSLError with the standard failure message.
  class FakeSSLSocket
    attr_reader :io, :context, :hostname, :peer_cert, :closed
    attr_accessor :sync_close

    def initialize(io, context, peer_cert:, layer_name:, expected_host:)
      @io = io
      @context = context
      @peer_cert = peer_cert
      @layer_name = layer_name
      @expected_host = expected_host
      @hostname = nil
      @closed = false
      @sync_close = false
    end

    def hostname=(value)
      @hostname = value
    end

    def session=(_value); end

    def connect
      verifying = @context.verify_mode == OpenSSL::SSL::VERIFY_PEER
      if verifying
        chain = [@peer_cert]
        unless @context.cert_store&.verify(@peer_cert, chain)
          raise OpenSSL::SSL::SSLError,
                "SSL_connect returned=1 errno=0 peeraddr= (fake): certificate verify failed (unable to get local issuer certificate)"
        end
        if @context.verify_hostname
          post_connection_check(@hostname || @expected_host)
        end
      end
      self
    end

    def connect_nonblock(**_opts)
      connect
      :ok
    end

    def post_connection_check(hostname)
      san = @peer_cert.extensions.find { |ext| ext.oid == "subjectAltName" }
      names = san.value.split(",").map { |entry| entry.strip.sub(/\ADNS:/, "") }
      unless names.include?(hostname)
        raise OpenSSL::SSL::SSLError,
              "hostname \"#{hostname}\" does not match the server certificate"
      end
    end

    def ssl_version
      "TLSv1.3"
    end

    def cipher
      ["TLS_AES_256_GCM_SHA384", "TLSv1.3", 256]
    end

    def write(data)
      @io.write(data)
      inbox = root_inbox
      case @layer_name
      when "proxy"
        inbox.string << CONNECT_RESPONSE if data.start_with?("CONNECT ")
      when "destination"
        inbox.string << TARGET_RESPONSE if data.start_with?("GET ")
      end
    end
    alias << write

    # Walks down nested TLS sockets to the inbox held by the raw TCP double.
    def root_inbox
      io = @io
      io = io.io while io.respond_to?(:io)
      io.instance_variable_get(:@inbox)
    end

    def write_nonblock(data, *_opts)
      write(data)
      data.bytesize
    end

    def read(length, dest = nil, *args)
      @io.read(length, dest, *args)
    end

    def read_nonblock(length, dest = nil, *opts)
      @io.read_nonblock(length, dest, *opts)
    end

    def eof?
      @io.eof?
    end

    def close
      @closed = true
      @io.close if @sync_close
    end

    def closed?
      @closed
    end

    def to_io
      @io
    end
  end

  def build_http
    http = Net::HTTP.new(TARGET_HOST, 443, PROXY_HOST, 8443, nil, nil, nil, true)
    http.use_ssl = true
    tcp = FakeTCP.new
    # TLS sockets inject the CONNECT/target responses themselves.
    tcp.auto_respond = false

    # Replace the real TCP and TLS factories on this instance only.
    http.define_singleton_method(:timeouted_connect) { |_addr, _port| tcp }

    layers = []
    http.define_singleton_method(:new_ssl_socket) do |io, context|
      if context.equal?(http.proxy_ssl_context)
        socket = FakeSSLSocket.new(io, context, peer_cert: PROXY_CERT,
                                          layer_name: "proxy", expected_host: PROXY_HOST)
        layers << [:proxy, socket]
        socket
      else
        socket = FakeSSLSocket.new(io, context, peer_cert: TARGET_CERT,
                                          layer_name: "destination", expected_host: TARGET_HOST)
        layers << [:destination, socket]
        socket
      end
    end

    [http, tcp, layers]
  end

  def test_proxy_and_destination_have_independent_ssl_contexts
    http, _tcp, layers = build_http
    http.proxy_cert_store = PROXY_STORE
    http.cert_store = TARGET_STORE

    http.start

    assert_not_same(http.ssl_context, http.proxy_ssl_context)
    assert_same(TARGET_STORE, http.ssl_context.cert_store)
    assert_same(PROXY_STORE, http.proxy_ssl_context.cert_store)
    assert_equal([:proxy, :destination], layers.map(&:first))
    # The business-facing peer certificate is the destination's, never the
    # proxy's.
    assert_equal(TARGET_CERT.to_der, http.peer_cert.to_der)
  ensure
    http&.finish if http&.started?
  end

  def test_trust_both_layers_succeeds_and_request_waits_for_connect
    http, tcp, layers = build_http
    http.proxy_cert_store = PROXY_STORE
    http.cert_store = TARGET_STORE

    http.start
    assert_equal(2, layers.size)
    assert_equal([:proxy, :destination], layers.map(&:first))

    # The business request must only be sent after the CONNECT tunnel is
    # established through the verified proxy.
    http.get("/")
    connect_pos = tcp.written.index("CONNECT ")
    request_pos = tcp.written.index("GET /")
    assert_not_nil(connect_pos)
    assert_not_nil(request_pos)
    assert_operator(connect_pos, :<, request_pos)
  ensure
    http&.finish if http&.started?
  end

  def test_trust_only_proxy_fails_at_destination_layer
    http, _tcp, layers = build_http
    http.proxy_cert_store = PROXY_STORE
    # Destination deliberately trusts the proxy CA instead of its own CA.
    http.cert_store = PROXY_STORE

    error = assert_raise(OpenSSL::SSL::SSLError) { http.start }
    assert_match(/TLS connection to destination failed/, error.message)
    assert_match(/certificate verify failed/, error.message)
    # The proxy handshake succeeds; only the destination handshake fails.
    assert_equal([:proxy, :destination], layers.map(&:first))
    assert_not_predicate(http, :started?)
  end

  def test_trust_only_target_fails_at_proxy_layer
    http, _tcp, layers = build_http
    # Proxy deliberately trusts the target CA instead of its own CA.
    http.proxy_cert_store = TARGET_STORE
    http.cert_store = TARGET_STORE

    error = assert_raise(OpenSSL::SSL::SSLError) { http.start }
    assert_match(/TLS connection to proxy failed/, error.message)
    assert_match(/certificate verify failed/, error.message)
    # The proxy socket is created before its handshake fails, but the
    # destination layer is never reached.
    assert_equal([:proxy], layers.map(&:first))
    assert_not_predicate(http, :started?)
  end

  def test_proxy_failure_never_reaches_destination
    http, _tcp, layers = build_http
    http.proxy_cert_store = TARGET_STORE
    http.cert_store = TARGET_STORE

    assert_raise(OpenSSL::SSL::SSLError) { http.start }
    proxy_socket = layers.find { |name, _| name == :proxy }
    assert_not_nil(proxy_socket)
    assert_nil(layers.find { |name, _| name == :destination })
    # The failed proxy socket closes its underlying transport (sync_close).
    assert_predicate(proxy_socket[1].io, :closed?)
  end

  def test_proxy_hostname_mismatch_is_reported_as_proxy_layer
    http, _tcp, _layers = build_http
    http.proxy_cert_store = PROXY_STORE
    http.proxy_verify_hostname = true
    http.cert_store = TARGET_STORE

    # Address the proxy by a name absent from its certificate SAN.
    http.proxy_address = "unexpected-proxy.example"
    error = assert_raise(OpenSSL::SSL::SSLError) { http.start }
    assert_match(/TLS connection to proxy failed/, error.message)
    assert_match(/hostname "unexpected-proxy.example" does not match/, error.message)
  end

  def test_proxy_verification_can_be_disabled_independently
    http, _tcp, layers = build_http
    http.proxy_verify_mode = OpenSSL::SSL::VERIFY_NONE
    http.cert_store = TARGET_STORE

    http.start
    assert_equal([:proxy, :destination], layers.map(&:first))
    assert_equal(OpenSSL::SSL::VERIFY_NONE, http.proxy_ssl_context.verify_mode)
    assert_equal(OpenSSL::SSL::VERIFY_PEER, http.ssl_context.verify_mode)
  ensure
    http&.finish if http&.started?
  end

  def test_direct_connection_without_proxy_keeps_existing_configuration
    tcp = FakeTCP.new
    http = Net::HTTP.new(TARGET_HOST, 443)
    http.use_ssl = true
    http.cert_store = TARGET_STORE
    http.define_singleton_method(:timeouted_connect) { |_addr, _port| tcp }

    layers = []
    http.define_singleton_method(:new_ssl_socket) do |io, context|
      socket = FakeSSLSocket.new(io, context, peer_cert: TARGET_CERT,
                                          layer_name: "destination", expected_host: TARGET_HOST)
      layers << [:destination, socket]
      socket
    end

    http.start
    assert_nil(http.proxy_ssl_context)
    assert_not_nil(http.ssl_context)
    assert_same(TARGET_STORE, http.ssl_context.cert_store)
    assert_equal([:destination], layers.map(&:first))
    http.get("/")
    assert(tcp.written.start_with?("GET /"))
  ensure
    http&.finish if http&.started?
  end

  def test_plaintext_proxy_only_verifies_destination
    tcp = FakeTCP.new
    http = Net::HTTP.new(TARGET_HOST, 443, PROXY_HOST, 8080)
    http.use_ssl = true
    http.cert_store = TARGET_STORE
    http.define_singleton_method(:timeouted_connect) { |_addr, _port| tcp }

    layers = []
    http.define_singleton_method(:new_ssl_socket) do |io, context|
      socket = FakeSSLSocket.new(io, context, peer_cert: TARGET_CERT,
                                          layer_name: "destination", expected_host: TARGET_HOST)
      layers << [:destination, socket]
      socket
    end
    http.start
    assert_nil(http.proxy_ssl_context)
    assert_equal([:destination], layers.map(&:first))
  ensure
    http&.finish if http&.started?
  end
end
