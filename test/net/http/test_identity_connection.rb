# frozen_string_literal: false
require "test/unit"
require "tmpdir"
begin
  require 'net/https'
rescue LoadError
  # skip the whole file if OpenSSL is unavailable
end

return unless defined?(OpenSSL::SSL)

# Generates a small in-memory PKI for the tests: one CA, a server
# certificate, and one client certificate per employee identity. Nothing
# is written to disk and the private keys never leave the test process.
module IdentityTestPKI
  module_function

  def generate_ca
    key = OpenSSL::PKey.generate_key("RSA", rsa_keygen_bits: 2048)
    name = OpenSSL::X509::Name.parse("/CN=Test Issuing CA")
    cert = build_cert(name, name, key, 1, nil, ca: true)
    [key, cert]
  end

  def generate_identity(ca_key, ca_cert, common_name, serial)
    key = OpenSSL::PKey.generate_key("RSA", rsa_keygen_bits: 2048)
    name = OpenSSL::X509::Name.parse("/O=Backend/C=JP/CN=#{common_name}")
    cert = build_cert(name, ca_cert.subject, ca_key, serial, key, issuer_cert: ca_cert)
    [key, cert]
  end

  def generate_server(ca_key, ca_cert)
    key = OpenSSL::PKey.generate_key("RSA", rsa_keygen_bits: 2048)
    name = OpenSSL::X509::Name.parse("/CN=localhost")
    cert = build_cert(name, ca_cert.subject, ca_key, 999, key,
                      issuer_cert: ca_cert,
                      extensions: [["subjectAltName", "DNS:localhost,IP:127.0.0.1", false]])
    [key, cert]
  end

  def build_cert(subject, issuer_name, issuer_key, serial, public_key_owner,
                 ca: false, issuer_cert: nil, extensions: [])
    cert = OpenSSL::X509::Certificate.new
    cert.version = 2
    cert.serial = serial
    cert.subject = subject
    cert.issuer = issuer_name
    cert.not_before = Time.now - 60
    cert.not_after = Time.now + 3600
    cert.public_key = public_key_owner ? public_key_owner.public_key : issuer_key.public_key
    factory = OpenSSL::X509::ExtensionFactory.new
    factory.subject_certificate = cert
    factory.issuer_certificate = ca ? cert : issuer_cert
    cert.add_extension(factory.create_extension("basicConstraints", ca ? "CA:TRUE" : "CA:FALSE", true))
    extensions.each do |oid, value, critical|
      cert.add_extension(factory.create_extension(oid, value, critical))
    end
    cert.sign(issuer_key, OpenSSL::Digest.new("SHA256"))
    cert
  end
end

class TestNetHTTPIdentityConnection < Test::Unit::TestCase
  CA_KEY, CA_CERT = IdentityTestPKI.generate_ca
  SERVER_KEY, SERVER_CERT = IdentityTestPKI.generate_server(CA_KEY, CA_CERT)
  ALICE_KEY, ALICE_CERT = IdentityTestPKI.generate_identity(CA_KEY, CA_CERT, "alice", 101)
  BOB_KEY, BOB_CERT = IdentityTestPKI.generate_identity(CA_KEY, CA_CERT, "bob", 102)
  ROTATED_KEY, ROTATED_CERT = IdentityTestPKI.generate_identity(CA_KEY, CA_CERT, "alice", 202)

  def builder
    store = OpenSSL::X509::Store.new.tap { |s| s.add_cert(CA_CERT) }
    Net::HTTP::IdentityConnection.new("localhost", 0, cert_store: store)
  end

  def identity(key, cert, approved = cert)
    Net::HTTP::ClientIdentity.new(cert, key, approved)
  end

  def fingerprint(cert)
    OpenSSL::Digest::SHA256.hexdigest(cert.to_der)
  end

  def test_loads_identity_and_verifies_approved_certificate
    id = identity(ALICE_KEY, ALICE_CERT)
    assert_equal ALICE_CERT.to_der, id.certificate.to_der
    assert_equal OpenSSL::Digest::SHA256.hexdigest(ALICE_CERT.to_der), id.fingerprint
    assert_equal ALICE_CERT.serial, id.serial
    assert_match(/CN=alice/, id.subject)
    assert_equal ALICE_CERT.public_key.to_pem, id.public_key_pem
    assert id.certificate_for?(ALICE_CERT)
    assert_false id.certificate_for?(BOB_CERT)
  end

  def test_rejects_certificate_that_does_not_match_approved_request
    error = assert_raise(Net::HTTP::ClientIdentity::MismatchError) do
      identity(ALICE_KEY, ALICE_CERT, BOB_CERT)
    end
    assert_match(/approved certificate/, error.message)
  end

  def test_from_pem_round_trip_and_approved_certificate_check
    id = Net::HTTP::ClientIdentity.from_pem(
      ALICE_CERT.to_pem, ALICE_KEY.to_pem, approved_pem: ALICE_CERT.to_pem
    )
    assert_equal ALICE_CERT.to_der, id.certificate.to_der
    assert_equal fingerprint(ALICE_CERT), id.fingerprint

    assert_raise(Net::HTTP::ClientIdentity::MismatchError) do
      Net::HTTP::ClientIdentity.from_pem(
        ALICE_CERT.to_pem, ALICE_KEY.to_pem, approved_pem: BOB_CERT.to_pem
      )
    end
  end

  def test_rejects_private_key_that_does_not_match_certificate
    error = assert_raise(Net::HTTP::ClientIdentity::MismatchError) do
      Net::HTTP::ClientIdentity.new(ALICE_CERT, BOB_KEY)
    end
    assert_match(/private key does not match/, error.message)
  end

  def test_load_failure_on_garbage_pem
    assert_raise(Net::HTTP::ClientIdentity::LoadError) do
      Net::HTTP::ClientIdentity.from_pem("not a certificate", ALICE_KEY.to_pem)
    end
    assert_raise(Net::HTTP::ClientIdentity::LoadError) do
      Net::HTTP::ClientIdentity.from_pem(ALICE_CERT.to_pem, "not a key")
    end
  end

  def test_load_failure_on_missing_file
    assert_raise(Net::HTTP::ClientIdentity::LoadError) do
      Net::HTTP::ClientIdentity.from_files("no-such-cert.pem", "no-such-key.pem")
    end
  end

  def test_from_files_loads_identity_without_keeping_file_contents
    Dir.mktmpdir do |dir|
      cert_path = File.join(dir, "alice.crt")
      key_path = File.join(dir, "alice.key")
      approved_path = File.join(dir, "approved.crt")
      File.binwrite(cert_path, ALICE_CERT.to_pem)
      File.binwrite(key_path, ALICE_KEY.to_pem)
      File.binwrite(approved_path, ALICE_CERT.to_pem)

      id = Net::HTTP::ClientIdentity.from_files(
        cert_path, key_path, approved_path: approved_path
      )
      assert_equal ALICE_CERT.to_der, id.certificate.to_der
      assert_equal fingerprint(ALICE_CERT), id.fingerprint
    end
  end

  def test_identity_does_not_expose_private_key_material
    id = identity(ALICE_KEY, ALICE_CERT)
    public_surface = id.public_methods(false).map(&:to_s)
    assert_not_empty public_surface
    assert_false public_surface.any? { |m| m =~ /\Akey\z|private|secret/ }
    rendered = "#{id.inspect} #{id}"
    assert_not_match(/BEGIN [A-Z ]*PRIVATE KEY/, rendered)
    assert_not_include rendered, ALICE_KEY.to_pem.lines[1]
  end

  def test_unknown_identity_is_rejected_before_connecting
    b = builder
    error = assert_raise(Net::HTTP::IdentityConnection::IdentityNotFound) do
      b.connection(:ghost)
    end
    assert_match(/ghost/, error.message)
  end

  def test_connection_selects_identity_before_start
    b = builder
    b.register(:alice, identity(ALICE_KEY, ALICE_CERT))
    http = b.connection(:alice)
    assert_kind_of Net::HTTP, http
    assert http.use_ssl?
    assert_equal ALICE_CERT.to_der, http.cert.to_der
    # The identity actually handed to the SSL context is what connect() copies in.
    context = OpenSSL::SSL::SSLContext.new
    context.set_params(cert: http.cert, key: http.key)
    assert_equal ALICE_CERT.to_der, context.cert.to_der
    assert_false http.started?
  end

  def test_parallel_connections_carry_distinct_identities
    b = builder
    b.register(:alice, identity(ALICE_KEY, ALICE_CERT))
    b.register(:bob, identity(BOB_KEY, BOB_CERT))

    alice_http = b.connection(:alice)
    bob_http = b.connection(:bob)

    assert_equal ALICE_CERT.to_der, alice_http.cert.to_der
    assert_equal BOB_CERT.to_der, bob_http.cert.to_der
    assert_not_equal alice_http.cert.to_der, bob_http.cert.to_der
    assert_not_same alice_http, bob_http
    assert_not_same alice_http.cert, bob_http.cert
    # building the second connection must not mutate the first
    assert_equal ALICE_CERT.to_der, b.connection(:alice).cert.to_der
  end

  def test_certificate_rotation_replaces_identity_for_new_connections_only
    b = builder
    b.register(:alice, identity(ALICE_KEY, ALICE_CERT))
    before = b.connection(:alice)
    assert_equal ALICE_CERT.serial, before.cert.serial

    b.register(:alice, identity(ROTATED_KEY, ROTATED_CERT))
    after = b.connection(:alice)

    assert_equal ROTATED_CERT.serial, after.cert.serial
    assert_equal ROTATED_CERT.to_der, after.cert.to_der
    # the connection built before the rotation is untouched
    assert_equal ALICE_CERT.serial, before.cert.serial
    assert_equal ALICE_CERT.to_der, before.cert.to_der
    assert_equal OpenSSL::Digest::SHA256.hexdigest(ALICE_CERT.to_der),
                 OpenSSL::Digest::SHA256.hexdigest(before.cert.to_der)
  end

  def test_failed_identity_does_not_affect_other_connection
    b = builder
    b.register(:alice, identity(ALICE_KEY, ALICE_CERT))
    good = b.connection(:alice)

    assert_raise(Net::HTTP::ClientIdentity::MismatchError) do
      b.register(:bob, identity(BOB_KEY, ALICE_CERT))
    end
    assert_raise(Net::HTTP::IdentityConnection::IdentityNotFound) do
      b.connection(:bob)
    end

    assert_equal [:alice], b.identities
    still_good = b.connection(:alice)
    assert_equal ALICE_CERT.to_der, good.cert.to_der
    assert_equal ALICE_CERT.to_der, still_good.cert.to_der
  end
end

# Full mutual-TLS handshake tests. No TCP port is bound: each connection is
# wired to a server thread through an in-memory Socket.pair, so the tests run
# in sandboxes that forbid bind(2). The server requires a client certificate
# and the response body carries the SHA-256 fingerprint of the certificate it
# observed during the handshake, proving which identity reached SSL.
class TestNetHTTPIdentityConnectionTLS < Test::Unit::TestCase
  CA_KEY, CA_CERT = IdentityTestPKI.generate_ca
  SERVER_KEY, SERVER_CERT = IdentityTestPKI.generate_server(CA_KEY, CA_CERT)
  ALICE_KEY, ALICE_CERT = IdentityTestPKI.generate_identity(CA_KEY, CA_CERT, "alice", 101)
  BOB_KEY, BOB_CERT = IdentityTestPKI.generate_identity(CA_KEY, CA_CERT, "bob", 102)
  ROTATED_KEY, ROTATED_CERT = IdentityTestPKI.generate_identity(CA_KEY, CA_CERT, "alice", 202)

  # Net::HTTP that dials an in-memory socket pair instead of opening a TCP
  # socket. The pair is AF_UNIX, where TCP_NODELAY is not defined, so the
  # raw socket ignores that one setsockopt call.
  def http_class(server_context)
    dial = method(:socket_pair)
    Class.new(Net::HTTP) do
      define_method(:timeouted_connect) do |_addr, _port|
        client_raw, server_raw = dial.call
        client_raw.define_singleton_method(:setsockopt) { |*| }
        Thread.new do
          ssl = OpenSSL::SSL::SSLSocket.new(server_raw, server_context)
          begin
            ssl.accept
            ssl.gets("\r\n\r\n")
            fingerprint = OpenSSL::Digest::SHA256.hexdigest(ssl.peer_cert.to_der)
            ssl.write("HTTP/1.1 200 OK\r\nContent-Length: #{fingerprint.bytesize}\r\n" \
                      "Connection: close\r\n\r\n#{fingerprint}")
          rescue OpenSSL::SSL::SSLError
            # expected when a client presents no (or an untrusted) certificate
          ensure
            ssl.close
          end
        end
        client_raw
      end
    end
  end

  def socket_pair
    Socket.pair(Socket::AF_UNIX, Socket::SOCK_STREAM, 0)
  end

  def server_context
    context = OpenSSL::SSL::SSLContext.new
    context.cert = SERVER_CERT
    context.key = SERVER_KEY
    context.verify_mode = OpenSSL::SSL::VERIFY_PEER | OpenSSL::SSL::VERIFY_FAIL_IF_NO_PEER_CERT
    store = OpenSSL::X509::Store.new.tap { |s| s.add_cert(CA_CERT) }
    context.cert_store = store
    context.client_ca = [CA_CERT]
    context
  end

  def builder
    store = OpenSSL::X509::Store.new.tap { |s| s.add_cert(CA_CERT) }
    klass = http_class(server_context)
    Net::HTTP::IdentityConnection.new("localhost", 443, cert_store: store).tap do |b|
      b.define_singleton_method(:connection) do |name, options = {}|
        id = identity(name)
        http = klass.new(@address, @port)
        http.verify_hostname = false
        id.apply!(http)
        http.cert_store = store
        http
      end
    end
  end

  def identity(key, cert, approved = cert)
    Net::HTTP::ClientIdentity.new(cert, key, approved)
  end

  def fingerprint(cert)
    OpenSSL::Digest::SHA256.hexdigest(cert.to_der)
  end

  def test_handshake_presents_the_selected_identity
    b = builder
    b.register(:alice, identity(ALICE_KEY, ALICE_CERT))
    b.start(:alice) do |http|
      response = http.get("/")
      assert_equal fingerprint(ALICE_CERT), response.body
      assert_equal SERVER_CERT.to_der, http.peer_cert.to_der
    end
  end

  def test_parallel_connections_present_two_identities
    b = builder
    b.register(:alice, identity(ALICE_KEY, ALICE_CERT))
    b.register(:bob, identity(BOB_KEY, BOB_CERT))

    results = {}
    threads = [:alice, :bob].map do |name|
      Thread.new do
        b.start(name) { |http| results[name] = http.get("/").body }
      end
    end
    threads.each(&:join)

    assert_equal fingerprint(ALICE_CERT), results[:alice]
    assert_equal fingerprint(BOB_CERT), results[:bob]
  end

  def test_rotated_certificate_is_presented_on_new_connection
    b = builder
    b.register(:alice, identity(ALICE_KEY, ALICE_CERT))
    b.start(:alice) do |http|
      assert_equal fingerprint(ALICE_CERT), http.get("/").body
    end

    b.register(:alice, identity(ROTATED_KEY, ROTATED_CERT))
    b.start(:alice) do |http|
      assert_equal fingerprint(ROTATED_CERT), http.get("/").body
    end
  end

  def test_server_rejects_connection_without_a_client_certificate
    store = OpenSSL::X509::Store.new.tap { |s| s.add_cert(CA_CERT) }
    http = http_class(server_context).new("localhost", 443)
    http.use_ssl = true
    http.cert_store = store
    http.verify_hostname = false
    assert_raise(OpenSSL::SSL::SSLError) { http.get("/") }
  end
end
