# frozen_string_literal: true

require "net/ftp"
require "test/unit"
require "socket"
require "timeout"

class FTPCredentialRotationTest < Test::Unit::TestCase
  CredentialMaterial = Struct.new(:id, :certificate, :private_key)

  # Address objects good enough for Net::FTP's PASV/PORT handling.
  LocalAddress = Struct.new(:ip_address) do
    def ipv4?
      true
    end

    def ipv6?
      false
    end
  end

  # Wraps a local socket pair endpoint so Net::FTP sees a plausible IPv4
  # peer.  Only the fake transport uses this; no TCP listener is opened.
  class FakeIO
    def initialize(io)
      @io = io
    end

    def remote_address
      LocalAddress.new("127.0.0.1")
    end

    def local_address
      LocalAddress.new("127.0.0.1")
    end

    def to_io
      @io
    end

    def method_missing(name, *args, **kwargs, &block)
      @io.__send__(name, *args, **kwargs, &block)
    end

    def respond_to_missing?(name, include_private = false)
      @io.respond_to?(name, include_private)
    end
  end

  class FakeTLSSocket < FakeIO
    def stop
      @io.close_write rescue nil
    end

    def post_connection_check(_host)
      true
    end
  end

  Handshake = Struct.new(:certificate_id, :certificate_subject,
                         :session_id, :host, :context_has_key,
                         keyword_init: true)

  # Records the order of connections and TLS handshakes, and hands the
  # server side of each socket pair to a scripted test thread.
  class FakeTransport
    attr_reader :handshakes, :opened

    def initialize
      @handshakes = []
      @opened = []
      @servers = Queue.new
    end

    def open(host, port, timeout: nil)
      client, server = Socket.pair(:UNIX, :STREAM, 0)
      @opened << [host, port]
      @servers << server
      FakeIO.new(client)
    end

    def next_server
      @servers.pop
    end

    def start_tls(io, context, host:, timeout: nil, session: nil,
                  credential: nil)
      certificate = context.cert
      @handshakes << Handshake.new(
        certificate_id: credential && credential.identifier,
        certificate_subject: certificate && certificate.subject.to_s,
        session_id: session && session.session_id,
        host: host,
        context_has_key: !context.key.nil?,
      )
      FakeTLSSocket.new(io)
    end
  end

  # A scripted FTP server over a socket pair.  It speaks plain text even on
  # the "TLS" connection because FakeTransport never encrypts.
  class ScriptedServer
    def initialize(io, transport)
      @io = io
      @transport = transport
    end

    def greeting
      @io.write("220 fake archive ready\r\n")
    end

    def expect(cmd)
      line = @io.gets
      unless line == cmd
        raise "expected #{cmd.inspect}, got #{line.inspect}"
      end
      line
    end

    def reply(line)
      @io.write(line + "\r\n")
    end

    def tls_setup
      expect("AUTH TLS\r\n")
      reply("234 AUTH accepted")
      expect("PBSZ 0\r\n")
      reply("200 PBSZ ok")
      expect("PROT P\r\n")
      reply("200 PROT ok")
    end

    def login
      expect("USER archive\r\n")
      reply("331 password required")
      expect("PASS secret\r\n")
      reply("230 logged in")
      expect("TYPE I\r\n")
      reply("200 binary")
    end

    def pasv
      expect("PASV\r\n")
      reply("227 Entering Passive Mode (127,0,0,1,200,1)")
      @transport.next_server
    end

    def close
      @io.close rescue nil
    end
  end

  def setup
    @threads = []
  end

  def teardown
    @threads.each do |t|
      t.join(2)
      t.kill if t.alive?
    end
  end

  def credential(id)
    key = OpenSSL::PKey::EC.generate("prime256v1")
    cert = OpenSSL::X509::Certificate.new
    cert.version = 2
    cert.serial = rand(1..100_000)
    cert.subject = OpenSSL::X509::Name.parse("/CN=archive-#{id}")
    cert.issuer = cert.subject
    cert.public_key = key
    cert.not_before = Time.now - 60
    cert.not_after = Time.now + 3600
    cert.sign(key, OpenSSL::Digest::SHA256.new)
    CredentialMaterial.new(id, cert, key)
  end

  def new_ftp(transport, initial)
    Net::FTP.new(
      nil,
      ssl: { verify_mode: OpenSSL::SSL::VERIFY_NONE },
      transport: transport,
      client_credential: {
        certificate: initial.certificate,
        private_key: initial.private_key,
      },
      certificate_id: initial.id,
    )
  end

  def spawn_server(transport, &block)
    thread = Thread.new do
      io = transport.next_server
      server = ScriptedServer.new(io, transport)
      begin
        block.call(server)
      ensure
        server.close
      end
    end
    @threads << thread
    thread
  end

  # One connection with TLS setup and login, used for plain handshake tests.
  def script_connect(transport)
    spawn_server(transport) do |server|
      server.greeting
      server.tls_setup
      server.login
    end
  end

  def connect_and_login(ftp)
    ftp.connect("archive.test", 2121)
    ftp.login("archive", "secret")
  end

  # An in-flight transfer keeps the old generation, finishes under it, and
  # the next control connection consumes the pending rotation.
  def test_in_flight_transfer_keeps_old_certificate_and_next_connect_uses_new
    old_cred = credential("old")
    new_cred = credential("new")
    transport = FakeTransport.new
    ftp = new_ftp(transport, old_cred)

    script_connect(transport)
    connect_and_login(ftp)
    assert_equal("old", ftp.connection_certificate_id)
    assert_equal("old", transport.handshakes.last.certificate_id)
    assert_equal("/CN=archive-old", transport.handshakes.last.certificate_subject)
    assert_equal(true, transport.handshakes.last.context_has_key)
    assert_equal("old", ftp.last_handshake[:certificate_id])
    assert_equal(:control, ftp.last_handshake[:purpose])
    assert_equal(["old"], transport.handshakes.map(&:certificate_id))
    ftp.close

    rotate_receipt = nil
    transfer_bytes = "ABCDEFGH"
    spawn_server(transport) do |server|
      server.greeting
      server.tls_setup
      server.login
      data = server.pasv
      server.expect("RETR payload\r\n")
      server.reply("150 opening data connection")
      data.write(transfer_bytes[0, 4])
      data.flush
      # Wait until the client has asked for the rotation mid-transfer.
      Timeout.timeout(5) { sleep 0.01 until rotate_receipt }
      data.write(transfer_bytes[4, 4])
      data.flush
      data.close_write
      server.reply("226 transfer complete")
    end
    connect_and_login(ftp)

    chunks = []
    ftp.retrbinary("RETR payload", 4) do |chunk|
      chunks << chunk
      if chunks.size == 1
        rotate_receipt = ftp.rotate_client_credential(
          certificate: new_cred.certificate,
          private_key: new_cred.private_key,
          identifier: "new",
        )
        # Still not applied: the transfer owns the old generation.
        assert_equal("old", ftp.active_certificate_id)
        assert_equal(true, rotate_receipt.pending?)
        assert_equal("new", rotate_receipt.certificate_id)
        assert_equal("old", rotate_receipt.previous_certificate_id)
        generations = ftp.credential_generations
        assert_equal(%w[old new], generations.map { |g| g[:certificate_id] })
        assert_equal([true, false], generations.map { |g| g[:in_use] })
        assert_equal(["xfer-0001", "old"],
                     [ftp.in_flight_transfers[0][:transfer_id],
                      ftp.in_flight_transfers[0][:certificate_id]])

        # A control connection attempt while the transfer is paused must not
        # silently adopt the new identity.
        credential, rotation, rotation_id =
          ftp.send(:select_credential_for_connect)
        assert_equal("old", credential.identifier)
        assert_nil(rotation)
        assert_nil(rotation_id)
        assert_equal("old", ftp.active_certificate_id)
      end
    end

    assert_equal(transfer_bytes, chunks.join)
    records = ftp.transfer_records
    assert_equal(1, records.size)
    assert_equal("old", records[0][:certificate_id])
    assert_equal(:completed, records[0][:status])
    # The data-connection handshake was also pinned to the old generation.
    data_handshake = ftp.credential_audit_log.reverse.find { |entry|
      entry[:event] == :handshake && entry[:purpose] == :data
    }
    assert_equal("old", data_handshake[:certificate_id])
    # Handshake order proves the data connection stayed on the old
    # generation while the rotation was pending.
    assert_equal(%w[old old old],
                 transport.handshakes.map(&:certificate_id))
    assert_equal(true, rotate_receipt.pending?)
    assert_nil(ftp.connection_rotation_id)
    ftp.close

    # Next connection: handshake uses the approved material.
    script_connect(transport)
    connect_and_login(ftp)
    assert_equal("new", ftp.connection_certificate_id)
    assert_equal("new", ftp.active_certificate_id)
    assert_equal("new", transport.handshakes.last.certificate_id)
    assert_equal("/CN=archive-new",
                 transport.handshakes.last.certificate_subject)
    assert_equal(%w[old old old new],
                 transport.handshakes.map(&:certificate_id))
    assert_equal("rot-0001", ftp.connection_rotation_id)
    assert_equal("new", ftp.last_handshake[:certificate_id])
    assert_equal("rot-0001", ftp.last_handshake[:rotation_id])
    assert_equal(:active, ftp.credential_rotation_receipt(rotate_receipt).state)
    assert_equal(["new"],
                 ftp.credential_generations.map { |g| g[:certificate_id] })
    ftp.close
  end

  # A rotation can be cancelled before any connection consumes it; the old
  # identity remains, and the approved material is dropped.
  def test_cancelled_rotation_keeps_old_certificate
    old_cred = credential("old")
    new_cred = credential("new")
    transport = FakeTransport.new
    ftp = new_ftp(transport, old_cred)

    script_connect(transport)
    connect_and_login(ftp)
    ftp.close

    receipt = ftp.rotate_client_credential(
      certificate: new_cred.certificate,
      private_key: new_cred.private_key,
      identifier: "new",
    )
    assert_equal(:pending, receipt.state)
    assert_equal("old", ftp.active_certificate_id)
    assert_equal(%w[old new],
                 ftp.credential_generations.map { |g| g[:certificate_id] })

    # The named entry point returns a receipt; a second pending rotation is
    # rejected while this one waits.
    assert_raise(Net::FTP::CredentialRotationError) do
      ftp.update_client_credential(
        certificate: new_cred.certificate,
        private_key: new_cred.private_key,
        identifier: "new",
      )
    end

    cancelled = ftp.cancel_credential_rotation(receipt)
    assert_equal(:cancelled, cancelled.state)
    assert_equal(:cancelled,
                 ftp.credential_rotation_receipt("rot-0001").state)
    assert_equal(["old"],
                 ftp.credential_generations.map { |g| g[:certificate_id] })

    script_connect(transport)
    connect_and_login(ftp)
    assert_equal("old", ftp.connection_certificate_id)
    assert_equal("old", ftp.active_certificate_id)
    assert_equal("old", transport.handshakes.last.certificate_id)
    assert_nil(ftp.connection_rotation_id)
    ftp.close

    # An activated rotation can no longer be cancelled.
    receipt2 = ftp.rotate_client_credential(
      certificate: new_cred.certificate,
      private_key: new_cred.private_key,
      identifier: "new",
    )
    script_connect(transport)
    connect_and_login(ftp)
    assert_equal("new", ftp.connection_certificate_id)
    assert_raise(Net::FTP::CredentialRotationError) do
      ftp.cancel_credential_rotation(receipt2)
    end
    ftp.close
  end

  # Cross-identity TLS session resumption is refused, and receipts expose
  # identifiers only, never private key material.
  def test_handshake_does_not_reuse_session_across_generations_and_receipt_is_safe
    old_cred = credential("old")
    new_cred = credential("new")
    transport = FakeTransport.new
    ftp = new_ftp(transport, old_cred)

    fake_session = Struct.new(:session_id, :time, :timeout).new("session-old",
                                                               Time.now,
                                                               300)
    ftp.instance_variable_set(:@ssl_session, fake_session)
    ftp.instance_variable_set(:@ssl_session_credential_id, "old")

    receipt = ftp.rotate_client_credential(
      certificate: new_cred.certificate,
      private_key: new_cred.private_key,
      identifier: "new",
    )
    script_connect(transport)
    connect_and_login(ftp)
    # New identity must not resume the old identity's session.
    assert_nil(transport.handshakes.last.session_id)
    assert_equal("new", ftp.connection_certificate_id)
    ftp.close

    receipt_hash = receipt.to_h
    assert_equal("new", receipt_hash[:certificate_id])
    assert_equal("old", receipt_hash[:previous_certificate_id])
    refute(receipt_hash.key?(:private_key))
    refute(receipt_hash.key?(:key))
    refute_match(/BEGIN .*PRIVATE KEY/, receipt.inspect)
    refute_match(/BEGIN .*PRIVATE KEY/, receipt.to_h.inspect)

    ftp.credential_audit_log.each do |entry|
      refute(entry.key?(:private_key))
      entry.each_value do |value|
        next unless value.is_a?(String)
        refute_match(/BEGIN .*PRIVATE KEY/, value)
      end
    end
    generation_hashes = ftp.credential_generations
    generation_hashes.each do |generation|
      refute(generation.key?(:private_key))
      refute(generation.key?(:key))
    end
  end

  # TLS handshake failures must not consume a pending rotation.
  def test_failed_handshake_does_not_activate_rotation
    old_cred = credential("old")
    new_cred = credential("new")
    transport = FakeTransport.new
    ftp = new_ftp(transport, old_cred)

    script_connect(transport)
    connect_and_login(ftp)
    ftp.close

    receipt = ftp.rotate_client_credential(
      certificate: new_cred.certificate,
      private_key: new_cred.private_key,
      identifier: "new",
    )

    # Server rejects AUTH TLS; connect raises before any handshake.
    spawn_server(transport) do |server|
      server.greeting
      server.expect("AUTH TLS\r\n")
      server.reply("534 TLS not available")
    end
    assert_raise(Net::FTPPermError) do
      ftp.connect("archive.test", 2121)
    end

    assert_equal(:pending, receipt.state)
    assert_equal("old", ftp.active_certificate_id)
    assert_nil(ftp.connection_certificate_id)
    assert_nil(ftp.connection_rotation_id)
    assert_equal(%w[old new],
                 ftp.credential_generations.map { |g| g[:certificate_id] })
  end

  # Rotating without TLS, or to the active identifier, is rejected.
  def test_rotation_validation
    old_cred = credential("old")
    transport = FakeTransport.new
    plain = Net::FTP.new(nil, transport: transport)
    assert_raise(Net::FTP::CredentialRotationError) do
      plain.rotate_client_credential(
        certificate: old_cred.certificate,
        private_key: old_cred.private_key,
        identifier: "old",
      )
    end

    ftp = new_ftp(transport, old_cred)
    assert_raise(Net::FTP::CredentialRotationError) do
      ftp.rotate_client_credential(
        certificate: old_cred.certificate,
        private_key: old_cred.private_key,
        identifier: "old",
      )
    end

    # A credential whose key does not match its certificate is rejected.
    other = credential("other")
    assert_raise(ArgumentError) do
      Net::FTP::ClientCredential.new(old_cred.certificate, other.private_key)
    end

    # A credential supplied without ssl is rejected at construction time.
    assert_raise(ArgumentError) do
      Net::FTP.new(nil,
                   client_credential: {
                     certificate: old_cred.certificate,
                     private_key: old_cred.private_key,
                   },
                   certificate_id: "old")
    end
  end
end
