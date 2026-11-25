# frozen_string_literal: true

require "net/ftp"
require "stringio"
require "socket"
require "test/unit"

class DualChannelCertificatePolicyTest < Test::Unit::TestCase
  class MemoryTLS
    attr_reader :peer_cert

    def initialize(io, peer_cert)
      @io = io
      @peer_cert = peer_cert
      @sync_close = true
    end

    def sync_close=(value)
      @sync_close = value
    end

    def stop
      @io.shutdown(Socket::SHUT_WR)
    rescue Errno::ENOTCONN, IOError
      nil
    end

    def method_missing(name, *args, **kwargs, &block)
      @io.public_send(name, *args, **kwargs, &block)
    end

    def respond_to_missing?(name, include_private = false)
      @io.respond_to?(name, include_private) || super
    end
  end

  class MemorySession
    attr_reader :ftp, :commands, :sent_replies, :uploads, :server_error,
                :current_plan

    def initialize(policy:, control_cert:, final_replies:, automatic: false)
      @control_server, control_client = Socket.pair(Socket::AF_UNIX, Socket::SOCK_STREAM)
      control_client.define_singleton_method(:remote_address) do
        Addrinfo.tcp("127.0.0.1", 21)
      end
      @commands = []
      @sent_replies = []
      @uploads = []
      @plans = []
      @opened = 0
      @final_replies = final_replies.dup
      @server_error = nil

      @ftp = Net::FTP.new(
        nil,
        ssl: {verify_mode: OpenSSL::SSL::VERIFY_NONE},
        passive: true,
        use_pasv_ip: true,
        read_timeout: 2,
        certificate_policy: policy,
        failed_transfer_control_reply: automatic ? :automatic : :manual
      )
      @ftp.instance_variable_set(:@bare_sock, control_client)
      @ftp.set_socket(
        Net::FTP::BufferedSocket.new(control_client, read_timeout: 2),
        false
      )
      @ftp.instance_variable_set(:@logged_in, true)
      @ftp.instance_variable_set(:@control_certificate, control_cert)

      session = self
      @ftp.define_singleton_method(:open_socket) do |_host, _port|
        session.next_data_client
      end
      @ftp.define_singleton_method(:start_tls_session) do |raw_socket|
        if session.current_plan[:handshake_error]
          raise OpenSSL::SSL::SSLError, "simulated data TLS failure"
        end
        MemoryTLS.new(raw_socket, session.current_data_cert)
      end

      @thread = Thread.new { run_control_server }
    end

    def prepare_data(cert, handshake_error: false)
      client, server = Socket.pair(Socket::AF_UNIX, Socket::SOCK_STREAM)
      plan = {
        cert: cert,
        client: client,
        server: server,
        handshake_error: handshake_error,
      }
      @plans << plan
      plan
    end

    def next_data_client
      plan = @plans[@opened]
      raise "unexpected data connection" unless plan
      @opened += 1
      @current_plan = plan
      plan[:client]
    end

    def current_data_cert
      @current_plan[:cert]
    end

    def serve_download(plan, payload)
      Thread.new do
        plan[:server].write(payload)
      ensure
        plan[:server].close
      end
    end

    def read_upload(plan)
      Thread.new do
        @uploads << plan[:server].read
      rescue EOFError, IOError
        @uploads << ""
      ensure
        plan[:server].close rescue nil
      end
    end

    def close
      @ftp.close rescue nil
      @control_server.close rescue nil
      @thread&.join(2)
      @plans.each do |plan|
        plan[:client].close unless plan[:client].closed?
        plan[:server].close unless plan[:server].closed?
      end
    end

    private

    def run_control_server
      loop do
        command_line = @control_server.gets
        break if command_line.nil?

        command = command_line.strip
        @commands << command

        case command
        when /\APASV/
          reply("227 Entering Passive Mode (127,0,0,1,0,0).\r\n")
        when /\A(?:RETR|STOR)/
          reply("150 Ready for in-memory transfer.\r\n")
          final_reply = @final_replies.shift || "226 Complete.\r\n"
          sleep 0.01
          reply(final_reply)
        when /\ANOOP/
          reply("200 NOOP complete.\r\n")
        when /\AQUIT/
          reply("221 Goodbye.\r\n")
          break
        else
          reply("200 OK.\r\n")
        end
      end
    rescue StandardError => error
      @server_error = error
    ensure
      @control_server.close rescue nil
    end

    def reply(text)
      @sent_replies << text.strip
      @control_server.write(text)
    end
  end

  def setup
    unless defined?(OpenSSL::X509::Certificate)
      omit "OpenSSL X509 is not available"
    end
    @control_cert = generate_certificate("control.example.test")
    @gateway_cert = generate_certificate("data-gateway.example.test")
    @rogue_cert = generate_certificate("unapproved.example.test")
    @sessions = []
  end

  def teardown
    @sessions&.each(&:close)
  end

  def test_same_certificate_deployment_verifies_every_download
    policy = Net::FTP::CertificatePolicy.new(relation: :same_certificate)
    session = start_session(policy, ["226 Download complete.\r\n"])
    plan = session.prepare_data(@control_cert)
    reader = session.serve_download(plan, "same-cert-data")

    chunks = []
    result = session.ftp.retrbinary("RETR managed/file.bin", 4) do |chunk|
      chunks << chunk
    end

    assert_nil(result)
    assert_equal("same-cert-data", chunks.join)
    assert_equal(%w[same -cer t-da ta], chunks)
    assert_equal(:same_certificate,
                 session.ftp.last_certificate_verification.matched_by)
    assert_equal(1, session.commands.grep(/\APASV/).size)
    assert_equal("RETR managed/file.bin", session.commands.grep(/\ARETR/).first)
    assert join_thread(reader)
  end

  def test_approved_different_gateway_certificate_deployment
    policy = Net::FTP::CertificatePolicy.new(
      relation: :approved_certificate,
      approved_data_certificates: [@gateway_cert]
    )
    session = start_session(policy, ["226 Upload complete.\r\n"])
    plan = session.prepare_data(@gateway_cert)
    reader = session.read_upload(plan)

    chunks = []
    payload = "gateway-upload"
    session.ftp.storbinary("STOR via-gateway.bin", StringIO.new(payload), 4) do |chunk|
      chunks << chunk
    end

    assert_equal(%w[gate way- uplo ad], chunks)
    assert join_thread(reader)
    assert_equal(payload.b, session.uploads.last)
    assert_equal(:certificate,
                 session.ftp.last_certificate_verification.matched_by)
  end

  def test_three_calls_record_data_replies_failure_state_and_recovery
    policy = Net::FTP::CertificatePolicy.new(
      relation: :same_or_approved,
      approved_data_certificates: [@gateway_cert]
    )
    session = start_session(policy, [
      "226 Download complete.\r\n",
      "226 Upload complete.\r\n",
      "425 Data certificate rejected by policy.\r\n",
    ])

    download_plan = session.prepare_data(@control_cert)
    download_thread = session.serve_download(download_plan, "DL-DATA!")
    download_chunks = []
    session.ftp.retrbinary("RETR approved-download.bin", 4) do |chunk|
      download_chunks << chunk
    end

    upload_plan = session.prepare_data(@gateway_cert)
    upload_thread = session.read_upload(upload_plan)
    upload_chunks = []
    upload_payload = "UPLOAD!"
    session.ftp.storbinary(
      "STOR gateway-upload.bin",
      StringIO.new(upload_payload),
      4
    ) { |chunk| upload_chunks << chunk }

    rejected_plan = session.prepare_data(@rogue_cert)
    rejected_reader = session.read_upload(rejected_plan)
    rejected_chunks = []
    error = assert_raise(Net::FTP::DataChannelCertificateError) do
      session.ftp.storbinary(
        "STOR rejected-third.bin",
        StringIO.new("must-not-be-sent"),
        4
      ) { |chunk| rejected_chunks << chunk }
    end

    assert join_thread(download_thread)
    assert join_thread(upload_thread)
    assert join_thread(rejected_reader)

    assert_equal(%w[DL-D ATA!], download_chunks)
    assert_equal(%w[UPLO AD!], upload_chunks)
    assert_equal(upload_payload.b, session.uploads[0])
    assert_equal("", session.uploads[1])
    assert_empty(rejected_chunks)

    assert_equal(:data, error.channel)
    assert_equal(:unapproved_data_certificate, error.verification.reason)
    assert_match(/\A150 /, error.preliminary_response)
    assert_match(/\A150 /, session.ftp.last_response)
    refute_predicate(error, :control_reply_finished?)
    refute_predicate(error, :reusable?)
    refute_predicate(session.ftp, :control_reply_finished?)
    refute_predicate(session.ftp, :connection_reusable?)

    outcome = error.recover_control_reply
    assert_predicate(outcome, :finished?)
    assert_kind_of(Net::FTPTempError, outcome.error)
    assert_match(/\A425 /, outcome.response)
    assert_predicate(outcome, :reusable?)
    assert_predicate(error, :control_reply_finished?)
    assert_predicate(error, :reusable?)
    assert_predicate(session.ftp, :control_reply_finished?)
    assert_predicate(session.ftp, :connection_reusable?)

    assert_nothing_raised do
      session.ftp.noop
    end
    assert_match(/\A200 /, session.ftp.last_response)

    assert_equal(3, session.ftp.certificate_verifications.size)
    assert_predicate(session.ftp.certificate_verifications[0], :approved?)
    assert_equal(:same_certificate,
                 session.ftp.certificate_verifications[0].matched_by)
    assert_predicate(session.ftp.certificate_verifications[1], :approved?)
    assert_equal(:certificate,
                 session.ftp.certificate_verifications[1].matched_by)
    assert_predicate(session.ftp.certificate_verifications[2], :rejected?)

    assert_equal(3, session.commands.grep(/\APASV/).size)
    assert_equal([
      "RETR approved-download.bin",
      "STOR gateway-upload.bin",
      "STOR rejected-third.bin",
    ], session.commands.grep(/\A(?:RETR|STOR)/))
    assert_includes(session.commands, "NOOP")
    assert_equal(3, session.sent_replies.grep(/\A150 /).size)
    assert_equal(2, session.sent_replies.grep(/\A226 /).size)
    assert_equal(1, session.sent_replies.grep(/\A425 /).size)
    assert_equal(1, session.sent_replies.grep(/\A200 NOOP/).size)
    assert_nil(session.server_error)
  end

  def test_automatic_recovery_makes_failed_session_immediately_usable
    policy = Net::FTP::CertificatePolicy.new(relation: :same_certificate)
    session = start_session(
      policy,
      ["425 Data TLS failed.\r\n", "200 NOOP complete.\r\n"],
      automatic: true
    )
    plan = session.prepare_data(@rogue_cert)
    reader = session.read_upload(plan)

    error = assert_raise(Net::FTP::DataChannelCertificateError) do
      session.ftp.storbinary("STOR bad.bin", StringIO.new("x"), 1)
    end

    assert join_thread(reader)
    assert_predicate(error, :control_reply_finished?)
    assert_kind_of(Net::FTPTempError, error.control_reply_error)
    assert_predicate(error, :reusable?)
    assert_predicate(session.ftp, :connection_reusable?)
    assert_nothing_raised { session.ftp.noop }
    assert_match(/\A200 /, session.ftp.last_response)
  end

  def test_original_handshake_error_keeps_control_state_observable
    policy = Net::FTP::CertificatePolicy.new(relation: :same_certificate)
    session = start_session(policy, [
      "425 Cannot open data connection.\r\n",
      "200 NOOP complete.\r\n",
    ])
    session.prepare_data(@control_cert, handshake_error: true)

    error = assert_raise(OpenSSL::SSL::SSLError) do
      session.ftp.retrbinary("RETR handshake-failure.bin", 4) { |_chunk| }
    end

    assert_equal(:data, error.channel)
    assert_match(/\A150 /, error.preliminary_response)
    refute_predicate(error, :control_reply_finished?)
    refute_predicate(error, :reusable?)

    outcome = error.recover_control_reply
    assert_kind_of(Net::FTPTempError, outcome.error)
    assert_match(/\A425 /, outcome.response)
    assert_predicate(error, :control_reply_finished?)
    assert_predicate(error, :reusable?)

    assert_nothing_raised { session.ftp.noop }
    assert_match(/\A200 /, session.ftp.last_response)
  end

  def test_fingerprint_allowlist_and_custom_verifier_are_supported
    fingerprint = OpenSSL::Digest::SHA256.hexdigest(@gateway_cert.to_der)
    policy = Net::FTP::CertificatePolicy.new(
      relation: :approved_certificate,
      approved_fingerprints: [fingerprint]
    )

    assert policy.approved?(
      control_certificate: @control_cert,
      data_certificate: @gateway_cert
    )

    seen = []
    custom = Net::FTP::CertificatePolicy.new do |control, data|
      seen << [control, data]
      data == @gateway_cert
    end
    verification = custom.verify(
      control_certificate: @control_cert,
      data_certificate: @gateway_cert
    )
    assert_predicate(verification, :approved?)
    assert_equal([[@control_cert, @gateway_cert]], seen)
  end

  private

  def start_session(policy, final_replies, automatic: false)
    MemorySession.new(
      policy: policy,
      control_cert: @control_cert,
      final_replies: final_replies,
      automatic: automatic
    ).tap { |session| @sessions << session }
  end

  def generate_certificate(common_name)
    key = OpenSSL::PKey::RSA.new(2048)
    name = OpenSSL::X509::Name.new([["CN", common_name]])
    certificate = OpenSSL::X509::Certificate.new
    certificate.version = 2
    certificate.serial = rand(1..1_000_000_000)
    certificate.subject = name
    certificate.issuer = name
    certificate.public_key = key.public_key
    certificate.not_before = Time.now.utc - 60
    certificate.not_after = Time.now.utc + 3600
    certificate.sign(key, OpenSSL::Digest.new("SHA256"))
    certificate
  end

  def join_thread(thread)
    thread.join(2)
    !thread.alive?
  end
end
