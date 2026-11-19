require 'common'
require 'ostruct'
require 'net/ssh/authentication/methods/publickey'
require 'net/ssh/authentication/certificate'
require 'net/ssh/transport/algorithms'

module Authentication
  module Methods
    # Handshake-level regression tests for RSA publickey authentication.
    #
    # A real Publickey method is driven against a recording fake transport and
    # a recording fake key manager, so every attempt can be checked end to
    # end: the offered key blob, the requested algorithm, the algorithm passed
    # to the signer, the signed bytes (session id included) and the server's
    # USERAUTH_PK_OK reply must all describe the same attempt. No external
    # ssh(1) and no on-disk private keys are involved.
    class TestPublickeyHandshake < NetSSHTest
      include Net::SSH::Authentication::Constants

      SESSION_ID = "handshake-session-id-\x00\x01\xFE".dup.force_encoding(Encoding::BINARY).freeze

      # Records every USERAUTH_REQUEST the client sends and answers through a
      # scripted server handler.
      class FakeTransport
        attr_reader :requests
        attr_accessor :server_version

        def initialize(pubkey_algorithms:, server_sig_algs: nil,
                       server_version: "SSH-2.0-OpenSSH_9.9", &handler)
          @pubkey_algorithms = pubkey_algorithms
          @server_sig_algs = server_sig_algs
          @server_version = OpenStruct.new(version: server_version)
          @handler = handler
          @requests = []
          @replies = []
        end

        attr_reader :pubkey_algorithms, :server_sig_algs

        def algorithms
          OpenStruct.new(session_id: SESSION_ID)
        end

        def send_message(message)
          raw = message.to_s
          @requests << raw
          @handler.call(self, raw)
        end

        def reply(type, *args)
          @replies << Net::SSH::Packet.new(Net::SSH::Buffer.from(:byte, type, *args))
        end

        def next_message
          @replies.shift or raise "fake server queued no reply"
        end
      end

      # Yields the configured identities and records every signing request,
      # capturing the exact bytes to be signed and the requested algorithm.
      class FakeKeyManager
        attr_reader :sign_calls

        def initialize(identities, signature_algorithm: nil)
          @identities = identities
          @signature_algorithm = signature_algorithm
          @sign_calls = []
        end

        def each_identity(&block)
          @identities.each(&block)
        end

        def sign(identity, data, sig_alg = nil)
          @sign_calls << { identity: identity, data: data.to_s, algorithm: sig_alg }
          declared = @signature_algorithm || sig_alg || identity.ssh_type
          Net::SSH::Buffer.from(:string, declared, :string, "fake-signature").to_s
        end
      end

      class FakeSession
        attr_reader :transport

        def initialize(transport)
          @transport = transport
        end

        def logger
          nil
        end

        def next_message
          transport.next_message
        end
      end

      # Parsed view of one USERAUTH_REQUEST packet.
      AuthRequest = Struct.new(:username, :service, :method, :has_signature,
                               :algorithm, :blob, :signature) do
        def blob_type
          Net::SSH::Buffer.new(blob).read_string
        end

        def signature_algorithm
          Net::SSH::Buffer.new(signature).read_string
        end
      end

      def test_rsa_sha2_512_handshake_binds_blob_algorithms_and_signature_to_one_attempt
        transport, key_manager = handshake(
          identities: [rsa_one],
          server_sig_algs: %w[rsa-sha2-512 rsa-sha2-256],
          &accepting_server
        )

        assert authenticate(transport, key_manager)
        assert_equal 2, transport.requests.size

        offer, signed = transport.requests.map { |packet| parse_auth_request(packet) }
        assert_equal "rsa-sha2-512", offer.algorithm
        assert_equal "ssh-rsa", offer.blob_type
        assert_equal rsa_one.to_blob, offer.blob
        assert_equal false, offer.has_signature

        assert_equal "rsa-sha2-512", signed.algorithm
        assert_equal rsa_one.to_blob, signed.blob
        assert_equal true, signed.has_signature
        assert_equal "rsa-sha2-512", signed.signature_algorithm

        assert_equal 1, key_manager.sign_calls.size
        sign_call = key_manager.sign_calls.first
        assert_same rsa_one, sign_call[:identity]
        assert_equal "rsa-sha2-512", sign_call[:algorithm]
        assert_signed_data(sign_call[:data], "rsa-sha2-512", rsa_one.to_blob)
      end

      def test_rsa_sha2_256_handshake_binds_blob_algorithms_and_signature_to_one_attempt
        transport, key_manager = handshake(
          identities: [rsa_one],
          server_sig_algs: %w[rsa-sha2-256],
          &accepting_server
        )

        assert authenticate(transport, key_manager)

        offer, signed = transport.requests.map { |packet| parse_auth_request(packet) }
        assert_equal "rsa-sha2-256", offer.algorithm
        assert_equal rsa_one.to_blob, offer.blob
        assert_equal "rsa-sha2-256", signed.algorithm
        assert_equal rsa_one.to_blob, signed.blob
        assert_equal "rsa-sha2-256", signed.signature_algorithm

        sign_call = key_manager.sign_calls.first
        assert_equal "rsa-sha2-256", sign_call[:algorithm]
        assert_signed_data(sign_call[:data], "rsa-sha2-256", rsa_one.to_blob)
      end

      def test_rsa_cert_handshake_uses_cert_algorithm_cert_blob_and_raw_signature_algorithm
        transport, key_manager = handshake(
          identities: [rsa_cert],
          server_sig_algs: %w[rsa-sha2-256],
          &accepting_server
        )

        assert authenticate(transport, key_manager)

        offer, signed = transport.requests.map { |packet| parse_auth_request(packet) }
        [offer, signed].each do |request|
          assert_equal "rsa-sha2-256-cert-v01@openssh.com", request.algorithm
          assert_equal "ssh-rsa-cert-v01@openssh.com", request.blob_type
          assert_equal rsa_cert.to_blob, request.blob
        end
        assert_equal "rsa-sha2-256", signed.signature_algorithm

        sign_call = key_manager.sign_calls.first
        assert_same rsa_cert, sign_call[:identity]
        assert_equal "rsa-sha2-256", sign_call[:algorithm]
        assert_signed_data(sign_call[:data], "rsa-sha2-256-cert-v01@openssh.com", rsa_cert.to_blob)
      end

      def test_openssh_74_compat_assumes_rsa_sha2_when_server_sig_algs_omits_it
        transport, key_manager = handshake(
          identities: [rsa_one],
          server_sig_algs: %w[ssh-ed25519 ssh-rsa],
          server_version: "SSH-2.0-OpenSSH_7.4",
          &accepting_server
        )

        assert authenticate(transport, key_manager)

        offer, signed = transport.requests.map { |packet| parse_auth_request(packet) }
        assert_equal "rsa-sha2-512", offer.algorithm
        assert_equal "rsa-sha2-512", signed.algorithm
        assert_equal "rsa-sha2-512", signed.signature_algorithm
        assert_equal "rsa-sha2-512", key_manager.sign_calls.first[:algorithm]
        assert_signed_data(key_manager.sign_calls.first[:data], "rsa-sha2-512", rsa_one.to_blob)
      end

      def test_sigtype_bug_server_falls_back_to_ssh_rsa_cert_signature_only
        transport, key_manager = handshake(
          identities: [rsa_cert],
          pubkey_algorithms: composed_pubkey_algorithms(pubkey_algorithms: %w[+ssh-rsa-cert-v01@openssh.com]),
          server_sig_algs: %w[rsa-sha2-512 rsa-sha2-256 ssh-rsa],
          server_version: "SSH-2.0-OpenSSH_7.7p1",
          &accepting_server
        )

        assert authenticate(transport, key_manager)

        offer, signed = transport.requests.map { |packet| parse_auth_request(packet) }
        [offer, signed].each do |request|
          assert_equal "ssh-rsa-cert-v01@openssh.com", request.algorithm
          assert_equal "ssh-rsa-cert-v01@openssh.com", request.blob_type
          assert_equal rsa_cert.to_blob, request.blob
        end
        assert_equal "ssh-rsa", signed.signature_algorithm
        assert_equal "ssh-rsa", key_manager.sign_calls.first[:algorithm]
        assert_signed_data(key_manager.sign_calls.first[:data], "ssh-rsa-cert-v01@openssh.com", rsa_cert.to_blob)
      end

      def test_interleaved_identities_sign_only_the_attempt_the_server_accepted
        server = proc do |t, packet|
          request = parse_auth_request(packet)
          if request.blob == rsa_one.to_blob
            t.reply(USERAUTH_FAILURE, :string, "publickey")
          elsif !request.has_signature
            t.reply(USERAUTH_PK_OK, :string, request.algorithm, :string, request.blob)
          else
            t.reply(USERAUTH_SUCCESS)
          end
        end
        transport, key_manager = handshake(
          identities: [rsa_one, rsa_two],
          server_sig_algs: %w[rsa-sha2-512 rsa-sha2-256],
          &server
        )

        assert authenticate(transport, key_manager)
        assert_equal 3, transport.requests.size

        refused, offer, signed = transport.requests.map { |packet| parse_auth_request(packet) }
        assert_equal rsa_one.to_blob, refused.blob
        assert_equal false, refused.has_signature
        assert_equal rsa_two.to_blob, offer.blob
        assert_equal rsa_two.to_blob, signed.blob
        assert_equal offer.algorithm, signed.algorithm

        assert_equal 1, key_manager.sign_calls.size
        sign_call = key_manager.sign_calls.first
        assert_same rsa_two, sign_call[:identity]
        assert_equal offer.algorithm, sign_call[:algorithm]
        assert_signed_data(sign_call[:data], offer.algorithm, rsa_two.to_blob)
      end

      def test_pk_ok_naming_another_key_does_not_induce_signing
        server = proc do |t, packet|
          request = parse_auth_request(packet)
          t.reply(USERAUTH_PK_OK, :string, request.algorithm, :string, rsa_two.to_blob)
        end
        transport, key_manager = handshake(
          identities: [rsa_one],
          server_sig_algs: %w[rsa-sha2-512],
          &server
        )

        assert_raises(Net::SSH::Exception) { authenticate(transport, key_manager) }
        assert_empty key_manager.sign_calls
        assert_equal 1, transport.requests.size
      end

      def test_pk_ok_naming_another_algorithm_does_not_induce_signing
        server = proc do |t, packet|
          request = parse_auth_request(packet)
          t.reply(USERAUTH_PK_OK, :string, "rsa-sha2-256", :string, request.blob)
        end
        transport, key_manager = handshake(
          identities: [rsa_one],
          server_sig_algs: %w[rsa-sha2-512 rsa-sha2-256],
          &server
        )

        assert_raises(Net::SSH::Exception) { authenticate(transport, key_manager) }
        assert_empty key_manager.sign_calls
        assert_equal 1, transport.requests.size
      end

      def test_pk_ok_naming_sha1_instead_of_negotiated_sha2_does_not_induce_signing
        server = proc do |t, packet|
          request = parse_auth_request(packet)
          t.reply(USERAUTH_PK_OK, :string, "ssh-rsa", :string, request.blob)
        end
        transport, key_manager = handshake(
          identities: [rsa_one],
          server_sig_algs: %w[rsa-sha2-512],
          &server
        )

        assert_raises(Net::SSH::Exception) { authenticate(transport, key_manager) }
        assert_empty key_manager.sign_calls
      end

      def test_missing_server_sig_algs_offers_only_ssh_rsa_when_explicitly_enabled
        transport, key_manager = handshake(
          identities: [rsa_one],
          pubkey_algorithms: composed_pubkey_algorithms(pubkey_algorithms: %w[+ssh-rsa]),
          server_sig_algs: nil,
          &accepting_server
        )

        assert authenticate(transport, key_manager)

        offer, signed = transport.requests.map { |packet| parse_auth_request(packet) }
        assert_equal "ssh-rsa", offer.algorithm
        assert_equal "ssh-rsa", signed.algorithm
        assert_equal "ssh-rsa", signed.signature_algorithm
        assert_equal "ssh-rsa", key_manager.sign_calls.first[:algorithm]
        assert_signed_data(key_manager.sign_calls.first[:data], "ssh-rsa", rsa_one.to_blob)
      end

      def test_missing_server_sig_algs_is_not_a_license_for_arbitrary_sha1_fallback
        transport, key_manager = handshake(
          identities: [rsa_one],
          server_sig_algs: nil,
          &accepting_server
        )

        assert_equal false, authenticate(transport, key_manager)
        assert_empty transport.requests
        assert_empty key_manager.sign_calls
      end

      def test_mixed_blob_type_and_signature_type_fails
        mixed_server = proc do |t, packet|
          request = parse_auth_request(packet)
          if !request.has_signature
            t.reply(USERAUTH_PK_OK, :string, request.algorithm, :string, request.blob)
          elsif request.blob_type == "ssh-rsa" && request.signature_algorithm == "rsa-sha2-512"
            t.reply(USERAUTH_SUCCESS)
          else
            t.reply(USERAUTH_FAILURE, :string, "publickey")
          end
        end
        transport, key_manager = handshake(
          identities: [rsa_one],
          server_sig_algs: %w[rsa-sha2-512],
          signature_algorithm: "ssh-rsa",
          &mixed_server
        )

        assert_equal false, authenticate(transport, key_manager)

        signed = parse_auth_request(transport.requests.last)
        assert_equal true, signed.has_signature
        assert_equal "rsa-sha2-512", signed.algorithm
        assert_equal "ssh-rsa", signed.signature_algorithm
      end

      private

      def handshake(identities:, pubkey_algorithms: default_pubkey_algorithms,
                    server_sig_algs: nil, server_version: "SSH-2.0-OpenSSH_9.9",
                    signature_algorithm: nil, &server)
        transport = FakeTransport.new(pubkey_algorithms: pubkey_algorithms,
                                      server_sig_algs: server_sig_algs,
                                      server_version: server_version, &server)
        key_manager = FakeKeyManager.new(identities, signature_algorithm: signature_algorithm)
        [transport, key_manager]
      end

      def authenticate(transport, key_manager)
        session = FakeSession.new(transport)
        method = Net::SSH::Authentication::Methods::Publickey.new(session, key_manager: key_manager)
        method.authenticate("ssh-connection", "jamis")
      end

      # A server that echoes every offer back as PK_OK and only accepts a
      # signed request whose signature blob declares the signature algorithm
      # implied by the negotiated algorithm and blob type.
      def accepting_server
        proc do |t, packet|
          request = parse_auth_request(packet)
          if !request.has_signature
            t.reply(USERAUTH_PK_OK, :string, request.algorithm, :string, request.blob)
          else
            mapping = Net::SSH::Authentication::Methods::Publickey::RSA_SIGNATURE_ALGORITHMS
            expected = mapping.dig(request.blob_type, request.algorithm) || request.algorithm
            if request.signature_algorithm == expected
              t.reply(USERAUTH_SUCCESS)
            else
              t.reply(USERAUTH_FAILURE, :string, "publickey")
            end
          end
        end
      end

      def parse_auth_request(raw)
        packet = Net::SSH::Packet.new(Net::SSH::Buffer.new(raw))
        assert_equal USERAUTH_REQUEST, packet.type
        parse_auth_request_fields(packet)
      end

      def parse_auth_request_fields(buffer)
        AuthRequest.new(
          buffer.read_string, # user-name
          buffer.read_string, # next service
          buffer.read_string, # auth-method
          buffer.read_bool,   # has signature
          buffer.read_string, # algorithm
          buffer.read_string, # key blob
          buffer.eof? ? nil : buffer.read_string # signature blob
        )
      end

      # Independently re-parses the captured to-be-signed bytes: the session
      # id from the transport, then the full signed USERAUTH_REQUEST.
      def assert_signed_data(data, algorithm, blob)
        buffer = Net::SSH::Buffer.new(data)
        assert_equal SESSION_ID, buffer.read_string
        assert_equal USERAUTH_REQUEST, buffer.read_byte
        request = parse_auth_request_fields(buffer)
        assert_equal "jamis", request.username
        assert_equal "ssh-connection", request.service
        assert_equal "publickey", request.method
        assert_equal true, request.has_signature
        assert_equal algorithm, request.algorithm
        assert_equal blob, request.blob
        assert buffer.eof?
      end

      def default_pubkey_algorithms
        Net::SSH::Transport::Algorithms::DEFAULT_ALGORITHMS[:pubkey_algorithms]
      end

      def composed_pubkey_algorithms(options = {})
        algorithms_transport = MockTransport.new(user_known_hosts_file: '/dev/null', global_known_hosts_file: '/dev/null')
        Net::SSH::Transport::Algorithms.new(algorithms_transport, options).algorithms[:pubkey_algorithms]
      end

      def rsa_one
        self.class.rsa_keys.first
      end

      def rsa_two
        self.class.rsa_keys.last
      end

      def rsa_cert
        self.class.rsa_cert
      end

      class << self
        def rsa_keys
          @rsa_keys ||= [OpenSSL::PKey::RSA.new(1024), OpenSSL::PKey::RSA.new(1024)]
        end

        def rsa_cert
          @rsa_cert ||= begin
            cert = Net::SSH::Authentication::Certificate.new
            cert.type = :user
            cert.key = rsa_keys.first.public_key
            cert.serial = 1
            cert.key_id = "handshake test key"
            cert.valid_principals = %w[jamis]
            cert.valid_after = Time.now - 86_400
            cert.valid_before = Time.now + 86_400
            cert.critical_options = {}
            cert.extensions = {}
            cert.reserved = ''
            cert.sign!(OpenSSL::PKey::RSA.new(1024))
            cert
          end
        end
      end
    end
  end
end
