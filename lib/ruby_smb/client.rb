module RubySMB
  # Represents an SMB client capable of talking to SMB1 or SMB2 servers and handling
  # all end-user client functionality.
  class Client
    require 'ruby_smb/ntlm'
    require 'ruby_smb/signing'
    require 'ruby_smb/client/negotiation'
    require 'ruby_smb/client/authentication'
    require 'ruby_smb/client/tree_connect'
    require 'ruby_smb/client/echo'
    require 'ruby_smb/client/utils'
    require 'ruby_smb/client/winreg'
    require 'ruby_smb/client/encryption'

    include RubySMB::Signing
    include RubySMB::NTLM
    include RubySMB::Client::Negotiation
    include RubySMB::Client::Authentication
    include RubySMB::Client::TreeConnect
    include RubySMB::Client::Echo
    include RubySMB::Client::Utils
    include RubySMB::Client::Winreg
    include RubySMB::Client::Encryption

    # The Default SMB1 Dialect string used in an SMB1 Negotiate Request
    SMB1_DIALECT_SMB1_DEFAULT = 'NT LM 0.12'.freeze
    # The Default SMB2 Dialect string used in an SMB1 Negotiate Request
    SMB1_DIALECT_SMB2_DEFAULT = 'SMB 2.002'.freeze
    # The SMB2 wildcard revision number Dialect string used in an SMB1 Negotiate Request
    # It indicates that the server implements SMB 2.1 or future dialect revisions
    # Note that this must be used for SMB3
    SMB1_DIALECT_SMB2_WILDCARD = 'SMB 2.???'.freeze

    SMB2_DIALECT_0202 = '0x0202'.freeze
    SMB2_DIALECT_0210 = '0x0210'.freeze
    SMB2_DIALECT_0300  = '0x0300'.freeze
    SMB2_DIALECT_0302  = '0x0302'.freeze
    SMB2_DIALECT_0311  = '0x0311'.freeze

    # Dialect values for SMB2
    SMB2_DIALECT_DEFAULT = [
      SMB2_DIALECT_0202,
      SMB2_DIALECT_0210,
    ].freeze

    # Dialect values for SMB3
    SMB3_DIALECT_DEFAULT = [
      SMB2_DIALECT_0300,
      SMB2_DIALECT_0302,
      SMB2_DIALECT_0311
    ].freeze

    # The default maximum size of a SMB message that the Client accepts (in bytes)
    MAX_BUFFER_SIZE = 64512
    # The default maximum size of a SMB message that the Server accepts (in bytes)
    SERVER_MAX_BUFFER_SIZE = 4356

    # SMB2 commands that are safe to replay after a STATUS_NETWORK_SESSION_EXPIRED
    # because they are read-only/idempotent: re-sending them cannot duplicate a
    # side effect on the server. Any command not listed here must not be retried
    # automatically once it may already have been executed.
    IDEMPOTENT_SMB2_COMMANDS = [
      RubySMB::SMB2::Commands::ECHO,
      RubySMB::SMB2::Commands::READ,
      RubySMB::SMB2::Commands::QUERY_DIRECTORY,
      RubySMB::SMB2::Commands::QUERY_INFO
    ].freeze

    # The application key. After authenticating to the remote server, this value is the session key for dialects less
    # than version 3 and a unique value for v3 dialects. See:
    # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/901ae284-31d3-4ea1-ae8a-766fc8bfe00e
    # @!attribute [rw] application_key
    #   @return [String]
    attr_accessor :application_key

    # The dispatcher responsible for sending packets
    # @!attribute [rw] dispatcher
    #   @return [RubySMB::Dispatcher::Socket]
    attr_accessor :dispatcher

    # The domain you're trying to authenticate to
    # @!attribute [rw] domain
    #   @return [String]
    attr_accessor :domain

    # The local workstation to pretend to be
    # @!attribute [rw] local_workstation
    #   @return [String]
    attr_accessor :local_workstation

    # The NTLM client used for authentication
    # @!attribute [rw] ntlm_client
    #   @return [String]
    attr_accessor :ntlm_client

    # The password to authenticate with
    # @!attribute [rw] password
    #   @return [String]
    attr_accessor :password

    # The Native OS of the Peer/Server.
    # Currently only available with SMB1.
    # @!attribute [rw] peer_native_os
    #   @return [String]
    attr_accessor :peer_native_os

    # The Native LAN Manager of the Peer/Server.
    # Currently only available with SMB1.
    # @!attribute [rw] peer_native_lm
    #   @return [String]
    attr_accessor :peer_native_lm

    # The Primary Domain of the Peer/Server.
    # Currently only available with SMB1 and only when authentiation
    # without NTLMSSP is used.
    # @!attribute [rw] primary_domain
    #   @return [String]
    attr_accessor :primary_domain

    # The Netbios Name of the Peer/Server.
    # @!attribute [rw] default_name
    #   @return [String]
    attr_accessor :default_name

    # The Netbios Domain of the Peer/Server.
    # @!attribute [rw] default_domain
    #   @return [String]
    attr_accessor :default_domain

    # The Fully Qualified Domain Name (FQDN) of the computer.
    # @!attribute [rw] dns_host_name
    #   @return [String]
    attr_accessor :dns_host_name

    # The Fully Qualified Domain Name (FQDN) of the domain.
    # @!attribute [rw] dns_domain_name
    #   @return [String]
    attr_accessor :dns_domain_name

    # The Fully Qualified Domain Name (FQDN) of the forest.
    # @!attribute [rw] dns_tree_name
    #   @return [String]
    attr_accessor :dns_tree_name

    # The OS version number (<major>.<minor>.<build>) of the Peer/Server.
    # @!attribute [rw] os_version
    #   @return [String]
    attr_accessor :os_version

    # The negotiated dialect.
    # @!attribute [rw] dialect
    #   @return [Integer]
    attr_accessor :dialect

    # The Sequence Counter used for SMB1 Signing.
    # It tracks the number of packets both sent and received
    # since the NTLM session was initialized with the Challenge.
    # @!attribute [rw] sequence_counter
    #   @return [Integer]
    attr_accessor :sequence_counter

    # The current Session ID setup by authentication
    # @!attribute [rw] session_id
    #   @return [Integer]
    attr_accessor :session_id

    # Whether or not the current session has the guest flag set
    # @!attribute [rw] session_is_guest
    #   @return [Boolean]
    attr_accessor :session_is_guest

    # Whether or not the Server requires signing
    # @!attribute [rw] signing_enabled
    #   @return [Boolean]
    attr_accessor :signing_required

    # Whether or not the Client should support SMB1
    # @!attribute [rw] smb1
    #   @return [Boolean]
    attr_accessor :smb1

    # Whether or not the Client should support SMB2
    # @!attribute [rw] smb2
    #   @return [Boolean]
    attr_accessor :smb2

    # Whether or not the Client should support SMB3
    # @!attribute [rw] smb3
    #   @return [Boolean]
    attr_accessor :smb3

    #  Tracks the current SMB2 Message ID that keeps communication in sync
    # @!attribute [rw] smb2_message_id
    #   @return [Integer]
    attr_accessor :smb2_message_id

    # The username to authenticate with
    # @!attribute [rw] username
    #   @return [String]
    attr_accessor :username

    # The UID set in SMB1
    # @!attribute [rw] user_id
    #   @return [Integer]
    attr_accessor :user_id

    # The Process ID set in SMB1
    # It is randomly generated during the client initialization, but can
    # be modified using the accessor.
    # @!attribute [rw] pid
    #   @return [Integer]
    attr_accessor :pid

    # The maximum size SMB message that the Client accepts (in bytes)
    # The default value is equal to {MAX_BUFFER_SIZE}.
    # @!attribute [rw] max_buffer_size
    #   @return [Integer]
    attr_accessor :max_buffer_size

    # The maximum size SMB message that the Server accepts (in bytes)
    # The default value is small by default
    # @!attribute [rw] max_buffer_size
    #   @return [Integer]
    attr_accessor :server_max_buffer_size

    # The maximum size SMB2 write request that the Server accepts (in bytes)
    # @!attribute [rw] server_max_write_size
    #   @return [Integer]
    attr_accessor :server_max_write_size

    # The maximum size SMB2 read request that the Server accepts (in bytes)
    # @!attribute [rw] server_max_read_size
    #   @return [Integer]
    attr_accessor :server_max_read_size

    # The maximum size SMB2 transaction that the Server accepts (in bytes)
    # For transactions that are not a read or write request
    # @!attribute [rw] server_max_transact_size
    #   @return [Integer]
    attr_accessor :server_max_transact_size

    # The algorithm to compute the preauthentication integrity hash (SMB 3.1.1).
    # @!attribute [rw] preauth_integrity_hash_algorithm
    #   @return [String]
    attr_accessor :preauth_integrity_hash_algorithm

    # The preauthentication integrity hash value (SMB 3.1.1).
    # @!attribute [rw] preauth_integrity_hash_value
    #   @return [String]
    attr_accessor :preauth_integrity_hash_value

    # The algorithm for encryption (SMB 3.x).
    # @!attribute [rw] encryption_algorithm
    #   @return [String]
    attr_accessor :encryption_algorithm

    # The client encryption key (SMB 3.x).
    # @!attribute [rw] client_encryption_key
    #   @return [String]
    attr_accessor :client_encryption_key

    # The server encryption key (SMB 3.x).
    # @!attribute [rw] server_encryption_key
    #   @return [String]
    attr_accessor :server_encryption_key

    # Whether or not the whole session needs to be encrypted (SMB 3.x)
    # @!attribute [rw] session_encrypt_data
    #   @return [Boolean]
    attr_accessor :session_encrypt_data

    # The encryption algorithms supported by the server (SMB 3.x).
    # @!attribute [rw] server_encryption_algorithms
    #   @return [Array<Integer>] list of supported encryption algorithms
    #     (constants defined in RubySMB::SMB2::EncryptionCapabilities)
    attr_accessor :server_encryption_algorithms

    # The compression algorithms supported by the server (SMB 3.x).
    # @!attribute [rw] server_compression_algorithms
    #   @return [Array<Integer>] list of supported compression algorithms
    #     (constants defined in RubySMB::SMB2::CompressionCapabilities)
    attr_accessor :server_compression_algorithms

    # The GUID of the server (SMB 2.x and 3.x).
    # @!attribute [rw] server_guid
    #   @return [String]
    attr_accessor :server_guid

    # The server's start time if it is reported as part of the negotiation
    # process (SMB 2.x and 3.x). This value is nil if the server does not report
    # it (reports a value of 0).
    # @!attribute [rw] server_start_time
    #   @return [Time] the time that the server reports that it was started at
    attr_accessor :server_start_time

    # The server's current time if it is reported as part of the negotiation
    # process (SMB 2.x and 3.x). This value is nil if the server does not report
    # it (reports a value of 0).
    # @!attribute [rw] server_system_time
    #   @return [Time] the time that the server reports as current
    attr_accessor :server_system_time

    # The SMB version that has been successfully negotiated. This value is only
    # set after the NEGOTIATE handshake has been performed.
    # @!attribute [rw] negotiated_smb_version
    #   @return [Integer] the negotiated SMB version
    attr_accessor :negotiated_smb_version

    # Whether or not the server supports multi-credit operations. It is
    # reported by the LARGE_MTU capability as part of the negotiation process
    # (SMB 2.x and 3.x).
    # @!attribute [rw] server_supports_multi_credit
    #   @return [Boolean] true if the server supports multi-credit operations,
    #   false otherwise
    attr_accessor :server_supports_multi_credit

    # The negotiated security buffer. This is nil until the negotiation process
    # has finished.
    # @!attribute [rw] negotiation_security_buffer
    #   @return [String] The raw security buffer bytes
    attr_accessor :negotiation_security_buffer

    # Whether the negotiated SMB1 server supports the "NT SMBs" capability
    # (i.e. SMB_COM_NT_CREATE_ANDX). Set false for Windows 95/98/ME and other
    # LAN Manager-era servers, which must use SMB_COM_OPEN_ANDX instead.
    # Always true for SMB2/3.
    # @!attribute [rw] supports_nt_smbs
    #   @return [Boolean]
    attr_accessor :server_supports_nt_smbs

    # @param dispatcher [RubySMB::Dispatcher::Socket] the packet dispatcher to use
    # @param smb1 [Boolean] whether or not to enable SMB1 support
    # @param smb2 [Boolean] whether or not to enable SMB2 support
    # @param smb3 [Boolean] whether or not to enable SMB3 support
    def initialize(dispatcher, smb1: true, smb2: true, smb3: true, username:, password:, domain: '.',
                   local_workstation: 'WORKSTATION', always_encrypt: true, ntlm_flags: NTLM::DEFAULT_CLIENT_FLAGS)
      raise ArgumentError, 'No Dispatcher provided' unless dispatcher.is_a? RubySMB::Dispatcher::Base
      if smb1 == false && smb2 == false && smb3 == false
        raise ArgumentError, 'You must enable at least one Protocol'
      end

      @dispatcher        = dispatcher
      @pid               = rand(0xFFFF)
      @domain            = domain
      @local_workstation = local_workstation
      @password          = (password || '')
      @sequence_counter  = 0
      @session_id        = 0x00
      @session_key       = ''
      @application_key   = ''
      @session_is_guest  = false
      @signing_required  = false
      @smb1              = smb1
      @smb2              = smb2
      @smb3              = smb3
      @username          = (username || '')
      @max_buffer_size   = MAX_BUFFER_SIZE
      # These sizes will be modified during negotiation
      @server_max_buffer_size = SERVER_MAX_BUFFER_SIZE
      @server_max_read_size = RubySMB::SMB2::File::MAX_PACKET_SIZE
      @server_max_write_size = RubySMB::SMB2::File::MAX_PACKET_SIZE
      @server_max_transact_size = RubySMB::SMB2::File::MAX_PACKET_SIZE
      @server_supports_multi_credit = false
      @server_supports_nt_smbs      = true

      # SMB 3.x options
      # this merely initializes the default value for session encryption, it may be changed as necessary when a
      # session setup response is received
      @session_encrypt_data = always_encrypt

      @ntlm_client = RubySMB::NTLM::Client.new(
        @username,
        @password,
        workstation: @local_workstation,
        domain: @domain,
        flags: ntlm_flags
      )

      @tree_connects = []
      @open_files = {}

      @smb2_message_id = 0
    end

    # Logs off any currently open session on the server
    # and closes the TCP socket connection.
    #
    # @return [void]
    def disconnect!
      begin
        logoff!
      rescue
        wipe_state!
      end
      dispatcher.tcp_socket.close
    end

    # Sends an Echo request to the server and returns the
    # NTStatus of the last response packet received.
    #
    # @param echo [Integer] the number of times the server should echo (ignored in SMB2)
    # @param data [String] the data the server should echo back (ignored in SMB2)
    # @return [WindowsError::ErrorCode] the NTStatus of the last response received
    def echo(count: 1, data: '')
      response = if smb2 || smb3
                   smb2_echo
                 else
                   smb1_echo(count: count, data: data)
                 end
      response.status_code
    end

    # Sets the message id field in an SMB2 packet's
    # header to the one tracked by the client. It then increments
    # the counter on the client.
    #
    # @param packet [RubySMB::GenericPacket] the packet to set the message id for
    # @return [RubySMB::GenericPacket] the modified packet
    def increment_smb_message_id(packet)
      packet.smb2_header.message_id = self.smb2_message_id
      self.smb2_message_id += 1
      packet
    end

    # Performs protocol negotiation and session setup. It defaults to using
    # the credentials supplied during initialization, but can take a new set of credentials if needed.
    def login(username: self.username, password: self.password,
              domain: self.domain, local_workstation: self.local_workstation,
              ntlm_flags: NTLM::DEFAULT_CLIENT_FLAGS)
      negotiate
      session_setup(username, password, domain,
                    local_workstation: local_workstation,
                    ntlm_flags: ntlm_flags)
    end

    def session_setup(user, pass, domain, do_recv=true,
                      local_workstation: self.local_workstation, ntlm_flags: NTLM::DEFAULT_CLIENT_FLAGS)
      @domain            = domain
      @local_workstation = local_workstation
      @password          = (pass || '')
      @username          = (user || '')

      @ntlm_client = RubySMB::NTLM::Client.new(
          @username,
          @password,
          workstation: @local_workstation,
          domain: @domain,
          flags: ntlm_flags
      )

      authenticate
    end

    # Sends a LOGOFF command to the remote server to terminate the session
    #
    # @return [WindowsError::ErrorCode] the NTStatus of the response
    # @raise [RubySMB::Error::InvalidPacket] if the response packet is not a LogoffResponse packet
    def logoff!
      if smb2 || smb3
        request      = RubySMB::SMB2::Packet::LogoffRequest.new
        raw_response = send_recv(request)
        response     = RubySMB::SMB2::Packet::LogoffResponse.read(raw_response)
        unless response.valid?
          raise RubySMB::Error::InvalidPacket.new(
            expected_proto: RubySMB::SMB2::SMB2_PROTOCOL_ID,
            expected_cmd:   RubySMB::SMB2::Packet::LogoffResponse::COMMAND,
            packet:         response
          )
        end
      else
        request      = RubySMB::SMB1::Packet::LogoffRequest.new
        raw_response = send_recv(request)
        response     = RubySMB::SMB1::Packet::LogoffResponse.read(raw_response)
        unless response.valid?
          raise RubySMB::Error::InvalidPacket.new(
            expected_proto: RubySMB::SMB1::SMB_PROTOCOL_ID,
            expected_cmd:   RubySMB::SMB1::Packet::LogoffResponse::COMMAND,
            packet:         response
          )
        end
      end
      wipe_state!
      response.status_code
    end

    # Sends a packet and receives the raw response through the Dispatcher.
    # It will also sign the packet if necessary.
    #
    # @param packet [RubySMB::GenericPacket] the request to be sent
    # @param encrypt [Boolean] true if encryption has to be enabled for this transaction
    #   (note that if @session_encrypt_data is set, encryption will be enabled
    #   regardless of this parameter value)
    # @param _reauthentication_attempted [Boolean] internal guard ensuring that at most
    #   one re-authentication and one retry are performed per call. It must not be set by
    #   callers.
    # @param _skip_message_id_allocation [Boolean] internal flag used when the packet's
    #   SMB2 message id has already been allocated by the caller. It must not be set by
    #   callers.
    # @return [String] the raw response data received
    def send_recv(packet, encrypt: false, _reauthentication_attempted: false, _skip_message_id_allocation: false)
      version = packet.packet_smb_version
      case version
      when 'SMB1'
        packet.smb_header.uid = self.user_id if self.user_id
        packet.smb_header.pid_low = self.pid if self.pid
        packet = smb1_sign(packet) if signing_required && !session_key.empty?
      when 'SMB2'
        increment_smb_message_id(packet) unless _skip_message_id_allocation
        packet.smb2_header.session_id = session_id
        unless packet.is_a?(RubySMB::SMB2::Packet::SessionSetupRequest) || session_key.empty?
          if self.smb2 && signing_required
            packet = smb2_sign(packet)
          elsif self.smb3
            # see: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/652e0c14-5014-4470-999d-b174d7b2da87
            if @dialect == '0x0311' && (signing_required || (!@session_is_guest && packet.is_a?(RubySMB::SMB2::Packet::TreeConnectRequest)))
              packet = smb3_sign(packet)
            elsif signing_required
              packet = smb3_sign(packet)
            end
          end
        end
      else
        packet = packet
      end

      encrypt_data = false
      if can_be_encrypted?(packet) && encryption_supported? && (@session_encrypt_data || encrypt)
        encrypt_data = true
      end
      send_packet(packet, encrypt: encrypt_data)
      raw_response = recv_packet(encrypt: encrypt_data)
      smb2_header = nil
      loop do
        smb2_header = RubySMB::SMB2::SMB2Header.read(raw_response)
        break unless is_status_pending?(smb2_header)
        sleep 1
        raw_response = recv_packet(encrypt: encrypt_data)
      rescue IOError
        # We're expecting an SMB2 packet, but the server sent an SMB1 packet
        # instead. This behavior has been observed with older versions of Samba
        # when something goes wrong on the server side. So, we just ignore it
        # and expect the caller to handle this wrong response packet.
        break
      end unless version == 'SMB1'

      # Handle STATUS_NETWORK_SESSION_EXPIRED. The 'net use' client upon receiving this error will automatically attempt
      # to re-authenticate, which makes relaying ntlm authentication to multiple targets possible. This block ensures
      # ruby_smb behaves in the same manner as 'net use'.
      if session_expired?(smb2_header)
        # The guard makes the re-authentication path strictly bounded: a server that keeps
        # answering with STATUS_NETWORK_SESSION_EXPIRED cannot cause unbounded recursion.
        raw_response = handle_session_expired(packet, smb2_header, raw_response, encrypt_data, _reauthentication_attempted)
        smb2_header = RubySMB::SMB2::SMB2Header.read(raw_response) unless raw_response.nil?
      end

      self.sequence_counter += 1 if signing_required && !session_key.empty?
      # update the SMB2 message ID according to the received Credit Charged
      self.smb2_message_id += smb2_header.credit_charge - 1 if smb2_header && self.server_supports_multi_credit
      raw_response
    end

    # Whether the given response header reports STATUS_NETWORK_SESSION_EXPIRED.
    #
    # @param smb2_header [RubySMB::SMB2::SMB2Header, nil] the parsed response header
    # @return [Boolean] true if the session has expired
    def session_expired?(smb2_header)
      !smb2_header.nil? && smb2_header.nt_status == WindowsError::NTStatus::STATUS_NETWORK_SESSION_EXPIRED
    end

    # Reacts to a STATUS_NETWORK_SESSION_EXPIRED response. The session security state is
    # always rebuilt through a fresh authentication; only idempotent requests are then
    # replayed once, everything else is reported as an unknown outcome.
    #
    # @param packet [RubySMB::GenericPacket] the request that received the expiry error
    # @param smb2_header [RubySMB::SMB2::SMB2Header] the parsed expiry response header
    # @param raw_response [String] the raw bytes of the expiry response
    # @param encrypt_data [Boolean] whether the original exchange was encrypted
    # @param reauthentication_attempted [Boolean] guard ensuring a single retry per call
    # @return [String] the raw response of the single retried request, or the untouched
    #   expiry response when no automatic re-authentication is possible
    # @raise [RubySMB::Error::RequestOutcomeUnknown] if the request may have executed and
    #   cannot be safely replayed, or if the session expired again after re-authentication
    # @raise [RubySMB::Error::ReauthenticationFailure] if the re-authentication itself fails
    def handle_session_expired(packet, smb2_header, raw_response, encrypt_data, reauthentication_attempted)
      if reauthentication_attempted
        # The freshly authenticated session was rejected immediately. Retrying again would
        # loop forever against a server that keeps returning the same error.
        raise RubySMB::Error::RequestOutcomeUnknown.new(
          "The server returned STATUS_NETWORK_SESSION_EXPIRED again after re-authentication; " \
          "the result of the request is unknown.",
          status_code: status_code_of(smb2_header),
          command: packet.smb2_header.command
        )
      end

      if @mech_type == :kerberos
        raise RubySMB::Error::RubySMBError, 'WindowsError::NTStatus::STATUS_NETWORK_SESSION_EXPIRED received, but kerberos authentication is being used, so automatic re-authentication cannot be attempted.'
      end

      unless @mech_type == :ntlm || @mech_type == :anonymous
        # No authenticated mechanism is known (e.g. the session was never fully set up):
        # there is nothing to re-run, surface the raw expiry response to the caller.
        return raw_response
      end

      reauthenticate!

      unless retryable_request?(packet)
        # The request may already have been executed on the server. Re-sending a
        # non-idempotent command could duplicate the operation, so its outcome can only be
        # reported as unknown instead of claiming a success that was never observed.
        raise RubySMB::Error::RequestOutcomeUnknown.new(
          "Re-authentication succeeded after STATUS_NETWORK_SESSION_EXPIRED, but the " \
          "#{RubySMB::SMB2::Commands.name(packet.smb2_header.command) || packet.smb2_header.command} " \
          "request may already have been executed and cannot safely be retried; its result is unknown.",
          status_code: status_code_of(smb2_header),
          command: packet.smb2_header.command
        )
      end

      # The packet still carries the message id of the failed request. Allocate the next
      # connection-wide id from the live counter (the session setup exchange already
      # consumed ids after the failed one) and skip the nested send_recv allocation so it
      # does not move the counter twice.
      new_message_id = smb2_message_id
      self.smb2_message_id = new_message_id + 1
      packet.smb2_header.message_id = new_message_id
      send_recv(packet, encrypt: encrypt_data, _reauthentication_attempted: true, _skip_message_id_allocation: true)
    end

    # Whether the request is safe to replay automatically after the session is rebuilt.
    #
    # @param packet [RubySMB::GenericPacket] the request to evaluate
    # @return [Boolean] true if the command is idempotent/read-only
    def retryable_request?(packet)
      return false unless packet.packet_smb_version == 'SMB2'
      IDEMPOTENT_SMB2_COMMANDS.include?(packet.smb2_header.command)
    end

    # Rebuilds the session after STATUS_NETWORK_SESSION_EXPIRED. All keying material,
    # signing sequence state and pre-authentication context derived from the expired
    # session is wiped first so nothing from the old generation can leak into the new one.
    #
    # @return [void]
    # @raise [RubySMB::Error::ReauthenticationFailure] if the new authentication does not succeed
    def reauthenticate!
      reset_session_security_state!
      begin
        session_setup(
          self.username,
          self.password,
          self.domain,
          local_workstation: self.local_workstation,
          ntlm_flags: NTLM::DEFAULT_CLIENT_FLAGS
        )
      rescue RubySMB::Error::RubySMBError => e
        raise RubySMB::Error::ReauthenticationFailure,
              "Automatic re-authentication after STATUS_NETWORK_SESSION_EXPIRED failed: #{e.message}"
      end
    end

    # Clears every piece of state bound to an authentication generation so that a new
    # session setup starts from a clean slate. Connection-wide negotiation results
    # (dialect, negotiated sizes, message id space) are deliberately preserved.
    #
    # @return [void]
    def reset_session_security_state!
      self.session_id       = 0x00
      self.user_id          = 0x00
      self.application_key  = ''
      self.session_key      = ''
      self.session_is_guest = false
      self.sequence_counter = 0
      self.client_encryption_key = nil
      self.server_encryption_key = nil
      # SMB 3.1.1 derives signing and encryption keys from the preauthentication integrity
      # hash. It must be restarted for the new generation, otherwise old-session exchange
      # bytes would pollute the derived keys of the new session.
      @preauth_integrity_hash_value = "\x00" * 64 if @dialect == '0x0311'
    end

    def status_code_of(smb2_header)
      WindowsError::NTStatus.find_by_retval(smb2_header.nt_status.value).first
    end

    # Check if the response is an asynchronous operation with STATUS_PENDING
    # status code.
    #
    # @param smb2_header [String] the response packet SMB2 header
    # @return [Boolean] true if it is a status pending operation, false otherwise
    def is_status_pending?(smb2_header)
      value = smb2_header.nt_status.value
      status_code = WindowsError::NTStatus.find_by_retval(value).first
      status_code == WindowsError::NTStatus::STATUS_PENDING &&
        smb2_header.flags.async_command == 1
    end

    # Check if the request packet can be encrypted. Per the SMB2 spec,
    # SessionSetupRequest and NegotiateRequest must not be encrypted.
    #
    # @param packet [RubySMB::GenericPacket] the request packet
    # @return [Boolean] true if the packet can be encrypted
    def can_be_encrypted?(packet)
      return false if packet.packet_smb_version == 'SMB1'
      [RubySMB::SMB2::Packet::SessionSetupRequest, RubySMB::SMB2::Packet::NegotiateRequest].none? do |klass|
        packet.is_a?(klass)
      end
    end

    # Check if the current dialect supports encryption.
    #
    # @return [Boolean] true if encryption is supported
    def encryption_supported?
      ['0x0300', '0x0302', '0x0311'].include?(@dialect)
    end

    # Encrypt (if required) and send a packet.
    #
    # @param encrypt [Boolean] true if the packet should be encrypted, false
    #   otherwise
    def send_packet(packet, encrypt: false)
      if encrypt
        begin
          packet = smb3_encrypt(packet.to_binary_s)
        rescue RubySMB::Error::RubySMBError => e
          raise RubySMB::Error::EncryptionError, "Error while encrypting #{packet.class.name} packet (SMB #{@dialect}): #{e}"
        end
      end
      dispatcher.send_packet(packet)
    end

    # Receives the raw response through the Dispatcher and decrypt the packet (if required).
    #
    # @param encrypt [Boolean] true if the packet is encrypted, false otherwise
    # @return [String] the raw unencrypted packet
    def recv_packet(encrypt: false)
      begin
        raw_response = dispatcher.recv_packet
      rescue RubySMB::Error::CommunicationError => e
        if encrypt
          raise e, "Communication error with the "\
            "remote host: #{e.message}. The server supports encryption and this error "\
            "may have been caused by encryption issues, but not always."
        else
          raise e
        end
      end
      if encrypt
        begin
          transform_response = RubySMB::SMB2::Packet::TransformHeader.read(raw_response)
        rescue IOError
          raise RubySMB::Error::InvalidPacket, 'Not a SMB2 TransformHeader packet'
        end
        begin
          raw_response = smb3_decrypt(transform_response)
        rescue RubySMB::Error::RubySMBError => e
          raise RubySMB::Error::EncryptionError, "Error while decrypting #{transform_response.class.name} packet (SMB #@dialect}): #{e}"
        end
      end
      raw_response
    end

    # Connects to the supplied share
    #
    # @param share [String] the path to the share in `\\server\share_name` format
    # @param password [String, nil] share-level password (SMB1 only, for
    #   servers using share-level auth such as Windows 95/98/ME)
    # @return [RubySMB::SMB1::Tree] if talking over SMB1
    # @return [RubySMB::SMB2::Tree] if talking over SMB2
    def tree_connect(share, password: nil)
      connected_tree = if smb2 || smb3
        smb2_tree_connect(share)
      else
        smb1_tree_connect(share, password: password)
      end
      @tree_connects << connected_tree
      connected_tree
    end

    # Returns array of shares
    #
    # @return [Array] of shares
    # @param [String] host
    def net_share_enum_all(host)
      tree = tree_connect("\\\\#{host}\\IPC$")
      named_pipe = tree.open_pipe(filename: "srvsvc", write: true, read: true)
      named_pipe.net_share_enum_all(host)
    end

    # Resets all of the session state on the client, setting it
    # back to scratch. Should only be called when a session is no longer
    # valid.
    #
    # @return [void]
    def wipe_state!
      self.session_id       = 0x00
      self.user_id          = 0x00
      self.application_key  = ''
      self.session_key      = ''
      self.session_is_guest = false
      self.sequence_counter = 0
      self.smb2_message_id  = 0
      self.client_encryption_key = nil
      self.server_encryption_key = nil
      self.server_supports_multi_credit = false
    end

    # Requests a NetBIOS Session Service using the provided name.
    #
    # On refusal the raised {RubySMB::Error::NetBiosSessionService} carries the
    # numeric NBSS `error_code`. A {RubySMB::Nbss::CALLED_NAME_NOT_PRESENT} rejection of
    # the default `'*SMBSERVER'` name means the server (e.g. Windows 9x) wants
    # its real name: resolve it with {RubySMB::Nbss::NodeStatus.file_server_name},
    # reconnect (the server drops the connection after a negative response), and
    # retry. Reconnecting is left to the caller so the new socket is routed the
    # same way as the original (e.g. through a Metasploit pivot).
    #
    # @param name [String] the NetBIOS name to request
    # @return [TrueClass] if session request is granted
    # @raise [RubySMB::Error::NetBiosSessionService] if session request is refused
    # @raise [RubySMB::Error::InvalidPacket] if the response packet is not a NBSS packet
    def session_request(name = '*SMBSERVER')
      session_request = session_request_packet(name)
      dispatcher.send_packet(session_request, nbss_header: false)
      raw_response = dispatcher.recv_packet(full_response: true)
      begin
        session_header = RubySMB::Nbss::SessionHeader.read(raw_response)
        if session_header.session_packet_type == RubySMB::Nbss::NEGATIVE_SESSION_RESPONSE
          negative_session_response = RubySMB::Nbss::NegativeSessionResponse.read(raw_response)
          raise RubySMB::Error::NetBiosSessionService.new(
            "Session Request failed: #{negative_session_response.error_msg}",
            error_code: negative_session_response.error_code.to_i
          )
        end
      rescue IOError
        raise RubySMB::Error::InvalidPacket, 'Not a NBSS packet'
      end

      return true
    end

    # Crafts the NetBIOS SessionRequest packet to be sent for session request operations.
    #
    # @param name [String] the NetBIOS name to request
    # @return [RubySMB::Nbss::SessionRequest] the SessionRequest packet
    def session_request_packet(name = '*SMBSERVER')
      called_name = "#{name.upcase.ljust(15)}\x20"
      calling_name = "#{@local_workstation.upcase.ljust(15)}\x00"

      session_request = RubySMB::Nbss::SessionRequest.new
      session_request.session_header.session_packet_type = RubySMB::Nbss::SESSION_REQUEST
      session_request.called_name  = called_name
      session_request.calling_name = calling_name
      session_request.session_header.stream_protocol_length =
        session_request.num_bytes - session_request.session_header.num_bytes
      session_request
    end

    def update_preauth_hash(data)
      unless @preauth_integrity_hash_algorithm
        raise RubySMB::Error::EncryptionError.new(
          'Cannot compute the Preauth Integrity Hash value: Preauth Integrity Hash Algorithm is nil'
        )
      end
      @preauth_integrity_hash_value = OpenSSL::Digest.digest(
        @preauth_integrity_hash_algorithm,
        @preauth_integrity_hash_value + data.to_binary_s
      )
    end

  end
end
