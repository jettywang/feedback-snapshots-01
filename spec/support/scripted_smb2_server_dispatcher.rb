require 'securerandom'

# A deterministic, in-memory SMB2/3 server used to drive the client through full
# authentication exchanges without a real socket. It speaks just enough of the protocol
# (NEGOTIATE, SESSION_SETUP with NTLMSSP, and scripted application replies) to let the
# client derive real session keys and signatures.
#
# Each authentication generation is built from distinct test material (a different server
# challenge) so keys derived for one generation can never validate traffic from another.
# The dispatcher records every raw frame it receives, which lets specs assert on the exact
# number of packets sent and independently verify the signatures on the wire.
class ScriptedSmb2ServerDispatcher < RubySMB::Dispatcher::Base
  # One entry per frame actually sent by the client: the raw binary string plus the
  # parsed command, message id, session id and signature bytes.
  attr_reader :wire

  # The completed authentication generations, each with its challenge, session id and
  # the NTLM session key computed server-side.
  attr_reader :generations

  # @param password [String] password the server validates NTLM responses against
  # @param challenges [Array<String>] one distinct 8-byte server challenge per
  #   authentication generation
  # @param dialect [Integer] negotiated SMB2 dialect revision
  def initialize(password:, challenges:, dialect: 0x0302)
    @password = password
    @challenges = challenges
    @dialect = dialect
    @wire = []
    @generations = []
    @generation_index = -1
    @current_generation = nil
    @expiry_policy = {}
    @reply_queue = []
  end

  # The preauthentication integrity hash computed independently by the fake server for
  # each completed 3.1.1 authentication generation, indexed by generation number.
  attr_reader :preauth_hashes

  # The next request of the given command receives STATUS_NETWORK_SESSION_EXPIRED once.
  def expire_next(command)
    @expiry_policy[command] = :once
  end

  # Every request of the given command receives STATUS_NETWORK_SESSION_EXPIRED.
  def always_expire(command)
    @expiry_policy[command] = :always
  end

  # Stop expiring the given command (used after an expected expiry has fired).
  def stop_expiring(command)
    @expiry_policy.delete(command)
  end

  def send_packet(packet, nbss_header: true)
    raw = packet.to_binary_s.b
    @wire << {
      raw: raw,
      command: raw[12, 2].unpack1('v'),
      message_id: raw[24, 8].unpack1('Q<'),
      session_id: raw[40, 8].unpack1('Q<'),
      signature: raw[48, 16].b
    }
    header = RubySMB::SMB2::SMB2Header.read(raw)
    @reply_queue << route(raw, header)
    nil
  end

  def recv_packet(full_response: false)
    @reply_queue.shift
  end

  # Recomputes the SMB3 signing key for a generation. For the 3.1.1 dialect the key is
  # bound to the preauthentication integrity hash of that generation, which is supplied
  # explicitly so a stale hash can never be used.
  def signing_key_for(generation, preauth_integrity_hash_value = nil)
    case @dialect
    when 0x0311
      RubySMB::Crypto::KDF.counter_mode(
        generation[:session_key],
        "SMBSigningKey\x00",
        preauth_integrity_hash_value
      )
    else
      RubySMB::Crypto::KDF.counter_mode(
        generation[:session_key],
        "SMB2AESCMAC\x00",
        "SmbSign\x00"
      )
    end
  end

  # Verifies an SMB3 CMAC signature against the captured frame, independently of the
  # client's own signing code.
  def valid_signature?(frame, generation, preauth_integrity_hash_value = nil)
    verifiable = frame[:raw].dup
    verifiable[48, 16] = "\x00" * 16
    expected = OpenSSL::CMAC.digest(
      'AES',
      signing_key_for(generation, preauth_integrity_hash_value),
      verifiable
    )[0, 16]
    expected == frame[:signature]
  end

  private

  def route(raw, header)
    case header.command
    when RubySMB::SMB2::Commands::NEGOTIATE
      negotiate(raw)
    when RubySMB::SMB2::Commands::SESSION_SETUP
      session_setup(raw, header)
    else
      application(raw, header)
    end
  end

  def negotiate(raw)
    request = RubySMB::SMB2::Packet::NegotiateRequest.read(raw)
    response = RubySMB::SMB2::Packet::NegotiateResponse.new
    response.smb2_header.message_id = request.smb2_header.message_id
    response.smb2_header.credits = 32
    response.security_mode.signing_required = 1
    response.dialect_revision = @dialect
    response.server_guid = SecureRandom.random_bytes(16)
    response.capabilities.large_mtu = 0
    response.max_transact_size = 0x10000
    response.max_read_size = 0x10000
    response.max_write_size = 0x10000
    response.security_buffer_offset = response.security_buffer.abs_offset
    response.security_buffer = ''

    if @dialect == 0x0311
      response.negotiate_context_offset = response.negotiate_context_list.abs_offset
      response.add_negotiate_context(
        RubySMB::SMB2::NegotiateContext.new(
          context_type: RubySMB::SMB2::NegotiateContext::SMB2_PREAUTH_INTEGRITY_CAPABILITIES,
          data: {
            hash_algorithms: [RubySMB::SMB2::PreauthIntegrityCapabilities::SHA_512],
            salt: SecureRandom.random_bytes(32)
          }
        )
      )
      response.add_negotiate_context(
        RubySMB::SMB2::NegotiateContext.new(
          context_type: RubySMB::SMB2::NegotiateContext::SMB2_ENCRYPTION_CAPABILITIES,
          data: {
            ciphers: [RubySMB::SMB2::EncryptionCapabilities::AES_128_GCM]
          }
        )
      )
      # The preauthentication hash starts at zero and first covers the negotiate exchange.
      @negotiate_preauth_hash = OpenSSL::Digest.digest('SHA512', "\x00" * 64 + request.to_binary_s)
      @negotiate_preauth_hash = OpenSSL::Digest.digest('SHA512', @negotiate_preauth_hash + response.to_binary_s)
    end

    response.to_binary_s
  end

  def session_setup(raw, header)
    request = RubySMB::SMB2::Packet::SessionSetupRequest.read(raw)
    ntlm_message = Net::NTLM::Message.parse(extract_ntlm(request.buffer))

    if ntlm_message.is_a?(Net::NTLM::Message::Type1)
      start_generation
      type2 = Net::NTLM::Message::Type2.new
      type2.flag = ntlm_message.flag
      type2.challenge = @current_generation[:challenge].unpack1('Q<')
      target_info = Net::NTLM::TargetInfo.new(nil)
      type2.target_info = target_info.to_s
      type2.enable(:target_info)

      response = RubySMB::SMB2::Packet::SessionSetupResponse.new
      response.smb2_header.nt_status = WindowsError::NTStatus::STATUS_MORE_PROCESSING_REQUIRED.value
      response.smb2_header.message_id = header.message_id
      response.smb2_header.credits = 1
      response.smb2_header.session_id = @current_generation[:session_id]
      response.set_type2_blob(type2.serialize)
      response_binary = response.to_binary_s
      track_preauth_hash(request, response) if @dialect == 0x0311
      return response_binary
    end

    @current_generation[:session_key] = derive_session_key(ntlm_message)
    @generations << @current_generation.dup

    response = RubySMB::SMB2::Packet::SessionSetupResponse.new
    response.smb2_header.nt_status = WindowsError::NTStatus::STATUS_SUCCESS.value
    response.smb2_header.message_id = header.message_id
    response.smb2_header.credits = 32
    response.smb2_header.session_id = @current_generation[:session_id]
    response.buffer = RubySMB::Gss.gss_type3('')
    response_binary = response.to_binary_s
    finalize_preauth_hash(request) if @dialect == 0x0311
    response_binary
  end

  def application(raw, header)
    if @expiry_policy[header.command]
      @expiry_policy.delete(header.command) if @expiry_policy[header.command] == :once
      return error_response(header, WindowsError::NTStatus::STATUS_NETWORK_SESSION_EXPIRED)
    end

    response = RubySMB::SMB2::Packet::ReadResponse.new
    response.smb2_header.message_id = header.message_id
    response.smb2_header.credits = 1
    response.smb2_header.session_id = header.session_id
    response.smb2_header.nt_status = WindowsError::NTStatus::STATUS_SUCCESS.value
    response.to_binary_s
  end

  def error_response(header, status)
    response = RubySMB::SMB2::Packet::ErrorPacket.new
    response.smb2_header.message_id = header.message_id
    response.smb2_header.credits = 1
    response.smb2_header.session_id = header.session_id
    response.smb2_header.nt_status = status.value
    response.to_binary_s
  end

  def start_generation
    @generation_index += 1
    @current_generation = {
      generation: @generation_index,
      session_id: rand(1..0xfffffffe),
      challenge: @challenges.fetch(@generation_index),
      session_key: nil
    }
    if @dialect == 0x0311
      # The first generation continues the negotiate hash; every later generation starts
      # from a fresh all-zero hash after the client reset the preauthentication context.
      @current_generation[:preauth_hash] =
        if @generation_index.zero? && @negotiate_preauth_hash
          @negotiate_preauth_hash.dup
        else
          "\x00" * 64
        end
    end
  end

  # Mirrors the client's update_preauth_hash for the session setup exchange so the fake
  # server can independently compute the same hash each generation must use.
  def track_preauth_hash(type1_request, type2_response)
    hash = @current_generation[:preauth_hash]
    hash = OpenSSL::Digest.digest('SHA512', hash + type1_request.to_binary_s)
    hash = OpenSSL::Digest.digest('SHA512', hash + type2_response.to_binary_s)
    @current_generation[:preauth_hash] = hash
  end

  def finalize_preauth_hash(type3_request)
    hash = OpenSSL::Digest.digest(
      'SHA512',
      @current_generation[:preauth_hash] + type3_request.to_binary_s
    )
    @current_generation[:preauth_hash] = hash
    @preauth_hashes ||= {}
    @preauth_hashes[@current_generation[:generation]] = hash
  end

  # Pulls the raw NTLMSSP message out of the SPNEGO-wrapped security buffer.
  def extract_ntlm(gss_blob)
    asn = OpenSSL::ASN1.decode(gss_blob)
    type1 = RubySMB::Gss.asn1dig(asn, 1, 0, 1, 0)
    return type1.value unless type1.nil?

    neg_token_init = Hash[
      RubySMB::Gss.asn1dig(asn, 0).value.map { |obj| [obj.tag, obj.value[0].value] }
    ]
    neg_token_init[2]
  end

  # Computes the NTLM session key from the Type3 response, mirroring the calculation a
  # real Windows server performs (MS-NLMP). The Type3 user field is already UTF-16LE.
  def derive_session_key(type3)
    their_proof = type3.ntlm_response[0...16]
    their_blob = type3.ntlm_response[16..-1]

    ntlmv2_hash = Net::NTLM.ntlmv2_hash(
      type3.user.b,
      Net::NTLM::EncodeUtil.encode_utf16le(@password),
      type3.domain.dup.force_encoding('ASCII-8BIT'),
      { client_challenge: their_blob[16...24], unicode: true }
    )

    proof = OpenSSL::HMAC.digest(
      OpenSSL::Digest::MD5.new,
      ntlmv2_hash,
      @current_generation[:challenge] + their_blob
    )
    raise 'NTLMv2 proof mismatch' unless proof == their_proof

    user_session_key = OpenSSL::HMAC.digest(OpenSSL::Digest::MD5.new, ntlmv2_hash, proof)
    rc4 = OpenSSL::Cipher.new('rc4')
    rc4.decrypt
    rc4.key = user_session_key
    rc4.update(type3.session_key) << rc4.final
  end
end
