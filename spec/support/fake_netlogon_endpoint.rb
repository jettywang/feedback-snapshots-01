# An in-memory DCERPC endpoint for the Netlogon interface. It consumes the
# serialized Request PDU a caller would put on the wire and answers with a
# serialized Response PDU; no socket, session setup or password operation is
# involved.
#
# The endpoint deliberately re-derives the session key and credentials from
# OpenSSL primitives instead of calling RubySMB::Dcerpc::Netlogon helpers. That
# way the specs compare two independent implementations rather than asserting
# that the library agrees with itself.
class FakeNetlogonEndpoint
  STATUS_SUCCESS = 0x00000000
  STATUS_ACCESS_DENIED = 0xC0000022
  NETLOGON_HEADER_SIZE = 24

  attr_reader :session_key, :client_challenge, :server_challenge

  # @param secret [String] shared secret (a test constant)
  # @param server_challenge [String] the 8 byte challenge this endpoint returns
  # @param accepted_flags [Integer] the capability bits this endpoint supports
  # @param subsequent_server_challenge [String, nil] when set, the challenge
  #   returned after the first exchange; used to model a re-issued challenge
  #   that produces a different session key on the same endpoint
  def initialize(secret:, server_challenge:, accepted_flags: NetlogonVectors::SERVER_CAPABILITIES,
                 subsequent_server_challenge: nil)
    @secret = secret
    @server_challenge = server_challenge
    @subsequent_server_challenge = subsequent_server_challenge
    @accepted_flags = accepted_flags
    @challenge_seen = false
    @authenticated = false
    @session_key = nil
    @client_challenge = nil
  end

  # @return [Boolean] whether the most recent Authenticate3 succeeded
  def authenticated?
    @authenticated
  end

  # Feed one serialized Request PDU in and get one serialized Response PDU out.
  def call(request_bytes)
    request = RubySMB::Dcerpc::Request.read(request_bytes, endpoint: 'Netlogon')
    raise ArgumentError, 'the double only handles call_id 1' unless request.pdu_header.call_id == 1

    body =
      case request.opnum
      when RubySMB::Dcerpc::Netlogon::NETR_SERVER_REQ_CHALLENGE
        handle_challenge(request)
      when RubySMB::Dcerpc::Netlogon::NETR_SERVER_AUTHENTICATE3
        handle_authenticate(request)
      when RubySMB::Dcerpc::Netlogon::DSR_GET_DC_NAME_EX2
        handle_dsr(request_bytes, request)
      else
        raise ArgumentError, "unexpected Netlogon opnum #{request.opnum}"
      end

    response(body)
  end

  # The raw stub bytes of a parsed request. Opnum 34 has no registered stub
  # type in Request#stub, so the double slices from the fixed header size.
  def self.request_stub_bytes(request_bytes, request)
    request_bytes[NETLOGON_HEADER_SIZE, request.pdu_header.frag_length - NETLOGON_HEADER_SIZE]
  end

  private

  def handle_challenge(request)
    stub = request.stub
    if @challenge_seen && @subsequent_server_challenge
      @server_challenge = @subsequent_server_challenge
    end
    @client_challenge = stub.client_challenge.to_binary_s
    @session_key = derive_session_key(@client_challenge, @server_challenge)
    @challenge_seen = names_match?(stub)
    @authenticated = false

    RubySMB::Dcerpc::Netlogon::NetrServerReqChallengeResponse.new(
      server_challenge: @server_challenge,
      error_status: @challenge_seen ? STATUS_SUCCESS : STATUS_ACCESS_DENIED
    )
  end

  def handle_authenticate(request)
    stub = request.stub
    expected_credential = @session_key && encrypt(@session_key, @client_challenge)
    flags = stub.flags.value

    accepted =
      @challenge_seen &&
      expected_credential &&
      stub.client_credential.to_binary_s == expected_credential &&
      names_match?(stub) &&
      stub.account_name.to_s.encode('UTF-8') == NetlogonVectors::ACCOUNT_NAME &&
      stub.secure_channel_type.value == RubySMB::Dcerpc::Netlogon::NetlogonSecureChannelType::SERVER_SECURE_CHANNEL &&
      flags != 0 &&
      (flags & ~@accepted_flags) == 0

    if accepted
      @authenticated = true
      RubySMB::Dcerpc::Netlogon::NetrServerAuthenticate3Response.new(
        server_credential: encrypt(@session_key, @server_challenge),
        negotiate_flags: flags & @accepted_flags,
        account_rid: NetlogonVectors::SERVER_RID,
        error_status: STATUS_SUCCESS
      )
    else
      @authenticated = false
      RubySMB::Dcerpc::Netlogon::NetrServerAuthenticate3Response.new(
        server_credential: "\x00".b * 8,
        negotiate_flags: 0,
        account_rid: 0,
        error_status: STATUS_ACCESS_DENIED
      )
    end
  end

  def handle_dsr(request_bytes, request)
    parsed = RubySMB::Dcerpc::Netlogon::DsrGetDcNameEx2Request.read(
      self.class.request_stub_bytes(request_bytes, request)
    )

    if @authenticated && parsed.computer_name.to_s.encode('UTF-8') == NetlogonVectors::PRIMARY_NAME
      info = RubySMB::Dcerpc::Netlogon::DomainControllerInfoW.new(
        domain_controller_name: '\\\\DC01',
        domain_controller_address: '10.0.0.10',
        domain_controller_address_type: 1,
        domain_name: 'example.test',
        dns_forest_name: 'example.test',
        flags: 0,
        dc_site_name: 'Default-First-Site-Name',
        client_site_name: 'Default-First-Site-Name'
      )
      RubySMB::Dcerpc::Netlogon::DsrGetDcNameEx2Response.new(
        domain_controller_info: info,
        error_status: STATUS_SUCCESS
      )
    else
      RubySMB::Dcerpc::Netlogon::DsrGetDcNameEx2Response.new(
        domain_controller_info: :null,
        error_status: STATUS_ACCESS_DENIED
      )
    end
  end

  def names_match?(stub)
    stub.primary_name.to_s.encode('UTF-8') == NetlogonVectors::PRIMARY_NAME &&
      stub.computer_name.to_s.encode('UTF-8') == NetlogonVectors::COMPUTER_NAME
  end

  def derive_session_key(client_challenge, server_challenge)
    digest = OpenSSL::HMAC.digest(
      OpenSSL::Digest.new('SHA256'),
      @secret,
      client_challenge + server_challenge
    )
    digest.byteslice(0, 16)
  end

  def encrypt(key, data)
    cipher = OpenSSL::Cipher.new('AES-128-CFB8').encrypt
    cipher.iv = "\x00".b * 16
    cipher.key = key
    cipher.update(data) + cipher.final
  end

  def response(body)
    response = RubySMB::Dcerpc::Response.new
    response.p_cont_id = 0
    response.pdu_header.call_id = 1
    response.stub = body.to_binary_s
    response.to_binary_s
  end
end
