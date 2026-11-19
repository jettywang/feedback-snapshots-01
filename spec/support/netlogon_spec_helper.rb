# Helpers shared by the Netlogon challenge / credential specs.
module NetlogonSpecHelper
  # @return [String] the raw bytes for a lowercase hex string
  def binary(hex_string)
    [hex_string].pack('H*')
  end

  # Wrap a typed Netlogon stub in the DCERPC Request envelope the client puts
  # on the wire (call_id 1, p_cont_id 0).
  def netlogon_request_pdu(stub)
    request = RubySMB::Dcerpc::Request.new({ opnum: stub.opnum, p_cont_id: 0 }, { endpoint: 'Netlogon' })
    request.pdu_header.call_id = 1
    request.stub.read(stub.to_binary_s)
    request.to_binary_s
  end

  # Build an Authenticate3 request PDU with an arbitrary credential so negative
  # cases do not depend on a committed literal.
  def netlogon_authenticate_pdu(credential, flags: NetlogonVectors::ACCEPTED_FLAGS,
                                account_name: NetlogonVectors::ACCOUNT_NAME,
                                computer_name: NetlogonVectors::COMPUTER_NAME, secure_channel_type: 6)
    stub = RubySMB::Dcerpc::Netlogon::NetrServerAuthenticate3Request.new(
      primary_name: NetlogonVectors::PRIMARY_NAME,
      account_name: account_name,
      secure_channel_type: secure_channel_type,
      computer_name: computer_name,
      client_credential: credential,
      flags: flags
    )
    netlogon_request_pdu(stub)
  end

  def netlogon_response(pdu_bytes)
    RubySMB::Dcerpc::Response.read(pdu_bytes)
  end

  def netlogon_response_stub(pdu_bytes)
    netlogon_response(pdu_bytes).stub.to_binary_s
  end

  def netlogon_authenticate_response(pdu_bytes)
    RubySMB::Dcerpc::Netlogon::NetrServerAuthenticate3Response.read(netlogon_response_stub(pdu_bytes))
  end

  def netlogon_challenge_response(pdu_bytes)
    RubySMB::Dcerpc::Netlogon::NetrServerReqChallengeResponse.read(netlogon_response_stub(pdu_bytes))
  end

  def netlogon_dsr_response(pdu_bytes)
    RubySMB::Dcerpc::Netlogon::DsrGetDcNameEx2Response.read(netlogon_response_stub(pdu_bytes))
  end
end
