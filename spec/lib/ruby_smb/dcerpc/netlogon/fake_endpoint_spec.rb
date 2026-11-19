require 'spec_helper'

# Exercises the challenge -> credential -> authenticate chain against an
# in-memory DCERPC endpoint. The endpoint (spec/support/fake_netlogon_endpoint.rb)
# consumes serialized Request PDUs and re-derives keys with OpenSSL directly, so
# these examples check the wire format and the authentication state machine
# instead of re-running the same helper twice.
RSpec.describe 'Netlogon authentication over an in-memory RPC double' do
  include NetlogonSpecHelper

  let(:vectors) { NetlogonVectors }

  subject(:endpoint) do
    FakeNetlogonEndpoint.new(
      secret: vectors::SHARED_SECRET,
      server_challenge: vectors::SERVER_CHALLENGE_A
    )
  end

  def open_session(challenge_pdu: binary(vectors::CHALLENGE_REQUEST_PDU))
    endpoint.call(challenge_pdu)
  end

  # Perform a complete, accepted exchange so later requests can be judged
  # against an established session.
  def authenticate_session
    open_session
    endpoint.call(binary(vectors::AUTHENTICATE_REQUEST_PDU))
  end

  describe 'challenge exchange' do
    it 'answers the committed challenge request with the committed response bytes' do
      expect(open_session.unpack1('H*')).to eq vectors::CHALLENGE_RESPONSE_PDU
    end

    it 'returns the server challenge unchanged, in little-endian field order' do
      parsed = netlogon_challenge_response(open_session)
      expect(parsed.server_challenge.to_binary_s).to eq vectors::SERVER_CHALLENGE_A
      expect(parsed.server_challenge.to_binary_s.unpack1('H*')).to eq '8899aabbccddeeff'
      expect(parsed.error_status.value).to eq 0
    end

    it 'derives the published session A key from the challenge it actually saw' do
      open_session
      expect(endpoint.client_challenge).to eq vectors::CLIENT_CHALLENGE_A
      expect(endpoint.session_key).to eq vectors::SESSION_KEY_A
      expect(endpoint.session_key.unpack1('H*')).to eq '4e7a918525b92da8ed4b4f264a130726'
    end

    it 'derives a different key for the second committed session' do
      other = FakeNetlogonEndpoint.new(
        secret: vectors::SHARED_SECRET,
        server_challenge: vectors::SERVER_CHALLENGE_B
      )
      other.call(binary(vectors::CHALLENGE_REQUEST_B_PDU))
      expect(other.session_key).to eq vectors::SESSION_KEY_B
      expect(other.session_key).to_not eq vectors::SESSION_KEY_A
    end

    it 'refuses a challenge directed at another computer name' do
      response = open_session(challenge_pdu: binary(vectors::CHALLENGE_OTHER_COMPUTER_REQUEST_PDU))
      expect(response.unpack1('H*')).to eq vectors::CHALLENGE_DENIED_RESPONSE_PDU
      expect(netlogon_challenge_response(response).error_status.value).to eq 0xc0000022
      expect(endpoint.authenticated?).to be false
    end

    it 'refuses the client credential when the challenge was rejected' do
      open_session(challenge_pdu: binary(vectors::CHALLENGE_OTHER_COMPUTER_REQUEST_PDU))
      response = endpoint.call(binary(vectors::AUTHENTICATE_REQUEST_PDU))
      expect(response.unpack1('H*')).to eq vectors::AUTHENTICATE_FAILURE_RESPONSE_PDU
      expect(endpoint.authenticated?).to be false
    end
  end

  describe 'authenticate exchange' do
    it 'accepts the committed authenticate PDU and returns the committed response bytes' do
      open_session
      response = endpoint.call(binary(vectors::AUTHENTICATE_REQUEST_PDU))
      expect(response.unpack1('H*')).to eq vectors::AUTHENTICATE_RESPONSE_PDU
      expect(endpoint.authenticated?).to be true
    end

    it 'reports the accepted capabilities, account RID and server credential' do
      open_session
      parsed = netlogon_authenticate_response(endpoint.call(binary(vectors::AUTHENTICATE_REQUEST_PDU)))
      expect(parsed.error_status.value).to eq 0
      expect(parsed.negotiate_flags.value).to eq vectors::ACCEPTED_FLAGS
      expect(parsed.negotiate_flags.to_binary_s.unpack1('H*')).to eq 'ffff2f21'
      expect(parsed.account_rid.value).to eq vectors::SERVER_RID
      expect(parsed.server_credential.to_binary_s).to eq vectors::SERVER_CREDENTIAL_A
      expect(parsed.server_credential.to_binary_s.unpack1('H*')).to eq '8051352c53b7dd9e'
    end

    it 'accepts a client credential that matches the session key locally' do
      open_session
      credential = RubySMB::Dcerpc::Netlogon.encrypt_credential(endpoint.session_key, vectors::CLIENT_CHALLENGE_A)
      response = endpoint.call(netlogon_authenticate_pdu(credential))
      expect(netlogon_authenticate_response(response).error_status.value).to eq 0
      expect(endpoint.authenticated?).to be true
    end

    it 'negotiates the server capability subset without inventing capabilities' do
      open_session
      response = endpoint.call(binary(vectors::AUTHENTICATE_SUBSET_FLAGS_REQUEST_PDU))
      expect(response.unpack1('H*')).to eq vectors::AUTHENTICATE_SUBSET_FLAGS_RESPONSE_PDU
      parsed = netlogon_authenticate_response(response)
      expect(parsed.negotiate_flags.value).to eq vectors::SUBSET_FLAGS
      expect(parsed.negotiate_flags.value & ~vectors::SERVER_CAPABILITIES).to eq 0
      expect(endpoint.authenticated?).to be true
    end

    context 'when the credential belongs to another session' do
      it 'rejects session A client credentials encrypted with the session B key' do
        open_session
        response = endpoint.call(binary(vectors::AUTHENTICATE_FOREIGN_SESSION_REQUEST_PDU))
        expect(response.unpack1('H*')).to eq vectors::AUTHENTICATE_FAILURE_RESPONSE_PDU
        parsed = netlogon_authenticate_response(response)
        expect(parsed.error_status.value).to eq 0xc0000022
        expect(parsed.server_credential.to_binary_s).to eq("\x00".b * 8)
        expect(parsed.negotiate_flags.value).to eq 0
        expect(endpoint.authenticated?).to be false
      end

      it 'does not mark the session authenticated after the rejected request' do
        open_session
        endpoint.call(binary(vectors::AUTHENTICATE_FOREIGN_SESSION_REQUEST_PDU))
        expect(endpoint.authenticated?).to be false
      end

      it 'still rejects the foreign credential after a legitimate session is established' do
        authenticate_session
        expect(endpoint.authenticated?).to be true
        response = endpoint.call(binary(vectors::AUTHENTICATE_FOREIGN_SESSION_REQUEST_PDU))
        expect(netlogon_authenticate_response(response).error_status.value).to eq 0xc0000022
        expect(endpoint.authenticated?).to be false
      end
    end

    context 'when the challenge order or byte order was mixed up' do
      it 'rejects the credential derived from the swapped challenge order' do
        open_session
        response = endpoint.call(binary(vectors::AUTHENTICATE_SWAPPED_ORDER_REQUEST_PDU))
        expect(netlogon_authenticate_response(response).error_status.value).to eq 0xc0000022
        expect(endpoint.authenticated?).to be false
      end

      it 'rejects the credential derived from reversed challenge bytes' do
        open_session
        response = endpoint.call(binary(vectors::AUTHENTICATE_REVERSED_DATA_REQUEST_PDU))
        expect(netlogon_authenticate_response(response).error_status.value).to eq 0xc0000022
        expect(endpoint.authenticated?).to be false
      end
    end

    context 'when the request names do not match the challenge context' do
      it 'rejects an authenticating account that differs from the negotiated one' do
        open_session
        response = endpoint.call(binary(vectors::AUTHENTICATE_OTHER_ACCOUNT_REQUEST_PDU))
        expect(netlogon_authenticate_response(response).error_status.value).to eq 0xc0000022
        expect(endpoint.authenticated?).to be false
      end

      it 'rejects a workstation name that differs from the challenge context' do
        open_session
        response = endpoint.call(binary(vectors::AUTHENTICATE_OTHER_COMPUTER_REQUEST_PDU))
        expect(netlogon_authenticate_response(response).error_status.value).to eq 0xc0000022
        expect(endpoint.authenticated?).to be false
      end

      it 'rejects a secure channel type other than the server channel' do
        open_session
        response = endpoint.call(binary(vectors::AUTHENTICATE_OTHER_CHANNEL_REQUEST_PDU))
        expect(netlogon_authenticate_response(response).error_status.value).to eq 0xc0000022
        expect(endpoint.authenticated?).to be false
      end
    end

    context 'when the requested capabilities are not acceptable' do
      it 'rejects a request that advertises no capabilities at all' do
        open_session
        response = endpoint.call(binary(vectors::AUTHENTICATE_ZERO_FLAGS_REQUEST_PDU))
        expect(netlogon_authenticate_response(response).error_status.value).to eq 0xc0000022
        expect(endpoint.authenticated?).to be false
      end

      it 'rejects a request that advertises bits the server does not support' do
        open_session
        response = endpoint.call(binary(vectors::AUTHENTICATE_EXTRA_FLAGS_REQUEST_PDU))
        expect(netlogon_authenticate_response(response).error_status.value).to eq 0xc0000022
        expect(netlogon_authenticate_response(response).negotiate_flags.value).to eq 0
        expect(endpoint.authenticated?).to be false
      end
    end

    it 'refuses an authenticate request that arrives before any challenge' do
      response = endpoint.call(binary(vectors::AUTHENTICATE_REQUEST_PDU))
      expect(response.unpack1('H*')).to eq vectors::AUTHENTICATE_FAILURE_RESPONSE_PDU
      expect(endpoint.authenticated?).to be false
    end

    it 'does not let a later request inherit authentication from an earlier success' do
      authenticate_session
      expect(endpoint.authenticated?).to be true

      endpoint.call(binary(vectors::AUTHENTICATE_FOREIGN_SESSION_REQUEST_PDU))
      expect(endpoint.authenticated?).to be false

      dsr = RubySMB::Dcerpc::Netlogon::DsrGetDcNameEx2Response.read(
        netlogon_response_stub(endpoint.call(binary(vectors::DSR_REQUEST_PDU)))
      )
      expect(dsr.error_status.value).to eq 0xc0000022
      expect(dsr.domain_controller_info).to eq :null
    end

    it 'drops authentication when a re-issued challenge produces a different key' do
      endpoint = FakeNetlogonEndpoint.new(
        secret: vectors::SHARED_SECRET,
        server_challenge: vectors::SERVER_CHALLENGE_A,
        subsequent_server_challenge: vectors::SERVER_CHALLENGE_B
      )

      endpoint.call(binary(vectors::CHALLENGE_REQUEST_PDU))
      endpoint.call(binary(vectors::AUTHENTICATE_REQUEST_PDU))
      expect(endpoint.authenticated?).to be true

      reissued = netlogon_challenge_response(endpoint.call(binary(vectors::CHALLENGE_REQUEST_PDU)))
      expect(reissued.server_challenge.to_binary_s).to eq vectors::SERVER_CHALLENGE_B
      expect(endpoint.session_key).to eq vectors::CROSS_SESSION_KEY

      # The old session A credential must not authenticate under the new key.
      replay = endpoint.call(binary(vectors::AUTHENTICATE_REQUEST_PDU))
      expect(netlogon_authenticate_response(replay).error_status.value).to eq 0xc0000022

      # The credential for the new challenge/key pair is accepted in its place.
      credential = RubySMB::Dcerpc::Netlogon.encrypt_credential(endpoint.session_key, vectors::CLIENT_CHALLENGE_A)
      expect(credential).to eq vectors::CROSS_SESSION_CREDENTIAL
      accepted = endpoint.call(netlogon_authenticate_pdu(credential))
      parsed = netlogon_authenticate_response(accepted)
      expect(parsed.error_status.value).to eq 0
      expect(parsed.server_credential.to_binary_s).to eq vectors::CROSS_SESSION_SERVER_CREDENTIAL
      expect(endpoint.authenticated?).to be true
    end

    it 'drops authentication when a challenge from another session replaces the key' do
      authenticate_session
      expect(endpoint.authenticated?).to be true

      other = FakeNetlogonEndpoint.new(
        secret: vectors::SHARED_SECRET,
        server_challenge: vectors::SERVER_CHALLENGE_B
      )
      other.call(binary(vectors::CHALLENGE_REQUEST_B_PDU))
      expect(other.session_key).to eq vectors::SESSION_KEY_B
      expect(endpoint.session_key).to eq vectors::SESSION_KEY_A

      # Session A's credential must not authenticate on the session B endpoint.
      foreign = other.call(binary(vectors::AUTHENTICATE_REQUEST_PDU))
      expect(netlogon_authenticate_response(foreign).error_status.value).to eq 0xc0000022
      expect(other.authenticated?).to be false
    end
  end

  describe 'safety of the double' do
    it 'never opens a socket while running a full exchange' do
      expect(TCPSocket).to_not receive(:new)

      authenticate_session
      endpoint.call(binary(vectors::DSR_REQUEST_PDU))
    end

    it 'never delegates key derivation or encryption to the library under test' do
      expect(RubySMB::Dcerpc::Netlogon).to_not receive(:calculate_session_key)
      expect(RubySMB::Dcerpc::Netlogon).to_not receive(:encrypt_credential)

      open_session
      endpoint.call(binary(vectors::AUTHENTICATE_REQUEST_PDU))
      expect(endpoint.authenticated?).to be true
    end

    it 'has no password-set operation and ignores such a request without authenticating' do
      stub = RubySMB::Dcerpc::Netlogon::NetrServerPasswordSet2Request.new(
        primary_name: vectors::PRIMARY_NAME,
        account_name: vectors::ACCOUNT_NAME,
        secure_channel_type: 6,
        computer_name: vectors::COMPUTER_NAME,
        authenticator: { credential: vectors::CLIENT_CREDENTIAL_A, timestamp: 0 },
        clear_new_password: "\x00".b * 516
      )
      expect { endpoint.call(netlogon_request_pdu(stub)) }.to raise_error(ArgumentError, /unexpected Netlogon opnum/)
      expect(endpoint.authenticated?).to be false
    end
  end

  describe 'subsequent authenticated request' do
    it 'returns STATUS_ACCESS_DENIED before the secure channel is established' do
      response = endpoint.call(binary(vectors::DSR_REQUEST_PDU))
      expect(response.unpack1('H*')).to eq vectors::DSR_DENIED_RESPONSE_PDU
      parsed = netlogon_dsr_response(response)
      expect(parsed.error_status.value).to eq 0xc0000022
      expect(parsed.domain_controller_info).to eq :null
    end

    it 'returns denied after an authenticate rejection' do
      open_session
      endpoint.call(binary(vectors::AUTHENTICATE_FOREIGN_SESSION_REQUEST_PDU))
      expect(endpoint.authenticated?).to be false

      parsed = netlogon_dsr_response(endpoint.call(binary(vectors::DSR_REQUEST_PDU)))
      expect(parsed.error_status.value).to eq 0xc0000022
      expect(parsed.domain_controller_info).to eq :null
    end

    it 'returns the committed success response only after authentication' do
      authenticate_session
      response = endpoint.call(binary(vectors::DSR_REQUEST_PDU))
      expect(response.unpack1('H*')).to eq vectors::DSR_SUCCESS_RESPONSE_PDU
    end

    it 'returns byte-identical field values for the established session' do
      authenticate_session
      parsed = netlogon_dsr_response(endpoint.call(binary(vectors::DSR_REQUEST_PDU)))
      info = parsed.domain_controller_info
      expect(parsed.error_status.value).to eq 0
      expect(info.domain_controller_name.to_s.encode('UTF-8')).to eq '\\\\DC01'
      expect(info.domain_controller_address.to_s.encode('UTF-8')).to eq '10.0.0.10'
      expect(info.domain_controller_address_type.value).to eq 1
      expect(info.domain_name.to_s.encode('UTF-8')).to eq 'example.test'
      expect(info.dns_forest_name.to_s.encode('UTF-8')).to eq 'example.test'
      expect(info.flags.value).to eq 0
      expect(info.dc_site_name.to_s.encode('UTF-8')).to eq 'Default-First-Site-Name'
      expect(info.client_site_name.to_s.encode('UTF-8')).to eq 'Default-First-Site-Name'
    end

    it 'matches the committed success stub byte for byte' do
      authenticate_session
      expect(netlogon_response_stub(endpoint.call(binary(vectors::DSR_REQUEST_PDU))).unpack1('H*')).to eq(
        vectors::DSR_SUCCESS_STUB
      )
    end
  end
end
