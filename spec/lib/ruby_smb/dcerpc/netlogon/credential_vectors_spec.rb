require 'spec_helper'

# These examples pin the Netlogon challenge -> session key -> credential chain
# to values derived outside this implementation (see
# spec/support/netlogon_vectors.rb). They intentionally avoid len-only or
# idempotence assertions: every expectation is a full byte string.
RSpec.describe 'Netlogon challenge and credential vectors' do
  include NetlogonSpecHelper

  let(:vectors) { NetlogonVectors }

  describe RubySMB::Dcerpc::Netlogon do
    describe '.calculate_session_key' do
      it 'derives the published session A key from the ordered challenges' do
        key = described_class.calculate_session_key(
          vectors::SHARED_SECRET,
          vectors::CLIENT_CHALLENGE_A,
          vectors::SERVER_CHALLENGE_A
        )
        expect(key).to eq vectors::SESSION_KEY_A
        expect(key.unpack1('H*')).to eq '4e7a918525b92da8ed4b4f264a130726'
      end

      it 'derives an independent key for a second session on the same secret' do
        expect(
          described_class.calculate_session_key(
            vectors::SHARED_SECRET,
            vectors::CLIENT_CHALLENGE_B,
            vectors::SERVER_CHALLENGE_B
          )
        ).to eq vectors::SESSION_KEY_B
      end

      it 'is order sensitive: swapping client and server challenges changes the key' do
        swapped = described_class.calculate_session_key(
          vectors::SHARED_SECRET,
          vectors::SERVER_CHALLENGE_A,
          vectors::CLIENT_CHALLENGE_A
        )
        expect(swapped).to eq vectors::SWAPPED_ORDER_KEY
        expect(swapped).to_not eq vectors::SESSION_KEY_A
      end

      it 'is byte-order sensitive: reversing the client challenge changes the key' do
        reversed = described_class.calculate_session_key(
          vectors::SHARED_SECRET,
          vectors::REVERSED_CLIENT_CHALLENGE,
          vectors::SERVER_CHALLENGE_A
        )
        expect(reversed).to eq vectors::REVERSED_CLIENT_KEY
        expect(reversed).to_not eq vectors::SESSION_KEY_A
      end

      it 'is byte-order sensitive: reversing the server challenge changes the key' do
        reversed = described_class.calculate_session_key(
          vectors::SHARED_SECRET,
          vectors::CLIENT_CHALLENGE_A,
          vectors::REVERSED_SERVER_CHALLENGE
        )
        expect(reversed).to eq vectors::REVERSED_SERVER_KEY
        expect(reversed).to_not eq vectors::SESSION_KEY_A
      end

      it 'accepts NetlogonCredential fields and treats them as the same bytes' do
        field = RubySMB::Dcerpc::Netlogon::NetlogonCredential.new(vectors::CLIENT_CHALLENGE_A)
        key = described_class.calculate_session_key(
          vectors::SHARED_SECRET,
          field,
          vectors::SERVER_CHALLENGE_A
        )
        expect(key).to eq vectors::SESSION_KEY_A
      end

      it 'only uses the first 16 bytes of the HMAC output' do
        key = described_class.calculate_session_key(
          vectors::SHARED_SECRET,
          vectors::CLIENT_CHALLENGE_A,
          vectors::SERVER_CHALLENGE_A
        )
        full_hmac = OpenSSL::HMAC.digest(
          OpenSSL::Digest.new('SHA256'),
          vectors::SHARED_SECRET,
          vectors::CLIENT_CHALLENGE_A + vectors::SERVER_CHALLENGE_A
        )
        expect(key).to eq full_hmac[0, 16]
        expect(key).to_not eq full_hmac[0, 32]
      end
    end

    describe '.encrypt_credential' do
      it 'produces the published client credential for session A' do
        credential = described_class.encrypt_credential(vectors::SESSION_KEY_A, vectors::CLIENT_CHALLENGE_A)
        expect(credential).to eq vectors::CLIENT_CREDENTIAL_A
        expect(credential.unpack1('H*')).to eq '08ed8742c929cf56'
      end

      it 'produces the published server credential for session A' do
        credential = described_class.encrypt_credential(vectors::SESSION_KEY_A, vectors::SERVER_CHALLENGE_A)
        expect(credential).to eq vectors::SERVER_CREDENTIAL_A
        expect(credential.unpack1('H*')).to eq '8051352c53b7dd9e'
      end

      it 'produces different credentials for the two challenges of one session' do
        client = described_class.encrypt_credential(vectors::SESSION_KEY_A, vectors::CLIENT_CHALLENGE_A)
        server = described_class.encrypt_credential(vectors::SESSION_KEY_A, vectors::SERVER_CHALLENGE_A)
        expect(client).to_not eq server
      end

      it 'produces the published session B credentials' do
        expect(described_class.encrypt_credential(vectors::SESSION_KEY_B, vectors::CLIENT_CHALLENGE_B)).to eq(
          vectors::CLIENT_CREDENTIAL_B
        )
        expect(described_class.encrypt_credential(vectors::SESSION_KEY_B, vectors::SERVER_CHALLENGE_B)).to eq(
          vectors::SERVER_CREDENTIAL_B
        )
      end

      it 'produces the published credentials under a swapped challenge order' do
        expect(
          described_class.encrypt_credential(vectors::SWAPPED_ORDER_KEY, vectors::SERVER_CHALLENGE_A)
        ).to eq vectors::SWAPPED_ORDER_CREDENTIAL
      end

      it 'rejects session A client credentials encrypted with the session B key' do
        foreign = described_class.encrypt_credential(vectors::SESSION_KEY_B, vectors::CLIENT_CHALLENGE_A)
        expect(foreign).to eq vectors::FOREIGN_SESSION_CREDENTIAL
        expect(foreign).to_not eq vectors::CLIENT_CREDENTIAL_A
      end

      it 'rejects session A credentials when the key was derived from reversed client bytes' do
        mixed = described_class.encrypt_credential(vectors::REVERSED_CLIENT_KEY, vectors::CLIENT_CHALLENGE_A)
        expect(mixed).to eq vectors::MIXED_BYTE_ORDER_CREDENTIAL
        expect(mixed).to_not eq vectors::CLIENT_CREDENTIAL_A
      end

      it 'produces the published credential for the reversed client challenge' do
        expect(
          described_class.encrypt_credential(vectors::REVERSED_CLIENT_KEY, vectors::REVERSED_CLIENT_CHALLENGE)
        ).to eq vectors::REVERSED_CLIENT_CREDENTIAL
      end
    end
  end

  describe 'challenge bytes on the wire' do
    let(:client_challenge_field) do
      RubySMB::Dcerpc::Netlogon::NetlogonCredential.new(vectors::CLIENT_CHALLENGE_A)
    end

    it 'keeps the client challenge byte order rather than swapping or reversing it' do
      expect(client_challenge_field.to_binary_s).to eq vectors::CLIENT_CHALLENGE_A
      expect(client_challenge_field.to_binary_s.unpack1('H*')).to eq '0011223344556677'
    end

    it 'keeps the server challenge byte order in the response structure' do
      response = RubySMB::Dcerpc::Netlogon::NetrServerReqChallengeResponse.new(
        server_challenge: vectors::SERVER_CHALLENGE_A,
        error_status: 0
      )
      parsed = RubySMB::Dcerpc::Netlogon::NetrServerReqChallengeResponse.read(response.to_binary_s)
      expect(parsed.server_challenge.to_binary_s).to eq vectors::SERVER_CHALLENGE_A
      expect(parsed.server_challenge.to_binary_s.unpack1('H*')).to eq '8899aabbccddeeff'
    end

    it 'serializes an authenticator as credential bytes followed by the timestamp' do
      authenticator = RubySMB::Dcerpc::Netlogon::NetlogonAuthenticator.new(
        credential: vectors::CLIENT_CREDENTIAL_A,
        timestamp: vectors::AUTHENTICATOR_TIMESTAMP
      )
      expect(authenticator.to_binary_s.unpack1('H*')).to eq '08ed8742c929cf5644332211'
    end

    it 'encodes the secure channel type as a 16-bit little-endian enum' do
      expect(
        RubySMB::Dcerpc::Netlogon::NetlogonSecureChannelType.new(
          RubySMB::Dcerpc::Netlogon::NetlogonSecureChannelType::SERVER_SECURE_CHANNEL
        ).to_binary_s.unpack1('H*')
      ).to eq '0600'
    end

    it 'encodes the negotiation flags as a 32-bit little-endian integer' do
      response = RubySMB::Dcerpc::Netlogon::NetrServerAuthenticate3Response.new(
        server_credential: vectors::SERVER_CREDENTIAL_A,
        negotiate_flags: vectors::ACCEPTED_FLAGS,
        account_rid: vectors::SERVER_RID,
        error_status: 0
      )
      expect(response.to_binary_s.unpack1('H*')).to eq(
        '8051352c53b7dd9e' + 'ffff2f21' + 'e8030000' + '00000000'
      )
    end

    it 'preserves a seeded challenge exactly when read back from a Request PDU' do
      stub = RubySMB::Dcerpc::Netlogon::NetrServerReqChallengeRequest.new(
        primary_name: vectors::PRIMARY_NAME,
        computer_name: vectors::COMPUTER_NAME,
        client_challenge: vectors::CLIENT_CHALLENGE_A
      )
      pdu = netlogon_request_pdu(stub)
      parsed = RubySMB::Dcerpc::Request.read(pdu, endpoint: 'Netlogon')
      expect(parsed.stub.client_challenge.to_binary_s).to eq vectors::CLIENT_CHALLENGE_A
      expect(parsed.stub.computer_name.to_s.encode('UTF-8')).to eq vectors::COMPUTER_NAME
    end

    it 'decodes a committed challenge request PDU into the documented fields' do
      pdu = binary(vectors::CHALLENGE_REQUEST_PDU)
      parsed = RubySMB::Dcerpc::Request.read(pdu, endpoint: 'Netlogon')
      expect(parsed.opnum).to eq RubySMB::Dcerpc::Netlogon::NETR_SERVER_REQ_CHALLENGE
      expect(parsed.pdu_header.call_id).to eq 1
      expect(parsed.stub.primary_name.to_s.encode('UTF-8')).to eq vectors::PRIMARY_NAME
      expect(parsed.stub.computer_name.to_s.encode('UTF-8')).to eq vectors::COMPUTER_NAME
      expect(parsed.stub.client_challenge.to_binary_s).to eq vectors::CLIENT_CHALLENGE_A
    end

    it 'decodes a committed authenticate request PDU into the documented fields' do
      pdu = binary(vectors::AUTHENTICATE_REQUEST_PDU)
      parsed = RubySMB::Dcerpc::Request.read(pdu, endpoint: 'Netlogon')
      expect(parsed.opnum).to eq RubySMB::Dcerpc::Netlogon::NETR_SERVER_AUTHENTICATE3
      expect(parsed.stub.primary_name.to_s.encode('UTF-8')).to eq vectors::PRIMARY_NAME
      expect(parsed.stub.account_name.to_s.encode('UTF-8')).to eq vectors::ACCOUNT_NAME
      expect(parsed.stub.computer_name.to_s.encode('UTF-8')).to eq vectors::COMPUTER_NAME
      expect(parsed.stub.secure_channel_type.value).to eq 6
      expect(parsed.stub.flags.value).to eq vectors::ACCEPTED_FLAGS
      expect(parsed.stub.client_credential.to_binary_s).to eq vectors::CLIENT_CREDENTIAL_A
    end
  end
end
