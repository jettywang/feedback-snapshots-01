require 'spec_helper'

RSpec.describe RubySMB::Client do
  describe 'inbound response signature verification' do
    let(:dispatcher)  { InMemoryDispatcher.new }
    let(:username)    { 'msfadmin' }
    let(:password)    { 'msfpasswd' }
    let(:session_key) { Random.new.bytes(16) }
    let(:session_id)  { 0x0000000000000042 }
    let(:share)       { '\\\\192.168.1.5\\share' }

    # Builds a raw SMB2/3 response, optionally signed with the given key
    def smb2_raw_response(packet_class, key: nil, sid: nil, sign: true, dialect: nil, preauth: nil)
      key ||= session_key
      sid ||= session_id
      response = packet_class.new
      response.smb2_header.session_id = sid
      response.smb2_header.nt_status  = WindowsError::NTStatus::STATUS_SUCCESS.value
      if sign
        if dialect.nil?
          RubySMB::Signing.smb2_sign(response, key)
        else
          RubySMB::Signing.smb3_sign(response, key, dialect, preauth)
        end
      end
      response.to_binary_s
    end

    # Returns a copy of the raw packet with one byte in the middle flipped
    def tamper(raw)
      tampered = raw.dup
      tampered.setbyte(raw.length / 2, tampered.getbyte(raw.length / 2) ^ 0xFF)
      tampered
    end

    context 'with an SMB2 session requiring signing' do
      let(:client) { described_class.new(dispatcher, smb1: false, smb3: false, username: username, password: password) }

      before :example do
        client.dialect          = RubySMB::Client::SMB2_DIALECT_0202
        client.signing_required = true
        client.session_key      = session_key
        client.session_id       = session_id
      end

      it 'accepts a correctly signed response' do
        dispatcher.queue_response(smb2_raw_response(RubySMB::SMB2::Packet::EchoResponse))
        expect(client.echo).to eq(WindowsError::NTStatus::STATUS_SUCCESS)
      end

      it 'rejects a response that is not signed' do
        dispatcher.queue_response(smb2_raw_response(RubySMB::SMB2::Packet::EchoResponse, sign: false))
        expect { client.echo }.to raise_error(RubySMB::Error::SigningError)
      end

      it 'rejects a response whose content was tampered with' do
        dispatcher.queue_response(tamper(smb2_raw_response(RubySMB::SMB2::Packet::EchoResponse)))
        expect { client.echo }.to raise_error(RubySMB::Error::SigningError)
      end

      it 'rejects a response signed with a different session key' do
        dispatcher.queue_response(smb2_raw_response(RubySMB::SMB2::Packet::EchoResponse, key: Random.new.bytes(16)))
        expect { client.echo }.to raise_error(RubySMB::Error::SigningError)
      end

      it 'rejects a response addressed to a different session' do
        dispatcher.queue_response(smb2_raw_response(RubySMB::SMB2::Packet::EchoResponse, sid: session_id + 1))
        expect { client.echo }.to raise_error(RubySMB::Error::SigningError)
      end

      it 'rejects a malformed response' do
        dispatcher.queue_response('A')
        expect { client.echo }.to raise_error(RubySMB::Error::SigningError)
      end

      it 'does not update the session state when verification fails' do
        client.server_supports_multi_credit = true
        response = RubySMB::SMB2::Packet::EchoResponse.new
        response.smb2_header.session_id    = session_id
        response.smb2_header.credit_charge = 5
        RubySMB::Signing.smb2_sign(response, session_key)
        dispatcher.queue_response(tamper(response.to_binary_s))

        expect { client.echo }.to raise_error(RubySMB::Error::SigningError)
        # only the send-side increment happened, the credit charge of the
        # untrusted response was not applied
        expect(client.smb2_message_id).to eq(1)
        expect(client.sequence_counter).to eq(0)
      end

      it 'allows the unsigned SessionSetupResponse handshake exception' do
        dispatcher.queue_response(smb2_raw_response(RubySMB::SMB2::Packet::SessionSetupResponse, sign: false))
        expect { client.send_recv(RubySMB::SMB2::Packet::SessionSetupRequest.new) }.to_not raise_error
      end

      it 'allows the unsigned NegotiateResponse handshake exception' do
        dispatcher.queue_response(smb2_raw_response(RubySMB::SMB2::Packet::NegotiateResponse, sign: false))
        expect { client.send_recv(RubySMB::SMB2::Packet::NegotiateRequest.new) }.to_not raise_error
      end

      context 'through the tree interface' do
        it 'accepts a correctly signed TreeConnectResponse' do
          dispatcher.queue_response(smb2_raw_response(RubySMB::SMB2::Packet::TreeConnectResponse))
          expect(client.tree_connect(share)).to be_a(RubySMB::SMB2::Tree)
        end

        it 'rejects a tampered TreeConnectResponse' do
          dispatcher.queue_response(tamper(smb2_raw_response(RubySMB::SMB2::Packet::TreeConnectResponse)))
          expect { client.tree_connect(share) }.to raise_error(RubySMB::Error::SigningError)
        end
      end

      context 'through the logoff interface' do
        it 'rejects a tampered LogoffResponse' do
          dispatcher.queue_response(tamper(smb2_raw_response(RubySMB::SMB2::Packet::LogoffResponse)))
          expect { client.logoff! }.to raise_error(RubySMB::Error::SigningError)
        end
      end

      context 'through the file interface' do
        let(:tree) do
          response = RubySMB::SMB2::Packet::TreeConnectResponse.new
          RubySMB::SMB2::Tree.new(client: client, share: share, response: response)
        end

        it 'rejects a tampered CreateResponse' do
          dispatcher.queue_response(tamper(smb2_raw_response(RubySMB::SMB2::Packet::CreateResponse)))
          expect { tree.open_file(filename: 'test.txt') }.to raise_error(RubySMB::Error::SigningError)
        end

        it 'rejects a tampered ReadResponse' do
          dispatcher.queue_response(smb2_raw_response(RubySMB::SMB2::Packet::CreateResponse))
          file = tree.open_file(filename: 'test.txt')
          dispatcher.queue_response(tamper(smb2_raw_response(RubySMB::SMB2::Packet::ReadResponse)))
          expect { file.read(bytes: 10) }.to raise_error(RubySMB::Error::SigningError)
        end
      end

      context 'through the pipe interface' do
        let(:tree) do
          response = RubySMB::SMB2::Packet::TreeConnectResponse.new
          RubySMB::SMB2::Tree.new(client: client, share: share, response: response)
        end

        it 'rejects a tampered response while opening the pipe' do
          dispatcher.queue_response(tamper(smb2_raw_response(RubySMB::SMB2::Packet::CreateResponse)))
          expect { tree.open_pipe(filename: 'srvsvc') }.to raise_error(RubySMB::Error::SigningError)
        end

        it 'rejects a tampered ReadResponse on the pipe' do
          dispatcher.queue_response(smb2_raw_response(RubySMB::SMB2::Packet::CreateResponse))
          pipe = tree.open_pipe(filename: 'srvsvc')
          dispatcher.queue_response(tamper(smb2_raw_response(RubySMB::SMB2::Packet::ReadResponse)))
          expect { pipe.read(bytes: 10) }.to raise_error(RubySMB::Error::SigningError)
        end
      end
    end

    context 'with an SMB3 session requiring signing' do
      let(:client) { described_class.new(dispatcher, smb1: false, smb2: false, username: username, password: password) }

      before :example do
        client.signing_required     = true
        client.session_key          = session_key
        client.session_id           = session_id
        client.session_encrypt_data = false
      end

      ['0x0300', '0x0302'].each do |dialect|
        context "with #{dialect} dialect" do
          before :example do
            client.dialect = dialect
          end

          it 'accepts a correctly signed response' do
            dispatcher.queue_response(smb2_raw_response(RubySMB::SMB2::Packet::EchoResponse, dialect: dialect))
            expect(client.echo).to eq(WindowsError::NTStatus::STATUS_SUCCESS)
          end

          it 'rejects a tampered response' do
            dispatcher.queue_response(tamper(smb2_raw_response(RubySMB::SMB2::Packet::EchoResponse, dialect: dialect)))
            expect { client.echo }.to raise_error(RubySMB::Error::SigningError)
          end

          it 'rejects a response signed with the SMB2 (HMAC-SHA256) algorithm' do
            dispatcher.queue_response(smb2_raw_response(RubySMB::SMB2::Packet::EchoResponse))
            expect { client.echo }.to raise_error(RubySMB::Error::SigningError)
          end
        end
      end

      context 'with 0x0311 dialect' do
        let(:preauth) { Random.new.bytes(64) }

        before :example do
          client.dialect                     = '0x0311'
          client.preauth_integrity_hash_value = preauth
        end

        it 'accepts a correctly signed response' do
          dispatcher.queue_response(smb2_raw_response(RubySMB::SMB2::Packet::EchoResponse, dialect: '0x0311', preauth: preauth))
          expect(client.echo).to eq(WindowsError::NTStatus::STATUS_SUCCESS)
        end

        it 'rejects a response signed with a different preauth integrity hash' do
          dispatcher.queue_response(smb2_raw_response(RubySMB::SMB2::Packet::EchoResponse, dialect: '0x0311', preauth: Random.new.bytes(64)))
          expect { client.echo }.to raise_error(RubySMB::Error::SigningError)
        end
      end

      context 'with an encrypted session' do
        let(:server_key) { RubySMB::Crypto::KDF.counter_mode(session_key, "SMB2AESCCM\x00", "ServerOut\x00") }

        before :example do
          client.dialect              = '0x0300'
          client.session_encrypt_data = true
          client.encryption_algorithm = 'AES-128-CCM'
        end

        def encrypt_response(raw_inner)
          transform_header = RubySMB::SMB2::Packet::TransformHeader.new(flags: 1, session_id: session_id)
          transform_header.encrypt(raw_inner, server_key, algorithm: 'AES-128-CCM')
          transform_header.to_binary_s
        end

        it 'accepts an encrypted response without a signature' do
          # encrypted messages are authenticated by the transform header and
          # are not required to be signed
          dispatcher.queue_response(encrypt_response(smb2_raw_response(RubySMB::SMB2::Packet::EchoResponse, sign: false)))
          expect(client.echo).to eq(WindowsError::NTStatus::STATUS_SUCCESS)
        end

        it 'rejects an encrypted response whose ciphertext was tampered with' do
          dispatcher.queue_response(tamper(encrypt_response(smb2_raw_response(RubySMB::SMB2::Packet::EchoResponse, sign: false))))
          expect { client.echo }.to raise_error(RubySMB::Error::EncryptionError)
        end
      end
    end

    context 'with an SMB1 session requiring signing' do
      let(:client)  { described_class.new(dispatcher, smb2: false, smb3: false, username: username, password: password) }
      let(:user_id) { 0x0800 }

      before :example do
        client.signing_required = true
        client.session_key      = session_key
        client.user_id          = user_id
      end

      # Builds a raw SMB1 response signed with the sequence counter the
      # server is expected to use (the request consumed counter 0)
      def smb1_raw_response(packet_class, key: nil, uid: nil, sequence_counter: 1, sign: true)
        key ||= session_key
        uid ||= user_id
        response = packet_class.new
        response.smb_header.uid       = uid
        response.smb_header.nt_status = WindowsError::NTStatus::STATUS_SUCCESS.value
        RubySMB::Signing.smb1_sign(response, key, sequence_counter) if sign
        response.to_binary_s
      end

      it 'accepts a correctly signed response' do
        dispatcher.queue_response(smb1_raw_response(RubySMB::SMB1::Packet::EchoResponse))
        expect(client.echo).to eq(WindowsError::NTStatus::STATUS_SUCCESS)
      end

      it 'rejects a response that is not signed' do
        dispatcher.queue_response(smb1_raw_response(RubySMB::SMB1::Packet::EchoResponse, sign: false))
        expect { client.echo }.to raise_error(RubySMB::Error::SigningError)
      end

      it 'rejects a response whose content was tampered with' do
        dispatcher.queue_response(tamper(smb1_raw_response(RubySMB::SMB1::Packet::EchoResponse)))
        expect { client.echo }.to raise_error(RubySMB::Error::SigningError)
      end

      it 'rejects a response signed with a different session key' do
        dispatcher.queue_response(smb1_raw_response(RubySMB::SMB1::Packet::EchoResponse, key: Random.new.bytes(16)))
        expect { client.echo }.to raise_error(RubySMB::Error::SigningError)
      end

      it 'rejects a response addressed to a different session (UID)' do
        dispatcher.queue_response(smb1_raw_response(RubySMB::SMB1::Packet::EchoResponse, uid: user_id + 1))
        expect { client.echo }.to raise_error(RubySMB::Error::SigningError)
      end

      it 'rejects a response signed with the wrong sequence counter' do
        dispatcher.queue_response(smb1_raw_response(RubySMB::SMB1::Packet::EchoResponse, sequence_counter: 5))
        expect { client.echo }.to raise_error(RubySMB::Error::SigningError)
      end

      it 'does not update the sequence counter when verification fails' do
        dispatcher.queue_response(tamper(smb1_raw_response(RubySMB::SMB1::Packet::EchoResponse)))
        expect { client.echo }.to raise_error(RubySMB::Error::SigningError)
        # only the send-side increment happened
        expect(client.sequence_counter).to eq(1)
      end

      context 'through the tree interface' do
        it 'accepts a correctly signed TreeConnectResponse' do
          dispatcher.queue_response(smb1_raw_response(RubySMB::SMB1::Packet::TreeConnectResponse))
          expect(client.tree_connect(share)).to be_a(RubySMB::SMB1::Tree)
        end

        it 'rejects a tampered TreeConnectResponse' do
          dispatcher.queue_response(tamper(smb1_raw_response(RubySMB::SMB1::Packet::TreeConnectResponse)))
          expect { client.tree_connect(share) }.to raise_error(RubySMB::Error::SigningError)
        end
      end
    end

    context 'when signing is not required' do
      let(:client) { described_class.new(dispatcher, smb1: false, smb3: false, username: username, password: password) }

      it 'accepts unsigned responses' do
        client.dialect          = RubySMB::Client::SMB2_DIALECT_0202
        client.signing_required = false
        client.session_key      = session_key
        client.session_id       = session_id
        dispatcher.queue_response(smb2_raw_response(RubySMB::SMB2::Packet::EchoResponse, sign: false))
        expect(client.echo).to eq(WindowsError::NTStatus::STATUS_SUCCESS)
      end
    end
  end
end
