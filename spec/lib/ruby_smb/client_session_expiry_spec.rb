require 'spec_helper'

RSpec.describe RubySMB::Client, 'STATUS_NETWORK_SESSION_EXPIRED handling' do
  let(:generation_challenges) do
    [
      "\xaa\x11\x22\x33\x44\x55\x66\x77".b,
      "\xbb\x88\x99\xaa\xbb\xcc\xdd\xee".b,
      "\xcc\x0f\x1e\x2d\x3c\x4b\x5a\x69".b
    ]
  end
  let(:dialect) { 0x0302 }
  let(:always_encrypt) { true }
  let(:dispatcher) do
    ScriptedSmb2ServerDispatcher.new(
      password: password,
      challenges: generation_challenges,
      dialect: dialect
    )
  end
  let(:username) { 'alice' }
  let(:password) { 'generation-password' }
  let(:client) do
    described_class.new(
      dispatcher,
      smb1: false,
      smb2: false,
      smb3: true,
      username: username,
      password: password,
      always_encrypt: always_encrypt
    )
  end

  def frames_for(command)
    dispatcher.wire.select { |frame| frame[:command] == command }
  end

  def generation_index_for(frame)
    dispatcher.generations.index { |generation| generation[:session_id] == frame[:session_id] }
  end

  # Verifies a frame's signature against a generation, supplying the preauthentication
  # hash of that generation for the 3.1.1 dialect.
  def signature_valid?(frame, generation)
    preauth_hash = dispatcher.preauth_hashes&.[](generation[:generation])
    dispatcher.valid_signature?(frame, generation, preauth_hash)
  end

  before do
    client.login
  end

  describe 'the healthy baseline session' do
    it 'negotiates an SMB3 dialect and completes one authentication generation' do
      expect(client.dialect).to eq('0x0302')
      expect(dispatcher.generations.size).to eq(1)
      expect(client.session_id).to eq(dispatcher.generations.first[:session_id])
    end

    it 'holds the same NTLM session key as the server' do
      expect(client.session_key).to eq(dispatcher.generations.first[:session_key])
    end

    it 'signs the first application request with the first generation key' do
      client.send_recv(RubySMB::SMB2::Packet::ReadRequest.new)
      read_frame = frames_for(RubySMB::SMB2::Commands::READ).first
      expect(signature_valid?(read_frame, dispatcher.generations[0])).to be true
    end
  end

  describe 're-authentication after expiry' do
    before do
      dispatcher.expire_next(RubySMB::SMB2::Commands::READ)
      @response = client.send_recv(RubySMB::SMB2::Packet::ReadRequest.new)
    end

    it 'rebuilds the session with a second authentication generation' do
      expect(dispatcher.generations.size).to eq(2)
      expect(client.session_id).to eq(dispatcher.generations[1][:session_id])
      expect(client.session_id).not_to eq(dispatcher.generations[0][:session_id])
    end

    it 'derives a fresh session key that matches the server and differs from the old one' do
      expect(client.session_key).to eq(dispatcher.generations[1][:session_key])
      expect(client.session_key).not_to eq(dispatcher.generations[0][:session_key])
    end

    it 'uses distinct NTLM challenges for the two generations' do
      expect(dispatcher.generations[0][:challenge]).not_to eq(dispatcher.generations[1][:challenge])
    end

    it 'wipes the derived application and encryption keys from the old generation' do
      expect(client.application_key).not_to eq('')
      expect(client.client_encryption_key).to be_nil
      expect(client.server_encryption_key).to be_nil
    end

    it 'resets the SMB1 signing sequence counter as part of the rebuild' do
      client.sequence_counter = 99
      expect(client).to receive(:reset_session_security_state!).and_wrap_original do |original, *args|
        original.call(*args)
        expect(client.sequence_counter).to eq(0)
      end
      dispatcher.expire_next(RubySMB::SMB2::Commands::ECHO)
      client.send_recv(RubySMB::SMB2::Packet::EchoRequest.new)
    end

    it 'returns the successful response of the retried request' do
      header = RubySMB::SMB2::SMB2Header.read(@response)
      expect(header.nt_status).to eq(WindowsError::NTStatus::STATUS_SUCCESS)
    end

    it 'sends exactly one expired request, two re-auth packets and one retried request' do
      expect(frames_for(RubySMB::SMB2::Commands::READ).size).to eq(2)
      session_setup_frames = frames_for(RubySMB::SMB2::Commands::SESSION_SETUP)
      expect(session_setup_frames.size).to eq(4)
      expect(session_setup_frames.map { |f| f[:message_id] }).to eq([1, 2, 4, 5])
    end

    it 'allocates a fresh, monotonically increasing message id to the retry' do
      read_frames = frames_for(RubySMB::SMB2::Commands::READ)
      expect(read_frames.map { |f| f[:message_id] }).to eq([3, 6])
    end

    it 'signs each read with its own generation key, never the other generation key' do
      read_frames = frames_for(RubySMB::SMB2::Commands::READ)
      read_frames.each do |frame|
        generation_index = generation_index_for(frame)
        generation = dispatcher.generations[generation_index]
        other_generation = dispatcher.generations[generation_index.zero? ? 1 : 0]

        expect(signature_valid?(frame, generation)).to be true
        expect(signature_valid?(frame, other_generation)).to be false
      end
    end

    it 'does not carry the old session id on the retried request' do
      retried_read = frames_for(RubySMB::SMB2::Commands::READ).last
      expect(retried_read[:session_id]).to eq(dispatcher.generations[1][:session_id])
      expect(retried_read[:session_id]).not_to eq(dispatcher.generations[0][:session_id])
    end
  end

  describe 'a second expiry on the next application message' do
    it 'drives expire, re-auth, new message, expire again without unbounded retries' do
      dispatcher.expire_next(RubySMB::SMB2::Commands::READ)
      client.send_recv(RubySMB::SMB2::Packet::ReadRequest.new)
      expect(dispatcher.generations.size).to eq(2)

      dispatcher.always_expire(RubySMB::SMB2::Commands::READ)
      expect do
        client.send_recv(RubySMB::SMB2::Packet::ReadRequest.new)
      end.to raise_error(RubySMB::Error::RequestOutcomeUnknown)

      # Only one additional re-authentication happens; the second expiry after that must
      # stop the chain instead of recursing forever.
      expect(dispatcher.generations.size).to eq(3)
      expect(frames_for(RubySMB::SMB2::Commands::READ).size).to eq(4)
    end
  end

  describe 'a server that keeps returning expiry' do
    it 'performs at most one re-authentication and raises instead of looping' do
      dispatcher.always_expire(RubySMB::SMB2::Commands::READ)
      expect do
        client.send_recv(RubySMB::SMB2::Packet::ReadRequest.new)
      end.to raise_error(RubySMB::Error::RequestOutcomeUnknown, /unknown/)

      expect(dispatcher.generations.size).to eq(2)
      expect(frames_for(RubySMB::SMB2::Commands::READ).size).to eq(2)
    end
  end

  describe 'a non-idempotent request that expires' do
    it 'rebuilds the session but never re-sends the request, reporting an unknown outcome' do
      dispatcher.expire_next(RubySMB::SMB2::Commands::WRITE)
      expect do
        client.send_recv(RubySMB::SMB2::Packet::WriteRequest.new)
      end.to raise_error(RubySMB::Error::RequestOutcomeUnknown) do |error|
        expect(error.command).to eq(RubySMB::SMB2::Commands::WRITE)
        expect(error.status_code).to eq(WindowsError::NTStatus::STATUS_NETWORK_SESSION_EXPIRED)
      end

      expect(frames_for(RubySMB::SMB2::Commands::WRITE).size).to eq(1)
      expect(dispatcher.generations.size).to eq(2)
      expect(client.session_key).to eq(dispatcher.generations[1][:session_key])
    end

    it 'treats CREATE, CLOSE and SET_INFO as unsafe to replay' do
      [
        RubySMB::SMB2::Packet::CreateRequest,
        RubySMB::SMB2::Packet::CloseRequest,
        RubySMB::SMB2::Packet::SetInfoRequest
      ].each do |packet_class|
        expect(client.retryable_request?(packet_class.new)).to be false
      end
    end

    it 'treats READ, ECHO, QUERY_INFO and QUERY_DIRECTORY as safe to replay' do
      [
        RubySMB::SMB2::Packet::ReadRequest,
        RubySMB::SMB2::Packet::EchoRequest,
        RubySMB::SMB2::Packet::QueryInfoRequest,
        RubySMB::SMB2::Packet::QueryDirectoryRequest
      ].each do |packet_class|
        expect(client.retryable_request?(packet_class.new)).to be true
      end
    end
  end

  describe 're-authentication failure' do
    it 'wraps the failure and does not retry the original request' do
      allow(client).to receive(:session_setup).and_raise(RubySMB::Error::UnexpectedStatusCode.new(
        WindowsError::NTStatus::STATUS_LOGON_FAILURE
      ))
      dispatcher.expire_next(RubySMB::SMB2::Commands::READ)

      expect do
        client.send_recv(RubySMB::SMB2::Packet::ReadRequest.new)
      end.to raise_error(RubySMB::Error::ReauthenticationFailure)

      expect(frames_for(RubySMB::SMB2::Commands::READ).size).to eq(1)
    end
  end

  describe 'Kerberos sessions' do
    it 'refuses automatic re-authentication with a clear error' do
      client.instance_variable_set(:@mech_type, :kerberos)
      dispatcher.expire_next(RubySMB::SMB2::Commands::READ)
      expect do
        client.send_recv(RubySMB::SMB2::Packet::ReadRequest.new)
      end.to raise_error(RubySMB::Error::RubySMBError, /kerberos/i)
      expect(dispatcher.generations.size).to eq(1)
    end
  end

  describe '#reset_session_security_state!' do
    it 'clears every value derived from the authentication generation' do
      client.session_id = 0x11223344
      client.user_id = 0x5566
      client.application_key = 'derived'
      client.session_key = 'derived'
      client.session_is_guest = true
      client.sequence_counter = 41
      client.client_encryption_key = 'client-key'
      client.server_encryption_key = 'server-key'

      client.reset_session_security_state!

      expect(client.session_id).to eq(0)
      expect(client.user_id).to eq(0)
      expect(client.application_key).to eq('')
      expect(client.session_key).to eq('')
      expect(client.session_is_guest).to be false
      expect(client.sequence_counter).to eq(0)
      expect(client.client_encryption_key).to be_nil
      expect(client.server_encryption_key).to be_nil
    end

    it 'preserves connection-wide negotiation state' do
      message_id = client.smb2_message_id
      dialect = client.dialect
      client.reset_session_security_state!
      expect(client.smb2_message_id).to eq(message_id)
      expect(client.dialect).to eq(dialect)
    end

    context 'with the SMB 3.1.1 dialect' do
      let(:client) do
        described_class.new(
          dispatcher,
          smb1: false,
          smb2: false,
          smb3: true,
          username: username,
          password: password
        )
      end

      it 'restarts the preauthentication integrity hash for the new generation' do
        client.dialect = '0x0311'
        client.preauth_integrity_hash_value = 'stale-hash-material'
        client.reset_session_security_state!
        expect(client.preauth_integrity_hash_value).to eq("\x00" * 64)
      end

      it 'leaves the preauthentication hash untouched for other dialects' do
        client.dialect = '0x0302'
        client.preauth_integrity_hash_value = 'stale-hash-material'
        client.reset_session_security_state!
        expect(client.preauth_integrity_hash_value).to eq('stale-hash-material')
      end
    end
  end

  describe 'SMB 3.1.1 preauthentication integrity isolation', dialect: 0x0311 do
    let(:dialect) { 0x0311 }
    # The fake server does not implement SMB3 transform messages, so run signed-only while
    # still negotiating the 3.1.1 dialect and its preauthentication contexts.
    let(:always_encrypt) { false }

    it 'agrees with the server on the preauthentication hash of the first generation' do
      expect(client.preauth_integrity_hash_value).to eq(dispatcher.preauth_hashes[0])
    end

    context 'after expiry and re-authentication' do
      before do
        dispatcher.expire_next(RubySMB::SMB2::Commands::READ)
        @response = client.send_recv(RubySMB::SMB2::Packet::ReadRequest.new)
      end

      it 'restarts the preauthentication hash from zero for the new generation' do
        expect(dispatcher.preauth_hashes[0]).not_to eq(dispatcher.preauth_hashes[1])
        expect(client.preauth_integrity_hash_value).to eq(dispatcher.preauth_hashes[1])
      end

      it 'derives distinct session keys for the two challenge materials' do
        expect(dispatcher.generations[0][:challenge]).not_to eq(dispatcher.generations[1][:challenge])
        expect(dispatcher.generations[0][:session_key]).not_to eq(dispatcher.generations[1][:session_key])
        expect(client.session_key).to eq(dispatcher.generations[1][:session_key])
      end

      it 'validates each read only with its own generation preauthentication hash' do
        frames_for(RubySMB::SMB2::Commands::READ).each do |frame|
          generation_index = generation_index_for(frame)
          own_generation = dispatcher.generations[generation_index]
          other_generation = dispatcher.generations[generation_index.zero? ? 1 : 0]

          expect(signature_valid?(frame, own_generation)).to be true
          expect(signature_valid?(frame, other_generation)).to be false
        end
      end

      it 'returns success for the retried read' do
        header = RubySMB::SMB2::SMB2Header.read(@response)
        expect(header.nt_status).to eq(WindowsError::NTStatus::STATUS_SUCCESS)
      end
    end
  end
end
