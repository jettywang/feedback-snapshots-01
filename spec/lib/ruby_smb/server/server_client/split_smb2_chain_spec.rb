RSpec.describe RubySMB::Server::ServerClient do
  # The SMB2 SYNC header is a fixed 64 bytes; NextCommand lives at offset 20 and
  # the protocol identifier occupies the first 4 bytes.
  HEADER_SIZE = 64
  NEXT_COMMAND_OFFSET = 20
  ALIGNMENT = 8

  # A command code that the server does not implement. It must still be accepted at
  # the chain-splitting layer so that the original evidence is preserved.
  UNKNOWN_COMMAND = 0x99

  let(:server) do
    authenticator = double('authenticator')
    gss_provider = double('gss_provider', new_authenticator: authenticator)
    double('server', gss_provider: gss_provider, logger: Logger.new(File::NULL))
  end
  let(:socket) { double('socket', peeraddr: '127.0.0.1') }
  let(:dispatcher) { RubySMB::Dispatcher::Socket.new(socket) }
  subject(:server_client) { described_class.new(server, dispatcher) }

  def split_chain(buffer)
    server_client.send(:split_smb2_chain, buffer)
  end

  # Build a raw SMB2 SYNC header with full control over the chain-relevant fields.
  def make_header(command:, next_command: 0, message_id: 0, related: 0, session_id: 0, tree_id: 0)
    header = RubySMB::SMB2::SMB2Header.new
    header.command = command
    header.next_command = next_command
    header.message_id = message_id
    header.flags.related_operations = related
    header.session_id = session_id
    header.tree_id = tree_id
    header.to_binary_s
  end

  def set_next_command(buffer, message_start, value)
    buffer[message_start + NEXT_COMMAND_OFFSET, 4] = [value].pack('V')
  end

  # Two commands whose data areas are sized to force 8-byte padding between them.
  let(:first_body) { 'A'.b * 13 }
  let(:second_body) { 'B'.b * 21 }
  let(:first_pad) { (-(HEADER_SIZE + first_body.length)) % ALIGNMENT }
  let(:second_pad) { (-(HEADER_SIZE + second_body.length)) % ALIGNMENT }
  let(:first_offset) { HEADER_SIZE + first_body.length + first_pad }
  let(:second_offset) { HEADER_SIZE + second_body.length + second_pad }
  let(:second_start) { first_offset }
  let(:third_start) { first_offset + second_offset }

  let(:compound) do
    first = make_header(command: RubySMB::SMB2::Commands::CLOSE, next_command: first_offset, message_id: 1)
    second = make_header(
      command: RubySMB::SMB2::Commands::CREATE,
      next_command: second_offset,
      message_id: 2,
      related: 1,
      session_id: 0x1122334455667788,
      tree_id: 0xdeadbeef
    )
    third = make_header(command: RubySMB::SMB2::Commands::READ, message_id: 3)
    first + first_body + ("\x00".b * first_pad) +
      second + second_body + ("\x00".b * second_pad) +
      third + 'C'.b * 5
  end

  describe '#split_smb2_chain' do
    context 'with a valid multi-command compound' do
      it 'returns one segment per command' do
        expect(split_chain(compound).length).to eq(3)
      end

      it 'cuts each segment at the chained offset and preserves all bytes' do
        segments = split_chain(compound)
        expected_lengths = [first_offset, second_offset, HEADER_SIZE + 5]
        expect(segments.map(&:length)).to eq(expected_lengths)
        expect(segments.join).to eq(compound)
      end

      it 'attributes the independent byte markers to the owning command data area' do
        segments = split_chain(compound)
        expect(segments[0][HEADER_SIZE]).to eq('A'.b)
        expect(segments[1][HEADER_SIZE]).to eq('B'.b)
        expect(segments[2][HEADER_SIZE]).to eq('C'.b)
      end

      it 'keeps the padding bytes inside the preceding command boundary' do
        segments = split_chain(compound)
        expect(segments[0].length).to eq(first_offset)
        expect(segments[0][(HEADER_SIZE + first_body.length)..]).to eq("\x00".b * first_pad)
      end

      it 'parses each command with its own session, tree and related-operation state' do
        second_header = RubySMB::SMB2::SMB2Header.read(split_chain(compound)[1])
        expect(second_header.flags.related_operations).to eq(1)
        expect(second_header.session_id).to eq(0x1122334455667788)
        expect(second_header.tree_id).to eq(0xdeadbeef)
        expect(second_header.message_id).to eq(2)
      end

      it 'interprets a chained NextCommand relative to that message, not the whole buffer' do
        second_header = RubySMB::SMB2::SMB2Header.read(split_chain(compound)[1])
        expect(second_header.next_command).to eq(second_offset)
        expect(second_offset).to be < compound.length
      end

      it 'accepts a single message with a zero NextCommand and retains its trailing data' do
        message = make_header(command: RubySMB::SMB2::Commands::ECHO) + 'Z'.b * 12
        segments = split_chain(message)
        expect(segments.length).to eq(1)
        expect(segments.first).to eq(message)
        expect(segments.first[HEADER_SIZE..]).to eq('Z'.b * 12)
      end
    end

    context 'with an explicit but unknown command code' do
      it 'still splits the chain and preserves the unknown command evidence' do
        first = make_header(command: UNKNOWN_COMMAND, next_command: first_offset, message_id: 1)
        buffer = first + first_body + ("\x00".b * first_pad) +
                 make_header(command: RubySMB::SMB2::Commands::READ, message_id: 2) + 'B'.b * 8
        segments = split_chain(buffer)
        expect(segments.length).to eq(2)
        unknown_header = RubySMB::SMB2::SMB2Header.read(segments.first)
        expect(unknown_header.command).to eq(UNKNOWN_COMMAND)
        expect(segments.first[HEADER_SIZE]).to eq('A'.b)
      end
    end

    shared_examples 'an invalid compound chain' do
      it 'raises InvalidPacket and does not scan for a later signature' do
        expect { split_chain(mutated) }.to raise_error(RubySMB::Error::InvalidPacket) do |error|
          expect(error.message).to include(expected_reason)
        end
      end

      it 'leaves no partial chain behind' do
        expect { split_chain(mutated) }.to raise_error(RubySMB::Error::InvalidPacket)
        expect(server_client.instance_variable_get(:@in_packet_queue)).to be_empty
      end
    end

    context 'with a corrupted first command' do
      let(:expected_reason) { 'beyond' }
      let(:mutated) do
        buffer = compound.dup
        beyond_offset = ((compound.length / ALIGNMENT) + 2) * ALIGNMENT
        set_next_command(buffer, 0, beyond_offset)
        buffer
      end
      include_examples 'an invalid compound chain'

      it 'does not expose the second command despite its intact signature' do
        expect { split_chain(mutated) }.to raise_error(RubySMB::Error::InvalidPacket)
      end
    end

    context 'when a NextCommand is an absolute buffer offset (wrong base point)' do
      let(:expected_reason) { 'beyond' }
      let(:mutated) do
        buffer = compound.dup
        set_next_command(buffer, second_start, first_offset + second_offset)
        buffer
      end
      include_examples 'an invalid compound chain'
    end

    context 'when a NextCommand jumps backward into the current header' do
      let(:expected_reason) { 'overlaps the current header' }
      let(:mutated) do
        buffer = compound.dup
        set_next_command(buffer, second_start, 8)
        buffer
      end
      include_examples 'an invalid compound chain'
    end

    context 'when a NextCommand is not 8-byte aligned (lands in padding)' do
      let(:expected_reason) { 'aligned' }
      let(:mutated) do
        buffer = compound.dup
        set_next_command(buffer, 0, first_offset - 1)
        buffer
      end
      include_examples 'an invalid compound chain'
    end

    context 'when the final message claims another command beyond itself' do
      let(:expected_reason) { 'beyond' }
      let(:mutated) do
        buffer = compound.dup
        set_next_command(buffer, third_start, 512)
        buffer
      end
      include_examples 'an invalid compound chain'
    end

    context 'when a chained header loses its SMB2 protocol identifier' do
      let(:expected_reason) { 'protocol identifier' }
      let(:mutated) do
        buffer = compound.dup
        buffer[second_start, 4] = 'XXXX'.b
        buffer
      end
      include_examples 'an invalid compound chain'
    end

    context 'when a NextCommand leaves fewer bytes than a header' do
      let(:expected_reason) { 'no room for a complete chained header' }
      let(:mutated) do
        buffer = compound.dup
        # Point inside the last header region but stay in-range and 8-byte aligned.
        near_end_offset = ((compound.length - (HEADER_SIZE / 2)) / ALIGNMENT) * ALIGNMENT
        set_next_command(buffer, 0, near_end_offset)
        buffer
      end
      include_examples 'an invalid compound chain'
    end

    context 'when the whole buffer is shorter than the fixed header' do
      let(:expected_reason) { 'smaller than the' }
      let(:mutated) { "\xfeSMB".b + 'short'.b }
      include_examples 'an invalid compound chain'
    end
  end

  describe '#recv_packet' do
    context 'when the dispatcher delivers a malformed compound' do
      let(:mutated) do
        buffer = compound.dup
        beyond_offset = ((compound.length / ALIGNMENT) + 2) * ALIGNMENT
        set_next_command(buffer, 0, beyond_offset)
        buffer
      end

      before do
        allow(dispatcher).to receive(:recv_packet).and_return(mutated)
        allow(dispatcher.tcp_socket).to receive(:closed?).and_return(false)
        allow(dispatcher.tcp_socket).to receive(:close)
      end

      it 'closes the connection instead of raising into the run loop' do
        expect(dispatcher.tcp_socket).to receive(:close)
        expect(server_client.recv_packet).to be_nil
      end

      it 'does not enqueue any segment from the broken chain' do
        server_client.recv_packet
        expect(server_client.instance_variable_get(:@in_packet_queue)).to be_empty
      end
    end

    context 'when the dispatcher delivers a well-formed compound' do
      before { allow(dispatcher).to receive(:recv_packet).and_return(compound) }

      it 'queues every command and returns the first one' do
        first = server_client.recv_packet
        queue = server_client.instance_variable_get(:@in_packet_queue)
        expect(first).to eq(split_chain(compound).first)
        expect(queue.length).to eq(2)
      end
    end
  end

  describe '#handle_smb3_transform' do
    let(:session_id) { 0x4242 }
    let(:transform_header) do
      RubySMB::SMB2::Packet::TransformHeader.new(session_id: session_id)
    end

    before do
      server_client.session_table[session_id] = RubySMB::Server::Session.new(session_id)
      allow(server_client).to receive(:smb3_decrypt).and_return(malformed_plaintext)
    end

    context 'when the decrypted plaintext is a malformed compound' do
      let(:malformed_plaintext) do
        buffer = compound.dup
        beyond_offset = ((compound.length / ALIGNMENT) + 2) * ALIGNMENT
        set_next_command(buffer, 0, beyond_offset)
        buffer
      end

      it 'answers with an error packet instead of raising' do
        response = server_client.send(:handle_smb3_transform, transform_header.to_binary_s, transform_header)
        expect(response).to be_a(RubySMB::SMB2::Packet::ErrorPacket)
        expect(response.smb2_header.nt_status).to eq(WindowsError::NTStatus::STATUS_INVALID_PARAMETER)
        expect(response.smb2_header.session_id).to eq(session_id)
      end
    end
  end
end
