RSpec.describe RubySMB::SMB1::TransactionReassembler do
  subject(:reassembler) { described_class.new }

  let(:command) { RubySMB::SMB1::Commands::SMB_COM_TRANSACTION }

  # Builds a raw SMB_COM_TRANSACTION response fragment. Offsets and counts
  # inside the packet are computed by the packet class itself.
  def build_fragment(mid:, command: RubySMB::SMB1::Commands::SMB_COM_TRANSACTION,
                     tid: 1, uid: 1, pid: 1,
                     total_params:, total_data:,
                     params: ''.b, param_disp: 0, data: ''.b, data_disp: 0)
    packet = RubySMB::SMB1::Packet::Trans::Response.new
    packet.smb_header.command = command
    packet.smb_header.mid = mid
    packet.smb_header.tid = tid
    packet.smb_header.uid = uid
    packet.smb_header.pid_low = pid
    packet.parameter_block.total_parameter_count = total_params
    packet.parameter_block.total_data_count = total_data
    packet.parameter_block.parameter_displacement = param_disp
    packet.parameter_block.data_displacement = data_disp
    packet.data_block.trans_parameters = params
    packet.data_block.trans_data = data
    packet.to_binary_s
  end

  # Offsets of the 16-bit fragment fields, relative to the packet start
  def set_total_data_count(raw, value)
    raw.dup.tap { |r| r[35, 2] = [value].pack('v') }
  end

  def set_data_offset(raw, value)
    raw.dup.tap { |r| r[47, 2] = [value].pack('v') }
  end

  def set_data_displacement(raw, value)
    raw.dup.tap { |r| r[49, 2] = [value].pack('v') }
  end

  describe '#add_fragment' do
    it 'completes a transaction delivered in a single fragment' do
      raw = build_fragment(mid: 1, total_params: 4, total_data: 5, params: 'PPPP', data: 'DDDDD')
      expect(reassembler.add_fragment(raw)).to be true
      expect(reassembler).to be_complete
      result = reassembler.assemble
      expect(result.parameters).to eq 'PPPP'
      expect(result.data).to eq 'DDDDD'
    end

    it 'reassembles out-of-order fragments' do
      reassembler.add_fragment(build_fragment(mid: 1, total_params: 0, total_data: 10, data: 'CDEF', data_disp: 2))
      reassembler.add_fragment(build_fragment(mid: 1, total_params: 0, total_data: 10, data: 'GHIJ', data_disp: 6))
      expect(reassembler).to_not be_complete
      expect(reassembler.add_fragment(build_fragment(mid: 1, total_params: 0, total_data: 10, data: 'AB', data_disp: 0))).to be true
      expect(reassembler.assemble.data).to eq 'ABCDEFGHIJ'
    end

    it 'tracks the parameter and data regions independently' do
      reassembler.add_fragment(build_fragment(mid: 1, total_params: 4, total_data: 4, params: 'PPPP'))
      expect(reassembler).to_not be_complete
      expect(reassembler.add_fragment(build_fragment(mid: 1, total_params: 4, total_data: 4, data: 'DDDD'))).to be true
      result = reassembler.assemble
      expect(result.parameters).to eq 'PPPP'
      expect(result.data).to eq 'DDDD'
    end

    it 'is not complete when a fragment delivers all data but no parameters' do
      # A fragment declaring the full data total does not imply the
      # parameter region is complete.
      reassembler.add_fragment(build_fragment(mid: 1, total_params: 4, total_data: 4, data: 'DDDD'))
      expect(reassembler).to_not be_complete
      expect { reassembler.assemble }.to raise_error(RubySMB::Error::RubySMBError)
    end

    it 'is not complete when a hole remains between fragments' do
      reassembler.add_fragment(build_fragment(mid: 1, total_params: 0, total_data: 10, data: 'AB', data_disp: 0))
      reassembler.add_fragment(build_fragment(mid: 1, total_params: 0, total_data: 10, data: 'IJ', data_disp: 8))
      expect(reassembler).to_not be_complete
    end

    it 'accepts an identical retransmission of a fragment' do
      raw = build_fragment(mid: 1, total_params: 0, total_data: 6, data: 'ABC', data_disp: 0)
      expect { reassembler.add_fragment(raw) }.to_not raise_error
      expect { reassembler.add_fragment(raw) }.to_not raise_error
      reassembler.add_fragment(build_fragment(mid: 1, total_params: 0, total_data: 6, data: 'DEF', data_disp: 3))
      expect(reassembler.assemble.data).to eq 'ABCDEF'
    end

    it 'accepts a retransmission that partially overlaps with identical bytes' do
      reassembler.add_fragment(build_fragment(mid: 1, total_params: 0, total_data: 6, data: 'ABCD', data_disp: 0))
      expect {
        reassembler.add_fragment(build_fragment(mid: 1, total_params: 0, total_data: 6, data: 'CDEF', data_disp: 2))
      }.to_not raise_error
      expect(reassembler.assemble.data).to eq 'ABCDEF'
    end

    it 'accepts a duplicate of the final fragment after completion' do
      raw = build_fragment(mid: 1, total_params: 0, total_data: 3, data: 'ABC')
      reassembler.add_fragment(raw)
      expect { reassembler.add_fragment(raw) }.to_not raise_error
      expect(reassembler.assemble.data).to eq 'ABC'
    end

    it 'rejects a conflicting overlap and does not overwrite accepted bytes' do
      reassembler.add_fragment(build_fragment(mid: 1, total_params: 0, total_data: 4, data: 'ABCD', data_disp: 0))
      expect {
        reassembler.add_fragment(build_fragment(mid: 1, total_params: 0, total_data: 4, data: 'ABXY', data_disp: 0))
      }.to raise_error(RubySMB::Error::InvalidPacket, /[Cc]onflicting/)
    end

    it 'rejects a fragment from a different transaction (different MID)' do
      reassembler.add_fragment(build_fragment(mid: 1, total_params: 0, total_data: 8, data: 'AAAA', data_disp: 0))
      expect {
        reassembler.add_fragment(build_fragment(mid: 2, total_params: 0, total_data: 8, data: 'BBBB', data_disp: 4))
      }.to raise_error(RubySMB::Error::InvalidPacket, /different transaction/)
    end

    it 'rejects a fragment from a different transaction (different command)' do
      reassembler.add_fragment(build_fragment(mid: 1, total_params: 0, total_data: 8, data: 'AAAA', data_disp: 0))
      expect {
        reassembler.add_fragment(build_fragment(mid: 1, command: RubySMB::SMB1::Commands::SMB_COM_TRANSACTION2,
                                              total_params: 0, total_data: 8, data: 'BBBB', data_disp: 4))
      }.to raise_error(RubySMB::Error::InvalidPacket, /different transaction/)
    end

    it 'rejects a fragment from a different transaction (different TID/UID/PID)' do
      reassembler.add_fragment(build_fragment(mid: 1, total_params: 0, total_data: 8, data: 'AAAA', data_disp: 0))
      expect {
        reassembler.add_fragment(build_fragment(mid: 1, tid: 2, uid: 3, pid: 4,
                                              total_params: 0, total_data: 8, data: 'BBBB', data_disp: 4))
      }.to raise_error(RubySMB::Error::InvalidPacket, /different transaction/)
    end

    it 'rejects a fragment whose declared totals change mid-transaction' do
      reassembler.add_fragment(build_fragment(mid: 1, total_params: 0, total_data: 8, data: 'AAAA', data_disp: 0))
      raw = build_fragment(mid: 1, total_params: 0, total_data: 8, data: 'BBBB', data_disp: 4)
      expect {
        reassembler.add_fragment(set_total_data_count(raw, 16))
      }.to raise_error(RubySMB::Error::InvalidPacket, /[Cc]onflicting data total/)
    end

    it 'rejects a fragment that extends past the declared total' do
      raw = build_fragment(mid: 1, total_params: 0, total_data: 4, data: 'ABCDEF', data_disp: 0)
      expect { reassembler.add_fragment(raw) }.to raise_error(RubySMB::Error::InvalidPacket, /exceeds the declared total/)
    end

    it 'rejects a fragment whose displacement plus count exceeds the declared total' do
      raw = build_fragment(mid: 1, total_params: 0, total_data: 4, data: 'AB', data_disp: 3)
      expect { reassembler.add_fragment(raw) }.to raise_error(RubySMB::Error::InvalidPacket, /exceeds the declared total/)
    end

    it 'rejects a short packet whose declared count exceeds the received bytes' do
      raw = build_fragment(mid: 1, total_params: 0, total_data: 8, data: 'ABCD', data_disp: 0)
      truncated = raw[0...-2]
      expect { reassembler.add_fragment(truncated) }.to raise_error(RubySMB::Error::InvalidPacket, /outside the received packet/)
    end

    it 'rejects a fragment whose in-packet offset points beyond the packet' do
      raw = build_fragment(mid: 1, total_params: 0, total_data: 8, data: 'ABCD', data_disp: 0)
      expect {
        reassembler.add_fragment(set_data_offset(raw, 60_000))
      }.to raise_error(RubySMB::Error::InvalidPacket, /outside the received packet/)
    end

    it 'rejects a fragment whose in-packet offset points into the SMB header' do
      raw = build_fragment(mid: 1, total_params: 0, total_data: 8, data: 'ABCD', data_disp: 0)
      expect {
        reassembler.add_fragment(set_data_offset(raw, 10))
      }.to raise_error(RubySMB::Error::InvalidPacket, /outside the received packet/)
    end

    it 'rejects a packet that is not SMB1' do
      expect { reassembler.add_fragment("\x00SMB".b + ("\x00".b * 60)) }
        .to raise_error(RubySMB::Error::InvalidPacket, /Not an SMB1 packet/)
    end

    it 'rejects a non-transaction SMB1 packet' do
      raw = build_fragment(mid: 1, total_params: 0, total_data: 0)
      raw = raw.dup.tap { |r| r.setbyte(4, RubySMB::SMB1::Commands::SMB_COM_ECHO) }
      expect { reassembler.add_fragment(raw) }.to raise_error(RubySMB::Error::InvalidPacket, /Not an SMB1 transaction response/)
    end

    it 'rejects a packet without the reply flag set' do
      packet = RubySMB::SMB1::Packet::Trans::Response.new
      packet.smb_header.command = command
      packet.smb_header.flags.reply = 0
      expect { reassembler.add_fragment(packet.to_binary_s) }
        .to raise_error(RubySMB::Error::InvalidPacket, /Not a server reply/)
    end

    it 'rejects a packet smaller than its declared parameter block' do
      raw = build_fragment(mid: 1, total_params: 0, total_data: 0)
      truncated = raw[0...40]
      expect { reassembler.add_fragment(truncated) }.to raise_error(RubySMB::Error::InvalidPacket, /[Tt]runcated/)
    end

    it 'rejects implausibly large declared totals' do
      raw = build_fragment(mid: 1, total_params: 0, total_data: 0)
      raw = set_total_data_count(raw, 0xFFFF)
      reassembler = described_class.new(max_total_size: 1024)
      expect { reassembler.add_fragment(raw) }.to raise_error(RubySMB::Error::InvalidPacket, /exceeds the maximum/)
    end

    it 'supports SMB_COM_TRANSACTION2 fragments' do
      raw = build_fragment(mid: 1, command: RubySMB::SMB1::Commands::SMB_COM_TRANSACTION2,
                           total_params: 2, total_data: 3, params: 'PP', data: 'DDD')
      expect(reassembler.add_fragment(raw)).to be true
      result = reassembler.assemble
      expect(result.parameters).to eq 'PP'
      expect(result.data).to eq 'DDD'
    end

    it 'supports SMB_COM_NT_TRANSACT fragments with 32-bit fields' do
      # Crafted on the wire: the library NtTrans::Response packet class does
      # not serialize the 3 reserved bytes, so the raw packet is built by hand.
      header = ["\xFFSMB".b, RubySMB::SMB1::Commands::SMB_COM_NT_TRANSACT].pack('a4C')
      header += [0].pack('V')           # NT status
      header += [0x80].pack('C')        # flags (reply)
      header += [0].pack('v')           # flags2
      header += [0].pack('v')           # pid_high
      header += "\x00".b * 8            # security features
      header += [0].pack('v')           # reserved
      header += [1, 1, 1, 9].pack('v4') # tid, pid_low, uid, mid
      expect(header.bytesize).to eq 32
      params = "\x00".b * 3             # reserved
      params += [2, 3, 2, 71, 0, 3, 73, 0].pack('V8')
      params += [0].pack('C')           # setup_count
      raw = header + [params.bytesize / 2].pack('C') + params + [0].pack('v') + 'PPDDD'
      expect(reassembler.add_fragment(raw)).to be true
      result = reassembler.assemble
      expect(result.parameters).to eq 'PP'
      expect(result.data).to eq 'DDD'
    end
  end

  describe 'state reset after failure' do
    it 'resets the transaction when a fragment is rejected' do
      reassembler.add_fragment(build_fragment(mid: 1, total_params: 0, total_data: 8, data: 'AAAA', data_disp: 0))
      expect {
        reassembler.add_fragment(build_fragment(mid: 1, total_params: 0, total_data: 8, data: 'BXAA', data_disp: 0))
      }.to raise_error(RubySMB::Error::InvalidPacket)
      expect(reassembler).to_not be_complete
      expect { reassembler.assemble }.to raise_error(RubySMB::Error::RubySMBError)
    end

    it 'does not let stale fragments leak into the next transaction' do
      # First transaction fails halfway through...
      reassembler.add_fragment(build_fragment(mid: 1, total_params: 4, total_data: 8, params: 'PPPP', data: 'AAAA', data_disp: 0))
      expect {
        reassembler.add_fragment(build_fragment(mid: 1, total_params: 4, total_data: 8, data: 'BXAA', data_disp: 0))
      }.to raise_error(RubySMB::Error::InvalidPacket)

      # ...and a brand new transaction must be delivered without any byte
      # from the failed one.
      reassembler.add_fragment(build_fragment(mid: 2, total_params: 2, total_data: 4, params: 'QQ', data: 'ZZZZ'))
      expect(reassembler).to be_complete
      result = reassembler.assemble
      expect(result.parameters).to eq 'QQ'
      expect(result.data).to eq 'ZZZZ'
    end
  end

  describe 'interleaved transactions' do
    it 'delivers bytes from a single complete transaction for each stream' do
      reassembler_a = described_class.new
      reassembler_b = described_class.new

      stream = [
        [reassembler_a, build_fragment(mid: 1, total_params: 4, total_data: 8, params: 'PP', param_disp: 0)],
        [reassembler_b, build_fragment(mid: 2, total_params: 2, total_data: 6, data: 'xyz', data_disp: 3)],
        [reassembler_a, build_fragment(mid: 1, total_params: 4, total_data: 8, data: 'EFGH', data_disp: 4)],
        [reassembler_b, build_fragment(mid: 2, total_params: 2, total_data: 6, params: 'QQ')],
        [reassembler_a, build_fragment(mid: 1, total_params: 4, total_data: 8, data: 'ABCD', data_disp: 0)],
        [reassembler_b, build_fragment(mid: 2, total_params: 2, total_data: 6, data: 'uvw', data_disp: 0)],
        # consistent retransmissions interleaved in the stream
        [reassembler_a, build_fragment(mid: 1, total_params: 4, total_data: 8, data: 'ABCD', data_disp: 0)],
        [reassembler_a, build_fragment(mid: 1, total_params: 4, total_data: 8, params: 'PP', param_disp: 2)]
      ]

      stream.each do |target, fragment|
        target.add_fragment(fragment)
      end

      expect(reassembler_a).to be_complete
      expect(reassembler_b).to be_complete
      result_a = reassembler_a.assemble
      result_b = reassembler_b.assemble
      expect(result_a.parameters).to eq 'PPPP'
      expect(result_a.data).to eq 'ABCDEFGH'
      expect(result_b.parameters).to eq 'QQ'
      expect(result_b.data).to eq 'uvwxyz'
    end

    it 'never splices fragments of the other transaction into a stream' do
      reassembler_a = described_class.new
      reassembler_b = described_class.new

      reassembler_a.add_fragment(build_fragment(mid: 1, total_params: 0, total_data: 8, data: 'AAAA', data_disp: 0))
      reassembler_b.add_fragment(build_fragment(mid: 2, total_params: 0, total_data: 8, data: 'BBBB', data_disp: 0))

      fragment_from_b = build_fragment(mid: 2, total_params: 0, total_data: 8, data: 'CCCC', data_disp: 4)
      expect { reassembler_a.add_fragment(fragment_from_b) }
        .to raise_error(RubySMB::Error::InvalidPacket, /different transaction/)

      # Transaction B is unaffected and completes on its own
      reassembler_b.add_fragment(fragment_from_b)
      expect(reassembler_b.assemble.data).to eq 'BBBBCCCC'
    end
  end

  describe '#assemble' do
    it 'raises when the transaction is incomplete' do
      reassembler.add_fragment(build_fragment(mid: 1, total_params: 0, total_data: 8, data: 'AAAA', data_disp: 0))
      expect { reassembler.assemble }.to raise_error(RubySMB::Error::RubySMBError, /not both complete/)
    end
  end

  describe '#reset!' do
    it 'drops all buffered fragments' do
      reassembler.add_fragment(build_fragment(mid: 1, total_params: 0, total_data: 8, data: 'AAAA', data_disp: 0))
      reassembler.reset!
      expect(reassembler).to_not be_complete
      reassembler.add_fragment(build_fragment(mid: 3, total_params: 0, total_data: 2, data: 'ZZ'))
      expect(reassembler.assemble.data).to eq 'ZZ'
    end
  end
end
