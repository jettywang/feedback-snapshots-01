require 'winrm/wsmv/command_output_decoder'

describe WinRM::WSMV::CommandOutputDecoder do
  let(:raw_output_with_bom) do
    '77u/' \
    'ICAgQ29ubmVjdGlvbi1zcGVjaWZpYyBETlMgU3VmZml4ICAuIDogDQogICBMaW5rLWxvY2FsIElQdjYgQWRkcmVzcyA' \
    'uIC4gLiAuIC4gOiBmZTgwOjo5MTFkOjE2OTQ6NTcwNDo1YjI5JTEyDQogICBJUHY0IEFkZHJlc3MuIC4gLiAuIC4gLi' \
    'AuIC4gLiAuIC4gOiAxMC4wLjIuMTUNCiAgIFN1Ym5ldCBNYXNrIC4gLiAuIC4gLiAuIC4gLiAuIC4gLiA6IDI1NS4yN' \
    'TUuMjU1LjANCiAgIERlZmF1bHQgR2F0ZXdheSAuIC4gLiAuIC4gLiAuIC4gLiA6IDEwLjAuMi4yDQoNClR1bm5lbCBh' \
    'ZGFwdGVyIGlzYXRhcC57RjBENTY2RDgtNzlCMS00QUYwLUJENUQtMkM5RkVEOEI3MTE3fToNCg0KICAgTWVkaWEgU3R' \
    'hdGUgLiAuIC4gLiAuIC4gLiAuIC4gLiAuIDogTWVkaWEgZGlzY29ubmVjdGVkDQogICBDb25uZWN0aW9uLXNwZWNpZm' \
    'ljIEROUyBTdWZmaXggIC4gOiANCg0KVHVubmVsIGFkYXB0ZXIgVGVyZWRvIFR1bm5lbGluZyBQc2V1ZG8tSW50ZXJmY' \
    'WNlOg0KDQogICBDb25uZWN0aW9uLXNwZWNpZmljIEROUyBTdWZmaXggIC4gOiANCiAgIElQdjYgQWRkcmVzcy4gLiAu' \
    'IC4gLiAuIC4gLiAuIC4gLiA6IDIwMDE6MDo5ZDM4OjZhYmQ6NGJiOjI4YjU6ZjVmZjpmZGYwDQogICBMaW5rLWxvY2F' \
    'sIElQdjYgQWRkcmVzcyAuIC4gLiAuIC4gOiBmZTgwOjo0YmI6MjhiNTpmNWZmOmZkZjAlMTQNCiAgIERlZmF1bHQgR2' \
    'F0ZXdheSAuIC4gLiAuIC4gLiAuIC4gLiA6IDo6DQo='
  end
  let(:expected) do
    "   Connection-specific DNS Suffix  . : \r\n   Link-local IPv6 Address . . . . . : fe80::911" \
    "d:1694:5704:5b29%12\r\n   IPv4 Address. . . . . . . . . . . : 10.0.2.15\r\n   Subnet Mask ." \
    " . . . . . . . . . . : 255.255.255.0\r\n   Default Gateway . . . . . . . . . : 10.0.2.2\r\n" \
    "\r\nTunnel adapter isatap.{F0D566D8-79B1-4AF0-BD5D-2C9FED8B7117}:\r\n\r\n   Media State . ." \
    " . . . . . . . . . : Media disconnected\r\n   Connection-specific DNS Suffix  . : \r\n\r\nT" \
    "unnel adapter Teredo Tunneling Pseudo-Interface:\r\n\r\n   Connection-specific DNS Suffix  " \
    ". : \r\n   IPv6 Address. . . . . . . . . . . : 2001:0:9d38:6abd:4bb:28b5:f5ff:fdf0\r\n   Li" \
    "nk-local IPv6 Address . . . . . : fe80::4bb:28b5:f5ff:fdf0%14\r\n   Default Gateway . . . ." \
    " . . . . . : ::\r\n"
  end
  subject(:decoder) { described_class.new }

  context 'valid UTF-8 raw output' do
    it 'decodes' do
      expect(decoder.decode(raw_output_with_bom)).to eq(expected)
    end
  end

  def decode_all(chunks)
    increments = chunks.map { |chunk| decoder.decode(chunk) }
    increments << decoder.finish
    increments
  end

  context 'when a UTF-8 character spans chunks' do
    let(:text) { "✓1234-äöü €𝄞\r\n" }

    it 'reassembles the text when split at every byte boundary' do
      chunks = text.b.bytes.map { |byte| Base64.strict_encode64(byte.chr) }

      increments = decode_all(chunks)

      expect(increments.join).to eq(text)
      increments.each do |increment|
        expect(increment).to be_valid_encoding
        expect(increment).not_to include("�")
      end
    end

    it 'withholds an incomplete character until its last byte arrives' do
      expect(decoder.decode(Base64.strict_encode64("\xE2".b))).to eq('')
      expect(decoder.decode(Base64.strict_encode64("\x9C".b))).to eq('')
      expect(decoder.decode(Base64.strict_encode64("\x93".b))).to eq('✓')
    end

    it 'reassembles chunks split inside the Base64 text' do
      chunks = Base64.strict_encode64(text).chars.each_slice(3).map(&:join)

      expect(decode_all(chunks).join).to eq(text)
    end

    it 'ignores whitespace inside Base64 chunks' do
      expect(decoder.decode(Base64.encode64("héllo"))).to eq('héllo')
    end

    it 'keeps two streams independent when their chunks interleave' do
      other = described_class.new
      stdout = +''
      stderr = +''

      [['ä'.b.byteslice(0, 1), 'ö'.b.byteslice(0, 1)],
       ['ä'.b.byteslice(1, 1), 'ö'.b.byteslice(1, 1)]].each do |left, right|
        stdout << decoder.decode(Base64.strict_encode64(left))
        stderr << other.decode(Base64.strict_encode64(right))
      end
      stdout << decoder.finish
      stderr << other.finish

      expect(stdout).to eq('ä')
      expect(stderr).to eq('ö')
    end
  end

  context 'with a BOM' do
    let(:bom) { "\xEF\xBB\xBF".b }

    def decode_bytes(*chunks)
      text = chunks.map { |chunk| decoder.decode(Base64.strict_encode64(chunk)) }.join
      text + decoder.finish
    end

    it 'removes a BOM split across chunks at the start' do
      expect(decode_bytes(bom.byteslice(0, 1), bom.byteslice(1, 2) + 'hi')).to eq('hi')
    end

    it 'keeps a BOM that appears later in the stream' do
      expect(decode_bytes('a' + bom + 'b')).to eq("a﻿b")
    end

    it 'treats only the first BOM as special' do
      expect(decode_bytes(bom + bom + 'x')).to eq("﻿x")
    end
  end

  context 'when the stream ends' do
    it 'scrubs a trailing incomplete character' do
      decoder.decode(Base64.strict_encode64("\xE2\x9C".b))

      expect(decoder.finish).to eq("�")
    end

    it 'does not let a new stream complete the old trailing character' do
      decoder.decode(Base64.strict_encode64("\xE2\x9C".b))
      expect(decoder.finish).to eq("�")

      fresh = described_class.new
      expect(fresh.decode(Base64.strict_encode64("\x93".b))).to eq("�")
      expect(fresh.finish).to eq('')
    end

    it 'rejects a truncated Base64 value' do
      decoder.decode('YWJjZA')

      expect { decoder.finish }.to raise_error(ArgumentError, /truncated Base64/)
    end

    it 'rejects more input after finishing' do
      decoder.finish

      expect { decoder.decode('YQ==') }.to raise_error(ArgumentError, /finished/)
    end
  end

  context 'with invalid Base64' do
    it 'raises instead of silently dropping the chunk' do
      expect { decoder.decode('!!!!') }.to raise_error(ArgumentError, /invalid Base64/)
    end

    it 'raises once a complete group is invalid' do
      expect { decoder.decode('YWJj!!') }.to raise_error(ArgumentError, /invalid Base64/)
    end

    it 'rejects padding that is not at a group boundary' do
      expect { decoder.decode('YQ==YQ==') }.to raise_error(ArgumentError, /invalid Base64/)
    end

    it 'accepts consecutive independently padded chunks' do
      text = decoder.decode(Base64.strict_encode64('ab'))
      text += decoder.decode(Base64.strict_encode64('cd'))
      text += decoder.finish

      expect(text).to eq('abcd')
    end
  end
end
