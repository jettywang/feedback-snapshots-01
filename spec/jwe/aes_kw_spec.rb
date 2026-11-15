# frozen_string_literal: true

require 'jwe/alg/a128_kw'
require 'jwe/alg/a192_kw'
require 'jwe/alg/a256_kw'

# Independent known-answer regression for AES Key Wrap and its use inside
# full JWE messages. All vectors come from public standards (RFC 3394 and
# RFC 7516), not from this implementation, so they catch mistakes that a
# same-code roundtrip would hide.
describe 'AES Key Wrap' do
  # Test vectors from RFC 3394, section 4. These vectors pin both the
  # 6-round structure and the A6A6A6A6A6A6A6A6 integrity register: a wrong
  # round count or a skipped register check produces different bytes and
  # fails these expectations.
  rfc3394_vectors = [
    # 4.1: 128 bits of key data with a 128-bit KEK
    { alg: JWE::Alg::A128kw,
      kek: '000102030405060708090A0B0C0D0E0F',
      key_data: '00112233445566778899AABBCCDDEEFF',
      wrapped: '1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5' },
    # 4.2: 128 bits of key data with a 192-bit KEK
    { alg: JWE::Alg::A192kw,
      kek: '000102030405060708090A0B0C0D0E0F1011121314151617',
      key_data: '00112233445566778899AABBCCDDEEFF',
      wrapped: '96778B25AE6CA435F92B5B97C050AED2468AB8A17AD84E5D' },
    # 4.3: 128 bits of key data with a 256-bit KEK
    { alg: JWE::Alg::A256kw,
      kek: '000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F',
      key_data: '00112233445566778899AABBCCDDEEFF',
      wrapped: '64E8C3F9CE0F5BA263E9777905818A2A93C8191E7D6E8AE7' },
    # 4.4: 192 bits of key data with a 192-bit KEK
    { alg: JWE::Alg::A192kw,
      kek: '000102030405060708090A0B0C0D0E0F1011121314151617',
      key_data: '00112233445566778899AABBCCDDEEFF0001020304050607',
      wrapped: '031D33264E15D33268F24EC260743EDCE1C6C7DDEE725A936BA814915C6762D2' },
    # 4.5: 192 bits of key data with a 256-bit KEK
    { alg: JWE::Alg::A256kw,
      kek: '000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F',
      key_data: '00112233445566778899AABBCCDDEEFF0001020304050607',
      wrapped: 'A8F9BC1612C68B3FF6E6F4FBE30E71E4769C8B80A32CB8958CD5D17D6B254DA1' },
    # 4.6: 256 bits of key data with a 256-bit KEK
    { alg: JWE::Alg::A256kw,
      kek: '000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F',
      key_data: '00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F',
      wrapped: '28C9F404C4B810F4CBCCB35CFB87F8263F5786E2D80ED326CBC7F0E71A99F43BFB988B9B7A02DD21' }
  ]

  rfc3394_vectors.each do |vector|
    context "#{vector[:alg]} with #{vector[:key_data].length * 4} bits of key data (RFC 3394)" do
      let(:alg) { vector[:alg].new([vector[:kek]].pack('H*')) }

      it 'wraps the key data to the published ciphertext' do
        expect(alg.encrypt([vector[:key_data]].pack('H*'))).to eq [vector[:wrapped]].pack('H*')
      end

      it 'unwraps the published ciphertext to the original key data' do
        expect(alg.decrypt([vector[:wrapped]].pack('H*'))).to eq [vector[:key_data]].pack('H*')
      end
    end
  end

  describe 'rejecting invalid input' do
    let(:alg) { JWE::Alg::A128kw.new(['000102030405060708090A0B0C0D0E0F'].pack('H*')) }
    let(:wrapped) { ['1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5'].pack('H*') }

    # Every counterexample below must raise: callers must never be handed a
    # readable candidate CEK for input that fails validation.

    it 'rejects a corrupted integrity register' do
      tampered = wrapped.dup
      tampered.setbyte(0, tampered.getbyte(0) ^ 0x01)
      expect { alg.decrypt(tampered) }.to raise_error(StandardError)
    end

    it 'rejects a corrupted ciphertext block' do
      tampered = wrapped.dup
      tampered.setbyte(12, tampered.getbyte(12) ^ 0x01)
      expect { alg.decrypt(tampered) }.to raise_error(StandardError)
    end

    it 'rejects input that is not a multiple of 8 bytes' do
      expect { alg.decrypt(wrapped + 'abc') }.to raise_error(StandardError)
      expect { alg.decrypt(wrapped[0..-2]) }.to raise_error(StandardError)
    end

    it 'rejects input shorter than the minimum wrapped length' do
      expect { alg.decrypt(wrapped[0, 8]) }.to raise_error(StandardError)
      expect { alg.decrypt('') }.to raise_error(StandardError)
    end

    it 'rejects unwrapping with the wrong KEK' do
      wrong_kek_alg = JWE::Alg::A128kw.new(SecureRandom.random_bytes(16))
      expect { wrong_kek_alg.decrypt(wrapped) }.to raise_error(StandardError)
    end

    it 'rejects wrapping key data that is not a multiple of 8 bytes' do
      expect { alg.encrypt('short') }.to raise_error(StandardError)
      expect { alg.encrypt('00112233445566778899AABBCCDDE' ) }.to raise_error(StandardError)
    end
  end

  # Full JWE from RFC 7516, Appendix A.3: A128KW key wrapping with
  # A128CBC-HS256 content encryption. The unwrapped CEK must actually fit
  # the content algorithm, and the message must authenticate end to end.
  describe 'RFC 7516 Appendix A.3 token (A128KW + A128CBC-HS256)' do
    let(:kek) { JWE::Base64.jwe_decode('GawgguFyGrWKav7AX4VKUg') }
    let(:token) do
      'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.' \
      '6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ.' \
      'AxY8DCtDaGlsbGljb3RoZQ.' \
      'KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY.' \
      'U0m_YmjN04DJvceFICbCVQ'
    end

    it 'unwraps the CEK published by the RFC' do
      encrypted_cek = JWE::Base64.jwe_decode('6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ')
      cek = JWE::Alg::A128kw.new(kek).decrypt(encrypted_cek)

      expect(cek.bytesize).to eq 32
      expect(cek.unpack1('H*')).to eq '04d31fc5549dfcfe0b649dfa3faa6ace6b7cd42d6f6b09dbc8b100f08f9c2ccf'
    end

    it 'decrypts the full token to the published plaintext' do
      expect(JWE.decrypt(token, kek)).to eq 'Live long and prosper.'
    end

    it 'rejects the token when the authentication tag is corrupted' do
      parts = token.split('.')
      tag = JWE::Base64.jwe_decode(parts[4])
      tag.setbyte(0, tag.getbyte(0) ^ 0x01)
      parts[4] = JWE::Base64.jwe_encode(tag)

      expect { JWE.decrypt(parts.join('.'), kek) }.to raise_error(JWE::InvalidData)
    end
  end

  describe 'a successfully unwrapped CEK that does not fit the enc algorithm' do
    let(:kek) { SecureRandom.random_bytes(16) }

    def reheader(token, enc)
      parts = token.split('.')
      header = JSON.parse(JWE::Base64.jwe_decode(parts[0]))
      header['enc'] = enc
      parts[0] = JWE::Base64.jwe_encode(header.to_json)
      parts.join('.')
    end

    it 'raises BadCEK for a GCM token instead of returning plaintext' do
      token = JWE.encrypt('secret', kek, alg: 'A128KW', enc: 'A128GCM')
      expect { JWE.decrypt(reheader(token, 'A256GCM'), kek) }.to raise_error(JWE::BadCEK)
    end

    it 'raises BadCEK for a CBC-HS token instead of returning plaintext' do
      token = JWE.encrypt('secret', kek, alg: 'A128KW', enc: 'A128CBC-HS256')
      expect { JWE.decrypt(reheader(token, 'A256CBC-HS512'), kek) }.to raise_error(JWE::BadCEK)
    end
  end

  describe 'a well-formed wrapped CEK that is not the content key' do
    # Unwrapping succeeds (the integrity register verifies), but a
    # successful unwrap must never be treated as proof that the message is
    # authentic: content authentication must still reject the token.
    let(:kek) { SecureRandom.random_bytes(16) }

    def swap_cek(token, kek, cek)
      parts = token.split('.')
      parts[1] = JWE::Base64.jwe_encode(JWE::Alg::A128kw.new(kek).encrypt(cek))
      parts.join('.')
    end

    it 'fails GCM content authentication instead of returning plaintext' do
      token = JWE.encrypt('secret', kek, alg: 'A128KW', enc: 'A128GCM')
      swapped = swap_cek(token, kek, SecureRandom.random_bytes(16))
      expect { JWE.decrypt(swapped, kek) }.to raise_error(JWE::InvalidData)
    end

    it 'fails CBC-HS content authentication instead of returning plaintext' do
      token = JWE.encrypt('secret', kek, alg: 'A128KW', enc: 'A128CBC-HS256')
      swapped = swap_cek(token, kek, SecureRandom.random_bytes(32))
      expect { JWE.decrypt(swapped, kek) }.to raise_error(JWE::InvalidData)
    end
  end

  describe 'JWE roundtrips with different content encryption algorithms' do
    {
      'A128KW' => 16,
      'A192KW' => 24,
      'A256KW' => 32
    }.each do |alg_name, kek_size|
      %w[A128GCM A256GCM A128CBC-HS256 A256CBC-HS512].each do |enc|
        it "decrypts a #{alg_name} token using #{enc}" do
          kek = SecureRandom.random_bytes(kek_size)
          token = JWE.encrypt('Live long and prosper.', kek, alg: alg_name, enc: enc)

          expect(JWE.decrypt(token, kek)).to eq 'Live long and prosper.'
        end
      end
    end
  end
end
