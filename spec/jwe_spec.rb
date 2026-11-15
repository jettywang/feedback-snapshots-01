# frozen_string_literal: true

describe JWE do
  let(:plaintext) { 'The true sign of intelligence is not knowledge but imagination.' }
  let(:rsa_key) { OpenSSL::PKey::RSA.new File.read("#{File.dirname(__FILE__)}/keys/rsa.pem") }
  let(:password) { SecureRandom.random_bytes(64) }

  it 'roundtrips' do
    encrypted = JWE.encrypt(plaintext, rsa_key)
    result = JWE.decrypt(encrypted, rsa_key)

    expect(result).to eq plaintext
  end

  describe 'when using DEF compression' do
    it 'roundtrips' do
      encrypted = JWE.encrypt(plaintext, rsa_key, zip: 'DEF')
      result = JWE.decrypt(encrypted, rsa_key)

      expect(result).to eq plaintext
    end
  end

  describe 'when using dir alg method' do
    it 'roundtrips' do
      aes_password = SecureRandom.random_bytes(16)
      encrypted = JWE.encrypt(plaintext, aes_password, alg: 'dir')
      result = JWE.decrypt(encrypted, aes_password)

      expect(result).to eq plaintext
    end
  end

  describe 'when using extra headers' do
    it 'roundtrips' do
      encrypted = JWE.encrypt(plaintext, rsa_key, kid: 'some-kid-1')
      result = JWE.decrypt(encrypted, rsa_key)
      header, = JWE::Serialization::Compact.decode(encrypted)
      header = JSON.parse(header)

      expect(header['kid']).to eq 'some-kid-1'
      expect(result).to eq plaintext
    end
  end

  it 'raises when passed a bad alg' do
    expect { JWE.encrypt(plaintext, rsa_key, alg: 'TEST') }.to raise_error(ArgumentError)
  end

  it 'raises when passed a bad enc' do
    expect { JWE.encrypt(plaintext, rsa_key, enc: 'TEST') }.to raise_error(ArgumentError)
  end

  it 'raises when passed a bad zip' do
    expect { JWE.encrypt(plaintext, rsa_key, zip: 'TEST') }.to raise_error(ArgumentError)
  end

  it 'raises when decoding a bad alg' do
    hdr = { alg: 'TEST', enc: 'A128GCM' }
    payload = "#{JWE::Base64.jwe_encode(hdr.to_json)}.QY.QY.QY.QY"
    expect { JWE.decrypt(payload, rsa_key) }.to raise_error(ArgumentError)
  end

  it 'raises when decoding a bad enc' do
    hdr = { alg: 'A192CBC-HS384', enc: 'TEST' }
    payload = "#{JWE::Base64.jwe_encode(hdr.to_json)}.QY.QY.QY.QY"
    expect { JWE.decrypt(payload, rsa_key) }.to raise_error(ArgumentError)
  end

  it 'raises when decoding a bad zip' do
    hdr = { alg: 'A192CBC-HS384', enc: 'A128GCM', zip: 'TEST' }
    payload = "#{JWE::Base64.jwe_encode(hdr.to_json)}.QY.QY.QY.QY"
    expect { JWE.decrypt(payload, rsa_key) }.to raise_error(ArgumentError)
  end

  it 'raises when encrypting with a nil key' do
    expect { JWE.encrypt(plaintext, nil) }.to raise_error(ArgumentError)
  end

  it 'raises when decrypting with a nil key' do
    hdr = { alg: 'A192CBC-HS384', enc: 'A128GCM', zip: 'TEST' }
    payload = "#{JWE::Base64.jwe_encode(hdr.to_json)}.QY.QY.QY.QY"
    expect { JWE.decrypt(payload, nil) }.to raise_error(ArgumentError)
  end

  it 'raises when encrypting with a blank key' do
    expect { JWE.encrypt(plaintext, "  \t \n ") }.to raise_error(ArgumentError)
  end

  it 'raises when decrypting with a blank key' do
    hdr = { alg: 'A192CBC-HS384', enc: 'A128GCM', zip: 'TEST' }
    payload = "#{JWE::Base64.jwe_encode(hdr.to_json)}.QY.QY.QY.QY"
    expect { JWE.decrypt(payload, "  \t \n ") }.to raise_error(ArgumentError)
  end

  it 'raises when encrypting with a nil key with `dir` algorithm' do
    expect { JWE.encrypt(plaintext, nil, alg: 'dir') }.to raise_error(ArgumentError)
  end

  it 'raises when decrypting with a nil key with `dir` algorithm' do
    hdr = { alg: 'A192CBC-HS384', enc: 'A128GCM', zip: 'TEST' }
    payload = "#{JWE::Base64.jwe_encode(hdr.to_json)}.QY.QY.QY.QY"
    expect { JWE.decrypt(payload, nil, alg: 'dir') }.to raise_error(ArgumentError)
  end
end

describe 'JWE with AES GCM Key Wrap algorithms' do
  let(:plaintext) { 'The true sign of intelligence is not knowledge but imagination.' }

  gcmkw_algs = {
    'A128GCMKW' => 16,
    'A192GCMKW' => 24,
    'A256GCMKW' => 32
  }

  def decode_header(token)
    JSON.parse(JWE::Serialization::Compact.decode(token).first)
  end

  def flip_first_byte(base64_value)
    raw = JWE::Base64.jwe_decode(base64_value)
    raw.setbyte(0, raw.getbyte(0) ^ 0x01)
    JWE::Base64.jwe_encode(raw)
  end

  def tamper_header(token)
    parts = token.split('.')
    header = JSON.parse(JWE::Base64.jwe_decode(parts[0]))
    yield header
    parts[0] = JWE::Base64.jwe_encode(header.to_json)
    parts.join('.')
  end

  gcmkw_algs.each do |alg, kek_size|
    describe alg do
      let(:kek) { SecureRandom.random_bytes(kek_size) }
      let(:token) { JWE.encrypt(plaintext, kek, alg: alg) }

      it 'roundtrips a compact serialization' do
        expect(JWE.decrypt(token, kek)).to eq plaintext
      end

      it 'roundtrips with a CBC-HMAC content encryption method' do
        token = JWE.encrypt(plaintext, kek, alg: alg, enc: 'A128CBC-HS256')

        expect(JWE.decrypt(token, kek)).to eq plaintext
      end

      it 'carries the wrapping iv and tag in the protected header' do
        header = decode_header(token)

        expect(JWE::Base64.jwe_decode(header['iv']).bytesize).to eq 12
        expect(JWE::Base64.jwe_decode(header['tag']).bytesize).to eq 16
      end

      it 'uses distinct iv and tag values for key wrapping and content encryption' do
        parts = token.split('.')
        header = decode_header(token)

        expect(header['iv']).to_not eq parts[2]
        expect(header['tag']).to_not eq parts[4]
      end

      it 'rejects a token with a tampered key wrap tag' do
        tampered = tamper_header(token) { |h| h['tag'] = flip_first_byte(h['tag']) }

        expect { JWE::Serialization::Compact.decode(tampered) }.to_not raise_error
        expect { JWE.decrypt(tampered, kek) }
          .to raise_error(JWE::InvalidData, /key wrap authentication tag/)
      end

      it 'rejects a token with a tampered key wrap iv' do
        tampered = tamper_header(token) { |h| h['iv'] = flip_first_byte(h['iv']) }

        expect { JWE::Serialization::Compact.decode(tampered) }.to_not raise_error
        expect { JWE.decrypt(tampered, kek) }
          .to raise_error(JWE::InvalidData, /key wrap authentication tag/)
      end

      it 'rejects a token missing the key wrap parameters' do
        tampered = tamper_header(token) do |h|
          h.delete('iv')
          h.delete('tag')
        end

        expect { JWE.decrypt(tampered, kek) }.to raise_error(JWE::InvalidData)
      end

      it 'rejects a token with a tampered content encryption tag' do
        parts = token.split('.')
        parts[4] = flip_first_byte(parts[4])
        tampered = parts.join('.')

        # The key wrapping layer still authenticates and unwraps the CEK...
        header, encrypted_cek, = JWE::Serialization::Compact.decode(tampered)
        unwrapper = JWE::Alg.for(alg).new(kek)
        unwrapper.apply_header(JSON.parse(header))
        expect(unwrapper.decrypt(encrypted_cek)).to_not be_nil

        # ...so the failure comes from the content encryption layer.
        expect { JWE.decrypt(tampered, kek) }
          .to raise_error(JWE::InvalidData, /ciphertext or authentication tag/)
      end

      it 'rejects a token with a tampered content encryption iv' do
        parts = token.split('.')
        parts[2] = flip_first_byte(parts[2])
        tampered = parts.join('.')

        expect { JWE.decrypt(tampered, kek) }
          .to raise_error(JWE::InvalidData, /ciphertext or authentication tag/)
      end

      it 'rejects a token with a tampered content ciphertext' do
        parts = token.split('.')
        parts[3] = flip_first_byte(parts[3])
        tampered = parts.join('.')

        expect { JWE.decrypt(tampered, kek) }
          .to raise_error(JWE::InvalidData, /ciphertext or authentication tag/)
      end

      it 'rejects decryption with a wrong key encryption key' do
        other_kek = SecureRandom.random_bytes(kek_size)

        expect { JWE.decrypt(token, other_kek) }.to raise_error(JWE::InvalidData)
      end

      it 'rejects a key encryption key with a wrong length' do
        expect { JWE.encrypt(plaintext, SecureRandom.random_bytes(kek_size + 8), alg: alg) }
          .to raise_error(ArgumentError)
      end
    end
  end
end
