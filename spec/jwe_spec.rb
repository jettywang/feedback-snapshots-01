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

  describe 'when decrypting RSA1_5 tokens' do
    let(:token) { JWE.encrypt(plaintext, rsa_key, alg: 'RSA1_5', enc: 'A128GCM') }
    let(:token_parts) { token.split('.') }

    let(:padding_invalid_token) do
      parts = token_parts.dup
      parts[1] = JWE::Base64.jwe_encode(SecureRandom.random_bytes(256))
      parts.join('.')
    end

    let(:wrong_length_cek_token) do
      parts = token_parts.dup
      parts[1] = JWE::Base64.jwe_encode(rsa_key.public_encrypt('short'))
      parts.join('.')
    end

    let(:auth_invalid_token) do
      parts = token_parts.dup
      parts[4] = JWE::Base64.jwe_encode(SecureRandom.random_bytes(16))
      parts.join('.')
    end

    def error_for(payload)
      JWE.decrypt(payload, rsa_key)
      nil
    rescue StandardError => e
      e
    end

    it 'roundtrips' do
      expect(JWE.decrypt(token, rsa_key)).to eq plaintext
    end

    it 'rejects padding-invalid, wrong-length and auth-invalid tokens with the same failure contract' do
      errors = [padding_invalid_token, wrong_length_cek_token, auth_invalid_token].map { |t| error_for(t) }

      expect(errors).to all(be_a(JWE::InvalidData))
      expect(errors.map(&:message).uniq.length).to eq 1
    end

    it 'does not return plaintext for implicitly rejected tokens' do
      expect(error_for(padding_invalid_token)).to be_a(JWE::InvalidData)
      expect(error_for(wrong_length_cek_token)).to be_a(JWE::InvalidData)
    end

    it 'does not expose private key operation errors or key material' do
      cek = rsa_key.private_decrypt(JWE::Base64.jwe_decode(token_parts[1]))
      errors = [padding_invalid_token, wrong_length_cek_token].map { |t| error_for(t) }

      expect(errors).to all(be_a(JWE::InvalidData))
      errors.each do |error|
        expect(error).to_not be_a(OpenSSL::PKey::PKeyError)
        expect(error.message).to_not include(cek)
        expect(error.cause).to be_a(JWE::BadCEK)
        expect(error.cause.message).to_not include(cek)
      end
    end

    it 'runs the content authentication path for implicitly rejected CEKs' do
      cbc_token = JWE.encrypt(plaintext, rsa_key, alg: 'RSA1_5', enc: 'A256CBC-HS512')
      parts = cbc_token.split('.')
      parts[1] = JWE::Base64.jwe_encode(SecureRandom.random_bytes(256))

      # This message is only raised after the HMAC over the ciphertext has
      # been computed and compared, proving authentication still runs.
      expect { JWE.decrypt(parts.join('.'), rsa_key) }
        .to raise_error(JWE::InvalidData, 'Authentication tag verification failed')
    end
  end

  describe '.unwrap_cek' do
    let(:cek) { SecureRandom.random_bytes(16) }

    it 'returns a valid CEK untouched' do
      unwrapped, reason = JWE.unwrap_cek('RSA1_5', rsa_key, rsa_key.public_encrypt(cek), 16)

      expect(unwrapped).to eq cek
      expect(reason).to be_nil
    end

    it 'substitutes secure random material matching the requested length on padding failure' do
      first, = JWE.unwrap_cek('RSA1_5', rsa_key, SecureRandom.random_bytes(256), 32)
      second, = JWE.unwrap_cek('RSA1_5', rsa_key, SecureRandom.random_bytes(256), 32)

      expect(first.bytesize).to eq 32
      expect(first).to_not eq "\0" * 32
      expect(first).to_not eq second
    end

    it 'substitutes secure random material when the unwrapped CEK length is wrong' do
      unwrapped, reason = JWE.unwrap_cek('RSA1_5', rsa_key, rsa_key.public_encrypt('short'), 64)

      expect(unwrapped.bytesize).to eq 64
      expect(unwrapped).to_not eq "\0" * 64
      expect(reason).to_not be_nil
    end
  end
end
