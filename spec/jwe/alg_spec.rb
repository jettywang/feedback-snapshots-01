# frozen_string_literal: true

require 'jwe/alg/dir'
require 'jwe/alg/rsa_oaep'
require 'jwe/alg/rsa15'
require 'jwe/alg/a128_kw'
require 'jwe/alg/a192_kw'
require 'jwe/alg/a256_kw'
require 'jwe/alg/a128_gcm_kw'
require 'jwe/alg/a192_gcm_kw'
require 'jwe/alg/a256_gcm_kw'
require 'openssl'

describe JWE::Alg do
  describe '.for' do
    it 'returns a class for the specified alg' do
      expect(JWE::Alg.for('RSA-OAEP')).to eq JWE::Alg::RsaOaep
    end

    it 'raises an error for a not-implemented alg' do
      expect { JWE::Alg.for('ERSA-4096-MAGIC') }.to raise_error(JWE::NotImplementedError)
    end
  end
end

describe JWE::Alg::Dir do
  # The direct encryption method does not Encrypt the CEK.
  # When building the final JWE object, the "Encrypted CEK" part is left blank

  describe '#encrypt' do
    it 'returns an empty string' do
      expect(JWE::Alg::Dir.new('whatever').encrypt('any')).to eq ''
    end
  end

  describe '#decrypt' do
    it 'returns the original key' do
      expect(JWE::Alg::Dir.new('whatever').decrypt('any')).to eq 'whatever'
    end
  end
end

key_path = "#{File.dirname(__FILE__)}/../keys/rsa.pem"
key = OpenSSL::PKey::RSA.new File.read(key_path)

describe JWE::Alg::RsaOaep do
  let(:alg) { JWE::Alg::RsaOaep.new(key) }

  describe '#encrypt' do
    it 'returns an encrypted string' do
      expect(alg.encrypt('random key')).to_not eq 'random key'
    end
  end

  it 'decrypts the encrypted key to the original key' do
    ciphertext = alg.encrypt('random key')
    expect(alg.decrypt(ciphertext)).to eq 'random key'
  end
end

if OpenSSL::VERSION >= '3.0'
  describe JWE::Alg::RsaOaep256 do
    let(:alg) { JWE::Alg::RsaOaep256.new(key) }

    describe '#encrypt' do
      it 'returns an encrypted string' do
        expect(alg.encrypt('random key')).to_not eq 'random key'
      end
    end

    it 'decrypts the encrypted key to the original key' do
      ciphertext = alg.encrypt('random key')
      expect(alg.decrypt(ciphertext)).to eq 'random key'
    end
  end
else
  describe JWE::Alg do
    it 'raises an error for rsa-oaep-256 if openssl < 3.0' do
      expect { JWE::Alg.for('rsa-oaep-256') }.to raise_error(JWE::NotImplementedError)
    end
  end
end

describe JWE::Alg::Rsa15 do
  let(:alg) { JWE::Alg::Rsa15.new(key) }

  describe '#encrypt' do
    it 'returns an encrypted string' do
      expect(alg.encrypt('random key')).to_not eq 'random key'
    end
  end

  it 'decrypts the encrypted key to the original key' do
    ciphertext = alg.encrypt('random key')
    expect(alg.decrypt(ciphertext)).to eq 'random key'
  end
end

[
  JWE::Alg::A128kw,
  JWE::Alg::A192kw,
  JWE::Alg::A256kw
].each_with_index do |klass, i|
  describe klass do
    let(:kek) { SecureRandom.random_bytes(16 + (i * 8)) }
    let(:cek) { SecureRandom.random_bytes(32) }
    let(:alg) { klass.new(kek) }

    describe '#encrypt' do
      it 'returns an encrypted string' do
        expect(alg.encrypt(cek)).to_not eq cek
      end
    end

    it 'decrypts the encrypted key to the original key' do
      ciphertext = alg.encrypt(cek)
      expect(alg.decrypt(ciphertext)).to eq cek
    end

    it 'raises when trying to decrypt tampered keys' do
      alg = klass.new(kek, "\xA7\xA7\xA7\xA7\xA6\xA6\xA6\xA6")
      ciphertext = alg.encrypt(cek)

      bad_alg = klass.new(kek, "\xA7\xA7\xA7\xA7\xA7\xA7\xA7\xA7")
      expect { bad_alg.decrypt(ciphertext) }.to raise_error(StandardError)
    end
  end
end

# Public known-answer vectors from "The Galois/Counter Mode of Operation (GCM)"
# (McGrew, Viega), Appendix B. AES GCM Key Wrap (RFC 7518, section 4.7) is plain
# AES GCM over the CEK with an empty Additional Authenticated Data value, so the
# no-AAD test cases apply directly: Test Case 3 (AES-128), Test Case 13
# (AES-192) and Test Case 15 (AES-256).
gcmkw_vector_cek = ['d9313225f88406e5a55909c5aff5269a' \
                    '86a7a9531534f7da2e4c303d8a318a72' \
                    '1c3c0c95956809532fcf0e2449a6b525' \
                    'b16aedf5aa0de657ba637b391aafd255'].pack('H*')
gcmkw_vector_iv = ['cafebabefacedbaddecaf888'].pack('H*')
gcmkw_vectors = {
  JWE::Alg::A128gcmkw => {
    kek: 'feffe9928665731c6d6a8f9467308308',
    ciphertext: '42831ec2217774244b7221b784d0d49c' \
                'e3aa212f2c02a4e035c17e2329aca12e' \
                '21d514b25466931c7d8f6a5aac84aa05' \
                '1ba30b396a0aac973d58e091473f5985',
    tag: '4d5c2af327cd64a62cf35abd2ba6fab4'
  },
  JWE::Alg::A192gcmkw => {
    kek: 'feffe9928665731c6d6a8f9467308308feffe9928665731c',
    ciphertext: '3980ca0b3c00e841eb06fac4872a2757' \
                '859e1ceaa6efd984628593b40ca1e19c' \
                '7d773d00c144c525ac619d18c84a3f47' \
                '18e2448b2fe324d9ccda2710acade256',
    tag: '9924a7c8587336bfb118024db8674a14'
  },
  JWE::Alg::A256gcmkw => {
    kek: 'feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308',
    ciphertext: '522dc1f099567d07f47f37a32a84427d' \
                '643a8cdcbfe5c0c97598a2bd2555d1aa' \
                '8cb08e48590dbb3da7b08b1056828838' \
                'c5f61e6393ba7a0abcc9f662898015ad',
    tag: 'b094dac5d93471bdec1a502270e3cc6c'
  }
}

gcmkw_vectors.each_with_index do |(klass, vector), i|
  describe klass do
    let(:kek) { [vector[:kek]].pack('H*') }
    let(:cek) { gcmkw_vector_cek }
    let(:iv) { gcmkw_vector_iv }
    let(:wrapped_cek) { [vector[:ciphertext]].pack('H*') }
    let(:wrap_tag) { [vector[:tag]].pack('H*') }

    it 'wraps a CEK matching the public known-answer vector' do
      alg = klass.new(kek, iv)

      expect(alg.encrypt(cek)).to eq wrapped_cek
      expect(alg.tag).to eq wrap_tag
    end

    it 'unwraps the public known-answer vector to the original CEK' do
      alg = klass.new(kek, iv, wrap_tag)

      expect(alg.decrypt(wrapped_cek)).to eq cek
    end

    it 'roundtrips a randomly generated CEK' do
      cek = SecureRandom.random_bytes(32)
      enc = klass.new(kek)
      encrypted = enc.encrypt(cek)

      dec = klass.new(kek, enc.iv, enc.tag)
      expect(dec.decrypt(encrypted)).to eq cek
    end

    it 'roundtrips the wrapping parameters through the JWE header' do
      enc = klass.new(kek)
      encrypted = enc.encrypt(cek)
      params = enc.header_params

      expect(JWE::Base64.jwe_decode(params[:iv]).bytesize).to eq 12
      expect(JWE::Base64.jwe_decode(params[:tag]).bytesize).to eq 16

      dec = klass.new(kek)
      dec.apply_header(JSON.parse(params.to_json))
      expect(dec.decrypt(encrypted)).to eq cek
    end

    it 'raises when the key encryption key has a wrong length' do
      bad_kek = SecureRandom.random_bytes(kek.bytesize + 8)

      expect { klass.new(bad_kek).encrypt(cek) }.to raise_error(ArgumentError)
      expect { klass.new(bad_kek, iv, wrap_tag).decrypt(wrapped_cek) }.to raise_error(ArgumentError)
    end

    it 'raises when the key encryption key is nil' do
      expect { klass.new.encrypt(cek) }.to raise_error(ArgumentError)
    end

    it 'raises when the wrapping iv is missing' do
      expect { klass.new(kek, nil, wrap_tag).decrypt(wrapped_cek) }.to raise_error(JWE::InvalidData, /iv/)
    end

    it 'raises when the wrapping iv has a wrong length' do
      expect { klass.new(kek, iv + "\x00", wrap_tag).decrypt(wrapped_cek) }.to raise_error(JWE::InvalidData, /iv/)
      expect { klass.new(kek, iv[0..-2], wrap_tag).decrypt(wrapped_cek) }.to raise_error(JWE::InvalidData, /iv/)
    end

    it 'raises when the wrapping tag is missing' do
      expect { klass.new(kek, iv).decrypt(wrapped_cek) }.to raise_error(JWE::InvalidData, /tag/)
    end

    it 'raises when the wrapping tag has a wrong length' do
      expect { klass.new(kek, iv, wrap_tag[0..-2]).decrypt(wrapped_cek) }.to raise_error(JWE::InvalidData, /tag/)
    end

    it 'raises when the wrapping tag has been tampered with' do
      tampered_tag = wrap_tag.dup
      tampered_tag.setbyte(0, tampered_tag.getbyte(0) ^ 0x01)

      expect { klass.new(kek, iv, tampered_tag).decrypt(wrapped_cek) }.to raise_error(JWE::InvalidData)
    end

    it 'raises when the wrapped CEK has been tampered with' do
      tampered_cek = wrapped_cek.dup
      tampered_cek.setbyte(0, tampered_cek.getbyte(0) ^ 0x01)

      expect { klass.new(kek, iv, wrap_tag).decrypt(tampered_cek) }.to raise_error(JWE::InvalidData)
    end

    it 'raises when unwrapping with a different key encryption key' do
      other_kek = SecureRandom.random_bytes(16 + (i * 8))

      expect { klass.new(other_kek, iv, wrap_tag).decrypt(wrapped_cek) }.to raise_error(JWE::InvalidData)
    end
  end
end
