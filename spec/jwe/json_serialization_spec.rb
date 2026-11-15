# frozen_string_literal: true

describe 'JWE JSON Serialization' do
  let(:plaintext) { 'The true sign of intelligence is not knowledge but imagination.' }
  let(:first_key) { OpenSSL::PKey::RSA.new(2048) }
  let(:second_key) { OpenSSL::PKey::RSA.new(2048) }
  let(:third_key) { OpenSSL::PKey::RSA.new(2048) }
  let(:kw_key) { SecureRandom.random_bytes(16) }

  describe 'General JWE JSON Serialization' do
    let(:recipients) do
      [
        { key: first_key, alg: 'RSA-OAEP', kid: 'first' },
        { key: second_key, alg: 'RSA-OAEP', kid: 'second' }
      ]
    end
    let(:token) { JWE.encrypt_general(plaintext, recipients) }

    it 'produces a general JSON object with one shared content encryption' do
      object = JSON.parse(token)

      expect(object['recipients'].length).to eq 2
      expect(object.keys).to include('protected', 'iv', 'ciphertext', 'tag')
      expect(object['recipients'].first.keys).to contain_exactly('header', 'encrypted_key')
      expect(object['recipients'].map { |recipient| recipient['encrypted_key'] }.uniq.length).to eq 2
    end

    it 'lets every legitimate recipient open the same ciphertext' do
      first_result = JWE.decrypt_general(token, first_key)
      second_result = JWE.decrypt_general(token, second_key)

      expect(first_result.plaintext).to eq plaintext
      expect(second_result.plaintext).to eq plaintext
      expect(first_result.recipient_index).to eq 0
      expect(second_result.recipient_index).to eq 1
      expect(first_result.header['kid']).to eq 'first'
      expect(second_result.header['kid']).to eq 'second'
    end

    it 'exposes the recipient that was actually used' do
      result = JWE.decrypt_general(token, second_key)

      expect(result).to be_a(JWE::DecryptionResult)
      expect(result.recipient_index).to eq 1
      expect(result.recipient_header['kid']).to eq 'second'
    end

    it 'supports different key management algorithms sharing one CEK' do
      mixed = JWE.encrypt_general(plaintext, [
        { key: first_key, alg: 'RSA-OAEP', kid: 'rsa' },
        { key: kw_key, alg: 'A128KW', kid: 'kw' }
      ])

      expect(JWE.decrypt_general(mixed, first_key).plaintext).to eq plaintext
      kw_result = JWE.decrypt_general(mixed, kw_key)
      expect(kw_result.plaintext).to eq plaintext
      expect(kw_result.recipient_index).to eq 1
    end

    it 'roundtrips with a CBC-HS content encryption algorithm' do
      cbc_token = JWE.encrypt_general(plaintext, recipients, enc: 'A128CBC-HS256')

      expect(JWE.decrypt_general(cbc_token, first_key).plaintext).to eq plaintext
      expect(JWE.decrypt_general(cbc_token, second_key).plaintext).to eq plaintext
    end

    it 'roundtrips with DEF compression' do
      zipped = JWE.encrypt_general(plaintext, recipients, zip: 'DEF')

      expect(JWE.decrypt_general(zipped, first_key).plaintext).to eq plaintext
    end

    it 'keeps the compact entry point working' do
      compact = JWE.encrypt(plaintext, first_key)

      expect(JWE.decrypt(compact, first_key)).to eq plaintext
    end

    context 'with external AAD and no protected header' do
      let(:aad) { 'external additional authenticated data' }
      let(:aad_token) do
        JWE.encrypt_general(plaintext, recipients, protected: false, aad: aad, cty: 'text/plain')
      end

      it 'authenticates the raw AAD and reads shared unprotected headers' do
        object = JSON.parse(aad_token)

        expect(object).not_to have_key('protected')
        expect(object['aad']).to eq JWE::Base64.jwe_encode(aad)
        expect(object['unprotected']['enc']).to eq 'A128GCM'
        expect(object['unprotected']['cty']).to eq 'text/plain'

        result = JWE.decrypt_general(aad_token, first_key)
        expect(result.plaintext).to eq plaintext
      end

      it 'rejects tampered AAD' do
        object = JSON.parse(aad_token)
        object['aad'] = JWE::Base64.jwe_encode('tampered aad')

        expect { JWE.decrypt_general(object.to_json, first_key) }.to raise_error(JWE::DecodeError)
      end

      it 'requires AAD when the protected header is omitted' do
        expect do
          JWE.encrypt_general(plaintext, recipients, protected: false)
        end.to raise_error(ArgumentError, /AAD/)
      end

      it 'rejects external AAD together with a protected header while encrypting' do
        expect do
          JWE.encrypt_general(plaintext, recipients, aad: 'aad')
        end.to raise_error(ArgumentError, /aad/)
      end
    end

    context 'header parameter uniqueness' do
      it 'rejects a name repeated in the protected and recipient headers' do
        object = JSON.parse(token)
        recipient = object['recipients'].first
        recipient['header'] = recipient['header'].merge('enc' => 'A256GCM')

        expect { JWE.decrypt_general(object.to_json, first_key) }.to raise_error(JWE::DecodeError, /Duplicate/)
      end

      it 'rejects a name repeated in shared unprotected and recipient headers' do
        aad_token = JWE.encrypt_general(plaintext, recipients, protected: false,
                                        aad: 'aad', cty: 'text/plain')
        object = JSON.parse(aad_token)
        object['recipients'].first['header'] = { 'alg' => 'RSA-OAEP', 'cty' => 'evil' }

        expect { JWE.decrypt_general(object.to_json, first_key) }.to raise_error(JWE::DecodeError, /Duplicate/)
      end

      it 'rejects duplicate header names while encrypting' do
        expect do
          JWE.encrypt_general(plaintext,
                              [{ key: first_key, alg: 'RSA-OAEP', enc: 'A256GCM' }])
        end.to raise_error(JWE::DecodeError, /Duplicate/)
      end
    end

    context 'when a recipient is corrupted' do
      let!(:object) do
        parsed = JSON.parse(token)
        parsed['recipients'][0]['encrypted_key'] = JWE::Base64.jwe_encode(SecureRandom.random_bytes(256))
        parsed
      end

      it 'still opens with another legitimate recipient' do
        result = JWE.decrypt_general(object.to_json, second_key)

        expect(result.plaintext).to eq plaintext
        expect(result.recipient_index).to eq 1
      end

      it 'fails without exposing partial plaintext when no recipient matches' do
        expect do
          JWE.decrypt_general(object.to_json, first_key)
        end.to raise_error(JWE::DecodeError, /No recipient could decrypt/)
      end

      it 'fails when the provided key matches none of the recipients' do
        expect do
          JWE.decrypt_general(token, third_key)
        end.to raise_error(JWE::DecodeError, /No recipient could decrypt/)
      end
    end

    it 'authenticates the original protected header bytes' do
      object = JSON.parse(token)
      header = JSON.parse(JWE::Base64.jwe_decode(object['protected']))
      header['kid'] = 'forged'
      object['protected'] = JWE::Base64.jwe_encode(header.to_json)

      expect { JWE.decrypt_general(object.to_json, first_key) }.to raise_error(JWE::DecodeError)
    end

    it 'rejects algorithms that cannot share a CEK across recipients' do
      expect do
        JWE.encrypt_general(plaintext, [{ key: kw_key, alg: 'dir' }])
      end.to raise_error(JWE::DecodeError, /dir/)
    end

    it 'rejects key agreement algorithms that derive a per-recipient CEK' do
      expect do
        JWE.encrypt_general(plaintext, [{ key: first_key, alg: 'ECDH-ES' }])
      end.to raise_error(JWE::DecodeError, /ECDH-ES/)
    end

    it 'rejects unsupported algorithms on the decrypt path' do
      object = JSON.parse(token)
      header = JSON.parse(JWE::Base64.jwe_decode(object['protected']))
      header['enc'] = 'A512GCM'
      object['protected'] = JWE::Base64.jwe_encode(header.to_json)

      expect { JWE.decrypt_general(object.to_json, first_key) }.to raise_error(ArgumentError)
    end

    it 'rejects an aad member alongside a protected header on the decrypt path' do
      object = JSON.parse(token)
      object['aad'] = JWE::Base64.jwe_encode('aad')

      expect { JWE.decrypt_general(object.to_json, first_key) }.to raise_error(JWE::DecodeError, /aad/)
    end

    it 'rejects a message where no header location provides the alg parameter' do
      object = JSON.parse(token)
      header = JSON.parse(JWE::Base64.jwe_decode(object['protected']))
      header.delete('alg')
      object['protected'] = JWE::Base64.jwe_encode(header.to_json)
      object['recipients'].each { |recipient| recipient['header'].delete('alg') }

      expect { JWE.decrypt_general(object.to_json, first_key) }.to raise_error(ArgumentError, /alg/)
    end
  end

  describe 'Flattened JWE JSON Serialization' do
    let(:token) { JWE.encrypt_flattened(plaintext, first_key, kid: 'solo') }

    it 'serializes the single recipient at the top level' do
      object = JSON.parse(token)

      expect(object.keys).to contain_exactly('protected', 'header', 'encrypted_key', 'iv', 'ciphertext', 'tag')
      expect(object['header']['kid']).to eq 'solo'
    end

    it 'decrypts and identifies the only recipient' do
      result = JWE.decrypt_flattened(token, first_key)

      expect(result.plaintext).to eq plaintext
      expect(result.recipient_index).to eq 0
      expect(result.recipient_header['kid']).to eq 'solo'
    end

    it 'supports external AAD through the flattened entry point' do
      aad_token = JWE.encrypt_flattened(plaintext, first_key, protected: false,
                                        aad: 'flat-aad', cty: 'text/plain')

      expect(JWE.decrypt_flattened(aad_token, first_key).plaintext).to eq plaintext
    end

    it 'rejects a flattened object that carries multiple recipients' do
      object = JSON.parse(token)
      object['recipients'] = []

      expect { JWE.decrypt_flattened(object.to_json, first_key) }.to raise_error(JWE::DecodeError, /recipients/)
    end
  end
end
