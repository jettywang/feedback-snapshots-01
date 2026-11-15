# frozen_string_literal: true

describe JWE::Serialization::General do
  let(:components) do
    {
      protected_header: { alg: 'RSA-OAEP', enc: 'A128GCM' },
      recipients: [
        { header: { kid: 'one' }, encrypted_key: 'a' },
        { header: { kid: 'two' }, encrypted_key: 'b' }
      ],
      iv: 'c',
      ciphertext: 'd',
      tag: 'e'
    }
  end

  describe '#encode' do
    it 'wraps every recipient and base64url encodes the shared members' do
      token = described_class.encode(**components)
      object = JSON.parse(token)

      expect(object['protected']).to eq JWE::Base64.jwe_encode(components[:protected_header].to_json)
      expect(object['iv']).to eq 'Yw'
      expect(object['ciphertext']).to eq 'ZA'
      expect(object['tag']).to eq 'ZQ'
      expect(object['recipients']).to eq [
        { 'header' => { 'kid' => 'one' }, 'encrypted_key' => 'YQ' },
        { 'header' => { 'kid' => 'two' }, 'encrypted_key' => 'Yg' }
      ]
    end

    it 'omits the protected member when there is no protected header' do
      token = described_class.encode(**components.merge(protected_header: nil,
                                                        shared_unprotected_header: { enc: 'A128GCM' },
                                                        aad: 'aad'))
      object = JSON.parse(token)

      expect(object).not_to have_key('protected')
      expect(object['unprotected']).to eq('enc' => 'A128GCM')
      expect(object['aad']).to eq JWE::Base64.jwe_encode('aad')
    end
  end

  describe '#decode' do
    it 'roundtrips the encoded message' do
      message = described_class.decode(described_class.encode(**components))

      expect(message.protected_header).to eq('alg' => 'RSA-OAEP', 'enc' => 'A128GCM')
      expect(message.iv).to eq 'c'
      expect(message.ciphertext).to eq 'd'
      expect(message.tag).to eq 'e'
      expect(message.recipients.map { |recipient| recipient[:encrypted_key] }).to eq %w[a b]
      expect(message.recipients.map { |recipient| recipient[:header]['kid'] }).to eq %w[one two]
    end

    it 'rejects JSON that is not an object' do
      expect { described_class.decode('[]') }.to raise_error(JWE::DecodeError)
    end

    it 'rejects malformed JSON' do
      expect { described_class.decode('{not-json') }.to raise_error(JWE::DecodeError)
    end

    it 'rejects a message without a recipients array' do
      token = described_class.encode(**components)
      object = JSON.parse(token)
      object.delete('recipients')

      expect { described_class.decode(object.to_json) }.to raise_error(JWE::DecodeError, /recipients/)
    end

    it 'rejects a message with no recipients' do
      token = described_class.encode(**components)
      object = JSON.parse(token)
      object['recipients'] = []

      expect { described_class.decode(object.to_json) }.to raise_error(JWE::DecodeError, /at least one recipient/)
    end

    it 'rejects a missing required member' do
      token = described_class.encode(**components)
      object = JSON.parse(token)
      object.delete('tag')

      expect { described_class.decode(object.to_json) }.to raise_error(JWE::DecodeError, /tag/)
    end

    it 'rejects an invalid base64url member' do
      token = described_class.encode(**components)
      object = JSON.parse(token)
      object['tag'] = 'not base64!!!'

      expect { described_class.decode(object.to_json) }.to raise_error(JWE::DecodeError)
    end

    it 'rejects a protected header that is not valid JSON' do
      token = described_class.encode(**components)
      object = JSON.parse(token)
      object['protected'] = JWE::Base64.jwe_encode('{broken')

      expect { described_class.decode(object.to_json) }.to raise_error(JWE::DecodeError, /protected header/)
    end

    it 'rejects an empty protected member' do
      token = described_class.encode(**components)
      object = JSON.parse(token)
      object['protected'] = ''

      expect { described_class.decode(object.to_json) }.to raise_error(JWE::DecodeError, /empty/)
    end

    it 'rejects a protected member that is not a string' do
      token = described_class.encode(**components)
      object = JSON.parse(token)
      object['protected'] = 123

      expect { described_class.decode(object.to_json) }.to raise_error(JWE::DecodeError, /string/)
    end

    it 'rejects an unprotected member that is not an object' do
      token = described_class.encode(**components)
      object = JSON.parse(token)
      object['unprotected'] = 'nope'

      expect { described_class.decode(object.to_json) }.to raise_error(JWE::DecodeError, /unprotected/)
    end

    it 'rejects a recipient that is not an object' do
      token = described_class.encode(**components)
      object = JSON.parse(token)
      object['recipients'] = ['nope']

      expect { described_class.decode(object.to_json) }.to raise_error(JWE::DecodeError, /recipient/)
    end

    it 'rejects the aad member when a protected header is present' do
      token = described_class.encode(**components)
      object = JSON.parse(token)
      object['aad'] = JWE::Base64.jwe_encode('aad')
      key = OpenSSL::PKey::RSA.new(2048)

      expect { JWE.decrypt_general(object.to_json, key) }.to raise_error(JWE::DecodeError, /aad/)
    end
  end
end
