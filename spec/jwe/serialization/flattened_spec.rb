# frozen_string_literal: true

describe JWE::Serialization::Flattened do
  let(:components) do
    {
      protected_header: { alg: 'RSA-OAEP', enc: 'A128GCM' },
      recipient_header: { kid: 'one' },
      encrypted_key: 'a',
      iv: 'c',
      ciphertext: 'd',
      tag: 'e'
    }
  end

  describe '#encode' do
    it 'places the single recipient members at the top level' do
      object = JSON.parse(described_class.encode(**components))

      expect(object['protected']).to eq JWE::Base64.jwe_encode(components[:protected_header].to_json)
      expect(object['header']).to eq('kid' => 'one')
      expect(object['encrypted_key']).to eq 'YQ'
      expect(object['iv']).to eq 'Yw'
      expect(object['ciphertext']).to eq 'ZA'
      expect(object['tag']).to eq 'ZQ'
      expect(object).not_to have_key('recipients')
    end
  end

  describe '#decode' do
    it 'normalizes the single recipient into the same shape as General' do
      message = described_class.decode(described_class.encode(**components))

      expect(message.recipients.length).to eq 1
      expect(message.recipients.first[:header]).to eq('kid' => 'one')
      expect(message.recipients.first[:encrypted_key]).to eq 'a'
      expect(message.protected_header).to eq('alg' => 'RSA-OAEP', 'enc' => 'A128GCM')
    end

    it 'rejects a recipients member' do
      token = described_class.encode(**components)
      object = JSON.parse(token)
      object['recipients'] = []

      expect { described_class.decode(object.to_json) }.to raise_error(JWE::DecodeError, /recipients/)
    end

    it 'rejects a missing encrypted_key' do
      token = described_class.encode(**components)
      object = JSON.parse(token)
      object.delete('encrypted_key')

      expect { described_class.decode(object.to_json) }.to raise_error(JWE::DecodeError, /encrypted_key/)
    end

    it 'rejects a header member that is not an object' do
      token = described_class.encode(**components)
      object = JSON.parse(token)
      object['header'] = 42

      expect { described_class.decode(object.to_json) }.to raise_error(JWE::DecodeError, /header/)
    end
  end
end
