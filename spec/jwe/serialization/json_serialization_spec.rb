# frozen_string_literal: true

describe JWE::Serialization::JsonSerialization do
  describe '.authenticated_data' do
    it 'uses the original encoded protected header verbatim' do
      encoded = JWE::Base64.jwe_encode('{"alg":"RSA-OAEP"}')

      expect(described_class.authenticated_data(encoded, nil)).to eq encoded
    end

    it 'base64url encodes the external AAD when there is no protected header' do
      expect(described_class.authenticated_data(nil, 'aad')).to eq JWE::Base64.jwe_encode('aad')
    end

    it 'falls back to empty AAD when neither is present' do
      expect(described_class.authenticated_data(nil, nil)).to eq ''
    end
  end

  describe '.assert_unique_header_names' do
    it 'passes when every header name lives in a single location' do
      expect do
        described_class.assert_unique_header_names({ 'alg' => 'RSA-OAEP' }, { 'cty' => 'x' }, { 'kid' => 'k' })
      end.not_to raise_error
    end

    it 'rejects a name shared by two locations' do
      expect do
        described_class.assert_unique_header_names({ 'alg' => 'RSA-OAEP' }, nil, { 'alg' => 'RSA-OAEP' })
      end.to raise_error(JWE::DecodeError, /Duplicate/)
    end
  end
end
