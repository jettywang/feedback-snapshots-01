RSpec.describe RubySMB::Dcerpc::Gkdi::GkdiGroupKeyEnvelope do
  include GkdiSupport

  let(:root_key_identifier) { '11111111-2222-3333-4444-555555555555' }

  it 'is little endian' do
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :little
  end

  describe 'reading a valid envelope' do
    let(:blob) do
      build_envelope(
        root_key_identifier: root_key_identifier,
        l0_index: 100, l1_index: 101, l2_index: 102,
        secret_agreement_parameters: [1, 2, 3, 4]
      )
    end
    subject(:envelope) { described_class.read(blob) }

    it 'parses without raising' do
      expect { envelope }.not_to raise_error
    end

    it 'consumes the whole blob' do
      expect(envelope.num_bytes).to eq(blob.bytesize)
    end

    it 'reads the root key GUID and L0/L1/L2 identifiers' do
      expect(envelope.root_key_identifier).to eq(root_key_identifier)
      expect(envelope.l0_index).to eq(100)
      expect(envelope.l1_index).to eq(101)
      expect(envelope.l2_index).to eq(102)
    end

    it 'reads the KDF algorithm and its nested hash name' do
      expect(envelope.kdf_algorithm.snapshot.encode('UTF-8')).to eq('SP800_108_CTR_HMAC')
      expect(envelope.cb_kdf_parameters).to eq(envelope.kdf_parameters_raw.snapshot.length)
      expect(envelope.kdf_parameters.hash_algorithm_name.snapshot.encode('UTF-8')).to eq('SHA256')
    end

    it 'reads the secret agreement parameters using their declared length' do
      expect(envelope.cb_secret_agreement_parameters).to eq(4)
      expect(envelope.secret_agreement_parameters.snapshot).to eq([1, 2, 3, 4])
    end

    it 'reads the L1 key and reports an absent L2 key without shifting later fields' do
      expect(envelope.cb_l1_key).to eq(64)
      expect(envelope.l1_key.snapshot.length).to eq(64)
      expect(envelope.cb_l2_key).to eq(0)
      expect(envelope.l2_key.snapshot).to be_empty
      expect(envelope.domain_name.snapshot.encode('UTF-8')).to eq('corp.example.com')
      expect(envelope.forest_name.snapshot.encode('UTF-8')).to eq('example.com')
    end
  end

  describe 'reading an FFC DH envelope with an L2 key' do
    let(:l2_key) { Array.new(128, 0xDD) }
    let(:blob) do
      build_envelope(
        root_key_identifier: root_key_identifier,
        dw_flags: (1 << 31),
        public_key_length: 128,
        l2_key: l2_key
      )
    end
    subject(:envelope) { described_class.read(blob) }

    it 'uses public_key_length for the L2 key when the FFC flag is set' do
      expect(envelope.l2_key.snapshot.length).to eq(128)
      expect(envelope.l2_key.snapshot).to eq(l2_key)
    end

    it 'keeps the domain and forest names aligned after the key material' do
      expect(envelope.domain_name.snapshot.encode('UTF-8')).to eq('corp.example.com')
      expect(envelope.forest_name.snapshot.encode('UTF-8')).to eq('example.com')
    end
  end

  describe 'write/read round trip' do
    it 'rebuilds an equivalent envelope from assigned values' do
      envelope = described_class.new
      envelope.root_key_identifier = root_key_identifier
      envelope.kdf_algorithm = 'SP800_108_CTR_HMAC'
      envelope.kdf_parameters = { hash_algorithm_name: 'SHA256' }
      envelope.secret_agreement_algorithm = 'DH'
      envelope.cb_secret_agreement_parameters = 3
      envelope.secret_agreement_parameters = [9, 9, 9]
      envelope.cb_l1_key = 0
      envelope.cb_l2_key = 0
      envelope.domain_name = 'corp.example.com'
      envelope.forest_name = 'example.com'

      rebuilt = described_class.read(envelope.to_binary_s)
      expect(rebuilt.root_key_identifier).to eq(root_key_identifier)
      expect(rebuilt.kdf_algorithm.snapshot.encode('UTF-8')).to eq('SP800_108_CTR_HMAC')
      expect(rebuilt.kdf_parameters.hash_algorithm_name.snapshot.encode('UTF-8')).to eq('SHA256')
      expect(rebuilt.secret_agreement_parameters.snapshot).to eq([9, 9, 9])
      expect(rebuilt.cb_kdf_parameters).to eq(rebuilt.kdf_parameters_raw.snapshot.length)
    end
  end

  describe 'reading an envelope without a KDF parameters block' do
    it 'exposes a nil parsed parameters block without shifting later fields' do
      kdf_name = wide_stringz('SP800_108_CTR_HMAC')
      sa_name = wide_stringz('DH')
      sa_parameters = [1, 2].pack('C*')
      domain = wide_stringz('corp.example.com')
      forest = wide_stringz('example.com')
      l1_key = Array.new(64, 0xAA)

      header =
        [1].pack('V') + [0x4b, 0x44, 0x53, 0x5b].pack('C*') + [0].pack('V') +
        [100, 101, 102].pack('V3') + guid_bytes(root_key_identifier)
      counts = [
        kdf_name.bytesize, 0, sa_name.bytesize, sa_parameters.bytesize,
        256, 256, l1_key.length, 0, domain.bytesize, forest.bytesize
      ]
      header += counts.pack('V10')
      zero_blob =
        (header + kdf_name + sa_name + sa_parameters + l1_key.pack('C*') + domain + forest).b

      envelope = described_class.read(zero_blob)
      expect(envelope.cb_kdf_parameters).to eq(0)
      expect(envelope.kdf_parameters_raw.snapshot).to be_empty
      expect(envelope.kdf_parameters).to be_nil
      expect(envelope.secret_agreement_parameters.snapshot).to eq([1, 2])
      expect(envelope.domain_name.snapshot.encode('UTF-8')).to eq('corp.example.com')
    end
  end
end
