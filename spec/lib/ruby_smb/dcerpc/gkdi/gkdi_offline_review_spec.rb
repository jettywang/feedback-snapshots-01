RSpec.describe RubySMB::Dcerpc::Gkdi::GkdiOfflineReview do
  include GkdiSupport

  let(:requested_guid) { '11111111-2222-3333-4444-555555555555' }
  let(:request) do
    {
      root_key_id: requested_guid,
      l0_key_id: 100,
      l1_key_id: 101,
      l2_key_id: 102,
      cb_target_sd: 128
    }
  end

  let(:matching_blob) do
    build_envelope(
      root_key_identifier: requested_guid,
      l0_index: 100, l1_index: 101, l2_index: 102
    )
  end
  let(:matching_wire) { build_get_key_response(matching_blob) }

  describe '#initialize' do
    it 'accepts raw NDR response bytes' do
      review = described_class.new(matching_wire, request)
      expect(review).to be_a(described_class)
    end

    it 'accepts an already parsed GkdiGetKeyResponse' do
      response = RubySMB::Dcerpc::Gkdi::GkdiGetKeyResponse.read(matching_wire)
      review = described_class.new(response, request)
      expect(review.success?).to be true
    end

    it 'raises InvalidPacket for malformed NDR bytes' do
      expect { described_class.new("\x01\x02\x03".b, request) }
        .to raise_error(RubySMB::Dcerpc::Error::InvalidPacket)
    end

    it 'raises GkdiError when the response status is not success' do
      wire = build_get_key_response(matching_blob, error_status: 0xC0000022)
      expect { described_class.new(wire, request) }
        .to raise_error(RubySMB::Dcerpc::Error::GkdiError)
    end
  end

  describe '#error_status and #success?' do
    it 'reports a successful response' do
      review = described_class.new(matching_wire, request)
      expect(review.error_status).to eq(WindowsError::NTStatus::STATUS_SUCCESS)
      expect(review.success?).to be true
    end
  end

  describe '#identity' do
    subject(:review) { described_class.new(matching_wire, request) }

    it 'exposes only identity metadata, never key bytes' do
      identity = review.identity
      expect(identity[:root_key_identifier]).to eq(requested_guid)
      expect(identity[:l0_index]).to eq(100)
      expect(identity[:l1_index]).to eq(101)
      expect(identity[:l2_index]).to eq(102)
      expect(identity[:domain_name]).to eq('corp.example.com')
      expect(identity[:forest_name]).to eq('example.com')
      expect(identity).not_to have_key(:l1_key)
      expect(identity).not_to have_key(:l2_key)
      expect(identity).not_to have_key(:private_key)
    end

    it 'uses the domain name as the display name' do
      expect(review.identity[:display_name]).to eq('corp.example.com')
    end
  end

  describe '#correlation and #correlated?' do
    it 'matches every identifier for the requested envelope' do
      review = described_class.new(matching_wire, request)
      expect(review.correlation).to eq(
        root_key_identifier: true,
        l0_index: true,
        l1_index: true,
        l2_index: true
      )
      expect(review.correlated?).to be true
    end

    it 'flags a parseable envelope that answers a different key id' do
      other_blob = build_envelope(
        root_key_identifier: '99999999-9999-9999-9999-999999999999',
        l0_index: 100, l1_index: 101, l2_index: 777
      )
      review = described_class.new(build_get_key_response(other_blob), request)
      expect(review.success?).to be true
      expect(review.correlated?).to be false
      expect(review.correlation[:root_key_identifier]).to be false
      expect(review.correlation[:l2_index]).to be false
      expect(review.correlation[:l0_index]).to be true
    end

    it 'treats a request with no identifiers as never correlated' do
      review = described_class.new(matching_wire, {})
      expect(review.correlation.values).to all(be false)
      expect(review.correlated?).to be false
    end
  end

  describe '#request_target' do
    it 'echoes the requested target security descriptor size without its bytes' do
      review = described_class.new(matching_wire, request)
      expect(review.request_target).to eq(cb_target_sd: 128, present: true)
    end

    it 'reports an absent target when none was supplied' do
      review = described_class.new(matching_wire, {})
      expect(review.request_target).to eq(cb_target_sd: nil, present: false)
    end
  end

  describe '#kdf_review' do
    it 'reports a supported KDF with length and encoding' do
      review = described_class.new(matching_wire, request)
      kdf = review.kdf_review
      expect(kdf[:algorithm]).to eq('SP800_108_CTR_HMAC')
      expect(kdf[:supported]).to be true
      expect(kdf[:encoding]).to eq(described_class::ENCODING_UTF16)
      expect(kdf[:parameters_encoding]).to eq(described_class::ENCODING_BINARY)
      expect(kdf[:hash_algorithm]).to eq('SHA256')
      expect(kdf[:hash_supported]).to be true
      expect(kdf[:length]).to be > 0
      expect(kdf[:parameters_length]).to be > 0
    end

    it 'retains an unknown KDF name without claiming support' do
      blob = build_envelope(
        root_key_identifier: requested_guid,
        kdf_algorithm: 'FUTURE_KDF_X',
        hash_algorithm: 'WEIRDHASH'
      )
      kdf = described_class.new(build_get_key_response(blob), request).kdf_review
      expect(kdf[:algorithm]).to eq('FUTURE_KDF_X')
      expect(kdf[:supported]).to be false
      expect(kdf[:hash_algorithm]).to eq('WEIRDHASH')
      expect(kdf[:hash_supported]).to be false
    end
  end

  describe '#secret_agreement_review' do
    it 'reports a supported secret agreement algorithm with binary parameters' do
      review = described_class.new(matching_wire, request)
      sa = review.secret_agreement_review
      expect(sa[:algorithm]).to eq('DH')
      expect(sa[:supported]).to be true
      expect(sa[:encoding]).to eq(described_class::ENCODING_UTF16)
      expect(sa[:parameters_encoding]).to eq(described_class::ENCODING_BINARY)
      expect(sa[:parameters_length]).to eq(4)
    end

    it 'retains an unknown secret agreement name without claiming support' do
      blob = build_envelope(
        root_key_identifier: requested_guid,
        secret_agreement_algorithm: 'QUANTUM_AGREE',
        secret_agreement_parameters: [1, 2, 3, 4, 5, 6, 7]
      )
      sa = described_class.new(build_get_key_response(blob), request).secret_agreement_review
      expect(sa[:algorithm]).to eq('QUANTUM_AGREE')
      expect(sa[:supported]).to be false
      expect(sa[:parameters_length]).to eq(7)
    end
  end

  describe 'algorithm parameter truncation' do
    # Build a valid envelope, then craft a response whose declared secret
    # agreement parameter length overstates the bytes physically present by
    # cutting the envelope short. The review must surface the discrepancy
    # rather than silently trusting the declared length.
    def build_physically_truncated_wire(declared_sa_length:, available_sa_bytes:)
      kdf_name = wide_stringz('SP800_108_CTR_HMAC')
      hash_name = wide_stringz('SHA256')
      kdf_parameters =
        ([0, 0, 0, 0, 1, 0, 0, 0].pack('C*') +
         [hash_name.bytesize].pack('V') + [0, 0, 0, 0].pack('C*') + hash_name).b
      sa_name = wide_stringz('DH')

      header =
        [1].pack('V') + [0x4b, 0x44, 0x53, 0x5b].pack('C*') + [0].pack('V') +
        [100, 101, 102].pack('V3') + guid_bytes(requested_guid)
      counts = [
        kdf_name.bytesize, kdf_parameters.bytesize, sa_name.bytesize, declared_sa_length,
        256, 256, 0, 0, 0, 0
      ]
      header += counts.pack('V10')
      (header + kdf_name + kdf_parameters + sa_name + available_sa_bytes).b
    end

    it 'raises InvalidPacket when the response is physically cut short' do
      wire = build_get_key_response(
        build_physically_truncated_wire(
          declared_sa_length: 16,
          available_sa_bytes: [1, 2, 3, 4].pack('C*')
        )
      )
      expect { described_class.new(wire, request) }
        .to raise_error(RubySMB::Dcerpc::Error::InvalidPacket)
    end

    it 'reports no truncation for a complete, correctly sized block' do
      blob = build_envelope(
        root_key_identifier: requested_guid,
        secret_agreement_parameters: [1, 2, 3, 4]
      )
      sa = described_class.new(build_get_key_response(blob), request).secret_agreement_review
      expect(sa[:parameters_length]).to eq(4)
      expect(sa[:parameters_actual_length]).to eq(4)
      expect(sa[:parameters_truncated]).to be false
    end
  end

  describe '#key_metadata' do
    it 'exposes key lengths and presence flags but no key material' do
      review = described_class.new(matching_wire, request)
      metadata = review.key_metadata
      expect(metadata[:private_key_length]).to eq(256)
      expect(metadata[:public_key_length]).to eq(256)
      expect(metadata[:l1_key_present]).to be true
      expect(metadata[:l1_key_length]).to eq(64)
      expect(metadata[:l2_key_present]).to be false
      expect(metadata[:l2_key_length]).to eq(0)
      expect(metadata).not_to have_key(:l1_key)
      expect(metadata).not_to have_key(:l2_key)
    end
  end

  describe 'two envelopes sharing a display name' do
    it 'keeps them distinguishable by root key GUID' do
      first = build_envelope(root_key_identifier: 'aaaaaaaa-0000-0000-0000-000000000001')
      second = build_envelope(root_key_identifier: 'aaaaaaaa-0000-0000-0000-000000000002')
      review_a = described_class.new(build_get_key_response(first), request)
      review_b = described_class.new(build_get_key_response(second), request)

      expect(review_a.identity[:display_name]).to eq(review_b.identity[:display_name])
      expect(review_a.identity[:root_key_identifier])
        .not_to eq(review_b.identity[:root_key_identifier])
    end
  end

  describe '#to_h' do
    it 'renders a serializable review without leaking key material' do
      review = described_class.new(matching_wire, request)
      hash = review.to_h
      expect(hash.keys).to include(
        :error_status, :success, :request, :request_target, :identity,
        :correlation, :correlated, :kdf, :secret_agreement, :key_metadata
      )
      rendered = hash.inspect
      # the L1 filler byte 0xAA must never appear as exposed key material
      expect(rendered).not_to include(Array.new(64, 0xAA).inspect)
      expect(rendered).not_to include(':l1_key=>')
      expect(rendered).not_to include(':l2_key=>')
    end
  end
end
