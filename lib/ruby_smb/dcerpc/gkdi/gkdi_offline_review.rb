module RubySMB
  module Dcerpc
    module Gkdi

      # Offline, metadata-only review of a captured GetKey response.
      #
      # This class never opens a network connection and never returns key
      # material (the L1/L2 key fields or any FFC DH private value). It parses
      # a fixed NDR response blob captured out-of-band and exposes only:
      #   * the request correlation identifiers (root key GUID and L0/L1/L2 ids),
      #   * identity metadata (domain / forest / display names), and
      #   * algorithm metadata (names, parameter lengths and encodings).
      #
      # A response that parses cleanly is not automatically the envelope the
      # caller asked for. {#correlation} compares the envelope identifiers
      # against the requested ones so a valid-but-unrelated envelope is
      # reported instead of being treated as a match.
      class GkdiOfflineReview
        # KDF algorithm identifiers defined by [MS-GKDI] 2.2.4.
        # The trailing parameters block always carries a UTF-16 hash name.
        KDF_ALGORITHMS = %w[
          SP800_108_CTR_HMAC
          SP800_108_CTR_HMAC_MD5
          SP800_108_CTR_HMAC_SHA1
          SP800_108_CTR_HMAC_SHA256
          SP800_108_CTR_HMAC_SHA384
          SP800_108_CTR_HMAC_SHA512
        ].freeze

        # Secret agreement algorithm identifiers defined by [MS-GKDI] 2.2.4.
        # Their parameters are a raw FFC DH parameters blob, not text.
        SECRET_AGREEMENT_ALGORITHMS = %w[
          DH
          ECDH_P256
          ECDH_P384
          ECDH_P521
        ].freeze

        HASH_ALGORITHMS = %w[MD5 SHA1 SHA256 SHA384 SHA512].freeze

        ENCODING_UTF16 = 'UTF-16LE null-terminated'
        ENCODING_BINARY = 'binary'

        # @return [Hash] the request identifiers the review was asked to match
        attr_reader :request

        # @param ndr_response [String, Array<Integer>] the raw
        #   GkdiGetKeyResponse NDR bytes, or the already-decoded response.
        # @param request [Hash] the request identifiers used for correlation.
        # @option request [String] :root_key_id expected root key GUID
        # @option request [Integer] :l0_key_id expected L0 key id
        # @option request [Integer] :l1_key_id expected L1 key id
        # @option request [Integer] :l2_key_id expected L2 key id
        # @option request [Integer] :cb_target_sd size of the requested target
        #   security descriptor (the request target), in bytes
        def initialize(ndr_response, request = {})
          @request = normalize_request(request)
          @response = parse_response(ndr_response)
          @envelope = parse_envelope(@response)
        end

        # The NDR-level status of the captured response. A value other than
        # STATUS_SUCCESS means no usable envelope was returned.
        #
        # @return [Integer]
        def error_status
          @response.error_status.to_i
        end

        def success?
          error_status == WindowsError::NTStatus::STATUS_SUCCESS
        end

        # Identity metadata only. Key material is deliberately omitted.
        #
        # @return [Hash]
        def identity
          {
            root_key_identifier: @envelope.root_key_identifier.to_s,
            l0_index: @envelope.l0_index.to_i,
            l1_index: @envelope.l1_index.to_i,
            l2_index: @envelope.l2_index.to_i,
            domain_name: text(@envelope.domain_name),
            forest_name: text(@envelope.forest_name),
            display_name: display_name
          }
        end

        # The request target: the security descriptor the caller asked the key
        # for. Only its size is echoed back here; the descriptor bytes are not
        # part of the review output.
        #
        # @return [Hash{Symbol => Integer, nil}]
        def request_target
          size = request[:cb_target_sd]
          { cb_target_sd: size, present: !size.nil? }
        end

        # Compare the envelope identifiers against the requested ones. Each
        # entry is +true+ when the response field equals the request field.
        # A fully matching response has every entry +true+. A +false+ entry
        # means the parsed envelope is not the one this request needs.
        #
        # @return [Hash{Symbol => Boolean}]
        def correlation
          result = {}
          result[:root_key_identifier] =
            request.key?(:root_key_id) &&
            @envelope.root_key_identifier.to_s.casecmp?(request[:root_key_id].to_s)
          { l0_index: :l0_key_id, l1_index: :l1_key_id, l2_index: :l2_key_id }.each do |field, req_key|
            result[field] =
              request.key?(req_key) &&
              @envelope.public_send(field).to_i == request[req_key].to_i
          end
          result
        end

        # True only when every requested identifier matches the envelope.
        #
        # @return [Boolean]
        def correlated?
          correlation.values.all?
        end

        # Metadata for the key derivation function. Unknown identifiers keep
        # their raw name but are not reported as supported. A +truncated+ flag
        # signals that the bytes actually present are fewer than the declared
        # parameter length, so the block was cut off in the captured response.
        #
        # @return [Hash]
        def kdf_review
          name = text(@envelope.kdf_algorithm)
          declared = @envelope.cb_kdf_parameters.to_i
          actual = @envelope.kdf_parameters_raw.snapshot.length
          {
            algorithm: name,
            supported: KDF_ALGORITHMS.include?(name),
            length: @envelope.cb_kdf_algorithm.to_i,
            encoding: ENCODING_UTF16,
            parameters_length: declared,
            parameters_actual_length: actual,
            parameters_truncated: actual < declared,
            parameters_encoding: ENCODING_BINARY,
            hash_algorithm: kdf_hash_name,
            hash_supported: HASH_ALGORITHMS.include?(kdf_hash_name)
          }
        end

        # Metadata for the secret agreement algorithm. Its parameters are a
        # raw binary blob (FFC DH parameters), so only the length and encoding
        # are surfaced; the bytes themselves are not returned. A +truncated+
        # flag signals that fewer bytes were captured than were declared.
        #
        # @return [Hash]
        def secret_agreement_review
          name = text(@envelope.secret_agreement_algorithm)
          declared = @envelope.cb_secret_agreement_parameters.to_i
          actual = @envelope.secret_agreement_parameters.snapshot.length
          {
            algorithm: name,
            supported: SECRET_AGREEMENT_ALGORITHMS.include?(name),
            length: @envelope.cb_secret_agreement_algorithm.to_i,
            encoding: ENCODING_UTF16,
            parameters_length: declared,
            parameters_actual_length: actual,
            parameters_truncated: actual < declared,
            parameters_encoding: ENCODING_BINARY
          }
        end

        # Sizes that describe the key material without exposing it. Only
        # lengths and presence flags are returned, never the bytes.
        #
        # @return [Hash]
        def key_metadata
          {
            private_key_length: @envelope.private_key_length.to_i,
            public_key_length: @envelope.public_key_length.to_i,
            l1_key_present: @envelope.cb_l1_key.to_i != 0,
            l1_key_length: @envelope.cb_l1_key.to_i,
            l2_key_present: @envelope.cb_l2_key.to_i != 0,
            l2_key_length: @envelope.cb_l2_key.to_i
          }
        end

        # Structured, serializable summary suitable for a review view.
        #
        # @return [Hash]
        def to_h
          {
            error_status: error_status,
            success: success?,
            request: request,
            request_target: request_target,
            identity: identity,
            correlation: correlation,
            correlated: correlated?,
            kdf: kdf_review,
            secret_agreement: secret_agreement_review,
            key_metadata: key_metadata
          }
        end

        private

        def normalize_request(request)
          normalized = {}
          request.each { |key, value| normalized[key.to_sym] = value }
          normalized
        end

        def parse_response(ndr_response)
          return ndr_response if ndr_response.is_a?(GkdiGetKeyResponse)

          bytes =
            case ndr_response
            when Array then ndr_response
            when String then ndr_response.b.bytes
            else
              raise ArgumentError, 'expected NDR response bytes or GkdiGetKeyResponse'
            end

          GkdiGetKeyResponse.read(bytes.pack('C*'))
        rescue IOError, ArgumentError => e
          raise RubySMB::Dcerpc::Error::InvalidPacket,
                "Could not parse GKDI GetKey response: #{e.message}"
        end

        def parse_envelope(response)
          unless success?
            raise RubySMB::Dcerpc::Error::GkdiError.new(
              "GetKey response status 0x#{error_status.to_s(16).rjust(8, '0')} carries no envelope",
              status_code: error_status
            )
          end

          envelope_bytes = response.pbb_out.snapshot
          GkdiGroupKeyEnvelope.read(envelope_bytes.pack('C*'))
        rescue IOError, ArgumentError => e
          raise RubySMB::Dcerpc::Error::InvalidPacket,
                "Could not parse GKDI group key envelope: #{e.message}"
        end

        def text(field)
          return nil if field.nil?

          field.snapshot.to_s.encode('UTF-8')
        rescue EncodingError
          field.snapshot.to_s.force_encoding('UTF-8')
        end

        def display_name
          # [MS-GKDI] stores the DNS domain name and the forest name as two
          # independent identity fields. The domain name is the human-readable
          # label; the forest is reported separately in {#identity}. No key
          # material is involved.
          text(@envelope.domain_name) || text(@envelope.forest_name)
        end

        def kdf_hash_name
          parameters = @envelope.kdf_parameters
          return nil if parameters.nil?

          text(parameters.hash_algorithm_name)
        end
      end
    end
  end
end
