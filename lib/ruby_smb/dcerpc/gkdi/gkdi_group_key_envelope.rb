module RubySMB
  module Dcerpc
    module Gkdi

      # [2.2.4 Group Key Envelope](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gkdi/192c061c-e740-4aa0-ab1d-6954fb3e58f7)
      class GkdiGroupKeyEnvelope < BinData::Record
        endian :little

        uint32      :version
        uint8_array :magic, initial_length: 4, initial_value: [ 0x4b, 0x44, 0x53, 0x5b ]
        uint32      :dw_flags
        uint32      :l0_index
        uint32      :l1_index
        uint32      :l2_index
        uuid        :root_key_identifier
        uint32      :cb_kdf_algorithm
        uint32      :cb_kdf_parameters
        uint32      :cb_secret_agreement_algorithm
        uint32      :cb_secret_agreement_parameters
        uint32      :private_key_length
        uint32      :public_key_length
        uint32      :cb_l1_key
        uint32      :cb_l2_key
        uint32      :cb_domain_name
        uint32      :cb_forest_name
        stringz16   :kdf_algorithm
        uint8_array :kdf_parameters_raw, initial_length: -> { cb_kdf_parameters }
        stringz16   :secret_agreement_algorithm
        uint8_array :secret_agreement_parameters, initial_length: -> { cb_secret_agreement_parameters }
        uint8_array :l1_key, initial_length: -> { cb_l1_key }
        uint8_array :l2_key, initial_length: -> { l2_key_length }
        stringz16   :domain_name
        stringz16   :forest_name

        # Lazily parsed view of {#kdf_parameters_raw}. Returns nil when the
        # envelope carries no KDF parameters block (cb_kdf_parameters == 0).
        def kdf_parameters
          return nil if cb_kdf_parameters.zero?

          @kdf_parameters ||= GkdiKdfParameters.read(kdf_parameters_raw.snapshot.pack('C*'))
        end

        # Assign a structured KDF parameters block. The raw bytes and the
        # accompanying length field are kept in sync so the envelope can be
        # serialized back onto the wire.
        def kdf_parameters=(parameters)
          parameters = GkdiKdfParameters.new(parameters) unless parameters.is_a?(GkdiKdfParameters)
          binary = parameters.to_binary_s
          self.cb_kdf_parameters = binary.bytesize
          self.kdf_parameters_raw = binary.bytes
          @kdf_parameters = parameters
        end

        private

        def l2_key_length
          return 0 if cb_l2_key == 0
          return 64 if (dw_flags & (1 << 31)) == 0

          public_key_length
        end
      end
    end
  end
end
