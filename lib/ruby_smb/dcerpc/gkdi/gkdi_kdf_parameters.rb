module RubySMB
  module Dcerpc
    module Gkdi

      # [2.2.4 Group Key Envelope - KDF Parameters](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gkdi/192c061c-e740-4aa0-ab1d-6954fb3e58f7)
      # The SP800-108 KDF parameters block: an 8-byte header, the byte length
      # of the hash name, a 4-byte spacer, then the UTF-16 hash algorithm name.
      class GkdiKdfParameters < BinData::Record
        endian :little

        uint8_array :block0, initial_length: 8, initial_value: [ 0, 0, 0, 0, 1, 0, 0, 0 ]
        uint32      :length_of_hash_name, initial_value: -> { hash_algorithm_name.num_bytes }
        uint8_array :block1, initial_length: 4, initial_value: [ 0, 0, 0, 0 ]
        stringz16   :hash_algorithm_name
      end
    end
  end
end
