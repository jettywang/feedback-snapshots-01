# frozen_string_literal: true

require 'jwe/alg/aes_gcm_kw'

module JWE
  module Alg
    # AES GCM Key Wrap with a 128-bit key encryption key (RFC 7518, section 4.7).
    class A128gcmkw
      include AesGcmKw

      def key_length
        16
      end

      def cipher_name
        'aes-128-gcm'
      end
    end
  end
end
