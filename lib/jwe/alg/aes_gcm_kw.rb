# frozen_string_literal: true

require 'jwe/enc/cipher'

module JWE
  module Alg
    # Generic AES GCM Key Wrapping algorithm for any key size (RFC 7518, section 4.7).
    #
    # The key wrapping layer uses its own IV and authentication tag, carried in the
    # "iv" and "tag" JWE protected header parameters. They are distinct from the
    # content encryption IV and tag, which travel in the JWE Compact serialization.
    module AesGcmKw
      WRAP_IV_LENGTH = 12
      WRAP_TAG_LENGTH = 16

      attr_accessor :key, :iv, :tag

      def initialize(key = nil, iv = nil, tag = nil)
        self.key = key
        self.iv = iv
        self.tag = tag
      end

      def encrypt(cek)
        check_key!
        self.iv ||= SecureRandom.random_bytes(WRAP_IV_LENGTH)

        cipher = setup_cipher(:encrypt)
        ciphertext = cipher.update(cek) + cipher.final
        self.tag = cipher.auth_tag(WRAP_TAG_LENGTH)

        ciphertext
      end

      def decrypt(encrypted_cek)
        check_key!
        raise JWE::InvalidData, 'Missing or invalid iv header parameter' unless iv && iv.bytesize == WRAP_IV_LENGTH
        raise JWE::InvalidData, 'Missing or invalid tag header parameter' unless tag && tag.bytesize == WRAP_TAG_LENGTH

        cipher = setup_cipher(:decrypt)
        cipher.update(encrypted_cek) + cipher.final
      rescue OpenSSL::Cipher::CipherError
        raise JWE::InvalidData, 'Invalid encrypted key or key wrap authentication tag'
      end

      # Parameters to merge into the JWE protected header once the CEK has been
      # wrapped. Must be called after #encrypt.
      def header_params
        { iv: Base64.jwe_encode(iv), tag: Base64.jwe_encode(tag) }
      end

      # Reads the key wrapping parameters from a received JWE protected header.
      def apply_header(header)
        self.iv = header['iv'] ? Base64.jwe_decode(header['iv']) : nil
        self.tag = header['tag'] ? Base64.jwe_decode(header['tag']) : nil
      rescue ArgumentError
        raise JWE::InvalidData, 'Malformed iv or tag header parameter'
      end

      def check_key!
        raise ArgumentError, "The supplied key is invalid. Required length: #{key_length}" if key.nil? || key.bytesize != key_length
      end

      def setup_cipher(direction)
        cipher.send(direction)
        cipher.key = key
        cipher.iv = iv
        cipher.auth_tag = tag if direction == :decrypt
        cipher.auth_data = ''
        cipher
      end

      def cipher
        @cipher ||= Enc::Cipher.for(cipher_name)
      end
    end
  end
end
