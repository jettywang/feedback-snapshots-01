# frozen_string_literal: true

module JWE
  module Serialization
    # RFC 7516 section 7.2.2 Flattened JWE JSON Serialization. It can only
    # represent a single recipient, whose per-recipient members live at the
    # top level of the JSON object.
    class Flattened
      class << self
        include JsonSerialization

        def encode(protected_header:, encrypted_key:, iv:, ciphertext:, tag:,
                   recipient_header: nil, shared_unprotected_header: nil, aad: nil)
          object = {}

          protected_encoded = JsonSerialization.encode_protected(protected_header)
          object['protected'] = protected_encoded if protected_encoded
          unless shared_unprotected_header.nil? || shared_unprotected_header.empty?
            object['unprotected'] = JsonSerialization.stringify(shared_unprotected_header)
          end
          object['aad'] = JWE::Base64.jwe_encode(aad) if aad
          unless recipient_header.nil? || recipient_header.empty?
            object['header'] = JsonSerialization.stringify(recipient_header)
          end
          object['encrypted_key'] = JWE::Base64.jwe_encode(encrypted_key)
          object['iv'] = JWE::Base64.jwe_encode(iv)
          object['ciphertext'] = JWE::Base64.jwe_encode(ciphertext)
          object['tag'] = JWE::Base64.jwe_encode(tag)

          JSON.generate(object)
        end

        def decode(payload)
          object = JsonSerialization.parse_json(payload)
          if object.key?('recipients')
            raise JWE::DecodeError.new('The Flattened JWE JSON Serialization cannot carry a "recipients" member')
          end

          protected_encoded = object['protected']
          assert_string_member(protected_encoded, 'protected')
          protected_header = JsonSerialization.parse_header(protected_encoded)
          shared_unprotected_header = object['unprotected']
          unless shared_unprotected_header.nil? || shared_unprotected_header.is_a?(Hash)
            raise JWE::DecodeError.new('The "unprotected" member must be a JSON object')
          end

          recipient_header = object['header']
          unless recipient_header.nil? || recipient_header.is_a?(Hash)
            raise JWE::DecodeError.new('The "header" member must be a JSON object')
          end

          JsonMessage.new(
            protected_header: protected_header,
            shared_unprotected_header: shared_unprotected_header,
            aad: JsonSerialization.decode_optional_member(object, 'aad'),
            recipients: [
              {
                header: recipient_header || {},
                encrypted_key: JsonSerialization.decode_required_member(object, 'encrypted_key')
              }
            ],
            iv: JsonSerialization.decode_required_member(object, 'iv'),
            ciphertext: JsonSerialization.decode_required_member(object, 'ciphertext'),
            tag: JsonSerialization.decode_required_member(object, 'tag'),
            protected_encoded: protected_encoded
          )
        end
      end
    end
  end
end
