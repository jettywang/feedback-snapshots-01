# frozen_string_literal: true

module JWE
  module Serialization
    # RFC 7516 section 7.2.1 General JWE JSON Serialization.
    class General
      class << self
        include JsonSerialization

        def encode(protected_header:, recipients:, iv:, ciphertext:, tag:,
                   shared_unprotected_header: nil, aad: nil)
          object = {}

          protected_encoded = JsonSerialization.encode_protected(protected_header)
          object['protected'] = protected_encoded if protected_encoded
          unless shared_unprotected_header.nil? || shared_unprotected_header.empty?
            object['unprotected'] = JsonSerialization.stringify(shared_unprotected_header)
          end
          object['aad'] = JWE::Base64.jwe_encode(aad) if aad
          object['recipients'] = recipients.map do |recipient|
            JsonSerialization.recipient_object(recipient[:encrypted_key], recipient[:header])
          end
          object['iv'] = JWE::Base64.jwe_encode(iv)
          object['ciphertext'] = JWE::Base64.jwe_encode(ciphertext)
          object['tag'] = JWE::Base64.jwe_encode(tag)

          JSON.generate(object)
        end

        def decode(payload)
          object = JsonSerialization.parse_json(payload)
          recipients = object['recipients']
          unless recipients.is_a?(Array)
            raise JWE::DecodeError.new('The General JWE JSON Serialization requires a "recipients" array')
          end
          if recipients.empty?
            raise JWE::DecodeError.new('The General JWE JSON Serialization requires at least one recipient')
          end

          build_message(object, recipients)
        end

        private

        def build_message(object, recipients)
          protected_encoded = object['protected']
          assert_string_member(protected_encoded, 'protected')
          protected_header = JsonSerialization.parse_header(protected_encoded)
          shared_unprotected_header = object['unprotected']
          unless shared_unprotected_header.nil? || shared_unprotected_header.is_a?(Hash)
            raise JWE::DecodeError.new('The "unprotected" member must be a JSON object')
          end

          decoded_recipients = recipients.map { |recipient| decode_recipient(recipient) }

          JsonMessage.new(
            protected_header: protected_header,
            shared_unprotected_header: shared_unprotected_header,
            aad: JsonSerialization.decode_optional_member(object, 'aad'),
            recipients: decoded_recipients,
            iv: JsonSerialization.decode_required_member(object, 'iv'),
            ciphertext: JsonSerialization.decode_required_member(object, 'ciphertext'),
            tag: JsonSerialization.decode_required_member(object, 'tag'),
            protected_encoded: protected_encoded
          )
        end

        def decode_recipient(recipient)
          raise JWE::DecodeError.new('Each recipient must be a JSON object') unless recipient.is_a?(Hash)

          header = recipient['header']
          unless header.nil? || header.is_a?(Hash)
            raise JWE::DecodeError.new('A recipient "header" must be a JSON object')
          end

          {
            header: header || {},
            encrypted_key: JsonSerialization.decode_required_member(recipient, 'encrypted_key')
          }
        end
      end
    end
  end
end
