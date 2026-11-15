# frozen_string_literal: true

module JWE
  module Serialization
    # Shared behaviour of the RFC 7516 General and Flattened JSON
    # Serialization formats. Both reuse one content ciphertext (and one
    # Content Encryption Key) and only wrap that CEK once per recipient.
    module JsonSerialization
      JsonMessage = Struct.new(:protected_header, :shared_unprotected_header,
                               :aad, :recipients, :iv, :ciphertext, :tag,
                               :protected_encoded, keyword_init: true)

      module_function

      # Decode a base64url member, rejecting anything that is not a String.
      def decode_optional_member(object, key)
        return nil unless object.key?(key)

        value = object[key]
        raise JWE::DecodeError.new("The \"#{key}\" member must be a string") unless value.is_a?(String)

        safe_decode(value)
      end

      def decode_required_member(object, key)
        value = decode_optional_member(object, key)
        raise JWE::DecodeError.new("The \"#{key}\" member is missing") if value.nil?

        value
      end

      def safe_decode(value)
        JWE::Base64.jwe_decode(value)
      rescue ArgumentError
        raise JWE::DecodeError.new('The JWE JSON Serialization contains an invalid base64url encoded member')
      end

      def assert_string_member(value, name)
        return if value.nil? || value.is_a?(String)

        raise JWE::DecodeError.new("The \"#{name}\" member must be a string")
      end

      def parse_json(payload)
        object = JSON.parse(payload)
        raise JWE::DecodeError.new('The JWE JSON Serialization must be a JSON object') unless object.is_a?(Hash)

        object
      rescue JSON::ParserError
        raise JWE::DecodeError.new('The JWE JSON Serialization is not valid JSON')
      end

      def parse_header(encoded)
        return {} if encoded.nil?
        raise JWE::DecodeError.new('The "protected" member must not be empty') if encoded.empty?

        header = JSON.parse(safe_decode(encoded))
        raise JWE::DecodeError.new('A JWE header must be a JSON object') unless header.is_a?(Hash)

        header
      rescue JSON::ParserError
        raise JWE::DecodeError.new('The JWE protected header is not valid JSON')
      end

      # RFC 7516 section 7.2.2: the same Header Parameter name MUST NOT
      # appear in more than one of the three header locations.
      def assert_unique_header_names(protected_header, shared_unprotected_header, recipient_header)
        locations = [protected_header, shared_unprotected_header, recipient_header].compact
        names = locations.flat_map { |header| header.keys.map(&:to_s) }
        duplicates = names.group_by(&:itself).select { |_, occurrences| occurrences.length > 1 }.keys
        return if duplicates.empty?

        raise JWE::DecodeError.new("Duplicate header parameter(s) across header locations: #{duplicates.sort.join(', ')}")
      end

      # A header location is represented as an empty JSON object ("{}") when
      # no protected header is present, and omitted entirely otherwise.
      def encode_protected(protected_header)
        return nil if protected_header.nil? || protected_header.empty?

        JWE::Base64.jwe_encode(protected_header.to_json)
      end

      def recipient_object(encrypted_cek, recipient_header)
        object = {}
        object['header'] = stringify(recipient_header) unless recipient_header.nil? || recipient_header.empty?
        object['encrypted_key'] = JWE::Base64.jwe_encode(encrypted_cek)
        object
      end

      def stringify(header)
        header.each_with_object({}) { |(key, value), result| result[key.to_s] = value }
      end

      # The Additional Authenticated Data uses the original base64url encoded
      # protected header exactly as it was serialized, never a re-encoded one.
      def authenticated_data(protected_encoded, aad)
        if protected_encoded
          protected_encoded
        elsif aad
          JWE::Base64.jwe_encode(aad)
        else
          ''
        end
      end
    end
  end
end
