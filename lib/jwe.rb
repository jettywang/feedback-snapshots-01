# frozen_string_literal: true

require 'base64'
require 'json'
require 'openssl'
require 'securerandom'

require 'jwe/base64'
require 'jwe/serialization/compact'
require 'jwe/serialization/json_serialization'
require 'jwe/serialization/general'
require 'jwe/serialization/flattened'
require 'jwe/alg'
require 'jwe/enc'
require 'jwe/zip'

# A ruby implementation of the RFC 7516 JSON Web Encryption (JWE) standard.
module JWE
  class DecodeError < RuntimeError; end
  class NotImplementedError < RuntimeError; end
  class BadCEK < RuntimeError; end
  class InvalidData < RuntimeError; end

  # Result of a JSON Serialization decryption. It exposes the plaintext along
  # with the recipient that actually produced it, so callers can tell which of
  # the wrapped keys opened the shared content.
  DecryptionResult = Struct.new(:plaintext, :recipient_index, :header, :recipient_header, keyword_init: true)

  VALID_ALG = ['RSA1_5', 'RSA-OAEP', 'RSA-OAEP-256', 'A128KW', 'A192KW', 'A256KW', 'dir', 'ECDH-ES', 'ECDH-ES+A128KW', 'ECDH-ES+A192KW', 'ECDH-ES+A256KW', 'A128GCMKW', 'A192GCMKW', 'A256GCMKW', 'PBES2-HS256+A128KW', 'PBES2-HS384+A192KW', 'PBES2-HS512+A256KW'].freeze
  VALID_ENC = %w[A128CBC-HS256 A192CBC-HS384 A256CBC-HS512 A128GCM A192GCM A256GCM].freeze
  VALID_ZIP = ['DEF'].freeze

  # RFC 7516 sections 6.1 and 11.1: these algorithms derive or use a unique
  # Content Encryption Key per recipient and therefore cannot be combined with
  # a JSON Serialization that shares one CEK across all recipients.
  JSON_INCOMPATIBLE_ALG = %w[dir ECDH-ES].freeze

  class << self
    def encrypt(payload, key, alg: 'RSA-OAEP', enc: 'A128GCM', **more_headers)
      header = generate_header(alg, enc, more_headers)
      check_params(header, key)

      payload = apply_zip(header, payload, :compress)

      cipher = Enc.for(enc)
      cipher.cek = key if alg == 'dir'

      json_hdr = header.to_json
      ciphertext = cipher.encrypt(payload, Base64.jwe_encode(json_hdr))

      generate_serialization(json_hdr, Alg.encrypt_cek(alg, key, cipher.cek), ciphertext, cipher)
    end

    def decrypt(payload, key)
      header, enc_key, iv, ciphertext, tag = Serialization::Compact.decode(payload)
      header = JSON.parse(header)
      check_params(header, key)

      cek = Alg.decrypt_cek(header['alg'], key, enc_key)
      cipher = Enc.for(header['enc'], cek, iv, tag)

      plaintext = cipher.decrypt(ciphertext, payload.split('.').first)

      apply_zip(header, plaintext, :decompress)
    end

    # Build a General JWE JSON Serialization (RFC 7516 section 7.2.1). The
    # payload is encrypted once with a single CEK, which is then wrapped
    # independently for every recipient.
    def encrypt_general(payload, recipients, enc: 'A128GCM', zip: nil,
                        protected: true, aad: nil, **shared_headers)
      encrypt_json(payload, normalize_recipients(recipients), enc: enc, zip: zip,
                   use_protected: protected, aad: aad, shared_headers: shared_headers)
    end

    # Build a Flattened JWE JSON Serialization (RFC 7516 section 7.2.2), which
    # can only carry a single recipient.
    def encrypt_flattened(payload, key, alg: 'RSA-OAEP', enc: 'A128GCM',
                          zip: nil, protected: true, aad: nil, **recipient_headers)
      recipients = normalize_recipients([{ key: key, alg: alg }.merge(recipient_headers)])
      encrypt_json(payload, recipients, enc: enc, zip: zip,
                   use_protected: protected, aad: aad, shared_headers: {}, flattened: true)
    end

    # Decode a General JWE JSON Serialization. The key is tried against every
    # recipient in order; the first recipient whose wrapped key opens the
    # shared content wins.
    def decrypt_general(payload, key)
      decrypt_json(Serialization::General.decode(payload), key)
    end

    # Decode a Flattened JWE JSON Serialization.
    def decrypt_flattened(payload, key)
      decrypt_json(Serialization::Flattened.decode(payload), key)
    end

    def check_params(header, key)
      check_alg(header[:alg] || header['alg'])
      check_enc(header[:enc] || header['enc'])
      check_zip(header[:zip] || header['zip'])
      check_key(key)
    end

    def check_alg(alg)
      raise ArgumentError.new('Missing required "alg" header parameter') if alg.nil?
      raise ArgumentError.new("\"#{alg}\" is not a valid alg method") unless VALID_ALG.include?(alg)
    end

    def check_enc(enc)
      raise ArgumentError.new('Missing required "enc" header parameter') if enc.nil?
      raise ArgumentError.new("\"#{enc}\" is not a valid enc method") unless VALID_ENC.include?(enc)
    end

    def check_zip(zip)
      raise ArgumentError.new("\"#{zip}\" is not a valid zip method") unless zip.nil? || zip == '' || VALID_ZIP.include?(zip)
    end

    def check_key(key)
      raise ArgumentError.new('The key must not be nil or blank') if key.nil? || (key.is_a?(String) && key.strip == '')
    end

    def param_to_class_name(param)
      klass = param.gsub(/[-+]/, '_').downcase.sub(/^[a-z\d]*/) { ::Regexp.last_match(0).capitalize }
      klass.gsub(/_([a-z\d]*)/i) { Regexp.last_match(1).capitalize }
    end

    def apply_zip(header, data, direction)
      zip = header[:zip] || header['zip']
      if zip
        Zip.for(zip).new.send(direction, data)
      else
        data
      end
    end

    def generate_header(alg, enc, more)
      header = { alg: alg, enc: enc }.merge(more)
      header.delete(:zip) if header[:zip] == ''
      header
    end

    def generate_serialization(hdr, cek, content, cipher)
      Serialization::Compact.encode(hdr, cek, cipher.iv, content, cipher.tag)
    end

    private

    def normalize_recipients(recipients)
      raise ArgumentError.new('At least one recipient is required') if recipients.nil? || recipients.empty?

      recipients.map do |recipient|
        key = recipient[:key] || recipient['key']
        alg = recipient[:alg] || recipient['alg']
        check_key(key)
        check_alg(alg)
        reject_json_alg(alg)

        extra = recipient.reject { |name, _| %i[key alg 'key' 'alg'].include?(name) }
        { key: key, alg: alg, header: Serialization::JsonSerialization.stringify(extra) }
      end
    end

    def reject_json_alg(alg)
      return unless JSON_INCOMPATIBLE_ALG.include?(alg)

      raise DecodeError.new("The \"#{alg}\" algorithm cannot be used with the JWE JSON Serialization")
    end

    def encrypt_json(payload, recipients, enc:, zip:, use_protected:, aad:, shared_headers:, flattened: false)
      check_enc(enc)
      check_zip(zip)
      if !use_protected && aad.nil?
        raise ArgumentError.new('External AAD is required when the protected header is omitted')
      end
      if use_protected && !aad.nil?
        raise ArgumentError.new('The "aad" member cannot coexist with a protected header')
      end

      shared = stringify_headers(shared_headers)
      shared['enc'] = enc
      shared['zip'] = zip unless zip.nil? || zip == ''

      recipient_headers = recipients.map { |recipient| recipient[:header].merge('alg' => recipient[:alg]) }
      recipient_headers.each do |recipient_header|
        Serialization::JsonSerialization.assert_unique_header_names(
          use_protected ? shared : nil, use_protected ? nil : shared, recipient_header
        )
      end

      payload = apply_zip(shared, payload, :compress)

      cipher = Enc.for(enc)
      protected_header = use_protected ? shared : nil
      protected_encoded = Serialization::JsonSerialization.encode_protected(protected_header)
      auth_data = Serialization::JsonSerialization.authenticated_data(protected_encoded, aad)
      ciphertext = cipher.encrypt(payload, auth_data)

      wrapped = recipients.map do |recipient|
        {
          header: recipient[:header].merge('alg' => recipient[:alg]),
          encrypted_key: Alg.encrypt_cek(recipient[:alg], recipient[:key], cipher.cek)
        }
      end

      if flattened
        Serialization::Flattened.encode(
          protected_header: protected_header,
          shared_unprotected_header: use_protected ? nil : shared,
          aad: aad,
          recipient_header: wrapped.first[:header],
          encrypted_key: wrapped.first[:encrypted_key],
          iv: cipher.iv,
          ciphertext: ciphertext,
          tag: cipher.tag
        )
      else
        Serialization::General.encode(
          protected_header: protected_header,
          shared_unprotected_header: use_protected ? nil : shared,
          aad: aad,
          recipients: wrapped,
          iv: cipher.iv,
          ciphertext: ciphertext,
          tag: cipher.tag
        )
      end
    end

    def decrypt_json(message, key)
      check_key(key)
      preflight_json(message)

      auth_data = Serialization::JsonSerialization.authenticated_data(message.protected_encoded, message.aad)
      last_error = nil

      message.recipients.each_with_index do |recipient, index|
        begin
          header = merge_json_headers(message, recipient)
          check_params(header, key)

          cek = Alg.decrypt_cek(header['alg'], key, recipient[:encrypted_key])
          cipher = Enc.for(header['enc'], cek, message.iv, message.tag)
          plaintext = cipher.decrypt(message.ciphertext, auth_data)
          plaintext = apply_zip(header, plaintext, :decompress)

          return DecryptionResult.new(
            plaintext: plaintext,
            recipient_index: index,
            header: header,
            recipient_header: recipient[:header]
          )
        rescue StandardError => error
          last_error = error
        end
      end

      raise DecodeError.new("No recipient could decrypt the JWE: #{last_error&.message}")
    end

    def preflight_json(message)
      if message.protected_encoded && !message.aad.nil?
        raise DecodeError.new('The "aad" member cannot coexist with a protected header')
      end

      message.recipients.each do |recipient|
        Serialization::JsonSerialization.assert_unique_header_names(
          message.protected_header, message.shared_unprotected_header, recipient[:header]
        )

        header = merge_json_headers(message, recipient)
        check_alg(header['alg'])
        check_enc(header['enc'])
        check_zip(header['zip'])
        reject_json_alg(header['alg'])
      end
    end

    def merge_json_headers(message, recipient)
      {}.merge(message.protected_header)
        .merge(message.shared_unprotected_header || {})
        .merge(recipient[:header])
    end

    def stringify_headers(headers)
      Serialization::JsonSerialization.stringify(headers)
    end
  end
end
