# frozen_string_literal: true

require "json"
require "openssl"
require "webauthn/encoder"
require "webauthn/error"

module WebAuthn
  # An immutable view of the relying-party settings that were in effect when a
  # credential ceremony was started.
  #
  # A snapshot is intentionally detached from the live WebAuthn::RelyingParty
  # instance. Updating the live instance (or the global configuration) after a
  # ceremony has been issued therefore cannot change how that ceremony is
  # decoded or verified.
  class ConfigurationSnapshot
    class FingerprintMismatchError < WebAuthn::Error; end
    class IncompleteError < WebAuthn::Error; end

    VERSION = 1

    # Fields that define the security-relevant flow of a ceremony. Changes to
    # these fields after issuance are reported as a `:stop` by
    # WebAuthn::CredentialOperation#compatibility_with.
    FLOW_FIELDS = [
      :allowed_origins,
      :rp_id,
      :encoding,
      :verify_attestation_statement,
      :acceptable_attestation_types,
      :algorithms,
      :verify_cross_origin,
      :allowed_top_origins,
      :silent_authentication,
      :legacy_u2f_appid
    ].freeze

    DEFAULT_ACCEPTABLE_ATTESTATION_TYPES = ['None', 'Self', 'Basic', 'AttCA', 'Basic_or_AttCA', 'AnonCA'].freeze
    DEFAULT_ALGORITHMS = ["ES256", "PS256", "RS256"].freeze

    attr_reader :allowed_origins,
                :allowed_top_origins,
                :rp_id,
                :rp_name,
                :encoding,
                :algorithms,
                :verify_attestation_statement,
                :verify_cross_origin,
                :credential_options_timeout,
                :silent_authentication,
                :acceptable_attestation_types,
                :attestation_root_certificates_finders,
                :legacy_u2f_appid

    def self.from_relying_party(relying_party)
      return relying_party if relying_party.is_a?(self)

      new(
        allowed_origins: relying_party.allowed_origins,
        allowed_top_origins: relying_party.allowed_top_origins,
        rp_id: relying_party.id,
        rp_name: relying_party.name,
        encoding: relying_party.encoding,
        algorithms: relying_party.algorithms,
        verify_attestation_statement: relying_party.verify_attestation_statement,
        verify_cross_origin: relying_party.verify_cross_origin,
        credential_options_timeout: relying_party.credential_options_timeout,
        silent_authentication: relying_party.silent_authentication,
        acceptable_attestation_types: relying_party.acceptable_attestation_types,
        attestation_root_certificates_finders: relying_party.attestation_root_certificates_finders,
        legacy_u2f_appid: relying_party.legacy_u2f_appid
      )
    end

    def self.from_h(hash, attestation_root_certificates_finders: [])
      hash = stringify_keys(hash)

      snapshot = new(
        allowed_origins: fetch(hash, "allowed_origins"),
        allowed_top_origins: fetch(hash, "allowed_top_origins"),
        rp_id: fetch(hash, "rp_id"),
        rp_name: fetch(hash, "rp_name"),
        encoding: parse_encoding(fetch(hash, "encoding", WebAuthn::Encoder::STANDARD_ENCODING)),
        algorithms: fetch(hash, "algorithms", DEFAULT_ALGORITHMS),
        verify_attestation_statement: fetch(hash, "verify_attestation_statement", true),
        verify_cross_origin: fetch(hash, "verify_cross_origin", false),
        credential_options_timeout: fetch(hash, "credential_options_timeout", 300_000),
        silent_authentication: fetch(hash, "silent_authentication", false),
        acceptable_attestation_types: fetch(hash, "acceptable_attestation_types", DEFAULT_ACCEPTABLE_ATTESTATION_TYPES),
        attestation_root_certificates_finders: attestation_root_certificates_finders,
        legacy_u2f_appid: fetch(hash, "legacy_u2f_appid")
      )

      expected_fingerprint = fetch(hash, "fingerprint")
      if expected_fingerprint && expected_fingerprint != snapshot.fingerprint
        raise FingerprintMismatchError,
              "configuration snapshot fingerprint #{expected_fingerprint.inspect} does not match " \
              "the recomputed fingerprint #{snapshot.fingerprint.inspect}"
      end

      snapshot
    end

    def self.from_json(json, attestation_root_certificates_finders: [])
      from_h(JSON.parse(json), attestation_root_certificates_finders: attestation_root_certificates_finders)
    end

    def self.parse_encoding(value)
      case value.to_s
      when "base64url"
        :base64url
      when "base64"
        :base64
      when "none", ""
        false
      else
        raise ArgumentError, "Unsupported encoding in configuration snapshot: #{value.inspect}"
      end
    end

    def self.stringify_keys(hash)
      return hash unless hash.respond_to?(:each_with_object)

      hash.each_with_object({}) do |(key, value), result|
        result[key.to_s] = value
      end
    end

    def self.fetch(hash, key, default = nil)
      hash.key?(key) ? hash[key] : default
    end

    def initialize(
      allowed_origins: nil,
      allowed_top_origins: nil,
      rp_id: nil,
      rp_name: nil,
      encoding: WebAuthn::Encoder::STANDARD_ENCODING,
      algorithms: DEFAULT_ALGORITHMS,
      verify_attestation_statement: true,
      verify_cross_origin: false,
      credential_options_timeout: 300_000,
      silent_authentication: false,
      acceptable_attestation_types: DEFAULT_ACCEPTABLE_ATTESTATION_TYPES,
      attestation_root_certificates_finders: [],
      legacy_u2f_appid: nil
    )
      @allowed_origins = freeze_strings(allowed_origins)
      @allowed_top_origins = freeze_strings(allowed_top_origins)
      @rp_id = freeze_string(rp_id)
      @rp_name = freeze_string(rp_name)
      @encoding = encoding
      @algorithms = freeze_strings(algorithms)
      @verify_attestation_statement = verify_attestation_statement ? true : false
      @verify_cross_origin = verify_cross_origin ? true : false
      @credential_options_timeout = credential_options_timeout
      @silent_authentication = silent_authentication ? true : false
      @acceptable_attestation_types = freeze_strings(acceptable_attestation_types)
      @attestation_root_certificates_finders = Array(attestation_root_certificates_finders).freeze
      @legacy_u2f_appid = freeze_string(legacy_u2f_appid)
    end

    def snapshot
      self
    end

    # Aliases so a snapshot can be used anywhere the issuing relying party is
    # accepted by option builders and response verifiers.
    def id
      rp_id
    end

    def name
      rp_name
    end

    def complete?
      return false if allowed_origins.nil? || allowed_origins.empty?
      return true if rp_id

      # Mirrors WebAuthn::AuthenticatorResponse, which derives the RP ID from
      # the origin when exactly one allowed origin is configured.
      allowed_origins.size == 1
    end

    def ensure_complete!
      return if complete?

      raise IncompleteError,
            "Configuration snapshot needs allowed_origins and either an rp_id (id) or a single origin " \
            "to verify a ceremony"
    end

    def encoder
      @encoder ||= WebAuthn::Encoder.new(encoding)
    end

    def encoding_label
      self.class.encoding_label(encoding)
    end

    def self.encoding_label(encoding)
      case encoding
      when :base64url, "base64url"
        "base64url"
      when :base64, "base64"
        "base64"
      when nil, false, "none"
        "none"
      else
        encoding.to_s
      end
    end

    # A stable digest of the fields that define the ceremony flow. It can be
    # logged next to a registration or authentication attempt and later used to
    # prove which site configuration was applied.
    def fingerprint
      @fingerprint ||= OpenSSL::Digest::SHA256.hexdigest(JSON.generate(canonical_flow_attributes))
    end

    # A hash of the flow-defining fields, normalized for comparison.
    def flow_attributes
      {
        allowed_origins: canonical_sorted_list(allowed_origins),
        rp_id: rp_id,
        encoding: encoding_label,
        verify_attestation_statement: verify_attestation_statement,
        acceptable_attestation_types: canonical_sorted_list(acceptable_attestation_types),
        algorithms: canonical_sorted_list(algorithms),
        verify_cross_origin: verify_cross_origin,
        allowed_top_origins: canonical_sorted_list(allowed_top_origins),
        silent_authentication: silent_authentication,
        legacy_u2f_appid: legacy_u2f_appid
      }
    end

    def same_flow_as?(other)
      other = other.snapshot if other.respond_to?(:snapshot)
      flow_attributes == other.flow_attributes
    end

    def to_h
      {
        "version" => VERSION,
        "rp_id" => rp_id,
        "rp_name" => rp_name,
        "allowed_origins" => allowed_origins,
        "allowed_top_origins" => allowed_top_origins,
        "encoding" => encoding_label,
        "algorithms" => algorithms,
        "verify_attestation_statement" => verify_attestation_statement,
        "verify_cross_origin" => verify_cross_origin,
        "credential_options_timeout" => credential_options_timeout,
        "silent_authentication" => silent_authentication,
        "acceptable_attestation_types" => acceptable_attestation_types,
        "legacy_u2f_appid" => legacy_u2f_appid,
        "fingerprint" => fingerprint
      }
    end

    def to_json(*arguments)
      JSON.generate(to_h, *arguments)
    end

    def explain
      {
        rp_id: rp_id,
        rp_name: rp_name,
        allowed_origins: allowed_origins,
        encoding: encoding_label,
        encoder: encoder.encoder_klass.name,
        verification: {
          verify_attestation_statement: verify_attestation_statement,
          acceptable_attestation_types: acceptable_attestation_types,
          algorithms: algorithms,
          verify_cross_origin: verify_cross_origin,
          allowed_top_origins: allowed_top_origins,
          silent_authentication: silent_authentication,
          legacy_u2f_appid: legacy_u2f_appid
        },
        fingerprint: fingerprint
      }
    end

    def ==(other)
      other.is_a?(ConfigurationSnapshot) && to_h == other.to_h
    end
    alias_method :eql?, :==

    def hash
      fingerprint.hash
    end

    def to_relying_party
      require "webauthn/relying_party"

      WebAuthn::RelyingParty.new(
        algorithms: algorithms.dup,
        encoding: encoding,
        allowed_origins: allowed_origins&.dup,
        allowed_top_origins: allowed_top_origins&.dup,
        id: rp_id,
        name: rp_name,
        verify_attestation_statement: verify_attestation_statement,
        verify_cross_origin: verify_cross_origin,
        credential_options_timeout: credential_options_timeout,
        silent_authentication: silent_authentication,
        acceptable_attestation_types: acceptable_attestation_types.dup,
        attestation_root_certificates_finders: attestation_root_certificates_finders.dup,
        legacy_u2f_appid: legacy_u2f_appid
      )
    end

    private

    def canonical_flow_attributes
      {
        "allowed_origins" => canonical_sorted_list(allowed_origins),
        "rp_id" => rp_id,
        "encoding" => encoding_label,
        "verify_attestation_statement" => verify_attestation_statement,
        "acceptable_attestation_types" => canonical_sorted_list(acceptable_attestation_types),
        "algorithms" => canonical_sorted_list(algorithms),
        "verify_cross_origin" => verify_cross_origin,
        "allowed_top_origins" => canonical_sorted_list(allowed_top_origins),
        "silent_authentication" => silent_authentication,
        "legacy_u2f_appid" => legacy_u2f_appid
      }
    end

    def canonical_sorted_list(value)
      return nil if value.nil?

      Array(value).map(&:to_s).sort
    end

    def freeze_string(value)
      value.is_a?(String) ? value.dup.freeze : value
    end

    def freeze_strings(value)
      return nil if value.nil?

      Array(value).map { |item| freeze_string(item) }.freeze
    end
  end
end
