# frozen_string_literal: true

require "json"
require "openssl"
require "time"
require "cbor"
require "webauthn/authenticator_data"
require "webauthn/client_data"
require "webauthn/configuration_snapshot"
require "webauthn/public_key_credential/creation_options"
require "webauthn/public_key_credential/request_options"
require "webauthn/error"

module WebAuthn
  # A self-contained, auditable representation of one registration or
  # authentication ceremony.
  #
  # It captures the relying-party configuration at issuance time and the
  # verification requirements requested for the ceremony. It can be serialized
  # and rehydrated in another process, so a callback does not need the same
  # WebAuthn::RelyingParty instance that issued the options.
  class CredentialOperation
    class KindMismatchError < WebAuthn::Error; end

    class CompatibilityError < WebAuthn::Error
      attr_reader :compatibility

      def initialize(message = nil, compatibility: nil)
        super(message)
        @compatibility = compatibility
      end
    end

    KINDS = [:registration, :authentication].freeze
    ON_CHANGE_POLICIES = [:raise, :continue].freeze

    class Compatibility
      attr_reader :decision, :changed_fields, :details

      def initialize(decision:, changed_fields: [], details: {})
        @decision = decision
        @changed_fields = changed_fields.freeze
        @details = details.freeze
      end

      def continue?
        decision == :continue
      end

      def stop?
        decision == :stop
      end

      def to_h
        {
          decision: decision,
          changed_fields: changed_fields,
          details: details
        }
      end

      def as_json(*)
        to_h
      end

      def explain
        if continue?
          "continue: the issued ceremony is still compatible with the current relying-party configuration"
        else
          "stop: the current relying-party configuration changed #{changed_fields.join(', ')} " \
            "after this ceremony was issued"
        end
      end
    end

    def self.for_registration(
      relying_party:,
      request_id: nil,
      user_presence: nil,
      user_verification: nil,
      verification_requirements: {},
      **keyword_arguments
    )
      new(
        kind: :registration,
        relying_party: relying_party,
        request_id: request_id,
        verification_requirements: merge_requirements(
          verification_requirements,
          user_presence: user_presence,
          user_verification: user_verification
        ),
        options_attributes: keyword_arguments
      )
    end

    def self.for_authentication(
      relying_party:,
      request_id: nil,
      user_presence: nil,
      user_verification: nil,
      verification_requirements: {},
      **keyword_arguments
    )
      # A string such as "required" or "preferred" is also a client-facing
      # WebAuthn option, so forward it to the request options.
      if user_verification.is_a?(String) || user_verification.is_a?(Symbol)
        keyword_arguments = keyword_arguments.merge(user_verification: user_verification.to_s)
      end

      new(
        kind: :authentication,
        relying_party: relying_party,
        request_id: request_id,
        verification_requirements: merge_requirements(
          verification_requirements,
          user_presence: user_presence,
          user_verification: user_verification
        ),
        options_attributes: keyword_arguments
      )
    end

    def self.merge_requirements(requirements, user_presence:, user_verification:)
      requirements
        .merge(user_presence: user_presence, user_verification: user_verification)
        .reject { |_key, value| value.nil? }
    end

    def self.from_h(hash, attestation_root_certificates_finders: [])
      hash = ConfigurationSnapshot.stringify_keys(hash)

      expected_fingerprint = ConfigurationSnapshot.fetch(hash, "fingerprint")
      configuration_snapshot = ConfigurationSnapshot.from_h(
        ConfigurationSnapshot.fetch(hash, "configuration_snapshot", {}),
        attestation_root_certificates_finders: attestation_root_certificates_finders
      )

      raw_challenge =
        if hash.key?("challenge_raw")
          WebAuthn.standard_encoder.decode(ConfigurationSnapshot.fetch(hash, "challenge_raw"))
        elsif hash.key?("challenge")
          WebAuthn.standard_encoder.decode(ConfigurationSnapshot.fetch(hash, "challenge"))
        end

      operation = new(
        kind: ConfigurationSnapshot.fetch(hash, "kind")&.to_sym,
        configuration_snapshot: configuration_snapshot,
        raw_challenge: raw_challenge,
        request_id: ConfigurationSnapshot.fetch(hash, "request_id"),
        issued_at: ConfigurationSnapshot.fetch(hash, "issued_at"),
        verification_requirements: symbolize_keys(ConfigurationSnapshot.fetch(hash, "verification_requirements", {})),
        options_json: ConfigurationSnapshot.fetch(hash, "options_json")
      )

      if expected_fingerprint && expected_fingerprint != operation.fingerprint
        raise ConfigurationSnapshot::FingerprintMismatchError,
              "operation fingerprint #{expected_fingerprint.inspect} does not match " \
              "the recomputed fingerprint #{operation.fingerprint.inspect}"
      end

      operation
    end

    def self.from_json(json, attestation_root_certificates_finders: [])
      from_h(JSON.parse(json), attestation_root_certificates_finders: attestation_root_certificates_finders)
    end

    # Binds an already-built options object to a new operation without
    # regenerating its challenge. Used by RelyingParty#options_for_* so the
    # options can expose their issuance-time operation.
    def self.for_options(kind:, relying_party:, options:, request_id: nil, verification_requirements: {})
      new(
        kind: kind,
        relying_party: relying_party,
        raw_challenge: options.raw_challenge,
        request_id: request_id,
        verification_requirements: verification_requirements,
        options_json: options.as_json
      ).bind_options(options)
    end

    def self.symbolize_keys(hash)
      hash.each_with_object({}) do |(key, value), result|
        result[key.to_sym] = value
      end
    end

    # The outcome of one verification attempt: which configuration was used,
    # whether the live configuration would still allow the ceremony, and which
    # credential/user was ultimately attributed.
    class VerificationRecord
      attr_reader :kind,
                  :decision,
                  :compared,
                  :details,
                  :credential_id,
                  :user_handle,
                  :origin,
                  :encoding,
                  :outcome,
                  :error_class,
                  :verified_at

      def initialize(
        kind:,
        decision:,
        compared:,
        details:,
        credential_id: nil,
        user_handle: nil,
        origin: nil,
        encoding: nil,
        outcome: :pending,
        error_class: nil,
        verified_at: Time.now.utc.iso8601
      )
        @kind = kind
        @decision = decision
        @compared = compared
        @details = details
        @credential_id = credential_id
        @user_handle = user_handle
        @origin = origin
        @encoding = encoding
        @outcome = outcome
        @error_class = error_class
        @verified_at = verified_at
      end

      def continue?
        decision == :continue
      end

      def stop?
        decision == :stop
      end

      def succeed!
        @outcome = :verified
        self
      end

      def fail!(error)
        @outcome = :failed
        @error_class = error.class.name
        self
      end

      def verified?
        outcome == :verified
      end

      def failed?
        outcome == :failed
      end

      def to_h
        {
          kind: kind,
          outcome: outcome,
          decision: decision,
          compared: compared,
          credential_id: json_safe(credential_id),
          user_handle: json_safe(user_handle),
          origin: origin,
          encoding: encoding,
          error_class: error_class,
          verified_at: verified_at,
          details: details
        }
      end

      def as_json(*)
        to_h
      end

      def explain
        comparison =
          if compared
            "#{decision} (#{Array(details[:changed_fields]).join(', ')})"
          else
            "continue (no live configuration supplied for comparison)"
          end

        "verified=#{outcome} kind=#{kind} configuration=#{comparison} " \
          "origin=#{origin.inspect} credential_id=#{credential_id.inspect} " \
          "user_handle=#{user_handle.inspect}"
      end

      private

      def json_safe(value)
        return value unless value.is_a?(String) && value.encoding == Encoding::ASCII_8BIT

        [value].pack("m0")
      end
    end

    attr_reader :kind,
                :raw_challenge,
                :request_id,
                :issued_at,
                :verification_requirements,
                :configuration_snapshot,
                :options_json

    def initialize(
      kind:,
      raw_challenge: nil,
      challenge: nil,
      request_id: nil,
      issued_at: nil,
      verification_requirements: {},
      configuration_snapshot: nil,
      relying_party: nil,
      options_attributes: nil,
      options_json: nil
    )
      unless KINDS.include?(kind)
        raise ArgumentError, "Unsupported credential operation kind: #{kind.inspect}"
      end

      @kind = kind
      @configuration_snapshot =
        configuration_snapshot ||
        ConfigurationSnapshot.from_relying_party(relying_party || WebAuthn.configuration.relying_party)
      @issued_at = issued_at || Time.now.utc.iso8601
      @request_id = request_id
      @verification_requirements = filter_requirements(verification_requirements)
      @options_json = options_json
      @raw_challenge = raw_challenge || challenge
      @verifications = []

      if options_attributes
        @options = build_options(**options_attributes)
        @raw_challenge ||= @options.raw_challenge
        @options_json ||= @options.as_json
      end

      raise ArgumentError, "A credential operation requires a challenge" if @raw_challenge.nil?

      freeze_requirements
    end

    def registration?
      kind == :registration
    end

    def authentication?
      kind == :authentication
    end

    def challenge
      @challenge ||= encoder.encode(raw_challenge)
    end

    def options
      @options ||= build_options_from_json(options_json)
    end

    def encoder
      configuration_snapshot.encoder
    end

    def fingerprint
      @fingerprint ||= OpenSSL::Digest::SHA256.hexdigest(
        JSON.generate(
          "kind" => kind.to_s,
          "challenge" => WebAuthn.standard_encoder.encode(raw_challenge),
          "request_id" => request_id,
          "issued_at" => issued_at,
          "verification_requirements" => verification_requirements_hash,
          "configuration" => configuration_snapshot.fingerprint
        )
      )
    end

    def relying_party
      @relying_party ||= configuration_snapshot.to_relying_party
    end

    def verifications
      @verifications.dup
    end

    def last_verification
      verifications.last
    end

    def bind_options(options)
      @options = options
      @raw_challenge ||= options.raw_challenge
      @options_json ||= options.as_json
      options.operation = self

      self
    end

    # Verifies a registration ceremony with the configuration captured when the
    # options were issued, regardless of later changes to the live instance.
    def verify_registration(
      raw_credential,
      against: nil,
      on_change: :raise,
      user_presence: nil,
      user_verification: nil
    )
      ensure_kind!(:registration)
      configuration_snapshot.ensure_complete!

      record = verification_record_for(raw_credential, against, on_change: on_change)

      with_verification_record(record) do
        relying_party.verify_registration(
          raw_credential,
          challenge,
          user_presence: resolve_requirement(:user_presence, user_presence),
          user_verification: resolve_requirement(:user_verification, user_verification)
        )
      end
    end

    # Verifies an authentication ceremony with the configuration captured when
    # the options were issued, regardless of later changes to the live instance.
    def verify_authentication(
      raw_credential,
      against: nil,
      on_change: :raise,
      user_presence: nil,
      user_verification: nil,
      public_key: nil,
      sign_count: nil,
      &block
    )
      ensure_kind!(:authentication)
      configuration_snapshot.ensure_complete!

      record = verification_record_for(raw_credential, against, on_change: on_change)

      with_verification_record(record) do
        relying_party.verify_authentication(
          raw_credential,
          challenge,
          user_presence: resolve_requirement(:user_presence, user_presence),
          user_verification: resolve_requirement(:user_verification, user_verification),
          public_key: public_key,
          sign_count: sign_count,
          &block
        )
      end
    end

    # Reports whether the issued ceremony can still be explained by the current
    # relying-party configuration.
    #
    # Flow-defining fields (origin, RP ID, encoder, verification policy, ...)
    # changing after issuance results in `:stop`. Descriptive or operational
    # fields (RP name, timeout) changing results in `:continue`.
    def compatibility_with(other)
      current_snapshot =
        if other.respond_to?(:configuration_snapshot)
          other.configuration_snapshot
        elsif other.is_a?(WebAuthn::ConfigurationSnapshot)
          other
        elsif other.respond_to?(:snapshot)
          other.snapshot
        else
          ConfigurationSnapshot.from_relying_party(other)
        end

      issued_flow = configuration_snapshot.flow_attributes
      current_flow = current_snapshot.flow_attributes

      changed_fields = WebAuthn::ConfigurationSnapshot::FLOW_FIELDS.select do |field|
        issued_flow[field] != current_flow[field]
      end

      decision = changed_fields.empty? ? :continue : :stop

      Compatibility.new(
        decision: decision,
        changed_fields: changed_fields,
        details: {
          operation_fingerprint: fingerprint,
          configuration_fingerprint: configuration_snapshot.fingerprint,
          current_configuration_fingerprint: current_snapshot.fingerprint,
          issued_flow: issued_flow,
          current_flow: current_flow
        }
      )
    end

    def continue_with?(other)
      compatibility_with(other).continue?
    end

    def stop_with?(other)
      compatibility_with(other).stop?
    end

    def ensure_compatible!(other)
      compatibility = compatibility_with(other)
      raise_compatibility_error(compatibility) unless compatibility.continue?

      compatibility
    end

    # Describes how a raw credential would be decoded and attributed under this
    # operation's issuance-time configuration.
    def diagnose(raw_credential)
      response = raw_credential["response"] || {}
      rp_id = configuration_snapshot.rp_id

      begin
        client_data = WebAuthn::ClientData.new(encoder.decode(response["clientDataJSON"]))
        authenticator_data = authenticator_data_from(raw_credential)
        origin = client_data.origin
        user_handle = response["userHandle"] && encoder.decode(response["userHandle"])
        credential_id_bytes = encoder.decode(raw_credential["rawId"] || "")
        rp_id_hash_matches = rp_id && OpenSSL::Digest::SHA256.digest(rp_id) == authenticator_data.rp_id_hash

        {
          operation_fingerprint: fingerprint,
          configuration_fingerprint: configuration_snapshot.fingerprint,
          encoding: configuration_snapshot.encoding_label,
          raw_credential_id: raw_credential["id"],
          credential_id: encoder.encode(credential_id_bytes),
          credential_id_bytes: credential_id_bytes,
          client_data_origin: origin,
          allowed_origins: configuration_snapshot.allowed_origins,
          origin_allowed: Array(configuration_snapshot.allowed_origins).include?(origin),
          rp_id: rp_id,
          rp_id_hash_matches: rp_id_hash_matches,
          user_handle: user_handle,
          sign_count: authenticator_data.sign_count
        }
      rescue StandardError => error
        {
          operation_fingerprint: fingerprint,
          configuration_fingerprint: configuration_snapshot.fingerprint,
          encoding: configuration_snapshot.encoding_label,
          raw_credential_id: raw_credential["id"],
          credential_id: nil,
          client_data_origin: nil,
          allowed_origins: configuration_snapshot.allowed_origins,
          origin_allowed: false,
          rp_id: rp_id,
          rp_id_hash_matches: false,
          user_handle: nil,
          sign_count: nil,
          diagnostic_error: "#{error.class}: #{error.message}"
        }
      end
    end

    def explain
      {
        kind: kind,
        challenge: challenge,
        request_id: request_id,
        issued_at: issued_at,
        verification_requirements: verification_requirements,
        fingerprint: fingerprint,
        configuration: configuration_snapshot.explain
      }
    end

    def to_h
      {
        "version" => 1,
        "kind" => kind.to_s,
        "challenge_raw" => WebAuthn.standard_encoder.encode(raw_challenge),
        "request_id" => request_id,
        "issued_at" => issued_at,
        "verification_requirements" => verification_requirements_hash,
        "fingerprint" => fingerprint,
        "options_json" => options_json,
        "configuration_snapshot" => configuration_snapshot.to_h
      }
    end

    def to_json(*arguments)
      JSON.generate(to_h, *arguments)
    end

    private

    def build_options(**attributes)
      new_options(**attributes)
    end

    def build_options_from_json(json)
      raise ArgumentError, "Serialized operation does not contain options" if json.nil?

      new_options(**symbolize_options_keys(json))
    end

    def new_options(**attributes)
      attributes = attributes.merge(challenge: raw_challenge, operation: self)

      case kind
      when :registration
        WebAuthn::PublicKeyCredential::CreationOptions.new(
          **attributes,
          relying_party: relying_party
        )
      when :authentication
        WebAuthn::PublicKeyCredential::RequestOptions.new(
          **attributes,
          relying_party: relying_party
        )
      end
    end

    def symbolize_options_keys(json)
      hash = ConfigurationSnapshot.stringify_keys(json)
      attributes = kind == :registration ? registration_options(hash) : authentication_options(hash)

      attributes.reject { |_key, value| value.nil? }
    end

    def registration_options(hash)
      {
        rp: symbolize_keys(hash["rp"]),
        user: symbolize_keys(hash["user"]),
        pub_key_cred_params: Array(hash["pubKeyCredParams"]).map { |params| symbolize_keys(params) },
        timeout: hash["timeout"],
        exclude_credentials: credential_descriptors(hash["excludeCredentials"]),
        authenticator_selection: symbolize_keys(hash["authenticatorSelection"]),
        attestation: hash["attestation"],
        attestation_formats: hash["attestationFormats"],
        hints: hash["hints"],
        extensions: symbolize_keys(hash["extensions"])
      }
    end

    def authentication_options(hash)
      {
        rp_id: hash["rpId"],
        allow_credentials: credential_descriptors(hash["allowCredentials"]),
        user_verification: hash["userVerification"],
        timeout: hash["timeout"],
        hints: hash["hints"],
        extensions: symbolize_keys(hash["extensions"])
      }
    end

    def credential_descriptors(descriptors)
      return nil if descriptors.nil?

      descriptors.map { |descriptor| symbolize_keys(descriptor) }
    end

    def symbolize_keys(value)
      return nil if value.nil?

      value.each_with_object({}) do |(key, nested), result|
        result[snake_case(key).to_sym] = nested
      end
    end

    def snake_case(key)
      key.to_s.gsub(/([a-z\d])([A-Z])/, '\\1_\\2').downcase
    end

    def fetch(hash, key)
      ConfigurationSnapshot.fetch(hash, key)
    end

    def filter_requirements(requirements)
      requirements.each_with_object({}) do |(key, value), result|
        symbol = key.to_sym
        next unless [:user_presence, :user_verification].include?(symbol)

        result[symbol] = value
      end
    end

    def freeze_requirements
      verification_requirements.each_value { |value| value.freeze if value.is_a?(String) }
      verification_requirements.freeze
    end

    def verification_requirements_hash
      verification_requirements.each_with_object({}) do |(key, value), result|
        result[key.to_s] = value
      end
    end

    def resolve_requirement(name, explicit)
      explicit.nil? ? verification_requirements[name] : explicit
    end

    def verification_record_for(raw_credential, against, on_change:)
      unless ON_CHANGE_POLICIES.include?(on_change)
        raise ArgumentError, "on_change must be one of #{ON_CHANGE_POLICIES.inspect}"
      end

      compatibility = against ? compatibility_with(against) : nil

      if compatibility&.stop? && on_change == :raise
        raise_compatibility_error(compatibility)
      end

      diagnostic = safe_diagnose(raw_credential)

      VerificationRecord.new(
        kind: kind,
        decision: compatibility ? compatibility.decision : :continue,
        compared: !compatibility.nil?,
        details: {
          operation_fingerprint: fingerprint,
          configuration_fingerprint: configuration_snapshot.fingerprint,
          current_configuration_fingerprint: compatibility&.details&.dig(:current_configuration_fingerprint),
          changed_fields: compatibility ? compatibility.changed_fields : [],
          on_change: on_change
        },
        credential_id: diagnostic[:credential_id],
        user_handle: diagnostic[:user_handle],
        origin: diagnostic[:client_data_origin],
        encoding: configuration_snapshot.encoding_label
      )
    end

    def raise_compatibility_error(compatibility)
      raise CompatibilityError.new(
        "Credential operation #{fingerprint} cannot continue: #{compatibility.explain}",
        compatibility: compatibility
      )
    end

    def with_verification_record(record)
      @verifications << record
      result = yield
      record.succeed!
      result
    rescue StandardError => error
      record.fail!(error)
      raise
    end

    def safe_diagnose(raw_credential)
      diagnose(raw_credential)
    rescue StandardError => error
      { credential_id: nil, user_handle: nil, client_data_origin: nil, diagnostic_error: error.class.name }
    end

    def ensure_kind!(expected)
      return if kind == expected

      raise KindMismatchError, "This credential operation is a #{kind} operation, not #{expected}"
    end

    def authenticator_data_from(raw_credential)
      response = raw_credential["response"] || {}

      if response["authenticatorData"]
        WebAuthn::AuthenticatorData.deserialize(encoder.decode(response["authenticatorData"]))
      elsif response["attestationObject"]
        attestation_object = CBOR.decode(encoder.decode(response["attestationObject"]))
        WebAuthn::AuthenticatorData.deserialize(attestation_object["authData"])
      else
        raise ArgumentError, "Raw credential does not contain authenticator data"
      end
    end

  end
end
