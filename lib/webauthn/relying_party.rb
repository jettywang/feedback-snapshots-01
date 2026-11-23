# frozen_string_literal: true

require "openssl"
require "webauthn/credential"
require "webauthn/encoder"
require "webauthn/error"
require "webauthn/registration_policy"

module WebAuthn
  class RootCertificateFinderNotSupportedError < Error; end

  class RelyingParty
    DEFAULT_ALGORITHMS = ["ES256", "PS256", "RS256"].compact.freeze

    def self.if_pss_supported(algorithm)
      OpenSSL::PKey::RSA.instance_methods.include?(:verify_pss) ? algorithm : nil
    end

    def initialize(
      algorithms: DEFAULT_ALGORITHMS.dup,
      encoding: WebAuthn::Encoder::STANDARD_ENCODING,
      allowed_origins: nil,
      allowed_top_origins: nil,
      origin: nil,
      id: nil,
      name: nil,
      verify_attestation_statement: true,
      verify_cross_origin: false,
      credential_options_timeout: 300_000,
      silent_authentication: false,
      acceptable_attestation_types: ['None', 'Self', 'Basic', 'AttCA', 'Basic_or_AttCA', 'AnonCA'],
      attestation_root_certificates_finders: [],
      registration_policy: nil,
      legacy_u2f_appid: nil
    )
      @algorithms = algorithms
      @encoding = encoding
      @allowed_origins = allowed_origins
      @allowed_top_origins = allowed_top_origins
      @id = id
      @name = name
      @verify_attestation_statement = verify_attestation_statement
      @verify_cross_origin = verify_cross_origin
      @credential_options_timeout = credential_options_timeout
      @silent_authentication = silent_authentication
      @acceptable_attestation_types = acceptable_attestation_types
      @legacy_u2f_appid = legacy_u2f_appid
      self.registration_policy = registration_policy
      self.origin = origin
      self.attestation_root_certificates_finders = attestation_root_certificates_finders
    end

    attr_accessor :algorithms,
                  :encoding,
                  :allowed_origins,
                  :allowed_top_origins,
                  :id,
                  :name,
                  :verify_attestation_statement,
                  :verify_cross_origin,
                  :credential_options_timeout,
                  :silent_authentication,
                  :acceptable_attestation_types,
                  :legacy_u2f_appid

    attr_reader :attestation_root_certificates_finders, :registration_policy

    # This is the user-data encoder.
    # Used to decode user input and to encode data provided to the user.
    def encoder
      @encoder ||= WebAuthn::Encoder.new(encoding)
    end

    def attestation_root_certificates_finders=(finders)
      if !finders.respond_to?(:each)
        finders = [finders]
      end

      finders.each do |finder|
        unless finder.respond_to?(:find)
          raise RootCertificateFinderNotSupportedError, "Finder must implement `find` method"
        end
      end

      @attestation_root_certificates_finders = finders
    end

    def registration_policy=(policy)
      unless policy.nil? || policy.is_a?(WebAuthn::RegistrationPolicy)
        raise ArgumentError, "registration_policy must be a WebAuthn::RegistrationPolicy"
      end

      @registration_policy = policy
    end

    def registration_policy?
      !registration_policy.nil?
    end

    # Confirms a registration.
    #
    # When a policy is given (or configured on the relying party) both pieces
    # of algorithm evidence must be approved independently. A rejected policy
    # raises RegistrationPolicy::RejectedError carrying the full result.
    #
    # Without a policy this keeps the original #verify_registration behavior.
    def verify_registration(
      raw_credential,
      challenge,
      user_presence: nil,
      user_verification: nil,
      policy: nil
    )
      policy ||= registration_policy

      unless policy
        return verify_registration_without_policy(
          raw_credential,
          challenge,
          user_presence: user_presence,
          user_verification: user_verification
        )
      end

      result = evaluate_registration(
        raw_credential,
        challenge,
        user_presence: user_presence,
        user_verification: user_verification,
        policy: policy
      )

      unless result.persistable?
        raise WebAuthn::RegistrationPolicy::RejectedError.new(result)
      end

      result.credential
    end
    alias_method :confirm_registration, :verify_registration

    # Confirms a registration and returns the policy result, which explains
    # each piece of evidence and the final admission reason. It does not raise
    # on policy rejection; inspect #persistable? on the result instead.
    def evaluate_registration(
      raw_credential,
      challenge,
      user_presence: nil,
      user_verification: nil,
      policy: nil
    )
      policy ||= registration_policy
      raise ArgumentError, "No registration policy configured" unless policy

      webauthn_credential = WebAuthn::Credential.from_create(raw_credential, relying_party: self)

      webauthn_credential.verify(
        challenge,
        user_presence: user_presence,
        user_verification: user_verification,
        verify_attestation_statement: false
      )

      policy.evaluate(webauthn_credential)
    end

    def options_for_registration(**keyword_arguments)
      WebAuthn::Credential.options_for_create(
        **keyword_arguments,
        relying_party: self
      )
    end

    def options_for_authentication(**keyword_arguments)
      WebAuthn::Credential.options_for_get(
        **keyword_arguments,
        relying_party: self
      )
    end

    def verify_authentication(
      raw_credential,
      challenge,
      user_presence: nil,
      user_verification: nil,
      public_key: nil,
      sign_count: nil
    )
      webauthn_credential = WebAuthn::Credential.from_get(raw_credential, relying_party: self)

      stored_credential = yield(webauthn_credential) if block_given?

      if webauthn_credential.verify(
        challenge,
        public_key: public_key || stored_credential.public_key,
        sign_count: sign_count || stored_credential.sign_count,
        user_presence: user_presence,
        user_verification: user_verification
      )
        block_given? ? [webauthn_credential, stored_credential] : webauthn_credential
      end
    end

    # DEPRECATED: This method will be removed in future.
    def origin
      warn(
        "DEPRECATION WARNING: `WebAuthn.origin` is deprecated and returns `nil` " \
        "when `WebAuthn.allowed_origins` contains more than one origin. " \
        "It will be removed in future. Please use `WebAuthn.allowed_origins` instead."
      )

      allowed_origins.first if allowed_origins&.size == 1
    end

    # DEPRECATED: This method will be removed in future.
    def origin=(new_origin)
      return if new_origin.nil?

      warn(
        "DEPRECATION WARNING: `WebAuthn.origin=` is deprecated and will be removed in future. "\
        "Please use `WebAuthn.allowed_origins=` instead "\
        "that also allows configuring multiple origins per Relying Party"
      )

      @allowed_origins ||= Array(new_origin) # rubocop:disable Naming/MemoizedInstanceVariableName
    end

    private

    def verify_registration_without_policy(raw_credential, challenge, user_presence: nil, user_verification: nil)
      webauthn_credential = WebAuthn::Credential.from_create(raw_credential, relying_party: self)

      if webauthn_credential.verify(challenge, user_presence: user_presence, user_verification: user_verification)
        webauthn_credential
      end
    end
  end
end
