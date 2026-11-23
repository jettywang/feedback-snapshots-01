# frozen_string_literal: true

require "openssl"
require "webauthn/authentication_operation"
require "webauthn/credential"
require "webauthn/encoder"
require "webauthn/error"

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

    attr_reader :attestation_root_certificates_finders

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

    def options_for_registration(**keyword_arguments)
      WebAuthn::Credential.options_for_create(
        **keyword_arguments,
        relying_party: self
      )
    end

    def verify_registration(raw_credential, challenge, user_presence: nil, user_verification: nil)
      webauthn_credential = WebAuthn::Credential.from_create(raw_credential, relying_party: self)

      if webauthn_credential.verify(challenge, user_presence: user_presence, user_verification: user_verification)
        webauthn_credential
      end
    end

    def options_for_authentication(**keyword_arguments)
      WebAuthn::Credential.options_for_get(
        **keyword_arguments,
        relying_party: self
      )
    end

    # Issues authentication options and records the terms approved for this
    # operation (e.g. the user verification requirement), so the ceremony is
    # later verified against those terms even if the caller's policy changes
    # while the operation is still pending. Multiple operations may be pending
    # at the same time, each is consumed by its own challenge.
    def begin_authentication(context: nil, **keyword_arguments)
      AuthenticationOperation.new(
        options_for_authentication(**keyword_arguments),
        context: context
      )
    end

    # Verifies a response against a recorded authentication operation.
    # The user verification requirement is taken from the operation record,
    # while the user verification result comes from the authenticator data.
    #
    # Raises WebAuthn::OperationConsumedError or WebAuthn::OperationRevokedError
    # when the operation is no longer pending, WebAuthn::VerificationError
    # subclasses when the response does not satisfy the recorded terms (the
    # operation stays pending and may be retried), and consumes the operation
    # upon successful verification.
    def verify_authentication_operation(
      operation,
      raw_credential,
      user_presence: nil,
      public_key: nil,
      sign_count: nil
    )
      operation.ensure_pending!

      webauthn_credential = WebAuthn::Credential.from_get(raw_credential, relying_party: self)

      stored_credential = yield(webauthn_credential) if block_given?

      if webauthn_credential.verify(
        operation.challenge,
        public_key: public_key || stored_credential.public_key,
        sign_count: sign_count || stored_credential.sign_count,
        user_presence: user_presence,
        user_verification: operation.user_verification_required?
      )
        operation.consume!

        block_given? ? [webauthn_credential, stored_credential] : webauthn_credential
      end
    end

    # Actively revokes a pending authentication operation, e.g. when the
    # finance department cancels a not-yet-completed confirmation.
    def revoke_authentication(operation)
      operation.revoke!
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
  end
end
