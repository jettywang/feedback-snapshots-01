# frozen_string_literal: true

require "openssl"
require "webauthn/credential"
require "webauthn/credential_replacement"
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

    # Starts a support-initiated passkey replacement.
    #
    # The returned Approval names the account, the credential being replaced
    # and the operators allowed to complete the replacement. It is persisted
    # through +store+ so that the eventual commit can be made atomically.
    def begin_credential_replacement(account_id:, replaced_credential_id:, operators:, store:)
      approval = CredentialReplacement::Approval.new(
        account_id: account_id,
        replaced_credential_id: replaced_credential_id,
        operators: operators
      )

      store.save_replacement_approval(approval)

      approval
    end

    # Registration options for the replacement device.
    #
    # This is a registration ceremony like any other; the only difference is
    # that the credential being replaced is excluded. Use
    # #verify_replacement_registration to verify its result. The ordinary
    # registration entry point (#options_for_registration and
    # #verify_registration) is unaffected.
    def options_for_replacement_registration(approval:, user:, exclude: nil, **keyword_arguments)
      excluded = Array(exclude).dup
      unless excluded.any? { |credential| credential_id_for(credential) == approval.replaced_credential_id }
        excluded << approval.replaced_credential_id
      end

      options_for_registration(
        **keyword_arguments,
        user: user,
        exclude: excluded
      )
    end

    # Verifies the replacement device's registration and checks that +operator+
    # may act on +approval+.
    #
    # Verification and the store write are separate on purpose: a caller may
    # retry #complete_credential_replacement after a write failure without
    # asking the user to register again.
    def verify_replacement_registration(
      raw_credential,
      challenge,
      approval:,
      operator:,
      user_presence: nil,
      user_verification: nil
    )
      verify_replacement_operator!(approval, operator)

      webauthn_credential = verify_registration(
        raw_credential,
        challenge,
        user_presence: user_presence,
        user_verification: user_verification
      )

      if webauthn_credential.id == approval.replaced_credential_id
        raise CredentialReplacement::ApprovalMismatchError,
              "the replacement credential must differ from the replaced credential"
      end

      webauthn_credential
    end

    # Commits an already verified replacement credential through +store+.
    #
    # The store must apply the swap atomically and idempotently. This method
    # never revokes a credential itself; it reports the store's Outcome as a
    # Result and only exposes revocation for the call that actually applied it.
    def complete_credential_replacement(approval:, credential:, operator:, store:)
      verify_replacement_operator!(approval, operator)

      outcome = store.commit_credential_replacement(
        approval: approval,
        credential: credential,
        operator: operator
      )

      CredentialReplacement::Result.from_outcome(outcome, approval: approval, credential: credential)
    rescue CredentialReplacement::Store::WriteError => error
      CredentialReplacement::Result.failure(approval: approval, credential: credential, error: error)
    end

    # Convenience handoff for a single request: verify the replacement device
    # and commit it. Retries of the same approval and credential are safe,
    # because the store makes the commit idempotent.
    def commit_credential_replacement(
      raw_credential,
      challenge,
      approval:,
      operator:,
      store:,
      user_presence: nil,
      user_verification: nil
    )
      credential = verify_replacement_registration(
        raw_credential,
        challenge,
        approval: approval,
        operator: operator,
        user_presence: user_presence,
        user_verification: user_verification
      )

      complete_credential_replacement(
        approval: approval,
        credential: credential,
        operator: operator,
        store: store
      )
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

    def credential_id_for(credential)
      credential.respond_to?(:webauthn_id) ? credential.webauthn_id : credential
    end

    def verify_replacement_operator!(approval, operator)
      unless approval.is_a?(CredentialReplacement::Approval)
        raise CredentialReplacement::InvalidApprovalError,
              "approval must be a WebAuthn::CredentialReplacement::Approval"
      end

      unless approval.authorized_operator?(operator)
        raise CredentialReplacement::OperatorNotAuthorizedError,
              "operator #{operator.inspect} is not allowed to act on approval #{approval.id}"
      end
    end
  end
end
