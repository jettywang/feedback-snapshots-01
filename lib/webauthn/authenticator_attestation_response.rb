# frozen_string_literal: true

require "cbor"
require "forwardable"
require "uri"
require "openssl"

require "webauthn/attestation_object"
require "webauthn/authenticator_response"
require "webauthn/client_data"
require "webauthn/encoder"

module WebAuthn
  class AttestationStatementVerificationError < VerificationError; end
  class AttestedCredentialVerificationError < VerificationError; end
  class CredentialIdLengthVerificationError < VerificationError; end

  class AuthenticatorAttestationResponse < AuthenticatorResponse
    extend Forwardable

    MAX_CREDENTIAL_ID_LENGTH = 1023

    def self.from_client(response, relying_party: WebAuthn.configuration.relying_party)
      encoder = relying_party.encoder

      new(
        attestation_object: encoder.decode(response["attestationObject"]),
        transports: response["transports"],
        client_data_json: encoder.decode(response["clientDataJSON"]),
        relying_party: relying_party
      )
    end

    attr_reader :attestation_type, :attestation_trust_path, :attestation_trust_path_checked, :transports

    def initialize(attestation_object:, transports: [], **options)
      super(**options)

      @attestation_object_bytes = attestation_object
      @transports = transports
      @relying_party = relying_party
    end

    def verify(
      expected_challenge,
      expected_origin = nil,
      user_presence: nil,
      user_verification: nil,
      rp_id: nil,
      verify_attestation_statement: nil
    )
      super(
        expected_challenge,
        expected_origin,
        user_presence: user_presence,
        user_verification: user_verification,
        rp_id: rp_id
      )

      verify_item(:attested_credential)

      should_verify_attestation =
        verify_attestation_statement.nil? ? relying_party.verify_attestation_statement : verify_attestation_statement

      if should_verify_attestation
        verify_item(:attestation_statement)
      end

      verify_item(:credential_id_length)

      true
    end

    def attestation_object
      @attestation_object ||= WebAuthn::AttestationObject.deserialize(attestation_object_bytes, relying_party)
    end

    # Stores the outcome of an attestation statement verification so callers
    # can inspect it even when the regular verification path skipped it.
    def record_attestation_result(attestation_type, attestation_trust_path, trust_path_checked: nil)
      @attestation_type = attestation_type
      @attestation_trust_path = attestation_trust_path
      @attestation_trust_path_checked = trust_path_checked
    end

    def_delegators(
      :attestation_object,
      :aaguid,
      :attestation_statement,
      :attestation_certificate_key_id,
      :authenticator_data,
      :credential
    )

    alias_method :attestation_certificate_key, :attestation_certificate_key_id

    private

    attr_reader :attestation_object_bytes, :relying_party

    def type
      WebAuthn::TYPES[:create]
    end

    def valid_attested_credential?
      attestation_object.valid_attested_credential? &&
        relying_party.algorithms.include?(authenticator_data.credential.algorithm)
    end

    def valid_attestation_statement?
      result = attestation_object.valid_attestation_statement?(client_data.hash)

      if result
        @attestation_type, @attestation_trust_path = result
        @attestation_trust_path_checked = attestation_object.attestation_statement.trust_path_checked?
      end

      result
    end

    def valid_credential_id_length?
      authenticator_data.credential.id.bytesize <= MAX_CREDENTIAL_ID_LENGTH
    end
  end
end
