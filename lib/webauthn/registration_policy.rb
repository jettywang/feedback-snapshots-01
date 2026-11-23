# frozen_string_literal: true

require "cose/algorithm"
require "cose/rsapkcs1_algorithm"
require "webauthn/error"

module WebAuthn
  # Optional policy applied when confirming a registration.
  #
  # It constrains two independent pieces of evidence:
  #
  # * the algorithm of the newly registered credential public key
  # * the algorithm of the statement that proves the authenticator's
  #   provenance (its attestation statement), which may be backed either by
  #   a validated certificate trust path or by self attestation
  #
  # A registration is only persistable when both pieces of evidence are
  # approved on their own. A successful credential algorithm check never
  # approves the attestation evidence, and vice versa.
  #
  # The policy is opt-in: without it, registration verification behaves
  # exactly as before.
  class RegistrationPolicy
    ATTESTATION_REQUIREMENTS = [:required, :optional].freeze

    class RejectedError < WebAuthn::VerificationError
      attr_reader :result

      def initialize(result)
        @result = result

        super("Registration rejected by policy: #{result.rejection_reasons.join(', ')}")
      end
    end

    Evidence = Struct.new(:kind, :algorithm, :verified, :approved, :reason, keyword_init: true) do
      def approved?
        approved
      end

      def to_h
        {
          kind: kind,
          algorithm: algorithm,
          verified: verified,
          approved: approved?,
          reason: reason
        }
      end
    end

    class Result
      attr_reader :credential,
                  :credential_evidence,
                  :attestation_evidence,
                  :attestation_source,
                  :attestation_trust_path,
                  :attestation_type,
                  :attestation_verification_error

      def initialize(
        credential:,
        credential_evidence:,
        attestation_evidence:,
        attestation_source:,
        attestation_trust_path:,
        attestation_type:,
        trust_path_checked:,
        attestation_verification_error: nil
      )
        @credential = credential
        @credential_evidence = credential_evidence
        @attestation_evidence = attestation_evidence
        @attestation_source = attestation_source
        @attestation_trust_path = attestation_trust_path
        @attestation_type = attestation_type
        @trust_path_checked = trust_path_checked
        @attestation_verification_error = attestation_verification_error
      end

      def approved?
        credential_evidence.approved? && attestation_evidence.approved?
      end
      alias_method :persistable?, :approved?

      def credential_algorithm
        credential_evidence.algorithm
      end

      def attestation_algorithm
        attestation_evidence.algorithm
      end

      def attestation_verified?
        attestation_evidence.verified
      end

      def trust_path_checked?
        !!@trust_path_checked
      end

      def self_attestation?
        attestation_source == :self_attestation
      end

      def no_attestation?
        attestation_source == :none
      end

      def rejection_reasons
        [credential_evidence, attestation_evidence]
          .reject(&:approved?)
          .map(&:reason)
      end

      def to_h
        {
          persistable: persistable?,
          credential: credential_evidence.to_h,
          attestation: attestation_evidence.to_h,
          attestation_source: attestation_source,
          attestation_type: attestation_type,
          attestation_trust_path: attestation_trust_path,
          trust_path_checked: trust_path_checked?,
          rejection_reasons: rejection_reasons
        }
      end

      def id
        credential.id
      end

      def public_key
        credential.public_key
      end

      def sign_count
        credential.sign_count
      end
    end

    attr_reader :credential_algorithms, :attestation_algorithms, :attestation_requirement

    def initialize(credential_algorithms: nil, attestation_algorithms: nil, attestation_requirement: :required)
      @credential_algorithms = normalize_algorithms(credential_algorithms)
      @attestation_algorithms = normalize_algorithms(attestation_algorithms)
      @attestation_requirement = normalize_attestation_requirement(attestation_requirement)
    end

    # Builds a policy that explicitly accepts registrations without external
    # attestation while still constraining the credential public key algorithm.
    def self.allowing_no_attestation(credential_algorithms: nil, attestation_algorithms: nil)
      new(
        credential_algorithms: credential_algorithms,
        attestation_algorithms: attestation_algorithms,
        attestation_requirement: :optional
      )
    end

    def attestation_required?
      attestation_requirement == :required
    end

    def attestation_optional?
      attestation_requirement == :optional
    end

    def evaluate(credential)
      response = credential.response
      statement = response.attestation_object.attestation_statement

      credential_evidence = evaluate_credential_evidence(response)
      attestation_evidence, source, trust_path, type, trust_path_checked, verification_error =
        evaluate_attestation_evidence(response, statement)

      if attestation_evidence.verified
        response.record_attestation_result(
          type,
          trust_path,
          trust_path_checked: trust_path_checked
        )
      end

      Result.new(
        credential: credential,
        credential_evidence: credential_evidence,
        attestation_evidence: attestation_evidence,
        attestation_source: source,
        attestation_trust_path: trust_path,
        attestation_type: type,
        trust_path_checked: trust_path_checked,
        attestation_verification_error: verification_error
      )
    end

    private

    def evaluate_credential_evidence(response)
      credential = response.authenticator_data.credential
      algorithm = credential&.algorithm
      verified = response.attestation_object.valid_attested_credential? && !algorithm.nil?

      approved, reason =
        if !verified
          [false, :credential_unverifiable]
        elsif credential_algorithms.nil?
          [true, :credential_unrestricted]
        elsif credential_algorithms.include?(algorithm)
          [true, :credential_algorithm_allowed]
        else
          [false, :credential_algorithm_not_allowed]
        end

      Evidence.new(
        kind: :credential,
        algorithm: algorithm,
        verified: verified,
        approved: approved,
        reason: reason
      )
    rescue StandardError
      Evidence.new(
        kind: :credential,
        algorithm: nil,
        verified: false,
        approved: false,
        reason: :credential_unverifiable
      )
    end

    def evaluate_attestation_evidence(response, statement)
      source = statement.attestation_source
      algorithm = statement.attestation_algorithm_name

      if source == :none && attestation_required?
        evidence = Evidence.new(
          kind: :attestation,
          algorithm: nil,
          verified: false,
          approved: false,
          reason: :attestation_missing
        )

        return [evidence, source, nil, nil, false, nil]
      end

      verified, type, trust_path, verification_error = verify_attestation(response)
      approved, reason = attestation_approval(source, algorithm, verified)
      trust_path_checked =
        if response.attestation_trust_path_checked.nil?
          statement.trust_path_checked?
        else
          response.attestation_trust_path_checked
        end

      evidence = Evidence.new(
        kind: :attestation,
        algorithm: algorithm,
        verified: verified,
        approved: approved,
        reason: reason
      )

      [evidence, source, trust_path, type, trust_path_checked, verification_error]
    end

    def verify_attestation(response)
      if response.attestation_type
        return [true, response.attestation_type, response.attestation_trust_path, nil]
      end

      type, trust_path =
        if statement_allows_no_attestation?(response)
          [WebAuthn::AttestationStatement::ATTESTATION_TYPE_NONE, nil]
        else
          response.attestation_object.valid_attestation_statement?(response.client_data.hash)
        end

      [!!type, type, trust_path, nil]
    rescue StandardError => error
      [false, nil, nil, error]
    end

    def statement_allows_no_attestation?(response)
      statement = response.attestation_object.attestation_statement

      statement.is_a?(WebAuthn::AttestationStatement::None) && statement.valid_format?
    end

    def attestation_approval(source, algorithm, verified)
      if source == :none
        [verified, verified ? :attestation_not_required : :attestation_unverifiable]
      elsif !verified
        [false, :attestation_unverifiable]
      elsif algorithm.nil?
        [false, :attestation_algorithm_missing]
      elsif attestation_algorithms.nil?
        [true, :attestation_unrestricted]
      elsif attestation_algorithms.include?(algorithm)
        [true, :attestation_algorithm_allowed]
      else
        [false, :attestation_algorithm_not_allowed]
      end
    end

    def normalize_algorithms(algorithms)
      return nil if algorithms.nil?

      Array(algorithms).map do |algorithm|
        name = algorithm.to_s

        unless COSE::Algorithm.find(name)
          raise ArgumentError, "Unknown COSE algorithm #{algorithm.inspect}"
        end

        name
      end.freeze
    end

    def normalize_attestation_requirement(requirement)
      normalized = requirement.to_s.to_sym

      unless ATTESTATION_REQUIREMENTS.include?(normalized)
        raise ArgumentError,
              "Unknown attestation requirement #{requirement.inspect}. " \
              "Expected one of #{ATTESTATION_REQUIREMENTS.inspect}"
      end

      normalized
    end
  end
end
