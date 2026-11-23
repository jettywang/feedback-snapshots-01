# frozen_string_literal: true

require "webauthn/credential_replacement/outcome"

module WebAuthn
  module CredentialReplacement
    # The public result of RelyingParty#commit_credential_replacement.
    #
    # It intentionally exposes +revoked_credential_id+ only when this call was
    # the one that actually applied the replacement. A late conflicting commit,
    # an idempotent replay and a failed write all report +revoked_credential_id+
    # as +nil+.
    class Result
      STATUSES = [:applied, :duplicate, :conflict, :invalid, :failed].freeze

      attr_reader :approval_id,
                  :status,
                  :credential,
                  :revoked_credential_id,
                  :winning_approval_id,
                  :approval_state,
                  :winning_approval_state,
                  :message,
                  :error

      def initialize(
        approval:,
        status:,
        credential: nil,
        revoked_credential_id: nil,
        winning_approval_id: nil,
        approval_state:,
        winning_approval_state: nil,
        message: nil,
        error: nil
      )
        @approval_id = approval.id
        @status = status
        @credential = credential
        @revoked_credential_id = revoked_credential_id
        @winning_approval_id = winning_approval_id
        @approval_state = approval_state
        @winning_approval_state = winning_approval_state
        @message = message
        @error = error
      end

      def self.from_outcome(outcome, approval:, credential: nil)
        outcome = Outcome.from(outcome)

        if !outcome.applied? && outcome.revoked_credential_id
          raise Store::ContractError, "only an applied replacement may revoke a credential"
        end

        case outcome.status
        when :applied
          unless outcome.revoked_credential_id == approval.replaced_credential_id
            raise Store::ContractError,
                  "an applied replacement must revoke the approval's replaced credential"
          end

          new(
            approval: approval,
            status: :applied,
            credential: credential,
            revoked_credential_id: approval.replaced_credential_id,
            winning_approval_id: outcome.winning_approval_id || approval.id,
            approval_state: :applied,
            winning_approval_state: outcome.winning_approval_state || :applied,
            message: outcome.message
          )
        when :already_applied
          new(
            approval: approval,
            status: :duplicate,
            credential: credential,
            winning_approval_id: outcome.winning_approval_id || approval.id,
            approval_state: :applied,
            winning_approval_state: outcome.winning_approval_state || :applied,
            message: outcome.message
          )
        when :conflict
          if outcome.winning_approval_id.nil? || outcome.winning_approval_state.nil?
            raise Store::ContractError,
                  "a conflicting replacement must identify the effective approval and its state"
          end

          new(
            approval: approval,
            status: :conflict,
            credential: credential,
            winning_approval_id: outcome.winning_approval_id,
            approval_state: outcome.approval_state,
            winning_approval_state: outcome.winning_approval_state,
            message: outcome.message
          )
        when :invalid
          new(
            approval: approval,
            status: :invalid,
            credential: credential,
            approval_state: :invalid,
            message: outcome.message
          )
        when :failed
          new(
            approval: approval,
            status: :failed,
            credential: credential,
            approval_state: :pending,
            message: outcome.message
          )
        end
      end

      def self.failure(approval:, credential: nil, error: nil, message: nil)
        new(
          approval: approval,
          status: :failed,
          credential: credential,
          approval_state: :pending,
          message: message || (error && error.message),
          error: error
        )
      end

      def applied?
        status == :applied
      end

      def duplicate?
        status == :duplicate
      end

      def conflict?
        status == :conflict
      end

      def invalid?
        status == :invalid
      end

      def failed?
        status == :failed
      end

      # Whether this call mutated the account's credential set.
      def credential_set_changed?
        applied?
      end

      # Whether the submitted approval can still be used. It stays valid after a
      # retryable write failure, and stops being valid once consumed, superseded
      # or invalidated.
      def approval_still_valid?
        approval_state == :pending
      end

      # For a late conflicting result: whether the approval that actually took
      # effect is still the valid one.
      def winning_approval_still_valid?
        winning_approval_state == :applied
      end

      def retryable?
        failed?
      end

      def to_h
        {
          approval_id: approval_id,
          status: status,
          credential_id: credential && credential.id,
          revoked_credential_id: revoked_credential_id,
          winning_approval_id: winning_approval_id,
          approval_still_valid: approval_still_valid?,
          winning_approval_still_valid: winning_approval_still_valid?,
          message: message
        }
      end
    end
  end
end
