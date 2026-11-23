# frozen_string_literal: true

require "securerandom"
require "webauthn/credential_replacement/error"

module WebAuthn
  module CredentialReplacement
    # Immutable record of a support-initiated passkey replacement.
    #
    # It names the account being changed, the credential being replaced and the
    # operators that are allowed to complete the replacement. The application's
    # store is responsible for persisting it (see CredentialReplacement::Store).
    class Approval
      attr_reader :id, :account_id, :replaced_credential_id, :operators

      def initialize(account_id:, replaced_credential_id:, operators:, id: nil)
        @id = normalize_identifier(id || SecureRandom.uuid, :id)
        @account_id = normalize_identifier(account_id, :account_id)
        @replaced_credential_id = normalize_identifier(replaced_credential_id, :replaced_credential_id)
        @operators = normalize_operators(operators)

        freeze
      end

      def authorized_operator?(operator)
        operator = operator.to_s

        !operator.empty? && operators.include?(operator)
      end

      def to_h
        {
          id: id,
          account_id: account_id,
          replaced_credential_id: replaced_credential_id,
          operators: operators
        }
      end

      def ==(other)
        other.is_a?(self.class) && to_h == other.to_h
      end
      alias_method :eql?, :==

      def hash
        to_h.hash
      end

      private

      def normalize_identifier(value, name)
        unless value.is_a?(String) && !value.empty?
          raise InvalidApprovalError, "#{name} must be a non-empty String"
        end

        value.dup.freeze
      end

      def normalize_operators(operators)
        values = Array(operators)

        if values.empty?
          raise InvalidApprovalError, "operators must include at least one operator"
        end

        values.map do |operator|
          unless operator.is_a?(String) && !operator.empty?
            raise InvalidApprovalError, "each operator must be a non-empty String"
          end

          operator.dup.freeze
        end.uniq.freeze
      end
    end
  end
end
