# frozen_string_literal: true

require "webauthn/credential_replacement/store"

module WebAuthn
  module CredentialReplacement
    # The store's answer to a single commit attempt.
    #
    # +status+ is one of:
    # * <tt>:applied</tt> - this call performed the swap.
    # * <tt>:already_applied</tt> - the same approval was applied before; no
    #   credential changed on this call.
    # * <tt>:conflict</tt> - another approval already replaced the credential;
    #   +winning_approval_id+ and +winning_approval_state+ identify it.
    # * <tt>:invalid</tt> - the approval cannot be used.
    # * <tt>:failed</tt> - the write failed and can be retried.
    class Outcome
      STATUSES = [:applied, :already_applied, :conflict, :invalid, :failed].freeze
      APPROVAL_STATES = [:pending, :applied, :superseded, :invalid].freeze
      ATTRIBUTES = [
        :status,
        :approval_state,
        :winning_approval_id,
        :winning_approval_state,
        :revoked_credential_id,
        :message
      ].freeze

      attr_reader :status,
                  :approval_state,
                  :winning_approval_id,
                  :winning_approval_state,
                  :revoked_credential_id,
                  :message

      def initialize(
        status:,
        approval_state: nil,
        winning_approval_id: nil,
        winning_approval_state: nil,
        revoked_credential_id: nil,
        message: nil
      )
        @status = normalize_status(status)
        @approval_state = normalize_approval_state(approval_state || default_approval_state)
        @winning_approval_id = winning_approval_id
        @winning_approval_state = normalize_optional_approval_state(winning_approval_state)
        @revoked_credential_id = revoked_credential_id
        @message = message

        freeze
      end

      def self.from(value)
        case value
        when self
          value
        when Hash
          attributes = value.each_with_object({}) do |(key, val), result|
            symbol = key.to_sym
            result[symbol] = val if ATTRIBUTES.include?(symbol)
          end

          begin
            new(**attributes)
          rescue ArgumentError => error
            raise Store::ContractError, "invalid credential replacement outcome: #{error.message}"
          end
        else
          raise Store::ContractError,
                "credential replacement store must return a CredentialReplacement::Outcome or a Hash"
        end
      end

      def applied?
        status == :applied
      end

      def already_applied?
        status == :already_applied
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

      private

      def normalize_status(status)
        status = status.to_sym if status.respond_to?(:to_sym)

        unless STATUSES.include?(status)
          raise Store::ContractError, "unknown credential replacement status: #{status.inspect}"
        end

        status
      end

      def normalize_approval_state(state)
        state = state.to_sym if state.respond_to?(:to_sym)

        unless APPROVAL_STATES.include?(state)
          raise Store::ContractError, "unknown approval state: #{state.inspect}"
        end

        state
      end

      def normalize_optional_approval_state(state)
        return if state.nil?

        normalize_approval_state(state)
      end

      def default_approval_state
        case status
        when :applied, :already_applied
          :applied
        when :conflict
          :superseded
        when :invalid
          :invalid
        when :failed
          :pending
        end
      end
    end
  end
end
