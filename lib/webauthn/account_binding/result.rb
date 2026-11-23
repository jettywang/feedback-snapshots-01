# frozen_string_literal: true

module WebAuthn
  module AccountBinding
    class Result
      attr_reader :entry,
                  :handle_policy,
                  :status,
                  :reason,
                  :principal,
                  :account_reads,
                  :credential_reads,
                  :credential_id,
                  :error

      def initialize(
        entry:,
        handle_policy:,
        status:,
        reason: nil,
        principal: nil,
        account_reads: 0,
        credential_reads: 0,
        credential_id: nil,
        error: nil
      )
        @entry = entry
        @handle_policy = handle_policy
        @status = status
        @reason = reason
        @principal = principal
        @account_reads = account_reads
        @credential_reads = credential_reads
        @credential_id = credential_id
        @error = error
      end

      def session_created?
        status == :authenticated && !principal.nil?
      end

      alias_method :authenticated?, :session_created?

      def rejected?
        !session_created?
      end

      def to_h
        {
          entry: entry,
          handle_policy: handle_policy,
          status: status,
          reason: reason,
          principal: principal&.to_h,
          account_reads: account_reads,
          credential_reads: credential_reads,
          credential_id: credential_id
        }
      end
    end
  end
end
