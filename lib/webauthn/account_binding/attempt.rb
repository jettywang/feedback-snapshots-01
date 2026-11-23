# frozen_string_literal: true

module WebAuthn
  module AccountBinding
    # The outcome of the verification phase. An attempt is *not* a session:
    # it only proves that the assertion matched the material read at that
    # moment. A principal can only be obtained from Contract#commit, which
    # re-reads the account and credential state.
    class Attempt
      attr_reader :entry,
                  :handle_policy,
                  :account_id,
                  :credential_id,
                  :user_handle,
                  :rejection,
                  :error,
                  :verified_credential,
                  :stored_credential,
                  :account_reads,
                  :credential_reads

      def initialize(
        entry:,
        handle_policy:,
        account_id: nil,
        credential_id: nil,
        user_handle: nil,
        rejection: nil,
        error: nil,
        assertion_verified: false,
        verified_credential: nil,
        stored_credential: nil,
        account_reads: 0,
        credential_reads: 0
      )
        @entry = entry
        @handle_policy = handle_policy
        @account_id = account_id
        @credential_id = credential_id
        @user_handle = user_handle
        @rejection = rejection
        @error = error
        @assertion_verified = assertion_verified
        @verified_credential = verified_credential
        @stored_credential = stored_credential
        @account_reads = account_reads
        @credential_reads = credential_reads
        @consumed = false
      end

      def verified?
        @assertion_verified && rejection.nil?
      end

      def rejected?
        !verified?
      end

      # A verification attempt never constitutes a session by itself.
      def session?
        false
      end

      def consumed?
        @consumed
      end

      def consume!
        @consumed = true
      end
    end
  end
end
