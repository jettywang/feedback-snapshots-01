# frozen_string_literal: true

require "webauthn/credential_replacement/error"

module WebAuthn
  module CredentialReplacement
    # Contract an application's credential storage must implement to take part
    # in a passkey replacement.
    #
    # The contract is deliberately small. The library performs WebAuthn
    # verification and delegates the state change to the application, because
    # only the application can make it transactional alongside its own data.
    #
    # === Required methods
    #
    # +save_replacement_approval(approval)+
    #   Persist a pending approval. Saving the same approval id twice must not
    #   reset an approval that has already been applied or superseded.
    #
    # +commit_credential_replacement(approval:, credential:, operator:)+
    #   Atomically consume +approval+ and swap +approval.replaced_credential_id+
    #   for +credential+. It must return a CredentialReplacement::Outcome (or an
    #   equivalent Hash) and must obey these rules:
    #
    #   * Commit at most once per approval id. Replaying an already applied
    #     approval returns <tt>status: :already_applied</tt> without changing
    #     the credential set.
    #   * Only the commit that actually takes effect may return
    #     <tt>status: :applied</tt>. It must set +revoked_credential_id+ to
    #     exactly +approval.replaced_credential_id+ and must not revoke any
    #     other credential.
    #   * If a different approval has already replaced the target credential,
    #     return <tt>status: :conflict</tt>, leave the credential set unchanged,
    #     and identify the effective approval through +winning_approval_id+ and
    #     +winning_approval_state+ so the caller can tell whether the earlier
    #     approval is still valid.
    #   * If the approval is unknown, tampered with or otherwise no longer
    #     applicable, return <tt>status: :invalid</tt> and change nothing.
    #   * If the write fails, raise CredentialReplacement::Store::WriteError (or
    #     return <tt>status: :failed</tt>) and leave both the credential set and
    #     the approval pending so the caller can retry.
    #   * Never report <tt>status: :applied</tt> unless the old credential was
    #     removed and the new credential was persisted in the same atomic write.
    #
    #   +credential+ is the verified WebAuthn credential and responds to
    #   +id+, +public_key+ and +sign_count+.
    #
    # Implementations must serialize commits that target the same account or
    # replaced credential; that serialization is what resolves concurrent
    # support approvals deterministically.
    module Store
      # Raised when the atomic write cannot be completed. The store must leave
      # state untouched and keep the approval pending for retry.
      class WriteError < Error; end

      # Raised when a store does not honour the contract (for example, by
      # returning an unknown outcome or revoking a credential on a conflict).
      class ContractError < Error; end

      def save_replacement_approval(approval)
        raise NotImplementedError, "Please define #save_replacement_approval in your credential replacement store"
      end

      def commit_credential_replacement(approval:, credential:, operator:)
        raise NotImplementedError, "Please define #commit_credential_replacement in your credential replacement store"
      end
    end
  end
end
