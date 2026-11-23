# frozen_string_literal: true

require "webauthn/credential_replacement/outcome"
require "webauthn/credential_replacement/store"

module WebAuthn
  module CredentialReplacement
    # Reference implementation of CredentialReplacement::Store for applications
    # and tests that keep credentials in memory.
    #
    # It serializes commits with a mutex, applies each approval at most once and
    # never mutates state when a write fails. Use #fail_next_write! to exercise
    # the retry path.
    class InMemoryStore
      include Store

      StoredCredential = Struct.new(:id, :public_key, :sign_count, keyword_init: true)

      def initialize
        @approvals = {}
        @credentials = Hash.new { |hash, account_id| hash[account_id] = {} }
        @lock = Mutex.new
        @fail_next_write = false
      end

      # Seeds a credential that can already authenticate, such as the device
      # that support is about to replace.
      def register_credential(account_id:, id:, public_key:, sign_count: 0)
        @lock.synchronize do
          credentials_for(account_id)[id] = StoredCredential.new(
            id: id,
            public_key: public_key,
            sign_count: sign_count
          )
        end
      end

      # The set of credentials that can actually log in for +account_id+.
      def credential_set(account_id)
        @lock.synchronize { credentials_for(account_id).values.map(&:id) }
      end

      def credential(account_id, credential_id)
        @lock.synchronize { credentials_for(account_id)[credential_id] }
      end

      def approval_state(approval_id)
        @lock.synchronize do
          record = @approvals[approval_id]
          record && record[:state]
        end
      end

      # Makes the next commit attempt fail before touching any state.
      def fail_next_write!
        @lock.synchronize { @fail_next_write = true }
      end

      def save_replacement_approval(approval)
        @lock.synchronize do
          existing = @approvals[approval.id]

          if existing && existing[:approval] != approval
            raise InvalidApprovalError, "approval #{approval.id} was already saved with different contents"
          end

          @approvals[approval.id] ||= { approval: approval, state: :pending, credential_id: nil }
        end

        approval
      end

      def commit_credential_replacement(approval:, credential:, operator:)
        @lock.synchronize do
          if @fail_next_write
            @fail_next_write = false
            raise Store::WriteError, "simulated write failure"
          end

          record = @approvals[approval.id]

          if record.nil? || record[:approval] != approval || !approval.authorized_operator?(operator)
            return Outcome.new(status: :invalid, message: "unknown approval or unauthorized operator")
          end

          case record[:state]
          when :applied
            return already_applied_outcome(record)
          when :superseded
            return conflict_outcome(record)
          when :invalid
            return Outcome.new(status: :invalid, message: "approval is no longer valid")
          end

          applied_credential = credentials_for(approval.account_id)[credential.id]

          if applied_credential
            return Outcome.new(status: :invalid, message: "credential is already registered")
          end

          unless credentials_for(approval.account_id).key?(approval.replaced_credential_id)
            winning = effective_approval_for(approval)
            record[:state] = winning ? :superseded : :invalid

            return winning ? conflict_outcome(record) :
              Outcome.new(status: :invalid, message: "replaced credential not found")
          end

          credentials_for(approval.account_id).delete(approval.replaced_credential_id)
          credentials_for(approval.account_id)[credential.id] = StoredCredential.new(
            id: credential.id,
            public_key: credential.public_key,
            sign_count: credential.sign_count
          )
          record[:state] = :applied
          record[:credential_id] = credential.id

          supersede_other_pending_approvals(approval, winning_approval_id: approval.id)

          Outcome.new(
            status: :applied,
            approval_state: :applied,
            winning_approval_id: approval.id,
            winning_approval_state: :applied,
            revoked_credential_id: approval.replaced_credential_id
          )
        end
      end

      private

      def credentials_for(account_id)
        @credentials[account_id]
      end

      def already_applied_outcome(record)
        Outcome.new(
          status: :already_applied,
          approval_state: :applied,
          winning_approval_id: record[:approval].id,
          winning_approval_state: :applied
        )
      end

      def conflict_outcome(record)
        winning = effective_approval_for(record[:approval])

        Outcome.new(
          status: :conflict,
          approval_state: record[:state],
          winning_approval_id: winning && winning[:approval].id,
          winning_approval_state: winning && winning[:state],
          message: "another approval already replaced credential #{record[:approval].replaced_credential_id}"
        )
      end

      # The applied approval that consumed the same replaced credential.
      def effective_approval_for(approval)
        @approvals.values.find do |candidate|
          candidate[:state] == :applied &&
            candidate[:approval].account_id == approval.account_id &&
            candidate[:approval].replaced_credential_id == approval.replaced_credential_id &&
            candidate[:approval].id != approval.id
        end
      end

      def supersede_other_pending_approvals(approval, winning_approval_id:)
        @approvals.each_value do |candidate|
          next if candidate[:approval].id == winning_approval_id
          next unless candidate[:state] == :pending
          next unless candidate[:approval].account_id == approval.account_id
          next unless candidate[:approval].replaced_credential_id == approval.replaced_credential_id

          candidate[:state] = :superseded
        end
      end
    end
  end
end
