# frozen_string_literal: true

require "webauthn/backup_attributes"
require "webauthn/backup_policy"
require "webauthn/backup_receipt"
require "webauthn/credential"
require "webauthn/in_memory_credential_store"

module WebAuthn
  class BackupCredentialManager
    attr_reader :relying_party, :store, :policy

    def initialize(relying_party:, store: InMemoryCredentialStore.new, policy: BackupPolicy.new)
      @relying_party = relying_party
      @store = store
      @policy = policy
    end

    def register(
      raw_credential,
      challenge,
      user_presence: nil,
      user_verification: nil,
      requested_actions: nil
    )
      credential = relying_party.verify_registration(
        raw_credential,
        challenge,
        user_presence: user_presence,
        user_verification: user_verification
      )

      attributes = BackupAttributes.from_credential(credential, source: :registration)
      decision = policy.registration(attributes, requested_actions: requested_actions)

      stored = store.register(
        id: credential.id,
        public_key: credential.public_key,
        sign_count: credential.sign_count,
        backup_attributes: attributes
      )

      receipt_for(decision, stored)
    end

    def migrate(
      id:,
      public_key:,
      sign_count:,
      backup_eligible: nil,
      backup_state: nil,
      requested_actions: nil,
      expected_version: nil
    )
      source = backup_eligible.nil? && backup_state.nil? ? :legacy : :migration
      attributes = BackupAttributes.new(
        eligible: backup_eligible,
        state: backup_state,
        source: source
      )
      decision = policy.migration(attributes, requested_actions: requested_actions)

      stored = store.migrate(
        id: id,
        public_key: public_key,
        sign_count: sign_count,
        backup_attributes: attributes,
        expected_version: expected_version
      )

      receipt_for(decision, stored)
    end

    def authenticate(
      raw_credential,
      challenge,
      user_presence: nil,
      user_verification: nil,
      requested_actions: nil,
      snapshot: nil
    )
      incoming = WebAuthn::Credential.from_get(raw_credential, relying_party: relying_party)
      snapshot ||= store.snapshot(incoming.id)

      unless snapshot
        raise CredentialNotFoundError, "Credential #{incoming.id} is not stored"
      end

      unless snapshot.id == incoming.id
        raise CredentialNotFoundError,
              "Snapshot for #{snapshot.id} does not match credential #{incoming.id}"
      end

      credential = relying_party.verify_authentication(
        raw_credential,
        challenge,
        public_key: snapshot.public_key,
        sign_count: snapshot.sign_count,
        user_presence: user_presence,
        user_verification: user_verification
      )

      observed = BackupAttributes.from_credential(credential, source: :authentication)
      decision = policy.authentication(
        stored: snapshot.backup_attributes,
        observed: observed,
        requested_actions: requested_actions
      )

      unless decision.writable?
        current = store.snapshot(incoming.id)

        return BackupReceipt.new(
          approved_actions: [],
          version: current&.version,
          basis: decision.basis
        )
      end

      committed = store.commit_authentication(
        snapshot: snapshot,
        backup_attributes: policy.next_attributes(stored: snapshot.backup_attributes, observed: observed),
        sign_count: credential.sign_count
      )

      if committed
        receipt_for(decision, committed)
      else
        current = store.snapshot(incoming.id)

        BackupReceipt.new(
          approved_actions: [],
          version: current&.version,
          basis: :stale_observation
        )
      end
    end

    private

    def receipt_for(decision, snapshot)
      BackupReceipt.new(
        approved_actions: decision.approved_actions,
        version: snapshot.version,
        basis: decision.basis
      )
    end
  end
end
