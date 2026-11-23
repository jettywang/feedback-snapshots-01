# frozen_string_literal: true

require "spec_helper"
require "webauthn/fake_client"

RSpec.describe WebAuthn::BackupCredentialManager do
  let(:origin) { "https://example.test" }
  let(:relying_party) do
    WebAuthn::RelyingParty.new(
      allowed_origins: [origin],
      id: "example.test",
      name: "Example"
    )
  end
  let(:client) { WebAuthn::FakeClient.new(origin) }
  let(:manager) { described_class.new(relying_party: relying_party) }
  let(:requested_actions) { [:login, :financial] }

  def challenge
    WebAuthn::Encoders::Base64UrlEncoder.encode(SecureRandom.random_bytes(32))
  end

  def register(backup_eligibility:, backup_state:, actions: requested_actions)
    registration_challenge = challenge
    raw_credential = client.create(
      challenge: registration_challenge,
      backup_eligibility: backup_eligibility,
      backup_state: backup_state
    )

    receipt = manager.register(
      raw_credential,
      registration_challenge,
      requested_actions: actions
    )
    credential = WebAuthn::Credential.from_create(raw_credential, relying_party: relying_party)

    [receipt, credential]
  end

  def assertion(credential, backup_eligibility:, backup_state:, sign_count:)
    authentication_challenge = challenge
    raw_credential = client.get(
      challenge: authentication_challenge,
      backup_eligibility: backup_eligibility,
      backup_state: backup_state,
      sign_count: sign_count,
      allow_credentials: [credential.id]
    )

    [raw_credential, authentication_challenge]
  end

  describe "legacy credentials without backup attributes" do
    it "applies the daily policy without promoting financial actions" do
      registration_challenge = challenge
      raw_registration = client.create(
        challenge: registration_challenge,
        backup_eligibility: true,
        backup_state: false
      )
      credential = WebAuthn::Credential.from_create(raw_registration, relying_party: relying_party)

      migration_receipt = manager.migrate(
        id: credential.id,
        public_key: credential.public_key,
        sign_count: credential.sign_count,
        requested_actions: requested_actions
      )

      raw_credential, authentication_challenge = assertion(
        credential,
        backup_eligibility: true,
        backup_state: true,
        sign_count: 1
      )
      authentication_receipt = manager.authenticate(
        raw_credential,
        authentication_challenge,
        requested_actions: requested_actions
      )

      expect(migration_receipt.to_h).to eq(
        approved_actions: [:login],
        version: 1,
        basis: :legacy_migration
      )
      expect(authentication_receipt.to_h).to eq(
        approved_actions: [:login],
        version: 2,
        basis: :legacy_daily_policy
      )

      snapshot = manager.store.snapshot(credential.id)

      expect(snapshot.backup_attributes.unknown_eligibility?).to be(true)
      expect(snapshot.backup_attributes.state).to be(true)
      expect(snapshot.version).to eq(2)
    end
  end

  describe "validated synced credential" do
    it "keeps registration eligibility stable while tracking the observed backup state" do
      registration_receipt, credential = register(backup_eligibility: true, backup_state: false)

      raw_credential, authentication_challenge = assertion(
        credential,
        backup_eligibility: true,
        backup_state: true,
        sign_count: 1
      )
      authentication_receipt = manager.authenticate(
        raw_credential,
        authentication_challenge,
        requested_actions: requested_actions
      )

      expect(registration_receipt.to_h).to eq(
        approved_actions: [:login],
        version: 1,
        basis: :synced_registration
      )
      expect(authentication_receipt.to_h).to eq(
        approved_actions: [:login],
        version: 2,
        basis: :backup_state_changed
      )

      snapshot = manager.store.snapshot(credential.id)

      expect(snapshot.backup_attributes.eligible).to be(true)
      expect(snapshot.backup_attributes.state).to be(true)
      expect(snapshot.version).to eq(2)
    end
  end

  describe "parallel authentication responses arriving out of order" do
    it "rejects a late older observation instead of restoring stale state" do
      registration_receipt, credential = register(backup_eligibility: true, backup_state: true)
      snapshot = manager.store.snapshot(credential.id)

      older_raw, older_challenge = assertion(
        credential,
        backup_eligibility: true,
        backup_state: true,
        sign_count: 1
      )
      newer_raw, newer_challenge = assertion(
        credential,
        backup_eligibility: true,
        backup_state: false,
        sign_count: 2
      )

      newer_receipt = manager.authenticate(
        newer_raw,
        newer_challenge,
        requested_actions: requested_actions,
        snapshot: snapshot
      )
      older_receipt = manager.authenticate(
        older_raw,
        older_challenge,
        requested_actions: requested_actions,
        snapshot: snapshot
      )

      expect(registration_receipt.to_h).to eq(
        approved_actions: [:login],
        version: 1,
        basis: :synced_registration
      )
      expect(newer_receipt.to_h).to eq(
        approved_actions: [:login],
        version: 2,
        basis: :backup_state_changed
      )
      expect(older_receipt.to_h).to eq(
        approved_actions: [],
        version: 2,
        basis: :stale_observation
      )

      final_snapshot = manager.store.snapshot(credential.id)

      expect(final_snapshot.backup_attributes.state).to be(false)
      expect(final_snapshot.version).to eq(2)
    end
  end
end
