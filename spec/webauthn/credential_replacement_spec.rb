# frozen_string_literal: true

require "spec_helper"
require "webauthn/fake_authenticator"
require "webauthn/fake_client"
require "webauthn/credential_replacement/in_memory_store"
require "webauthn/relying_party"

RSpec.describe "Credential replacement handoff" do
  let(:relying_party) do
    WebAuthn::RelyingParty.new(
      allowed_origins: ["https://support.example.test"],
      id: "support.example.test",
      name: "Support Application"
    )
  end
  let(:authenticator) { WebAuthn::FakeAuthenticator.new }
  let(:client) { WebAuthn::FakeClient.new("https://support.example.test", authenticator: authenticator) }
  let(:store) { WebAuthn::CredentialReplacement::InMemoryStore.new }
  let(:account_id) { "account-1" }
  let(:operator) { "support-agent-7" }
  let(:user) { { id: WebAuthn.generate_user_id, name: "John Doe" } }

  def register_device(approval: nil, exclude: nil)
    options =
      if approval
        relying_party.options_for_replacement_registration(approval: approval, user: user, exclude: exclude)
      else
        relying_party.options_for_registration(user: user)
      end

    raw_credential = client.create(challenge: options.challenge, rp_id: relying_party.id)

    credential =
      if approval
        relying_party.verify_replacement_registration(
          raw_credential,
          options.challenge,
          approval: approval,
          operator: operator
        )
      else
        relying_party.verify_registration(raw_credential, options.challenge)
      end

    [credential, options]
  end

  def store_credential(credential)
    store.register_credential(
      account_id: account_id,
      id: credential.id,
      public_key: credential.public_key,
      sign_count: credential.sign_count
    )
  end

  def sign_in
    credential_ids = store.credential_set(account_id)
    options = relying_party.options_for_authentication(allow: credential_ids)
    raw_credential = client.get(
      challenge: options.challenge,
      rp_id: relying_party.id,
      allow_credentials: credential_ids
    )

    relying_party.verify_authentication(raw_credential, options.challenge) do |webauthn_credential|
      store.credential(account_id, webauthn_credential.id)
    end
  end

  def begin_approval
    relying_party.begin_credential_replacement(
      account_id: account_id,
      replaced_credential_id: old_credential.id,
      operators: [operator],
      store: store
    )
  end

  let!(:old_credential) do
    credential, = register_device
    store_credential(credential)
    credential
  end

  describe "initiating an approval" do
    it "names the account, the replaced credential and the operators allowed to act" do
      approval = begin_approval

      expect(approval.account_id).to eq(account_id)
      expect(approval.replaced_credential_id).to eq(old_credential.id)
      expect(approval.operators).to eq([operator])
      expect(approval.authorized_operator?(operator)).to be(true)
      expect(approval.authorized_operator?("another-agent")).to be(false)
      expect(store.approval_state(approval.id)).to eq(:pending)
    end

    it "rejects an approval without an account, replaced credential or operator" do
      expect do
        WebAuthn::CredentialReplacement::Approval.new(
          account_id: "", replaced_credential_id: old_credential.id, operators: [operator]
        )
      end.to raise_error(WebAuthn::CredentialReplacement::InvalidApprovalError)

      expect do
        WebAuthn::CredentialReplacement::Approval.new(
          account_id: account_id, replaced_credential_id: nil, operators: [operator]
        )
      end.to raise_error(WebAuthn::CredentialReplacement::InvalidApprovalError)

      expect do
        WebAuthn::CredentialReplacement::Approval.new(
          account_id: account_id, replaced_credential_id: old_credential.id, operators: []
        )
      end.to raise_error(WebAuthn::CredentialReplacement::InvalidApprovalError)
    end

    it "lets only an allowed operator verify and commit the replacement" do
      approval = begin_approval
      raw_credential = client.create(
        challenge: relying_party.options_for_replacement_registration(approval: approval, user: user).challenge,
        rp_id: relying_party.id
      )
      challenge = relying_party.options_for_replacement_registration(approval: approval, user: user).challenge

      expect do
        relying_party.verify_replacement_registration(
          raw_credential,
          challenge,
          approval: approval,
          operator: "intruder"
        )
      end.to raise_error(WebAuthn::CredentialReplacement::OperatorNotAuthorizedError)
    end
  end

  describe "exclusion of the replaced credential" do
    it "asks the authenticator to avoid re-registering the credential being replaced" do
      approval = begin_approval

      options = relying_party.options_for_replacement_registration(approval: approval, user: user)

      expect(options.exclude_credentials).to eq([{ type: "public-key", id: old_credential.id }])
    end
  end

  describe "committing after verification" do
    it "applies the replacement once and revokes only the approval's old credential" do
      approval = begin_approval
      new_credential, = register_device(approval: approval)

      result = relying_party.complete_credential_replacement(
        approval: approval,
        credential: new_credential,
        operator: operator,
        store: store
      )

      expect(result).to be_applied
      expect(result.credential_set_changed?).to be(true)
      expect(result.revoked_credential_id).to eq(old_credential.id)
      expect(result.approval_still_valid?).to be(false)
      expect(store.credential_set(account_id)).to eq([new_credential.id])
      expect(store.approval_state(approval.id)).to eq(:applied)

      duplicate = relying_party.complete_credential_replacement(
        approval: approval,
        credential: new_credential,
        operator: operator,
        store: store
      )

      expect(duplicate).to be_duplicate
      expect(duplicate.credential_set_changed?).to be(false)
      expect(duplicate.revoked_credential_id).to be_nil
      expect(store.credential_set(account_id)).to eq([new_credential.id])
    end
  end

  describe "a retryable write failure followed by two local approvals" do
    let!(:approval_one) { begin_approval }
    let!(:first_credential) { register_device(approval: approval_one).first }
    let!(:approval_two) { begin_approval }
    let!(:second_credential) { register_device(approval: approval_two).first }

    it "keeps the old device usable after the failure and never changes the set on failed or conflicting commits" do
      store.fail_next_write!

      failed = relying_party.complete_credential_replacement(
        approval: approval_one,
        credential: first_credential,
        operator: operator,
        store: store
      )

      expect(failed).to be_failed
      expect(failed).to be_retryable
      expect(failed.approval_still_valid?).to be(true)
      expect(failed.credential_set_changed?).to be(false)
      expect(failed.revoked_credential_id).to be_nil
      expect(store.credential_set(account_id)).to eq([old_credential.id])
      expect(store.approval_state(approval_one.id)).to eq(:pending)

      verified_old, = sign_in
      expect(verified_old.id).to eq(old_credential.id)

      applied = relying_party.complete_credential_replacement(
        approval: approval_one,
        credential: first_credential,
        operator: operator,
        store: store
      )

      expect(applied).to be_applied
      expect(applied.revoked_credential_id).to eq(old_credential.id)
      expect(store.credential_set(account_id)).to eq([first_credential.id])

      late = relying_party.complete_credential_replacement(
        approval: approval_two,
        credential: second_credential,
        operator: operator,
        store: store
      )

      expect(late).to be_conflict
      expect(late.credential_set_changed?).to be(false)
      expect(late.revoked_credential_id).to be_nil
      expect(late.approval_still_valid?).to be(false)
      expect(late.winning_approval_id).to eq(approval_one.id)
      expect(late.winning_approval_still_valid?).to be(true)
      expect(store.credential_set(account_id)).to eq([first_credential.id])
      expect(store.approval_state(approval_two.id)).to eq(:superseded)

      applied_again = relying_party.complete_credential_replacement(
        approval: approval_one,
        credential: first_credential,
        operator: operator,
        store: store
      )

      expect(applied_again).to be_duplicate
      expect(applied_again.credential_set_changed?).to be(false)
      expect(store.credential_set(account_id)).to eq([first_credential.id])
    end

    it "lets the replacement device log in and rejects the revoked device" do
      store.fail_next_write!

      relying_party.complete_credential_replacement(
        approval: approval_one,
        credential: first_credential,
        operator: operator,
        store: store
      )

      relying_party.complete_credential_replacement(
        approval: approval_one,
        credential: first_credential,
        operator: operator,
        store: store
      )

      verified_new, stored_new = sign_in
      expect(verified_new.id).to eq(first_credential.id)
      expect(stored_new.id).to eq(first_credential.id)
      expect(store.credential(account_id, old_credential.id)).to be_nil
      expect(store.credential_set(account_id)).not_to include(old_credential.id)
    end

    it "serializes concurrent commits so exactly one approval takes effect" do
      results = [approval_one, approval_two].zip([first_credential, second_credential]).map do |approval, credential|
        Thread.new do
          relying_party.complete_credential_replacement(
            approval: approval,
            credential: credential,
            operator: operator,
            store: store
          )
        end
      end.map(&:value)

      expect(results.count(&:applied?)).to eq(1)
      expect(results.count(&:conflict?)).to eq(1)
      expect(store.credential_set(account_id).size).to eq(1)
      expect(store.credential_set(account_id)).not_to include(old_credential.id)
    end
  end

  describe "conflict reporting" do
    it "reports an earlier approval that is no longer effective" do
      approval = begin_approval
      credential = instance_double(
        "WebAuthn::PublicKeyCredentialWithAttestation",
        id: "new-credential",
        public_key: "public-key",
        sign_count: 0
      )
      store = instance_double(WebAuthn::CredentialReplacement::Store)

      allow(store).to receive(:commit_credential_replacement).and_return(
        status: :conflict,
        approval_state: :superseded,
        winning_approval_id: "approval-before",
        winning_approval_state: :superseded
      )

      result = relying_party.complete_credential_replacement(
        approval: approval,
        credential: credential,
        operator: operator,
        store: store
      )

      expect(result).to be_conflict
      expect(result.winning_approval_id).to eq("approval-before")
      expect(result.winning_approval_still_valid?).to be(false)
      expect(result.revoked_credential_id).to be_nil
    end

    it "rejects a store that revokes a credential on a non-applied outcome" do
      approval = begin_approval
      credential = instance_double(
        "WebAuthn::PublicKeyCredentialWithAttestation",
        id: "new-credential",
        public_key: "public-key",
        sign_count: 0
      )
      store = instance_double(WebAuthn::CredentialReplacement::Store)

      allow(store).to receive(:commit_credential_replacement).and_return(
        status: :already_applied,
        revoked_credential_id: old_credential.id
      )

      expect do
        relying_party.complete_credential_replacement(
          approval: approval,
          credential: credential,
          operator: operator,
          store: store
        )
      end.to raise_error(WebAuthn::CredentialReplacement::Store::ContractError)
    end

    it "rejects an applied outcome that does not revoke the approval's credential" do
      approval = begin_approval
      credential = instance_double(
        "WebAuthn::PublicKeyCredentialWithAttestation",
        id: "new-credential",
        public_key: "public-key",
        sign_count: 0
      )
      store = instance_double(WebAuthn::CredentialReplacement::Store)

      allow(store).to receive(:commit_credential_replacement).and_return(
        status: :applied,
        revoked_credential_id: "some-other-credential"
      )

      expect do
        relying_party.complete_credential_replacement(
          approval: approval,
          credential: credential,
          operator: operator,
          store: store
        )
      end.to raise_error(WebAuthn::CredentialReplacement::Store::ContractError)
    end
  end

  describe "the convenience handoff" do
    it "verifies the replacement registration and commits it in one call" do
      approval = begin_approval
      options = relying_party.options_for_replacement_registration(approval: approval, user: user)
      raw_credential = client.create(challenge: options.challenge, rp_id: relying_party.id)

      result = relying_party.commit_credential_replacement(
        raw_credential,
        options.challenge,
        approval: approval,
        operator: operator,
        store: store
      )

      expect(result).to be_applied
      expect(result.revoked_credential_id).to eq(old_credential.id)
      expect(store.credential_set(account_id).size).to eq(1)
    end
  end

  describe "a store returning plain hashes" do
    it "accepts a Hash outcome and ignores keys outside the contract" do
      approval = begin_approval
      credential = instance_double(
        "WebAuthn::PublicKeyCredentialWithAttestation",
        id: "new-credential",
        public_key: "public-key",
        sign_count: 0
      )
      store = instance_double(WebAuthn::CredentialReplacement::Store)

      allow(store).to receive(:commit_credential_replacement).and_return(
        "status" => "applied",
        "revoked_credential_id" => old_credential.id,
        "audit_note" => "support ticket 42"
      )

      result = relying_party.complete_credential_replacement(
        approval: approval,
        credential: credential,
        operator: operator,
        store: store
      )

      expect(result).to be_applied
      expect(result.revoked_credential_id).to eq(old_credential.id)
    end
  end

  describe "the ordinary registration entry point" do
    it "remains independent from the replacement flow" do
      begin_approval
      credential, = register_device

      expect(credential).to be_truthy
      expect(credential.id).not_to eq(old_credential.id)
      expect(store.credential_set(account_id)).to eq([old_credential.id])
    end
  end
end
