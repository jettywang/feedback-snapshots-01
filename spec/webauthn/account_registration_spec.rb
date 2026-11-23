# frozen_string_literal: true

require "spec_helper"
require "webauthn/fake_authenticator"
require "webauthn/fake_client"
require "webauthn/relying_party"

RSpec.describe WebAuthn::AccountRegistration do
  let(:authenticator) { WebAuthn::FakeAuthenticator.new }

  let(:relying_party) do
    WebAuthn::RelyingParty.new(
      allowed_origins: ["https://admin.example.test"],
      id: "admin.example.test",
      name: "Admin Application"
    )
  end

  let(:fake_client) do
    WebAuthn::FakeClient.new("https://admin.example.test", authenticator: authenticator)
  end

  let(:store) { InMemoryRegistrationStore.new }
  let(:registration) { relying_party.account_registration(store: store) }

  let(:alice) { TestAccount.new(id: WebAuthn.generate_user_id, name: "Alice") }
  let(:bob) { TestAccount.new(id: WebAuthn.generate_user_id, name: "Bob") }

  before do
    store.add(
      account_id: alice.id,
      encoded_id: "YWxpY2UtbGVnYWN5LWNyZWRlbnRpYWw",
      transports: ["usb"]
    )
    store.add(
      account_id: bob.id,
      encoded_id: "Ym9iLWxlZ2FjeS1jcmVkZW50aWFs",
      transports: ["nfc"]
    )
  end

  describe "#options_for_create" do
    it "sends the browser only the requesting account's exclusion entries" do
      attempt = registration.options_for_create(account_id: alice.id, user: alice.to_h)

      expect(attempt.exclude_credentials.size).to eq(1)
      expect(attempt.exclude_credentials.first[:id]).to eq("YWxpY2UtbGVnYWN5LWNyZWRlbnRpYWw")
      expect(attempt.exclude_credentials.first[:transports]).to eq(["usb"])
      expect(attempt.to_h[:excludeCredentials]).to eq(attempt.exclude_credentials)
    end

    it "normalizes the two stored identifier encodings to one exclusion entry" do
      raw_id = SecureRandom.random_bytes(16)
      store.add(account_id: alice.id, raw_id: raw_id)
      store.add(account_id: alice.id, encoded_id: WebAuthn::Encoders::Base64UrlEncoder.encode(raw_id))
      store.add(account_id: alice.id, encoded_id: WebAuthn::Encoders::Base64Encoder.encode(raw_id))

      attempt = registration.options_for_create(account_id: alice.id, user: alice.to_h)

      expect(attempt.exclude_credentials.length).to eq(2)
      expect(attempt.exclude_credentials.map { |entry| entry[:id] }).to include(
        "YWxpY2UtbGVnYWN5LWNyZWRlbnRpYWw",
        WebAuthn.standard_encoder.encode(raw_id)
      )
    end

    it "does not leak credentials that were archived before the options were sent" do
      attempt = registration.options_for_create(account_id: alice.id, user: alice.to_h)
      archived_before = attempt.exclude_credentials.map { |entry| entry[:id] }

      store.archive(account_id: alice.id, encoded_id: "YWxpY2UtbGVnYWN5LWNyZWRlbnRpYWw")

      expect(archived_before).to eq(["YWxpY2UtbGVnYWN5LWNyZWRlbnRpYWw"])
      expect(store.active_credentials(account_id: alice.id)).to be_empty
    end

    it "ignores a credential archived after the options were issued when confirming" do
      attempt = registration.options_for_create(account_id: alice.id, user: alice.to_h)
      raw_credential = fake_client.create(challenge: attempt.challenge, rp_id: relying_party.id)

      store.archive(account_id: alice.id, encoded_id: "YWxpY2UtbGVnYWN5LWNyZWRlbnRpYWw")

      receipt = registration.complete_registration(raw_credential, attempt: attempt)

      expect(receipt).to be_registered
      expect(receipt.stored_credential[:raw_id]).to eq(credential_raw_id(raw_credential))
      expect(store.active_credentials(account_id: alice.id).length).to eq(1)
    end

    it "ignores records explicitly marked inactive" do
      store.add(account_id: alice.id, encoded_id: "b2xkLWluYWN0aXZlLWNyZWRlbnRpYWw", active: false)

      attempt = registration.options_for_create(account_id: alice.id, user: alice.to_h)

      expect(attempt.exclude_credentials.map { |entry| entry[:id] }).not_to include("b2xkLWluYWN0aXZlLWNyZWRlbnRpYWw")
    end

    it "rejects caller-supplied exclusion lists so another account cannot be merged in" do
      expect do
        registration.options_for_create(account_id: alice.id, user: alice.to_h, exclude: [bob.id])
      end.to raise_error(WebAuthn::AccountRegistration::ContractError)
    end

    it "accepts the legacy direct construction path for options" do
      options = WebAuthn::PublicKeyCredential::CreationOptions.new(
        user: { id: alice.id, name: alice.name },
        exclude: "legacy-id",
        relying_party: relying_party
      )

      expect(options.as_json[:excludeCredentials]).to eq([{ type: "public-key", id: "legacy-id" }])
      expect(options.challenge).to be_truthy
    end
  end

  describe "#complete_registration" do
    it "registers both accounts independently and verifies each receipt" do
      alice_attempt = registration.options_for_create(account_id: alice.id, user: alice.to_h)
      alice_raw = fake_client.create(challenge: alice_attempt.challenge, rp_id: relying_party.id)
      alice_receipt = registration.complete_registration(alice_raw, attempt: alice_attempt)

      bob_attempt = registration.options_for_create(account_id: bob.id, user: bob.to_h)
      bob_raw = fake_client.create(challenge: bob_attempt.challenge, rp_id: relying_party.id)
      bob_receipt = registration.complete_registration(bob_raw, attempt: bob_attempt)

      expect(alice_receipt).to be_registered
      expect(bob_receipt).to be_registered
      expect(store.submissions).to eq(2)
      expect(store.active_credentials(account_id: alice.id).length).to eq(2)
      expect(store.active_credentials(account_id: bob.id).length).to eq(2)
      expect(alice_receipt.stored_credential[:account_id]).to eq(alice.id)
      expect(bob_receipt.stored_credential[:account_id]).to eq(bob.id)
    end

    it "treats a store conflict as a conflict and leaves both accounts readable" do
      attempt = registration.options_for_create(account_id: alice.id, user: alice.to_h)
      raw_credential = fake_client.create(challenge: attempt.challenge, rp_id: relying_party.id)

      store.conflict_on_next_register!

      receipt = registration.complete_registration(raw_credential, attempt: attempt)

      expect(receipt).to be_conflict
      expect(receipt).not_to be_registered
      expect(receipt.stored_credential).to be_nil
      expect(store.submissions).to eq(1)
      expect(store.active_credentials(account_id: alice.id).length).to eq(1)

      bob_attempt = registration.options_for_create(account_id: bob.id, user: bob.to_h)
      bob_raw = fake_client.create(challenge: bob_attempt.challenge, rp_id: relying_party.id)
      bob_receipt = registration.complete_registration(bob_raw, attempt: bob_attempt)

      expect(bob_receipt).to be_registered
      expect(store.submissions).to eq(2)
    end

    it "does not call the stored credential successful when the final write disappears" do
      attempt = registration.options_for_create(account_id: alice.id, user: alice.to_h)
      raw_credential = fake_client.create(challenge: attempt.challenge, rp_id: relying_party.id)

      store.discard_after_register!

      receipt = registration.complete_registration(raw_credential, attempt: attempt)

      expect(receipt).to be_unconfirmed
      expect(receipt).not_to be_registered
      expect(receipt.reason).to eq(:not_found_in_active_credentials)
      expect(store.submissions).to eq(1)
    end

    it "uses only still-active account credentials when confirming" do
      attempt = registration.options_for_create(account_id: alice.id, user: alice.to_h)
      raw_credential = fake_client.create(challenge: attempt.challenge, rp_id: relying_party.id)

      store.archive_after_register_prefix!

      receipt = registration.complete_registration(raw_credential, attempt: attempt)

      expect(receipt).to be_registered
      expect(receipt.stored_credential[:account_id]).to eq(alice.id)
    end

    it "refuses to report an already-active credential as a new registration" do
      attempt = registration.options_for_create(account_id: alice.id, user: alice.to_h)
      raw_credential = fake_client.create(challenge: attempt.challenge, rp_id: relying_party.id)
      raw_id = credential_raw_id(raw_credential)

      store.add(account_id: alice.id, raw_id: raw_id)
      store.silently_ignore_writes!

      receipt = registration.complete_registration(raw_credential, attempt: attempt)

      expect(receipt).to be_conflict
      expect(receipt.reason).to eq(:already_active)
      expect(store.submissions).to eq(0)
      expect(registration.credential_active?(account_id: alice.id, raw_id: raw_id)).to be(true)
    end

    it "supports a store that implements only the optional find_credential lookup" do
      store.define_singleton_method(:find_credential) do |account_id:, raw_id:|
        active_credentials(account_id: account_id).find { |record| record[:raw_id] == raw_id }
      end

      attempt = registration.options_for_create(account_id: alice.id, user: alice.to_h)
      raw_credential = fake_client.create(challenge: attempt.challenge, rp_id: relying_party.id)
      receipt = registration.complete_registration(raw_credential, attempt: attempt)

      expect(receipt).to be_registered
      expect(receipt.stored_credential[:account_id]).to eq(alice.id)
    end

    it "refuses an approval issued for another account" do
      alice_attempt = registration.options_for_create(account_id: alice.id, user: alice.to_h)
      raw_credential = fake_client.create(challenge: alice_attempt.challenge, rp_id: relying_party.id)

      expect do
        registration.complete_registration(raw_credential, attempt: alice_attempt, account_id: bob.id)
      end.to raise_error(WebAuthn::AccountRegistration::ApprovalMismatchError)
    end
  end

  context "with two relying parties sharing one store" do
    let(:second_relying_party) do
      WebAuthn::RelyingParty.new(
        allowed_origins: ["https://staff.example.test"],
        id: "staff.example.test",
        name: "Staff Application"
      )
    end

    let(:second_client) do
      WebAuthn::FakeClient.new("https://staff.example.test", authenticator: authenticator)
    end

    let(:second_registration) { second_relying_party.account_registration(store: store) }

    it "registers both accounts and keeps each approval bound to its relying party" do
      alice_attempt = registration.options_for_create(account_id: alice.id, user: alice.to_h)
      alice_raw = fake_client.create(challenge: alice_attempt.challenge, rp_id: relying_party.id)
      alice_receipt = registration.complete_registration(alice_raw, attempt: alice_attempt)

      bob_attempt = second_registration.options_for_create(account_id: bob.id, user: bob.to_h)
      bob_raw = second_client.create(challenge: bob_attempt.challenge, rp_id: second_relying_party.id)
      bob_receipt = second_registration.complete_registration(bob_raw, attempt: bob_attempt)

      expect(alice_receipt).to be_registered
      expect(bob_receipt).to be_registered
      expect(store.submissions).to eq(2)

      expect do
        registration.complete_registration(bob_raw, attempt: bob_attempt)
      end.to raise_error(WebAuthn::AccountRegistration::ApprovalMismatchError)
    end

    it "does not turn one service's conflict into the other's success" do
      alice_attempt = registration.options_for_create(account_id: alice.id, user: alice.to_h)
      alice_raw = fake_client.create(challenge: alice_attempt.challenge, rp_id: relying_party.id)

      bob_attempt = second_registration.options_for_create(account_id: bob.id, user: bob.to_h)
      bob_raw = second_client.create(challenge: bob_attempt.challenge, rp_id: second_relying_party.id)

      store.conflict_on_next_register!
      alice_receipt = registration.complete_registration(alice_raw, attempt: alice_attempt)
      bob_receipt = second_registration.complete_registration(bob_raw, attempt: bob_attempt)

      expect(alice_receipt).to be_conflict
      expect(bob_receipt).to be_registered
      expect(store.submissions).to eq(2)
      expect(store.active_credentials(account_id: alice.id).length).to eq(1)
      expect(store.active_credentials(account_id: bob.id).length).to eq(2)
    end
  end

  describe "store contract" do
    it "requires active_credentials and register" do
      expect do
        relying_party.account_registration(store: Object.new)
      end.to raise_error(WebAuthn::AccountRegistration::ContractError)
    end
  end

  class TestAccount
    attr_reader :id, :name

    def initialize(id:, name:)
      @id = id
      @name = name
    end

    def to_h
      { id: id, name: name }
    end
  end

  def credential_raw_id(raw_credential)
    WebAuthn::Encoders::Base64UrlEncoder.decode(raw_credential["rawId"])
  end

  class InMemoryRegistrationStore
    attr_reader :submissions, :last_registered_raw_id

    def initialize
      @records = []
      @submissions = 0
      @conflict_on_next = false
      @discard_after_register = false
      @archive_after_register_prefix = false
      @silently_ignore_writes = false
    end

    def add(account_id:, encoded_id: nil, raw_id: nil, transports: [], active: nil)
      raw_id ||= WebAuthn::Encoders::Base64UrlEncoder.decode(encoded_id)

      @records << {
        account_id: account_id,
        raw_id: raw_id,
        encoded_id: encoded_id,
        transports: transports,
        active: active
      }
    end

    def archive(account_id:, encoded_id:)
      @records.each do |record|
        if record[:account_id].to_s == account_id.to_s && record[:encoded_id] == encoded_id
          record[:archived] = true
        end
      end
    end

    def conflict_on_next_register!
      @conflict_on_next = true
    end

    def discard_after_register!
      @discard_after_register = true
    end

    def archive_after_register_prefix!
      @archive_after_register_prefix = true
    end

    def silently_ignore_writes!
      @silently_ignore_writes = true
    end

    def active_credentials(account_id:)
      @records.select do |record|
        record[:account_id].to_s == account_id.to_s && !record[:archived]
      end
    end

    def register(account_id:, credential:)
      @submissions += 1

      if @conflict_on_next
        @conflict_on_next = false
        return WebAuthn::AccountRegistration::Result.conflict
      end

      record = {
        account_id: account_id,
        raw_id: credential.raw_id,
        encoded_id: WebAuthn.standard_encoder.encode(credential.raw_id),
        public_key: credential.public_key,
        sign_count: credential.sign_count,
        transports: credential.transports
      }

      unless @discard_after_register || @silently_ignore_writes
        if @archive_after_register_prefix
          @records.each { |existing| existing[:archived] = true }
          @archive_after_register_prefix = false
        end

        @records << record
        @last_registered_raw_id = credential.raw_id
      end

      WebAuthn::AccountRegistration::Result.created(credential: record)
    end
  end
end
