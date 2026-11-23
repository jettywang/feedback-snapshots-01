# frozen_string_literal: true

require "spec_helper"
require "webauthn/relying_party"
require "webauthn/account_binding"

RSpec.describe WebAuthn::AccountBinding::Contract do
  let(:origin) { "https://example.test" }
  let(:rp) { WebAuthn::RelyingParty.new(allowed_origins: [origin], id: "example.test", name: "Example") }
  let(:authenticator) { WebAuthn::FakeAuthenticator.new }
  let(:client) { WebAuthn::FakeClient.new(origin, authenticator: authenticator) }
  let(:store) { WebAuthn::AccountBinding::InMemoryStore.new }

  let(:alpha_handle) { WebAuthn.generate_user_handle }
  let(:beta_handle) { WebAuthn.generate_user_handle }

  let!(:alpha_credential) { create_credential(client: client, relying_party: rp) }
  let!(:beta_credential) { create_credential(client: client, relying_party: rp) }

  let(:options) { rp.options_for_authentication }

  before do
    store.add_account(id: "alpha", user_handle: alpha_handle)
    store.add_account(id: "beta", user_handle: beta_handle)

    store.add_credential(
      id: alpha_credential.first,
      account_id: "alpha",
      public_key: rp.encoder.encode(alpha_credential[1]),
      sign_count: alpha_credential[2],
      user_handle: alpha_handle,
      handle_format: :modern,
      discoverable: true
    )

    store.add_credential(
      id: beta_credential.first,
      account_id: "beta",
      public_key: rp.encoder.encode(beta_credential[1]),
      sign_count: beta_credential[2],
      user_handle: beta_handle,
      handle_format: :modern,
      discoverable: true
    )
  end

  def usernameless_assertion(credential_id:, handle:, sign_count: 1)
    client.get(
      challenge: options.challenge,
      rp_id: rp.id,
      user_handle: rp.encoder.decode(handle),
      allow_credentials: [credential_id],
      sign_count: sign_count
    )
  end

  def known_account_assertion(credential_id:, handle: nil, sign_count: 1)
    client.get(
      challenge: options.challenge,
      rp_id: rp.id,
      user_handle: handle,
      allow_credentials: [credential_id],
      sign_count: sign_count
    )
  end

  describe "usernameless entry" do
    it "creates a session principal for the account behind the verified credential" do
      raw = usernameless_assertion(credential_id: alpha_credential.first, handle: alpha_handle)

      result = described_class.new(store: store, relying_party: rp).authenticate(
        entry: :usernameless,
        raw_credential: raw,
        challenge: options.challenge
      )

      expect(result).to be_authenticated
      expect(result.principal.account_id).to eq("alpha")
      expect(result.principal.user_handle).to eq(alpha_handle)
      expect(result.account_reads).to eq(2)
      expect(result.credential_reads).to eq(2)
    end

    it "rejects an attempt whose account was merged after the verification callback returned" do
      contract = described_class.new(store: store, relying_party: rp)
      raw = usernameless_assertion(credential_id: alpha_credential.first, handle: alpha_handle)

      attempt = contract.verify(entry: :usernameless, raw_credential: raw, challenge: options.challenge)

      expect(attempt).to be_verified
      expect(attempt).not_to be_session

      store.merge_accounts!(from: "alpha", into: "beta")

      result = contract.commit(attempt)

      expect(result).to be_rejected
      expect(result.reason).to eq(:account_merged)
      expect(result.principal).to be_nil
      expect(result.account_reads).to eq(2)
      expect(result.credential_reads).to eq(2)
    end

    it "rejects an attempt whose account was disabled after the verification callback returned" do
      contract = described_class.new(store: store, relying_party: rp)
      raw = usernameless_assertion(credential_id: alpha_credential.first, handle: alpha_handle)

      attempt = contract.verify(entry: :usernameless, raw_credential: raw, challenge: options.challenge)
      store.disable_account!("alpha")

      result = contract.commit(attempt)

      expect(result.reason).to eq(:account_disabled)
      expect(result.principal).to be_nil
      expect(result.account_reads).to eq(2)
    end

    it "rejects an attempt whose credential was unbound after the verification callback returned" do
      contract = described_class.new(store: store, relying_party: rp)
      raw = usernameless_assertion(credential_id: alpha_credential.first, handle: alpha_handle)

      attempt = contract.verify(entry: :usernameless, raw_credential: raw, challenge: options.challenge)
      store.unbind_credential!(alpha_credential.first)

      result = contract.commit(attempt)

      expect(result.reason).to eq(:credential_unbound)
      expect(result.principal).to be_nil
      expect(result.account_reads).to eq(2)
      expect(result.credential_reads).to eq(2)
    end

    it "rejects an attempt whose credential was disabled after the verification callback returned" do
      contract = described_class.new(store: store, relying_party: rp)
      raw = usernameless_assertion(credential_id: alpha_credential.first, handle: alpha_handle)

      attempt = contract.verify(entry: :usernameless, raw_credential: raw, challenge: options.challenge)
      store.disable_credential!(alpha_credential.first)

      result = contract.commit(attempt)

      expect(result.reason).to eq(:credential_disabled)
      expect(result.principal).to be_nil
    end

    it "rejects an assertion without a user handle under the modern-only policy" do
      raw = client.get(
        challenge: options.challenge,
        rp_id: rp.id,
        allow_credentials: [alpha_credential.first],
        sign_count: 1
      )

      result = described_class.new(store: store, relying_party: rp).authenticate(
        entry: :usernameless,
        raw_credential: raw,
        challenge: options.challenge
      )

      expect(result.reason).to eq(:handle_missing)
      expect(result.principal).to be_nil
      expect(result.account_reads).to eq(1)
    end

    it "rejects a user handle that does not match the account bound to the credential" do
      raw = usernameless_assertion(credential_id: alpha_credential.first, handle: beta_handle)

      result = described_class.new(store: store, relying_party: rp).authenticate(
        entry: :usernameless,
        raw_credential: raw,
        challenge: options.challenge
      )

      expect(result.reason).to eq(:handle_mismatch)
      expect(result.principal).to be_nil
    end

    it "refuses the legacy fallback policy for the usernameless entry" do
      expect do
        described_class.new(
          store: store,
          relying_party: rp,
          handle_policies: { usernameless: :legacy_fallback }
        )
      end.to raise_error(ArgumentError, /legacy_fallback is only available for the known_account entry/)
    end

    it "rejects a credential whose public key changed after verification" do
      contract = described_class.new(store: store, relying_party: rp)
      raw = usernameless_assertion(credential_id: alpha_credential.first, handle: alpha_handle)

      attempt = contract.verify(entry: :usernameless, raw_credential: raw, challenge: options.challenge)
      store.find_credential(alpha_credential.first).public_key = rp.encoder.encode(beta_credential[1])

      result = contract.commit(attempt)

      expect(result.reason).to eq(:credential_changed)
      expect(result.principal).to be_nil
    end

    it "rejects a replayed assertion sign count at commit time" do
      contract = described_class.new(store: store, relying_party: rp)
      raw = usernameless_assertion(credential_id: alpha_credential.first, handle: alpha_handle, sign_count: 1)

      attempt = contract.verify(entry: :usernameless, raw_credential: raw, challenge: options.challenge)
      store.record_sign_count!(alpha_credential.first, 1)

      result = contract.commit(attempt)

      expect(result.reason).to eq(:sign_count_replayed)
      expect(result.principal).to be_nil
    end

    it "only commits a verified attempt once" do
      contract = described_class.new(store: store, relying_party: rp)
      raw = usernameless_assertion(credential_id: alpha_credential.first, handle: alpha_handle)

      attempt = contract.verify(entry: :usernameless, raw_credential: raw, challenge: options.challenge)

      expect(contract.commit(attempt)).to be_authenticated
      expect(contract.commit(attempt).reason).to eq(:attempt_consumed)
    end
  end

  describe "known-account entry" do
    let(:legacy_handle) { "legacy-handle-for-beta" }

    before do
      beta = store.find_account("beta")
      beta.user_handle = nil
      beta.legacy_user_handle = legacy_handle
      store.credentials_for("beta").each do |credential|
        credential.handle_format = :legacy
        credential.user_handle = legacy_handle
      end
    end

    it "rejects the legacy material unless the compatibility policy is explicitly enabled" do
      raw = known_account_assertion(credential_id: beta_credential.first)

      result = described_class.new(store: store, relying_party: rp).authenticate(
        entry: :known_account,
        account_id: "beta",
        raw_credential: raw,
        challenge: options.challenge
      )

      expect(result.reason).to eq(:legacy_handle_not_allowed)
      expect(result.principal).to be_nil
    end

    it "uses the legacy material when the known-account compatibility policy is enabled" do
      raw = known_account_assertion(credential_id: beta_credential.first)

      result = described_class.new(
        store: store,
        relying_party: rp,
        handle_policies: { known_account: :legacy_fallback }
      ).authenticate(
        entry: :known_account,
        account_id: "beta",
        raw_credential: raw,
        challenge: options.challenge
      )

      expect(result).to be_authenticated
      expect(result.principal.account_id).to eq("beta")
      expect(result.account_reads).to eq(2)
      expect(result.credential_reads).to eq(2)
    end

    it "accepts the legacy handle when the compatibility policy is enabled" do
      raw = known_account_assertion(credential_id: beta_credential.first, handle: legacy_handle)

      result = described_class.new(
        store: store,
        relying_party: rp,
        handle_policies: { known_account: :legacy_fallback }
      ).authenticate(
        entry: :known_account,
        account_id: "beta",
        raw_credential: raw,
        challenge: options.challenge
      )

      expect(result).to be_authenticated
      expect(result.principal.account_id).to eq("beta")
    end

    it "rejects an unrelated handle even with the compatibility policy enabled" do
      raw = known_account_assertion(credential_id: beta_credential.first, handle: alpha_handle)

      result = described_class.new(
        store: store,
        relying_party: rp,
        handle_policies: { known_account: :legacy_fallback }
      ).authenticate(
        entry: :known_account,
        account_id: "beta",
        raw_credential: raw,
        challenge: options.challenge
      )

      expect(result.reason).to eq(:handle_mismatch)
      expect(result.principal).to be_nil
    end

    it "does not let the earlier verification read decide a later account state" do
      contract = described_class.new(
        store: store,
        relying_party: rp,
        handle_policies: { known_account: :legacy_fallback }
      )
      raw = known_account_assertion(credential_id: beta_credential.first)

      attempt = contract.verify(
        entry: :known_account,
        account_id: "beta",
        raw_credential: raw,
        challenge: options.challenge
      )

      expect(attempt).to be_verified

      store.merge_accounts!(from: "beta", into: "alpha")

      result = contract.commit(attempt)

      expect(result.reason).to eq(:account_merged)
      expect(result.principal).to be_nil
      expect(result.account_reads).to eq(2)
      expect(result.credential_reads).to eq(2)
    end

    it "rejects a credential that is bound to a different account" do
      raw = known_account_assertion(credential_id: alpha_credential.first, handle: alpha_handle)

      result = described_class.new(
        store: store,
        relying_party: rp,
        handle_policies: { known_account: :legacy_fallback }
      ).authenticate(
        entry: :known_account,
        account_id: "beta",
        raw_credential: raw,
        challenge: options.challenge
      )

      expect(result.reason).to eq(:credential_rebound)
      expect(result.principal).to be_nil
    end

    it "requires the account id selected before the ceremony" do
      expect do
        described_class.new(store: store, relying_party: rp).verify(
          entry: :known_account,
          raw_credential: known_account_assertion(credential_id: beta_credential.first),
          challenge: options.challenge
        )
      end.to raise_error(ArgumentError, /known_account entry requires an account_id/)
    end
  end
end
