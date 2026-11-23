# frozen_string_literal: true

require "spec_helper"
require "webauthn/relying_party"
require "webauthn/account_binding"

RSpec.describe "Account binding reported scenarios" do
  ORIGIN = "https://example.test"

  World = Struct.new(
    :rp, :client, :store, :alpha, :beta, :alpha_handle, :beta_handle, :legacy_handle,
    keyword_init: true
  )

  def raw(handle)
    WebAuthn::Encoders::Base64UrlEncoder.decode(handle)
  end

  def build_world
    rp = WebAuthn::RelyingParty.new(allowed_origins: [ORIGIN], id: "example.test", name: "Example")
    client = WebAuthn::FakeClient.new(ORIGIN, authenticator: WebAuthn::FakeAuthenticator.new)
    store = WebAuthn::AccountBinding::InMemoryStore.new
    alpha_handle = WebAuthn.generate_user_handle
    beta_handle = WebAuthn.generate_user_handle
    legacy_handle = "legacy-user-handle"

    alpha_credential = create_credential(client: client, relying_party: rp)
    beta_credential = create_credential(client: client, relying_party: rp)

    store.add_account(id: "alpha", user_handle: alpha_handle)
    store.add_account(id: "beta", user_handle: nil, legacy_user_handle: legacy_handle)

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
      user_handle: legacy_handle,
      handle_format: :legacy,
      discoverable: true
    )

    World.new(
      rp: rp,
      client: client,
      store: store,
      alpha: alpha_credential.first,
      beta: beta_credential.first,
      alpha_handle: alpha_handle,
      beta_handle: beta_handle,
      legacy_handle: legacy_handle
    )
  end

  def assertion_for(world, entry:, handle: nil, sign_count: 1)
    options = world.rp.options_for_authentication

    raw_credential =
      world.client.get(
        challenge: options.challenge,
        rp_id: world.rp.id,
        user_handle: handle,
        allow_credentials: [entry == :usernameless ? world.alpha : world.beta],
        sign_count: sign_count
      )

    [raw_credential, options.challenge]
  end

  def mutation_for(world, mutation)
    case mutation
    when :merge_alpha_into_beta
      -> { world.store.merge_accounts!(from: "alpha", into: "beta") }
    when :unbind_alpha_credential
      -> { world.store.unbind_credential!(world.alpha) }
    when :disable_alpha_account
      -> { world.store.disable_account!("alpha") }
    when :disable_beta_account
      -> { world.store.disable_account!("beta") }
    end
  end

  def run_scenario(entry:, mutation: nil, handle_policy: :modern_only, assertion_handle: :alpha)
    world = build_world
    contract = WebAuthn::AccountBinding::Contract.new(
      store: world.store,
      relying_party: world.rp,
      handle_policies: { known_account: handle_policy }
    )

    presented_handle =
      case assertion_handle
      when :alpha then raw(world.alpha_handle)
      when :beta then raw(world.beta_handle)
      end

    raw_credential, challenge = assertion_for(world, entry: entry, handle: presented_handle)

    attempt = contract.verify(
      entry: entry,
      raw_credential: raw_credential,
      challenge: challenge,
      account_id: entry == :known_account ? "beta" : nil
    )

    verify_state = attempt.verified? ? :verified : attempt.rejection

    mutation_for(world, mutation)&.call

    result = contract.commit(attempt)
    commit_state = result.session_created? ? :authenticated : result.reason

    {
      entry: entry,
      mutation: mutation || :none,
      verify: verify_state,
      commit: commit_state,
      principal: result.principal&.account_id,
      verify_account_reads: attempt.account_reads,
      commit_account_reads: result.account_reads - attempt.account_reads,
      total_account_reads: result.account_reads,
      total_credential_reads: result.credential_reads
    }
  end

  it "reports both entries, final session principals and account reads" do
    report = [
      run_scenario(entry: :usernameless),
      run_scenario(entry: :usernameless, mutation: :merge_alpha_into_beta),
      run_scenario(entry: :usernameless, mutation: :unbind_alpha_credential),
      run_scenario(entry: :usernameless, mutation: :disable_alpha_account),
      run_scenario(entry: :known_account, assertion_handle: nil, handle_policy: :legacy_fallback),
      run_scenario(entry: :known_account, mutation: :disable_beta_account, assertion_handle: nil,
                   handle_policy: :legacy_fallback),
      run_scenario(entry: :known_account, assertion_handle: nil, handle_policy: :modern_only)
    ]

    expected = [
      {
        entry: :usernameless,
        mutation: :none,
        verify: :verified,
        commit: :authenticated,
        principal: "alpha",
        verify_account_reads: 1,
        commit_account_reads: 1,
        total_account_reads: 2,
        total_credential_reads: 2
      },
      {
        entry: :usernameless,
        mutation: :merge_alpha_into_beta,
        verify: :verified,
        commit: :account_merged,
        principal: nil,
        verify_account_reads: 1,
        commit_account_reads: 1,
        total_account_reads: 2,
        total_credential_reads: 2
      },
      {
        entry: :usernameless,
        mutation: :unbind_alpha_credential,
        verify: :verified,
        commit: :credential_unbound,
        principal: nil,
        verify_account_reads: 1,
        commit_account_reads: 1,
        total_account_reads: 2,
        total_credential_reads: 2
      },
      {
        entry: :usernameless,
        mutation: :disable_alpha_account,
        verify: :verified,
        commit: :account_disabled,
        principal: nil,
        verify_account_reads: 1,
        commit_account_reads: 1,
        total_account_reads: 2,
        total_credential_reads: 2
      },
      {
        entry: :known_account,
        mutation: :none,
        verify: :verified,
        commit: :authenticated,
        principal: "beta",
        verify_account_reads: 1,
        commit_account_reads: 1,
        total_account_reads: 2,
        total_credential_reads: 2
      },
      {
        entry: :known_account,
        mutation: :disable_beta_account,
        verify: :verified,
        commit: :account_disabled,
        principal: nil,
        verify_account_reads: 1,
        commit_account_reads: 1,
        total_account_reads: 2,
        total_credential_reads: 2
      },
      {
        entry: :known_account,
        mutation: :none,
        verify: :legacy_handle_not_allowed,
        commit: :legacy_handle_not_allowed,
        principal: nil,
        verify_account_reads: 1,
        commit_account_reads: 0,
        total_account_reads: 1,
        total_credential_reads: 1
      }
    ]

    expect(report).to eq(expected)
  end
end
