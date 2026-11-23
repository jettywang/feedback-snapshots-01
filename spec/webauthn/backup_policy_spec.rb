# frozen_string_literal: true

require "spec_helper"
require "webauthn/backup_policy"

RSpec.describe WebAuthn::BackupPolicy do
  subject(:policy) { described_class.new }

  def attributes(eligible:, state:, source:)
    WebAuthn::BackupAttributes.new(eligible: eligible, state: state, source: source)
  end

  describe "#registration" do
    it "preserves device-bound eligibility for sensitive actions" do
      decision = policy.registration(
        attributes(eligible: false, state: false, source: :registration),
        requested_actions: [:login, :financial]
      )

      expect(decision.approved_actions).to eq([:login, :financial])
      expect(decision.basis).to eq(:device_bound_registration)
    end

    it "limits synced eligibility to daily actions" do
      decision = policy.registration(
        attributes(eligible: true, state: true, source: :registration),
        requested_actions: [:login, :financial]
      )

      expect(decision.approved_actions).to eq([:login])
      expect(decision.basis).to eq(:synced_registration)
    end

    it "limits unknown legacy eligibility to daily actions" do
      decision = policy.registration(
        attributes(eligible: nil, state: nil, source: :legacy),
        requested_actions: [:login, :financial]
      )

      expect(decision.approved_actions).to eq([:login])
      expect(decision.basis).to eq(:legacy_registration)
    end
  end

  describe "#authentication" do
    it "keeps a legacy row on the daily policy after observing backup state" do
      decision = policy.authentication(
        stored: attributes(eligible: nil, state: nil, source: :legacy),
        observed: attributes(eligible: true, state: true, source: :authentication),
        requested_actions: [:login, :financial]
      )

      expect(decision.approved_actions).to eq([:login])
      expect(decision.basis).to eq(:legacy_daily_policy)
    end

    it "refuses to update state when eligibility changes" do
      decision = policy.authentication(
        stored: attributes(eligible: false, state: false, source: :registration),
        observed: attributes(eligible: true, state: true, source: :authentication),
        requested_actions: [:login, :financial]
      )

      expect(decision.approved_actions).to eq([])
      expect(decision.basis).to eq(:eligibility_mismatch)
      expect(decision).not_to be_writable
    end

    it "updates only state for synced credentials" do
      stored = attributes(eligible: true, state: false, source: :registration)
      observed = attributes(eligible: true, state: true, source: :authentication)

      updated = policy.next_attributes(stored: stored, observed: observed)

      expect(updated.eligible).to be(true)
      expect(updated.state).to be(true)
      expect(updated.source).to eq(:registration)
    end
  end
end
