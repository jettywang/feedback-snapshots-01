require "flipper"

RSpec.describe Flipper::Managed do
  let(:start) { Time.utc(2026, 3, 1, 9, 0, 0) }
  let(:clock) { { now: start } }
  let(:storage) { Flipper::Adapters::Memory.new }
  let(:flipper) { described_class.new(storage, clock: -> { clock[:now] }) }
  let(:alice) { Flipper::Actor.new("Employee;1") }
  let(:bob) { Flipper::Actor.new("Employee;2") }

  it "is a Flipper DSL over an expiration-capable adapter" do
    expect(flipper).to be_a(Flipper::DSL)
    expect(flipper.adapter.actor_expiration?).to be(true)
  end

  it "supports the pilot approval lifecycle with a fake clock" do
    flipper.enable :unrelated_feature
    flipper.enable_group :sensitive_pilot, :staff

    flipper.enable_actor :sensitive_pilot, alice, expires_in: 60
    flipper.enable_actor :sensitive_pilot, bob, expires_in: 120

    expect(flipper.enabled?(:sensitive_pilot, alice)).to be(true)
    expect(flipper.enabled?(:sensitive_pilot, bob)).to be(true)

    # Boundary: alice expires, bob is extended so he stays approved.
    clock[:now] = start + 60
    flipper.extend_actor :sensitive_pilot, bob, expires_at: start + 300

    # Expired alice is still in storage until the reap.
    expect(storage.get(flipper[:sensitive_pilot])[:actors]).to eq(
      Set["Employee;1", "Employee;2"]
    )

    expect(flipper.reap_expired_actors(:sensitive_pilot)).to eq(
      [["sensitive_pilot", "Employee;1"]]
    )
    expect(storage.get(flipper[:sensitive_pilot])[:actors]).to eq(Set["Employee;2"])
    expect(flipper.actor_expirations(:sensitive_pilot)).to eq(
      "Employee;2" => start + 300
    )
    expect(flipper.enabled?(:sensitive_pilot, bob)).to be(true)
    expect(flipper.enabled?(:sensitive_pilot, alice)).to be(false)

    # A new approval is not in the reaper's expired set and survives.
    carol = Flipper::Actor.new("Employee;3")
    flipper.enable_actor :sensitive_pilot, carol, expires_in: 600
    expect(flipper.reap_expired_actors(:sensitive_pilot)).to eq([])
    expect(flipper.enabled?(:sensitive_pilot, carol)).to be(true)

    # Non-actor gates remain as configured.
    expect(flipper.enabled?(:unrelated_feature)).to be(true)
    expect(flipper[:sensitive_pilot].enabled_gate_names).to include(:group)
  end

  it "rejects expiring grants when no adapter can enforce expiration" do
    plain_storage = Flipper::Adapters::Memory.new
    plain_storage.define_singleton_method(:actor_expiration?) { false }
    plain = Flipper.new(plain_storage)

    expect {
      plain.enable_actor :sensitive_pilot, alice, expires_in: 60
    }.to raise_error(Flipper::ActorExpirationNotSupported)
  end

  it "can be built through Flipper.managed" do
    expect(Flipper.managed(storage)).to be_a(described_class)
  end
end
