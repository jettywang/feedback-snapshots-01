require "flipper/adapters/actor_expiration"

RSpec.describe Flipper::Adapters::ActorExpiration do
  let(:start) { Time.utc(2026, 3, 1, 9, 0, 0) }
  let(:clock) { { now: start } }
  let(:storage) { Flipper::Adapters::Memory.new }
  let(:adapter) { described_class.new(storage, clock: -> { clock[:now] }) }
  let(:flipper) { Flipper.new(adapter) }
  let(:alice) { Flipper::Actor.new("Employee;1") }
  let(:bob) { Flipper::Actor.new("Employee;2") }

  it_should_behave_like 'a flipper adapter' do
    subject { described_class.new(Flipper::Adapters::Memory.new) }
  end

  it "gives two employees independent expiration times" do
    flipper.enable_actor :pilot, alice, expires_in: 60
    flipper.enable_actor :pilot, bob, expires_at: start + 120

    expect(flipper.actor_expirations(:pilot)).to eq(
      "Employee;1" => start + 60,
      "Employee;2" => start + 120,
    )

    expect(flipper.enabled?(:pilot, alice)).to be(true)
    expect(flipper.enabled?(:pilot, bob)).to be(true)
  end

  it "stops opening the actor gate when a grant expires but keeps the stored grant until reaped" do
    flipper.enable_actor :pilot, alice, expires_in: 60
    clock[:now] = start + 60

    expect(flipper.enabled?(:pilot, alice)).to be(false)
    expect(flipper.actor_enabled?(:pilot, alice)).to be(false)
    expect(storage.get(flipper[:pilot])[:actors]).to eq(Set["Employee;1"])
    expect(adapter.actor_expirations(flipper[:pilot])).to include("Employee;1")
  end

  it "extends only the approval at the boundary and does not reap it" do
    flipper.enable_actor :pilot, alice, expires_in: 60
    flipper.enable_actor :pilot, bob, expires_in: 120
    clock[:now] = start + 60

    flipper.extend_actor :pilot, bob, expires_at: start + 180
    expect(flipper.actor_expires_at(:pilot, bob)).to eq(start + 180)

    removed = flipper.reap_expired_actors(:pilot)
    expect(removed).to eq([["pilot", "Employee;1"]])
    expect(flipper.enabled?(:pilot, bob)).to be(true)
    expect(flipper.actor_expirations(:pilot)).to eq("Employee;2" => start + 180)
    expect(storage.get(flipper[:pilot])[:actors]).to eq(Set["Employee;2"])
  end

  it "does not remove a grant extended after the reaper's snapshot" do
    flipper.enable_actor :pilot, bob, expires_in: 60
    clock[:now] = start + 60
    flipper.extend_actor :pilot, bob, expires_in: 600

    expect(flipper.reap_expired_actors(:pilot)).to eq([])
    expect(flipper.enabled?(:pilot, bob)).to be(true)
  end

  it "reaps every feature when no feature is named" do
    flipper.enable_actor :pilot, alice, expires_in: 60
    flipper.enable_actor :other, bob, expires_in: 60
    clock[:now] = start + 60
    flipper.extend_actor :other, bob, expires_in: 600

    expect(flipper.reap_expired_actors).to eq([["pilot", "Employee;1"]])
    expect(flipper.enabled?(:other, bob)).to be(true)
  end

  it "leaves global and group gates alone" do
    flipper.enable :global
    flipper.enable_group :pilot, :staff
    flipper.enable_actor :pilot, alice, expires_in: 60
    clock[:now] = start + 60
    flipper.reap_expired_actors(:pilot)

    expect(flipper.enabled?(:global)).to be(true)
    expect(flipper[:pilot].enabled_gate_names).to include(:group)
    expect(flipper.actor_expirations(:pilot)).to eq({})
  end

  it "clears expiration metadata when the actor is explicitly disabled" do
    flipper.enable_actor :pilot, alice, expires_in: 60
    flipper.disable_actor :pilot, alice

    expect(flipper.actor_expirations(:pilot)).to eq({})
    expect(storage.get(flipper[:pilot])[:actors]).to eq(Set[])
  end

  it "delegates to storage for normal gate values" do
    flipper.enable_percentage_of_actors :pilot, 25
    flipper.enable_percentage_of_time :pilot, 10

    expect(storage.get(flipper[:pilot])[:percentage_of_actors]).to eq("25")
    expect(storage.get(flipper[:pilot])[:percentage_of_time]).to eq("10")
  end

  it "keeps expirations in export and import" do
    flipper.enable_actor :pilot, alice, expires_in: 60
    export = adapter.export

    imported = described_class.new(Flipper::Adapters::Memory.new)
    imported.import(export)
    imported_feature = Flipper::Feature.new("pilot", imported)

    expect(imported.actor_expirations(imported_feature)).to eq(
      "Employee;1" => start + 60
    )
  end
end
