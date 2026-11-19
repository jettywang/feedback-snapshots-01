require "flipper/adapters/memory"

RSpec.describe Flipper::Adapters::Memory, "actor expiration" do
  let(:start) { Time.utc(2026, 3, 1, 9, 0, 0) }
  let(:clock) { { now: start } }
  subject(:adapter) { described_class.new(clock: -> { clock[:now] }) }
  let(:flipper) { Flipper.new(adapter) }
  let(:actor) { Flipper::Actor.new("Employee;1") }
  let(:feature) { flipper[:pilot] }

  it "returns tamper-resistant copies of expiration metadata" do
    flipper.enable_actor :pilot, actor, expires_in: 60
    copy = adapter.actor_expirations(feature)
    copy["Employee;1"] = start + 999

    expect(adapter.actor_expirations(feature)).to eq("Employee;1" => start + 60)
  end

  it "drops expiration metadata when the boolean gate is enabled" do
    flipper.enable_actor :pilot, actor, expires_in: 60
    flipper.enable :pilot

    expect(adapter.actor_expirations(feature)).to eq({})
  end

  it "drops expiration metadata when the feature is removed or cleared" do
    flipper.enable_actor :pilot, actor, expires_in: 60
    feature.clear
    expect(adapter.actor_expirations(feature)).to eq({})

    flipper.enable_actor :pilot, actor, expires_in: 60
    flipper.remove(:pilot)
    expect(adapter.actor_expirations(feature)).to eq({})
  end

  it "keeps expirations in export and import" do
    flipper.enable_actor :pilot, actor, expires_in: 60
    export = adapter.export

    imported = described_class.new
    imported.import(export)
    imported_feature = Flipper::Feature.new("pilot", imported)

    expect(imported.actor_expirations(imported_feature)).to eq(
      "Employee;1" => start + 60
    )
  end

  it "keeps expirations when rebuilt from a get_all snapshot" do
    flipper.enable_actor :pilot, actor, expires_in: 60
    copy = described_class.new(adapter.get_all)
    copied_feature = Flipper::Feature.new("pilot", copy)

    expect(copy.actor_expirations(copied_feature)).to eq("Employee;1" => start + 60)
    expect(copy.get(copied_feature)).to eq(adapter.default_config.merge(actors: Set["Employee;1"]))
  end
end
