require 'flipper/exporters/json/redacted'

RSpec.describe Flipper::Exporters::Json::Redacted do
  let(:adapter) { Flipper::Adapters::Memory.new }
  let(:flipper) { Flipper.new(adapter) }

  before do
    flipper.enable_actor :beta, Flipper::Actor.new('User;42')
    flipper.enable_actor :beta, Flipper::Actor.new('User;43')
    flipper.enable_group :beta, :pilot_members
    flipper.enable :plain_switch
    flipper.disable :retired_switch
    flipper.enable_percentage_of_actors :rollout, 25
    flipper.enable_expression :internal_only, Flipper.property('internal_plan').eq('enterprise')
  end

  subject(:export) { described_class.new.call(adapter) }

  let(:data) { JSON.parse(export.contents) }

  it "includes the view-only license marker" do
    expect(data["license"]).to eq("view-only")
  end

  it "keeps gate types with anonymous counts" do
    expect(data["features"]["beta"]).to eq({
      "boolean" => nil,
      "actors" => 2,
      "groups" => 1,
      "percentage_of_actors" => nil,
      "percentage_of_time" => nil,
      "expression" => nil,
    })
    expect(data["features"]["plain_switch"]["boolean"]).to eq("true")
    expect(data["features"]["retired_switch"]["boolean"]).to be_nil
    expect(data["features"]["rollout"]["percentage_of_actors"]).to eq("25")
  end

  it "redacts expressions" do
    expect(data["features"]["internal_only"]["expression"]).to eq("[REDACTED]")
  end

  it "omits actor identifiers, group names, and expression values" do
    expect(export.contents).not_to include("User;42")
    expect(export.contents).not_to include("User;43")
    expect(export.contents).not_to include("pilot_members")
    expect(export.contents).not_to include("internal_plan")
    expect(export.contents).not_to include("enterprise")
  end

  it "cannot be imported through the normal import path" do
    expect { export.features }.to raise_error(Flipper::Exporters::Json::InvalidError)
    expect { export.adapter }.to raise_error(Flipper::Exporters::Json::InvalidError)

    destination = Flipper.new(Flipper::Adapters::Memory.new)
    destination.enable :production_gate
    expect { destination.import(export) }.to raise_error(Flipper::Exporters::Json::InvalidError)
    expect(destination.enabled?(:production_gate)).to be(true)
  end

  it "validates the license marker" do
    exporter = described_class.new
    payload = { "version" => 1, "features" => {} }
    expect {
      exporter.send(:validate!, payload, {})
    }.to raise_error(Flipper::Exporters::Json::Redacted::InvalidRedactionError, /license/)
  end

  it "validates that sensitive values are absent" do
    exporter = described_class.new
    all = { "beta" => { actors: Set["User;42"], groups: Set.new, expression: nil } }
    payload = {
      "license" => "view-only",
      "features" => { "beta" => { "actors" => ["User;42"] } },
    }
    expect {
      exporter.send(:validate!, payload, all)
    }.to raise_error(Flipper::Exporters::Json::Redacted::InvalidRedactionError, /sensitive/)
  end

  it "leaves the full backup export untouched" do
    full = flipper.export
    expect(full.contents).to include("User;42")
    expect(full.contents).to include("pilot_members")

    destination = Flipper.new(Flipper::Adapters::Memory.new)
    destination.import(full)
    expect(destination.enabled?(:beta, Flipper::Actor.new('User;42'))).to be(true)
  end
end
