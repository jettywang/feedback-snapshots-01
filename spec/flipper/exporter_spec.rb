RSpec.describe Flipper::Exporter do
  describe ".build" do
    it "builds instance of exporter" do
      exporter = described_class.build(format: :json, version: 1)
      expect(exporter).to be_instance_of(Flipper::Exporters::Json::V1)
    end

    it "raises if format not found" do
      expect { described_class.build(format: :nope, version: 1) }.to raise_error(KeyError)
    end

    it "raises if version not found" do
      expect { described_class.build(format: :json, version: 0) }.to raise_error(KeyError)
    end
  end
end

RSpec.describe Flipper::Exporter, ".build with redacted" do
  it "builds the redacted exporter" do
    exporter = described_class.build(format: :json, redacted: true)
    expect(exporter).to be_instance_of(Flipper::Exporters::Json::Redacted)
  end

  it "raises for non-json formats" do
    expect {
      described_class.build(format: :yaml, redacted: true)
    }.to raise_error(ArgumentError)
  end
end
