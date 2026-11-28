require 'spec_helper'
require 'bundler/audit/results/insecure_source'

describe Bundler::Audit::Results::InsecureSource do
  let(:source) { 'git://example.com/foo/bar.git' }

  subject { described_class.new(source) }

  describe "#initialize" do
    it "must set the source attribute" do
      expect(subject.source).to be(source)
    end
  end

  describe "#==" do
    context "when the other class is different" do
      let(:other) { Object.new }

      it "must return false" do
        expect(subject).to_not be == other
      end
    end

    context "when the source is different" do
      let(:other_source) { "https://example.com/other/repo.git" }
      let(:other) { described_class.new(other_source) }

      it "must return false" do
        expect(subject).to_not be == other
      end
    end

    context "when the source is the same" do
      let(:other) { described_class.new(source) }

      it "must return true" do
        expect(subject).to be == other
      end
    end
  end

  describe "#to_s" do
    it "should return the source attribute" do
      expect(subject.to_s).to be == source
    end
  end

  describe "#disposition" do
    it "is blocked" do
      expect(subject.disposition).to eq(:blocked)
      expect(subject).to be_blocked
      expect(subject).to_not be_undetermined
      expect(subject).to_not be_allowed
    end

    it "blocks the release" do
      expect(subject).to be_blocks_release
      expect(subject).to_not be_permits_release
      expect(subject).to_not be_approved
    end
  end

  describe "#to_h" do
    it "includes the reason and the disposition" do
      expect(subject.to_h).to include(
        type:        :insecure_source,
        source:      source,
        disposition: :blocked
      )
      expect(subject.to_h[:reason]).to eq('insecure source')
    end

    context "when given a reason and evidence" do
      subject do
        described_class.new(source,
          reason: 'insecure http source',
          evidence: {scheme: 'git',internal: false})
      end

      it "keeps them in the output" do
        expect(subject.disposition).to eq(:blocked)
        expect(subject.reason).to eq('insecure http source')
        expect(subject.to_h[:evidence]).to eq(scheme: 'git',internal: false)
      end
    end
  end
end
