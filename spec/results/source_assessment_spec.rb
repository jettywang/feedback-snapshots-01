require 'spec_helper'
require 'bundler/audit/results/source_assessment'

describe Bundler::Audit::Results::SourceAssessment do
  let(:source) { 'http://gems.internal.example/' }

  subject do
    described_class.new(source,:undetermined,
      reason: 'source host could not be resolved',
      evidence: {scheme: 'http',host: 'gems.internal.example',addresses: []})
  end

  describe "#initialize" do
    it "sets the source" do
      expect(subject.source).to eq(source)
    end

    it "sets the disposition" do
      expect(subject.disposition).to eq(:undetermined)
    end

    it "sets the reason" do
      expect(subject.reason).to eq('source host could not be resolved')
    end

    it "sets the evidence" do
      expect(subject.evidence[:host]).to eq('gems.internal.example')
    end

    it "rejects unknown dispositions" do
      expect {
        described_class.new(source,:maybe,reason: 'x')
      }.to raise_error(ArgumentError,/disposition/)
    end
  end

  describe "disposition predicates" do
    it { expect(subject).to be_undetermined }
    it { expect(subject).to_not be_blocked }
    it { expect(subject).to_not be_allowed }
    it { expect(subject).to_not be_permits_release }

    context "when allowed" do
      subject { described_class.new(source,:allowed,reason: 'external source') }

      it { expect(subject).to be_allowed }
      it { expect(subject).to be_permits_release }
      it { expect(subject).to_not be_blocks_release }
    end

    context "when blocked" do
      subject { described_class.new(source,:blocked,reason: 'insecure http source') }

      it { expect(subject).to be_blocked }
      it { expect(subject).to be_blocks_release }
      it { expect(subject).to_not be_permits_release }
    end
  end

  describe "#==" do
    it "compares source and disposition" do
      expect(subject).to eq(described_class.new(source,:undetermined,reason: 'x'))
      expect(subject).to_not eq(described_class.new(source,:blocked,reason: 'x'))
    end
  end

  describe "#to_h" do
    it "keeps the disposition, reason and evidence" do
      expect(subject.to_h).to include(
        type:        :source_assessment,
        source:      source,
        disposition: :undetermined,
        reason:      'source host could not be resolved'
      )
      expect(subject.to_h[:evidence]).to include(host: 'gems.internal.example')
    end
  end
end
