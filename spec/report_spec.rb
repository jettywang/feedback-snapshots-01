require 'spec_helper'
require 'bundler/audit/report'

describe Bundler::Audit::Report do
  let(:uri) { URI('git://github.com/foo/bar.git') }
  let(:insecure_source) do
    Bundler::Audit::Results::InsecureSource.new(uri)
  end

  let(:gem) do
    Gem::Specification.new do |spec|
      spec.name = 'test'
      spec.version = '0.0.0'
    end
  end
  let(:advisory) { double('Bundler::Audit::Advisory', id: 'CVE-3000-1234') }
  let(:unpatched_gem) do
    Bundler::Audit::Results::UnpatchedGem.new(gem,advisory)
  end

  let(:results) do
    [insecure_source, unpatched_gem]
  end

  subject { described_class.new(results) }

  describe "#version" do
    it "should be the VERSION constant" do
      expect(subject.version).to be(Bundler::Audit::VERSION)
    end
  end

  describe "#time" do
    it { expect(subject.created_at).to be_kind_of(Time) }
  end

  describe "#<<" do
    subject { described_class.new }

    it "should return self" do
      expect(subject << insecure_source).to be(subject)
    end

    context "when given a Result::InsecureSource" do
      let(:result) { insecure_source }

      before { subject << result }

      it "should add the result to the report" do
        expect(subject.results.last).to be(result)
      end

      it "should also add the result to #insecure_sources" do
        expect(subject.insecure_sources.last).to be(result)
      end
    end

    context "when given a Result::UnpatchedGem" do
      let(:result) { unpatched_gem }

      before { subject << result }

      it "should add the result to the report" do
        expect(subject.results.last).to be(result)
      end

      it "should also add the result to #unpatched_gems" do
        expect(subject.unpatched_gems.last).to be(result)
      end
    end
  end

  describe "#each" do
    context "when given a block" do
      it "should enumerate over each result in the report" do
        expect { |b| subject.each(&b) }.to yield_successive_args(*results)
      end
    end

    context "when no block is given" do
      it "should return an Enumerator" do
        expect(subject.each).to be_kind_of(Enumerator)
      end
    end
  end

  describe "#vulnerable?" do
    context "when the report is empty" do
      subject { described_class.new }

      it { expect(subject.vulnerable?).to be false }
    end

    context "when then report contains results" do
      it { expect(subject.vulnerable?).to be true }
    end

    context "when the only results were approved" do
      let(:exemption) do
        Bundler::Audit::Exemption.new(
          advisory: 'CVE-3000-1234',
          reason:   'vendor patch',
          expires_on: '2026-12-31'
        )
      end
      let(:exempted_gem) do
        Bundler::Audit::Results::ExemptedGem.new(gem,advisory,exemption)
      end

      subject { described_class.new([exempted_gem]) }

      it { expect(subject.vulnerable?).to be false }
      it { expect(subject.passes?).to be true }
      it { expect(subject.approved_results).to eq([exempted_gem]) }
    end
  end

  describe "#passes?" do
    context "when the report is empty" do
      subject { described_class.new }

      it { expect(subject.passes?).to be true }
    end

    context "when the report contains a blocked source" do
      subject { described_class.new([insecure_source]) }

      it { expect(subject.passes?).to be false }
      it { expect(subject.blocked_sources).to eq([insecure_source]) }
    end

    context "when the report contains an undetermined source" do
      let(:assessment) do
        Bundler::Audit::Results::SourceAssessment.new(uri,:undetermined,
          reason: 'source host could not be resolved')
      end

      subject { described_class.new([assessment]) }

      it { expect(subject.passes?).to be false }
      it { expect(subject.undetermined_sources).to eq([assessment]) }
      it { expect(subject.blocked_sources).to be_empty }
    end

    context "when mixed with an approved version result" do
      let(:assessment) do
        Bundler::Audit::Results::SourceAssessment.new(uri,:undetermined,
          reason: 'source host could not be resolved')
      end

      subject { described_class.new([insecure_source,assessment,unpatched_gem]) }

      it "still blocks on the unapproved results" do
        expect(subject.passes?).to be false
        expect(subject.blocking_results).to eq([insecure_source,assessment,unpatched_gem])
      end
    end
  end

  describe "#to_h" do
    subject { described_class.new([insecure_source]) }

    it "includes the pass decision" do
      expect(subject.to_h[:passed]).to be(false)
    end
  end
end
