require 'spec_helper'
require 'bundler/audit/exemption'

describe Bundler::Audit::Exemption do
  let(:attributes) do
    {
      advisory:    'CVE-2026-0001',
      gem:         'testgem',
      reason:      'vendor patch shipped in the application image',
      expires_on:  '2026-12-31',
      approved_by: 'security-team'
    }
  end

  subject { described_class.new(**attributes) }

  describe "#initialize" do
    it { expect(subject.advisory).to eq('CVE-2026-0001') }
    it { expect(subject.gem).to eq('testgem') }
    it { expect(subject.reason).to eq('vendor patch shipped in the application image') }
    it { expect(subject.expires_on).to eq(Date.new(2026,12,31)) }
    it { expect(subject.approved_by).to eq('security-team') }

    it "requires a reason" do
      expect {
        described_class.new(advisory: 'CVE-2026-0001',reason: '')
      }.to raise_error(ArgumentError,/reason/)
    end

    it "requires an advisory" do
      expect {
        described_class.new(advisory: nil,reason: 'vendor patch')
      }.to raise_error(ArgumentError,/advisory/)
    end

    it "rejects invalid expiry dates" do
      expect {
        described_class.new(advisory: 'CVE-2026-0001',reason: 'x',expires_on: 'not-a-date')
      }.to raise_error(ArgumentError,/expires_on/)
    end
  end

  describe "#active?" do
    it "is active on the expiry date" do
      expect(subject.active?(on: Date.new(2026,12,31))).to be(true)
    end

    it "is active before the expiry date" do
      expect(subject.active?(on: Date.new(2026,12,30))).to be(true)
    end

    it "is expired after the expiry date" do
      expect(subject.expired?(on: Date.new(2027,1,1))).to be(true)
    end

    context "when no expiry is set" do
      subject { described_class.new(advisory: 'CVE-2026-0001',reason: 'permanent') }

      it "never expires" do
        expect(subject.active?(on: Date.new(2099,1,1))).to be(true)
      end
    end
  end

  describe "#applies_to?" do
    let(:advisory) do
      Bundler::Audit::Advisory.new(
        'path','CVE-2026-0001',nil,'title',nil,nil,nil,nil,nil,
        '2026-0001',nil,'aaaa-bbbb-0001',[],[]
      )
    end
    let(:gem) { Gem::Specification.new { |spec| spec.name = 'testgem' } }

    it "matches the advisory identifier" do
      expect(subject.applies_to?(advisory,gem)).to be(true)
    end

    it "matches any of the advisory identifiers" do
      expect(subject.applies_to?(advisory,Gem::Specification.new { |s| s.name = 'other' })).to be(false)
    end

    context "when the exemption names a different gem" do
      subject { described_class.new(**attributes.merge(gem: 'other')) }

      it "does not apply" do
        expect(subject.applies_to?(advisory,gem)).to be(false)
      end
    end

    context "when the advisory does not match" do
      it "does not apply" do
        expect(subject.applies_to?(double(id: 'CVE-2026-9999',identifiers: []),gem)).to be(false)
      end
    end
  end

  describe ".from_h" do
    it "accepts string keys" do
      exemption = described_class.from_h(attributes.transform_keys(&:to_s))

      expect(exemption.advisory).to eq('CVE-2026-0001')
      expect(exemption.expires_on).to eq(Date.new(2026,12,31))
    end
  end

  describe "#to_h" do
    it "keeps the approval reason and expiry" do
      expect(subject.to_h).to eq(
        advisory:    'CVE-2026-0001',
        gem:         'testgem',
        reason:      'vendor patch shipped in the application image',
        expires_on:  '2026-12-31',
        approved_by: 'security-team'
      )
    end
  end
end
