require 'spec_helper'
require 'bundler/audit/approval'

describe Bundler::Audit::Approval do
  describe ".load" do
    context "when given a String" do
      it "must create an unbound approval for the advisory identifier" do
        approval = described_class.load('CVE-2026-1111')

        expect(approval.advisory).to eq('CVE-2026-1111')
        expect(approval.gem).to be_nil
        expect(approval.expires).to be_nil
      end
    end

    context "when given a Hash with String keys" do
      it "must create a bound approval" do
        approval = described_class.load(
          'advisory' => 'GHSA-aaaa-bbbb-cccc',
          'gem'      => 'beta',
          'expires'  => '2027-01-01'
        )

        expect(approval.advisory).to eq('GHSA-aaaa-bbbb-cccc')
        expect(approval.gem).to eq('beta')
        expect(approval.expires).to eq(Date.new(2027,1,1))
      end
    end

    context "when given a Hash with Symbol keys" do
      it "must create a bound approval" do
        approval = described_class.load(
          advisory: 'CVE-2026-1111',
          gem:      'alpha'
        )

        expect(approval.advisory).to eq('CVE-2026-1111')
        expect(approval.gem).to eq('alpha')
      end
    end

    context "when given a Hash without an advisory" do
      it "must raise an ArgumentError" do
        expect {
          described_class.load({'gem' => 'alpha'})
        }.to raise_error(ArgumentError)
      end
    end

    context "when given another object" do
      it "must raise an ArgumentError" do
        expect {
          described_class.load(42)
        }.to raise_error(ArgumentError)
      end
    end
  end

  describe "#bound?" do
    it "must be false when no gem was given" do
      expect(described_class.new('CVE-2026-1111')).not_to be_bound
    end

    it "must be true when a gem was given" do
      expect(described_class.new('CVE-2026-1111', gem: 'alpha')).to be_bound
    end
  end

  describe "#expired?" do
    subject { described_class.new('CVE-2026-1111', expires: '2026-06-01') }

    it "must be false before the expiration date" do
      expect(subject.expired?(Date.new(2026,5,31))).to be(false)
    end

    it "must be false on the expiration date" do
      expect(subject.expired?(Date.new(2026,6,1))).to be(false)
    end

    it "must be true after the expiration date" do
      expect(subject.expired?(Date.new(2026,6,2))).to be(true)
    end

    context "when no expiration date was given" do
      subject { described_class.new('CVE-2026-1111') }

      it "must be false" do
        expect(subject.expired?(Date.new(2999,1,1))).to be(false)
      end
    end
  end

  describe "#to_h" do
    it "must include the advisory, gem and expires" do
      approval = described_class.new('CVE-2026-1111', gem: 'alpha', expires: '2026-06-01')

      expect(approval.to_h).to eq(
        advisory: 'CVE-2026-1111',
        gem:      'alpha',
        expires:  Date.new(2026,6,1)
      )
    end
  end
end
