require 'spec_helper'
require 'bundler/audit/results/exempted_gem'
require 'bundler/audit/advisory'

describe Bundler::Audit::Results::ExemptedGem do
  let(:gem) { Gem::Specification.new { |spec| spec.name = 'testgem'; spec.version = '1.0.0' } }
  let(:advisory) do
    Bundler::Audit::Advisory.new(
      'path','CVE-2026-0001',nil,'title',nil,nil,nil,nil,nil,
      '2026-0001',nil,'aaaa-bbbb-0001',[],[]
    )
  end
  let(:exemption) do
    Bundler::Audit::Exemption.new(
      advisory:    'CVE-2026-0001',
      gem:         'testgem',
      reason:      'vendor patch shipped in the application image',
      expires_on:  '2026-12-31',
      approved_by: 'security-team'
    )
  end

  subject { described_class.new(gem,advisory,exemption) }

  it "exposes the gem, advisory and exemption" do
    expect(subject.gem).to be(gem)
    expect(subject.advisory).to be(advisory)
    expect(subject.exemption).to be(exemption)
  end

  it "is approved and does not block the release" do
    expect(subject.disposition).to eq(:approved)
    expect(subject).to be_approved
    expect(subject).to_not be_blocks_release
  end

  it "keeps the approval reason and expiry" do
    expect(subject.reason).to eq('vendor patch shipped in the application image')
    expect(subject.expires_on).to eq(Date.new(2026,12,31))
  end

  it "serializes the reason and exemption" do
    expect(subject.to_h).to include(
      type:        :exempted_gem,
      disposition: :approved,
      reason:      'vendor patch shipped in the application image'
    )
    expect(subject.to_h[:exemption]).to include(approved_by: 'security-team')
  end

  it "compares by gem, advisory and exemption" do
    expect(subject).to eq(described_class.new(gem,advisory,exemption))
    expect(subject).to_not eq(described_class.new(gem,advisory,
      Bundler::Audit::Exemption.new(advisory: 'CVE-2026-0001',reason: 'other')))
  end
end
