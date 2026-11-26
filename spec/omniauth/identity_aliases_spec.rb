require 'helper'
require 'omniauth/identity_pinning'

describe 'identity migration compatibility aliases' do
  it 'exposes top-level contract names' do
    expect(OmniAuth::Migration).to equal(OmniAuth::IdentityMigration)
    expect(OmniAuth::IdentityPinning).to equal(OmniAuth::IdentityMigration)
    expect(OmniAuth::IdentityContract).to eq(OmniAuth::IdentityMigration::Contract)
    expect(OmniAuth::CallbackContract).to eq(OmniAuth::IdentityMigration::Contract)
  end

  it 'exposes namespace, review, ledger, and mapping aliases' do
    expect(OmniAuth::IdentityMigration::Registry).to eq(OmniAuth::IdentityMigration::Contract)
    expect(OmniAuth::IdentityMigration::Directory).to eq(OmniAuth::IdentityMigration::Registration)
    expect(OmniAuth::IdentityMigration::Identity).to eq(OmniAuth::IdentityMigration::Principal)
    expect(OmniAuth::IdentityMigration::Conversion).to eq(OmniAuth::IdentityMigration::Receipt)
    expect(OmniAuth::IdentityMigration::MigrationResult).to eq(OmniAuth::IdentityMigration::Receipt)

    principal = OmniAuth::IdentityMigration::Principal.new(:registration => 'legacy', :uid => '7')
    receipt = OmniAuth::IdentityMigration::Receipt.new(:status => 'pending_review', :principal => principal)
    ledger = OmniAuth::IdentityMigration::Ledger.new
    contract = OmniAuth::IdentityMigration::Contract.new

    expect(principal.namespace).to eq('legacy')
    expect(receipt).to be_pending_verification
    expect(receipt).to be_unverified
    expect(receipt).to be_needs_review
    expect(receipt.subject).to eq(principal)
    expect(receipt.verification_status).to eq('pending_verification')
    expect(OmniAuth::IdentityMigration::Receipt.new(:status => 'mapped').verification_status).to eq('mapped')
    expect(ledger.events).to eq([])
    expect(ledger.records).to eq([])
    expect(contract.mapping_for(principal)).to be_nil
    expect(contract.find_mapping(principal)).to be_nil
    expect(contract.method(:approve)).to eq(contract.method(:approve_mapping!))
  end
end
