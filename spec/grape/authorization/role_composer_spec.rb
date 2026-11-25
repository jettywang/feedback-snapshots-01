# frozen_string_literal: true

require 'grape'

RSpec.describe Grape::Authorization::RoleComposer do
  let(:ledger_policy) { Grape::Authorization::SourcePolicy.new(name: :ledger, management: true) }
  let(:desk_policy) { Grape::Authorization::SourcePolicy.new(name: :desk) }
  let(:sources) { { ledger: ledger_policy, desk: desk_policy } }
  let(:version_roles) { { 'v1' => { steward: :admin }, 'v2' => { steward: :auditor } } }

  def identity(source: :ledger, name: 'ada', roles: %i[reader steward])
    Grape::Authorization::Identity.new(name:, source:, roles:)
  end

  def compose(**options)
    described_class.new(
      identity: options.fetch(:identity, identity),
      sources: options.key?(:sources) ? options[:sources] : sources,
      version: options.fetch(:version, 'v1'),
      version_roles:,
      grants: options.fetch(:grants, []),
      ceilings: options.fetch(:ceilings, [])
    ).call
  end

  it 'elevates a attested role through the negotiated version map' do
    expect(compose).to include(:admin)
  end

  it 'does not apply an elevation declared for another API version' do
    expect(compose(version: 'v2')).not_to include(:admin)
    expect(compose(version: 'v2')).to include(:auditor)
  end

  it 'strips management roles from a non-management source even when mapped' do
    expect(compose(identity: identity(source: :desk))).not_to include(:admin)
    expect(compose(identity: identity(source: :desk))).to include(:reader)
  end

  it 'recognizes no roles for a source absent from the registry' do
    expect(compose(identity: identity(source: :unknown))).to eq([])
  end

  it 'adds mount/scope grants' do
    expect(compose(grants: [:auditor])).to include(:auditor)
  end

  it 'intersects every declared ceiling' do
    roles = compose(grants: %i[auditor admin], ceilings: [%i[reader auditor], %i[reader]])
    expect(roles).to eq([:reader])
  end

  it 'never lets a grant restore a management role for an untrusted source' do
    roles = compose(identity: identity(source: :desk), grants: [:admin])
    expect(roles).not_to include(:admin)
  end

  it 'works standalone with no source policies, honoring identity roles directly' do
    roles = compose(sources: {}, identity: identity(roles: %i[admin]))
    expect(roles).to eq([:admin])
  end

  it 'returns no roles without an identity' do
    expect(compose(identity: nil)).to eq([])
  end

  it 'does not share state between same-named identities of different sources' do
    ledger = compose(identity: identity(source: :ledger))
    desk = compose(identity: identity(source: :desk))
    expect(ledger).not_to eq(desk)
    expect(ledger).to include(:admin)
    expect(desk).not_to include(:admin)
  end
end
