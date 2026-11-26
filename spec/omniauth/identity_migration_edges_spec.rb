require 'helper'

describe 'identity migration coverage edges' do
  Migration = OmniAuth::IdentityMigration

  let(:legacy) { Migration::Principal.new(:registration => 'legacy', :uid => '7', :mapping_version => 'v1') }
  let(:current) { Migration::Principal.new(:registration => 'current', :uid => '7', :mapping_version => 'v1') }
  let(:contract) do
    Migration::Contract.new(
      :mapping_version => 'global-v9',
      :registrations => [
        {'name' => 'legacy', 'provider' => 'legacy', :mapping_version => 'v1'},
        {'name' => 'retired', 'provider' => 'retired', :valid => false}
      ]
    )
  end

  it 'covers registration and mapping object registration paths' do
    registration = Migration::Registration.new(:name => 'object')
    expect(contract.register(registration)).to equal(registration)
    expect(contract.registration_for(nil)).to be_nil

    mapping = Migration::Mapping.new(:left => legacy, :right => current, :version => 'v1')
    expect(contract.add_mapping(mapping)).to equal(mapping)

    receipt = contract.evaluate(legacy)
    expect(receipt.principal).to equal(legacy)
  end

  it 'classifies unknown and invalid registrations and falls back through versions' do
    unknown = contract.evaluate(OmniAuth::AuthHash.new(:provider => 'unknown', :uid => '7'))
    expect(unknown.status).to eq('unregistered')
    expect(unknown.reasons).to eq(['registration_not_found'])
    expect(unknown.principal.mapping_version).to eq('global-v9')

    registered = contract.evaluate(OmniAuth::AuthHash.new(:provider => 'legacy', :uid => '9'))
    expect(registered.status).to eq('ordinary')
    expect(registered.principal.mapping_version).to eq('v1')

    invalid = contract.evaluate(OmniAuth::AuthHash.new(:provider => 'retired', :uid => '7'))
    expect(invalid.status).to eq('registration_inactive')
    expect(invalid.reasons).to eq(['registration_inactive'])
    expect(invalid.registration).not_to be_valid
    expect(contract.subjects).not_to have_key(['retired', '7'])
  end

  it 'requires a conversion source and accepts explicit positional hashes' do
    expect { contract.convert! }.to raise_error(Migration::UnknownRegistration)

    contract.approve_mapping!(legacy, current, :version => 'v1')
    contract.approve_mapping!({:left => legacy, :right => current, :version => 'v2'})

    conversion = contract.convert!({
      :source => legacy.to_h,
      :target => current.to_h,
      :mapping_version => 'v1'
    })
    expect(conversion).to be_converted
  end

  it 'requires a registration name' do
    expect { Migration::Registration.new({}) }.to raise_error(ArgumentError, /name/)
  end

  it 'enumerates without a block and exposes the enumerator' do
    ledger = Migration::Ledger.new
    expect(ledger.each).to be_a(Enumerator)
  end

  it 'covers one-sided mappings and version edge cases' do
    left_only = Migration::Mapping.new(:left => legacy)
    right_only = Migration::Mapping.new(:right => current)

    expect(left_only.to_h['right']).to be_nil
    expect(right_only.to_h['left']).to be_nil
    expect(Migration::Mapping.new({})).not_to be_bilateral

    approved = Migration::Mapping.new(:left => legacy, :right => current, :approved => true, :version => 'v1')
    unversioned = Migration::Mapping.new(:left => legacy, :right => current, :approved => true)

    expect(approved.matches?(legacy)).to be(true)
    expect(unversioned.matches?(legacy, 'v1')).to be(false)
  end

  it 'covers mapped receipts without target and non-hash registration output' do
    principal = legacy
    attributed = current
    mapped = Migration::Receipt.new(
      :status => 'mapped',
      :principal => principal,
      :attributed_principal => attributed
    )
    hash = mapped.to_h
    expect(hash['migration_result']['target']['qualified_uid']).to eq('current:7')

    string_registration = Migration::Receipt.new(:registration => 'legacy-name')
    expect(string_registration.to_h['registration']).to eq('legacy-name')
  end

  describe OmniAuth::Strategy::IdentityPinning do
    let(:app) { ->(_env) { [200, {}, ['ok']] } }

    def strategy_with(options = {})
      strategy = ExampleStrategy.new(app, {:name => 'pin'}.merge(options))
      env = Rack::MockRequest.env_for('http://app.example/auth/pin/callback', 'rack.session' => {})
      strategy.instance_variable_set(:@env, env)
      strategy
    end

    it 'ignores non-hash sign-in identity payloads' do
      strategy = strategy_with
      expect(strategy.identity_initiation_from_sign_in(nil)).to be_nil
    end

    it 'allows an unmapped initiation version' do
      strategy = strategy_with(:identity_contract => Object.new)
      payload = strategy.send(:build_identity_initiation, strategy.identity_contract)
      expect(payload['mapping_version']).to be_nil
    end

    it 'returns nil for a contract object with no supported interface' do
      strategy = strategy_with(:identity_contract => Object.new)
      expect(strategy.send(:call_identity_contract, strategy.identity_contract, {})).to be_nil
    end

    it 'writes an approved mapping and tolerates an auth without array writers' do
      mapping = Migration::Mapping.new(:left => legacy, :right => current, :approved => true)
      receipt = Migration::Receipt.new(
        :status => 'mapped',
        :principal => legacy,
        :attributed_principal => current,
        :mapping => mapping
      )
      strategy = strategy_with(:identity_contract => proc { receipt })
      strategy.env['omniauth.auth'] = Object.new

      strategy.send(:apply_identity_contract!)

      expect(strategy.env['omniauth.mapping']).to equal(mapping)
      expect(strategy.env['omniauth.principal']).to eq(current)
      expect(strategy.env['omniauth.auth']).not_to respond_to(:[]=)
    end
  end
end
