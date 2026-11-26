require 'helper'

describe OmniAuth::IdentityMigration do
  let(:module_namespace) { OmniAuth::IdentityMigration }

  it 'exposes the same framework under the provider migration alias' do
    expect(OmniAuth::ProviderMigration).to equal(module_namespace)
  end

  describe OmniAuth::IdentityMigration::Principal do
    it 'accepts string keys and version aliases and hashes by namespace and uid' do
      principal = described_class.new(
        'registration' => 'legacy',
        'uid' => '7',
        'provider' => 'old',
        'version' => 'v1'
      )

      expect(principal.mapping_version).to eq('v1')
      expect(principal.qualified_uid).to eq('legacy:7')
      expect(principal.to_s).to eq('legacy:7')
      expect(principal.hash).to eq(['legacy', '7'].hash)
      expect(principal).to eql(described_class.new(:registration => 'legacy', :uid => 7))
      expect(principal.to_h['qualified_uid']).to eq('legacy:7')
    end

    it 'returns nil for omitted optional attributes' do
      principal = described_class.new(:registration => 'legacy', :uid => '7')

      expect(principal.provider).to be_nil
      expect(principal.mapping_version).to be_nil
    end

    it 'requires a registration and uid' do
      expect { described_class.new(:uid => '7') }.to raise_error(ArgumentError, /registration/)
      expect { described_class.new(:registration => 'legacy') }.to raise_error(ArgumentError, /uid/)
    end
  end

  describe OmniAuth::IdentityMigration::Registration do
    it 'uses provider and active status defaults' do
      registration = described_class.new(:name => 'legacy')

      expect(registration.provider).to eq('legacy')
      expect(registration.mapping_version).to eq('unversioned')
      expect(registration).to be_active
      expect(registration.to_h['valid']).to be(true)
    end

    it 'accepts metadata hashes and ignores unsupported metadata' do
      with_hash = described_class.new(:name => 'legacy', :metadata => {'team' => 'id'})
      bad = described_class.new(:name => 'legacy', :metadata => 'not-a-hash')

      expect(with_hash.metadata).to eq('team' => 'id')
      expect(bad.metadata).to eq({})
    end

    it 'can be explicitly invalid' do
      registration = described_class.new(:name => 'legacy', :valid => false)

      expect(registration).not_to be_valid
      expect(registration).not_to be_active
    end

    it 'accepts an explicit active flag' do
      active = described_class.new(:name => 'legacy', :active => true)
      inactive = described_class.new(:name => 'legacy', :active => false)

      expect(active).to be_valid
      expect(inactive).not_to be_valid
    end
  end

  describe OmniAuth::IdentityMigration::Mapping do
    let(:left) { OmniAuth::IdentityMigration::Principal.new(:registration => 'legacy', :uid => '7') }
    let(:right) { OmniAuth::IdentityMigration::Principal.new(:registration => 'current', :uid => '7') }

    it 'coerces hash endpoints and finds either side as counterpart' do
      mapping = described_class.new(
        :source => left.to_h,
        :target => right.to_h,
        :approved => true,
        :version => 'v1'
      )
      unrelated = OmniAuth::IdentityMigration::Principal.new(:registration => 'other', :uid => '9')

      expect(mapping.left).to be_a(OmniAuth::IdentityMigration::Principal)
      expect(mapping.right).to be_a(OmniAuth::IdentityMigration::Principal)
      expect(mapping.counterpart(right)).to eq(left)
      expect(mapping.counterpart(left)).to eq(right)
      expect(mapping.counterpart(unrelated)).to be_nil
      expect(mapping).to be_bilateral
      expect(mapping.matches?(left, 'v1')).to be(true)
      expect(mapping.matches?(left, 'v2')).to be(false)
    end

    it 'treats explicit false approval as pending and accepts a status string' do
      pending = described_class.new(:left => left, :right => right, :approved => false)
      rejected = described_class.new(:left => left, :right => right, :status => 'rejected')

      expect(pending.status).to eq('pending')
      expect(rejected.status).to eq('rejected')
      expect(pending).not_to be_approved
      expect(pending.to_h['approved']).to be(false)
    end
  end

  describe OmniAuth::IdentityMigration::Receipt do
    it 'coerces nested mapping and registration hashes' do
      receipt = described_class.new(
        :status => 'converted',
        :mapping => {'left' => {'registration' => 'l', 'uid' => '1'},
                     'right' => {'registration' => 'c', 'uid' => '1'},
                     'approved' => true},
        :registration => {'name' => 'l'}
      )

      expect(receipt.mapping).to be_a(OmniAuth::IdentityMigration::Mapping)
      expect(receipt.registration).to be_a(OmniAuth::IdentityMigration::Registration)
      expect(receipt).to be_approved_mapping
      expect(receipt).to be_converted
      expect(receipt.migration_result['status']).to eq('converted')
    end

    it 'reports missing approved mappings as false' do
      expect(described_class.new(:status => 'ordinary')).not_to be_approved_mapping
    end
  end

  describe OmniAuth::IdentityMigration::Ledger do
    it 'records sequential reviewable receipts' do
      ledger = described_class.new
      first = ledger.record(:kind => 'login', :status => 'ordinary')
      second = ledger.record(:kind => 'conversion', :status => 'converted')

      expect(first.sequence).to eq(1)
      expect(second.sequence).to eq(2)
      expect(ledger.last).to eq(second)
      expect(ledger.to_a).to eq([first, second])
      expect(ledger.deliveries).to eq([first])
      expect(ledger.conversions).to eq([second])
      expect(ledger.to_h['entries'].length).to eq(2)
    end
  end

  describe OmniAuth::IdentityMigration::Contract do
    let(:legacy) { OmniAuth::IdentityMigration::Principal.new(:registration => 'legacy', :uid => '7', :mapping_version => 'v1') }
    let(:current) { OmniAuth::IdentityMigration::Principal.new(:registration => 'current', :uid => '7', :mapping_version => 'v1') }
    let(:contract) do
      described_class.new(
        :registrations => [
          {'name' => 'legacy', 'provider' => 'legacy', :mapping_version => 'v1'},
          {'name' => 'current', 'provider' => 'current', :mapping_version => 'v1'}
        ]
      )
    end

    it 'evaluates a Rack environment through call' do
      auth = OmniAuth::AuthHash.new(:provider => 'legacy', :uid => '7')
      receipt = contract.call(
        'omniauth.auth' => auth,
        'omniauth.identity_initiation' => {'registration' => 'legacy', 'mapping_version' => 'v1'}
      )

      expect(receipt).to be_ordinary
      expect(receipt.principal).to eq(legacy)
    end

    it 'pins an explicitly supplied registration object' do
      registration = OmniAuth::IdentityMigration::Registration.new(:name => 'custom')
      payload = contract.pin_initiation('provider-name', :registration => registration)

      expect(payload['registration']).to eq('custom')
      expect { contract.pin_initiation('missing') }.to raise_error(OmniAuth::IdentityMigration::UnknownRegistration)
    end

    it 'reports an unapproved explicit mapping without merging' do
      contract.add_mapping(:left => legacy, :right => current)
      receipt = contract.evaluate(
        OmniAuth::AuthHash.new(:provider => 'legacy', :uid => '7'),
        'registration' => 'legacy',
        'mapping_version' => 'v1'
      )

      expect(receipt).to be_pending_review
      expect(receipt.reasons).to eq(['mapping_pending'])
      expect(receipt.attributed_principal).to eq(legacy)
    end

    it 'reports an approved mapping whose pinned version differs' do
      contract.approve_mapping!(legacy, current, :version => 'old')
      receipt = contract.evaluate(
        OmniAuth::AuthHash.new(:provider => 'legacy', :uid => '7'),
        'registration' => 'legacy',
        'mapping_version' => 'v1'
      )

      expect(receipt).to be_pending_review
      expect(receipt.reasons).to eq(['mapping_version_mismatch'])
    end

    it 'accepts mapping objects, hashes, receipts, and hash conversions' do
      mapping = OmniAuth::IdentityMigration::Mapping.new(:left => legacy, :right => current, :version => 'v1')
      contract.approve_mapping!(mapping)
      contract.approve_mapping!(:left => legacy, :right => current, :version => 'v2')

      receipt = contract.evaluate(
        OmniAuth::AuthHash.new(:provider => 'legacy', :uid => '7'),
        'registration' => 'legacy',
        'mapping_version' => 'v1'
      )
      conversion = contract.convert!(receipt)
      expect(conversion.target_principal).to eq(current)

      hash_conversion = contract.convert!(
        'source' => legacy.to_h,
        'target' => current.to_h,
        'mapping_version' => 'v1'
      )
      expect(hash_conversion).to be_converted
    end

    it 'rejects conversions without a matching approved mapping or target' do
      other = OmniAuth::IdentityMigration::Principal.new(:registration => 'current', :uid => 'other')
      expect { contract.convert!(legacy, current) }.to raise_error(OmniAuth::IdentityMigration::UnapprovedMapping)

      contract.approve_mapping!(legacy, current, :version => 'v1')
      expect { contract.convert!(legacy, other, :mapping_version => 'v1') }
        .to raise_error(OmniAuth::IdentityMigration::UnapprovedMapping)
    end

    it 'reads provider attributes through methods and returns nil for missing attributes' do
      authentication = double(:provider => 'legacy', :uid => '7')
      expect(contract.send(:read_attribute, authentication, :provider)).to eq('legacy')
      expect(contract.send(:read_attribute, Object.new, :provider)).to be_nil
    end
  end
end
