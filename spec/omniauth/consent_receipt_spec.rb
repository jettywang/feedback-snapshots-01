require 'helper'

describe OmniAuth::ConsentReceipt do
  let(:provider) { 'directory' }
  let(:purposes) do
    {
      'profile' => {
        'status' => 'approved',
        'requested_claims' => %w[organization_name contact_email],
        'claims' => ['organization_name'],
        'declined_claims' => ['contact_email'],
        'pending_claims' => [],
        'provider' => provider
      },
      'billing' => {
        'status' => 'pending',
        'requested_claims' => ['invoice_address'],
        'claims' => [],
        'declined_claims' => [],
        'pending_claims' => ['invoice_address'],
        'provider' => provider
      },
      'audit' => {
        'status' => 'cancelled',
        'requested_claims' => ['access_log'],
        'claims' => [],
        'declined_claims' => ['access_log'],
        'pending_claims' => [],
        'provider' => provider
      }
    }
  end
  let(:receipt) do
    described_class.new(:provider => provider, :uid => 'user-1', :identity_confirmed => true, :purposes => purposes)
  end

  it 'reports the registered provider, uid, and confirmed identity' do
    expect(receipt.provider).to eq(provider)
    expect(receipt.uid).to eq('user-1')
    expect(receipt.identity_confirmed?).to be(true)
    expect(receipt.confirmed?).to be(true)
  end

  it 'separates approved, pending, and cancelled purposes' do
    expect(receipt.approved).to eq('profile' => {'provider' => provider, 'claims' => ['organization_name']})
    expect(receipt.pending).to eq(['billing'])
    expect(receipt.cancelled).to eq(['audit'])
    expect(receipt.statuses).to eq('profile' => 'approved', 'billing' => 'pending', 'audit' => 'cancelled')
  end

  it 'answers the status of a purpose by name, as a symbol too' do
    expect(receipt.status_for('profile')).to eq('approved')
    expect(receipt.status_for(:profile)).to eq('approved')
    expect(receipt.status_for('billing')).to eq('pending')
    expect(receipt.status_for('audit')).to eq('cancelled')
    expect(receipt.status_for('unknown')).to be_nil
  end

  it 'answers whether a purpose is approved, pending, or cancelled' do
    expect(receipt.approved?('profile')).to be(true)
    expect(receipt.approved?('billing')).to be(false)
    expect(receipt.pending?('billing')).to be(true)
    expect(receipt.pending?('profile')).to be(false)
    expect(receipt.cancelled?('audit')).to be(true)
    expect(receipt.cancelled?('profile')).to be(false)
  end

  it 'reports the approved, declined, and still pending claims of a purpose' do
    expect(receipt.claims_for('profile')).to eq(['organization_name'])
    expect(receipt.declined_claims_for('profile')).to eq(['contact_email'])
    expect(receipt.pending_claims_for('billing')).to eq(['invoice_address'])
    expect(receipt.declined_claims_for(:audit)).to eq(['access_log'])
  end

  it 'gives empty results for a purpose the request never included' do
    expect(receipt.status_for('missing')).to be_nil
    expect(receipt.claims_for('missing')).to eq([])
    expect(receipt.declined_claims_for('missing')).to eq([])
    expect(receipt.pending_claims_for('missing')).to eq([])
  end

  it 'exposes the whole receipt as a hash' do
    expect(receipt.to_hash).to eq(
      'identity' => {'confirmed' => true, 'provider' => provider, 'uid' => 'user-1'},
      'approved' => {'profile' => {'provider' => provider, 'claims' => ['organization_name']}},
      'pending' => ['billing'],
      'cancelled' => ['audit'],
      'purposes' => purposes
    )
    expect(receipt.to_h).to eq(receipt.to_hash)
  end

  it 'reports an unconfirmed identity with every purpose still pending' do
    receipt = described_class.new(:provider => provider, :uid => nil, :identity_confirmed => false, :purposes => {})
    expect(receipt.identity_confirmed?).to be(false)
    expect(receipt.uid).to be_nil
    expect(receipt.approved).to eq({})
    expect(receipt.pending).to eq([])
    expect(receipt.cancelled).to eq([])
    expect(receipt.to_hash['identity']).to eq('confirmed' => false, 'provider' => provider, 'uid' => nil)
  end
end
