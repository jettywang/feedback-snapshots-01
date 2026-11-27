# frozen_string_literal: true

require 'spec_helper'

describe Sorcery::RecentAuthenticationRecord, :active_record do
  before(:all) do
    MigrationHelper.migrate("#{Rails.root}/db/migrate/recent_authentication")
  end

  after(:all) do
    MigrationHelper.rollback("#{Rails.root}/db/migrate/recent_authentication")
  end

  after { described_class.delete_all }

  let(:store) { Sorcery::RecentAuthenticationStore::ActiveRecordStore.new }
  let(:now) { Time.now.in_time_zone }

  def create_proof(attributes = {})
    store.create(
      user_id: 1,
      session_id: 'session-a',
      operation: 'sensitive',
      authenticated_at: now,
      expires_at: now + 60,
      **attributes
    )
  end

  it 'finds an active proof for the matching user, session and operation' do
    create_proof

    expect(store.active(user_id: 1, session_id: 'session-a', operations: [:sensitive], at: now)).to be_present
  end

  it 'does not match another session' do
    create_proof

    expect(store.active(user_id: 1, session_id: 'session-b', operations: [:sensitive], at: now)).to be_nil
  end

  it 'does not match another user' do
    create_proof

    expect(store.active(user_id: 2, session_id: 'session-a', operations: [:sensitive], at: now)).to be_nil
  end

  it 'does not match another operation' do
    create_proof

    expect(store.active(user_id: 1, session_id: 'session-a', operations: [:export], at: now)).to be_nil
  end

  it 'ignores expired proofs' do
    create_proof

    expect(store.active(user_id: 1, session_id: 'session-a', operations: [:sensitive], at: now + 61)).to be_nil
  end

  it 'ignores revoked proofs' do
    create_proof
    store.revoke_session(user_id: 1, session_id: 'session-a', at: now)

    expect(store.active(user_id: 1, session_id: 'session-a', operations: [:sensitive], at: now)).to be_nil
  end

  it 'reports the expiry of the active proof' do
    proof = create_proof

    expect(store.expires_at(user_id: 1, session_id: 'session-a', operations: [:sensitive], at: now)).to eq proof.expires_at
  end

  it 'revokes only the requested operation within a session' do
    create_proof(operation: 'sensitive')
    create_proof(operation: 'export')

    store.revoke_session(user_id: 1, session_id: 'session-a', operations: [:export], at: now)

    expect(store.active(user_id: 1, session_id: 'session-a', operations: [:sensitive], at: now)).to be_present
    expect(store.active(user_id: 1, session_id: 'session-a', operations: [:export], at: now)).to be_nil
  end

  it 'revokes every proof for a user' do
    create_proof
    create_proof(session_id: 'session-b')

    store.revoke_user(user_id: 1, at: now)

    expect(described_class.where(revoked_at: nil)).to be_empty
  end
end
