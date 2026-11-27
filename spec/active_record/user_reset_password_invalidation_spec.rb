# frozen_string_literal: true

require 'spec_helper'

# Model-level contract for the opt-in transition that terminates earlier
# persistent logins after a committed password change.
describe User, :active_record do
  before(:all) do
    MigrationHelper.migrate("#{Rails.root}/db/migrate/remember_me")
    MigrationHelper.migrate("#{Rails.root}/db/migrate/reset_password")
    MigrationHelper.migrate("#{Rails.root}/db/migrate/invalidate_active_sessions")
    sorcery_reload!([:reset_password, :remember_me], reset_password_mailer: SorceryMailer)
  end

  after(:all) do
    MigrationHelper.rollback("#{Rails.root}/db/migrate/invalidate_active_sessions")
    MigrationHelper.rollback("#{Rails.root}/db/migrate/remember_me")
    MigrationHelper.rollback("#{Rails.root}/db/migrate/reset_password")
  end

  let(:user) { create_new_user }

  describe 'when the option is on' do
    before do
      sorcery_model_property_set(:reset_password_invalidate_active_sessions_enabled, true)
    end

    after do
      sorcery_model_property_set(:reset_password_invalidate_active_sessions_enabled, false)
    end

    it 'records the cutoff and rotates the persistent login in the same save' do
      user.remember_me!
      old_token = user.reload.remember_me_token

      expect(user.change_password('newpassword')).to be_truthy

      user.reload
      expect(user.invalidate_sessions_before).to be_present
      expect(user.remember_me_token).to be_present
      expect(user.remember_me_token).not_to eq old_token
      expect(user.password_change_invalidated_at).to be_within(1.second).of(user.invalidate_sessions_before)
    end

    it 'rotates the token together with the password so an old cookie cannot resolve' do
      user.remember_me!
      old_token = user.reload.remember_me_token

      user.change_password('newpassword')

      expect(User.sorcery_adapter.find_by_remember_me_token(old_token)).to be_nil
      expect(User.sorcery_adapter.find_by_remember_me_token(user.reload.remember_me_token)).to eq user
    end

    it 'exposes the committed cutoff so a controller can keep the current session' do
      user.change_password('newpassword')

      expect(user.password_change_invalidated_at).to be_present
      expect(user.password_change_invalidated_at).to be_within(1.second).of(user.reload.invalidate_sessions_before)
    end

    it 'leaves the cutoff, token and password alone when the save fails silently' do
      user.remember_me!
      old_token = user.reload.remember_me_token
      allow(user.sorcery_adapter).to receive(:save).and_return(false)

      expect(user.change_password('newpassword')).to be false

      expect(user.password_change_invalidated_at).to be_nil
      expect(user.invalidate_sessions_before).to be_nil
      expect(user.remember_me_token).to eq old_token
      expect(user.valid_password?('secret')).to be true
      expect(User.find(user.id).invalidate_sessions_before).to be_nil
    end

    it 'leaves the cutoff, token and password alone when the save raises' do
      user.remember_me!
      old_token = user.reload.remember_me_token
      allow(user.sorcery_adapter).to receive(:save).and_raise(ActiveRecord::RecordNotSaved.new('nope', user))

      expect { user.change_password!('newpassword') }.to raise_error(ActiveRecord::RecordNotSaved)

      expect(user.password_change_invalidated_at).to be_nil
      expect(user.invalidate_sessions_before).to be_nil
      expect(user.remember_me_token).to eq old_token
    end

    it 'does not touch sessions when no password is submitted' do
      user.remember_me!
      old_token = user.reload.remember_me_token
      user.generate_reset_password_token!
      token = user.reset_password_token

      user.change_password(nil)

      user.reload
      expect(user.invalidate_sessions_before).to be_nil
      expect(user.remember_me_token).to eq old_token
      expect(user.reset_password_token).to eq token
    end

    it 'does not report a committed change after the transaction rolls back' do
      user.remember_me!
      old_token = user.reload.remember_me_token

      ActiveRecord::Base.transaction do
        user.change_password('newpassword')
        raise ActiveRecord::Rollback
      end

      # The marker is cleared by the rollback callback, and the persisted state
      # is the pre-change one.
      expect(user.password_change_invalidated_at).to be_nil
      user.reload
      expect(user.invalidate_sessions_before).to be_nil
      expect(user.remember_me_token).to eq old_token
      expect(user.valid_password?('secret')).to be true
      expect(user.valid_password?('newpassword')).to be false
    end

    it 'raises a clear error when the configured cutoff attribute does not exist' do
      sorcery_model_property_set(:reset_password_invalidate_sessions_before_attribute_name, :missing_cutoff)

      expect { user.change_password('newpassword') }.to raise_error(ArgumentError, /missing_cutoff/)
    end
  end

  describe 'when the option is off' do
    before do
      sorcery_model_property_set(:reset_password_invalidate_active_sessions_enabled, false)
    end

    it 'keeps the existing reset behavior: no cutoff and the old token survives' do
      user.remember_me!
      old_token = user.reload.remember_me_token

      user.change_password('newpassword')

      user.reload
      expect(user.invalidate_sessions_before).to be_nil
      expect(user.remember_me_token).to eq old_token
      expect(user.password_change_invalidated_at).to be_nil
      expect(user.valid_password?('newpassword')).to be true
    end
  end
end
