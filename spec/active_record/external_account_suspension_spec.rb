# frozen_string_literal: true

require 'spec_helper'

describe User, :active_record do
  context 'with external provider suspension notifications' do
    before(:all) do
      MigrationHelper.migrate("#{Rails.root}/db/migrate/external")
      described_class.reset_column_information
      sorcery_reload!([:external])
      sorcery_model_property_set(:authentications_class, Authentication)
    end

    after(:all) do
      MigrationHelper.rollback("#{Rails.root}/db/migrate/external")
    end

    before do
      User.sorcery_adapter.delete_all
      Authentication.sorcery_adapter.delete_all
      user
    end

    let(:user) do
      record = create_new_user(username: 'gizmo', email: 'gizmo@example.com', password: 'secret')
      record.authentications.create!(provider: 'github', uid: 'uid-github')
      record.authentications.create!(provider: 'google', uid: 'uid-google')
      record
    end

    def authentication_for(provider)
      Authentication.where(user_id: user.id, provider: provider).first
    end

    describe 'configuration' do
      after do
        sorcery_model_property_set(:authentication_disabled_at_attribute_name, :disabled_at)
      end

      it "exposes the 'authentication_disabled_at_attribute_name' option" do
        expect(User.sorcery_config.authentication_disabled_at_attribute_name).to eq :disabled_at
      end

      it 'allows the disabled-at attribute name to be overridden' do
        sorcery_model_property_set(:authentication_disabled_at_attribute_name, :suspended_on)
        expect(User.sorcery_config.authentication_disabled_at_attribute_name).to eq :suspended_on
      end
    end

    describe '.disable_provider (application-confirmed notification)' do
      it 'switches only the named external association to unavailable' do
        freeze_time = Time.utc(2026, 1, 2, 3, 4, 5)
        Timecop.freeze(freeze_time) do
          User.disable_provider('github', 'uid-github')

          expect(authentication_for('github').disabled_at).to eq freeze_time
          expect(authentication_for('google').disabled_at).to be_nil
        end
      end

      it 'keeps the binding record for later reconciliation instead of deleting it' do
        expect { User.disable_provider('github', 'uid-github') }
          .not_to(change { Authentication.count })
        expect(authentication_for('github')).to be_persisted
      end

      it 'leaves the other provider and the password login working' do
        User.disable_provider('github', 'uid-github')

        expect(User.load_from_provider('google', 'uid-google')).to eq user
        expect(User.authenticate('gizmo@example.com', 'secret')).to eq user
      end

      it 'blocks the suspended external login' do
        User.disable_provider('github', 'uid-github')

        expect(User.load_from_provider('github', 'uid-github')).to be_nil
      end

      it 'is idempotent across duplicate suspension notifications' do
        Timecop.freeze(Time.utc(2026, 1, 2, 3, 4, 5)) do
          User.disable_provider('github', 'uid-github')
          first_timestamp = authentication_for('github').disabled_at

          Timecop.freeze(Time.current + 1.hour) do
            User.disable_provider('github', 'uid-github')
          end

          expect(authentication_for('github').disabled_at).to eq first_timestamp
        end
      end

      it 'returns nil when no association matches the notification' do
        expect(User.disable_provider('github', 'unknown-uid')).to be_nil
      end
    end

    describe '#disable_external_authentication (scoped to one account)' do
      it 'changes only the current user association' do
        other = create_new_user(username: 'other', email: 'other@example.com', password: 'secret')
        other.authentications.create!(provider: 'github', uid: 'uid-github')

        user.disable_external_authentication('github', 'uid-github')

        expect(authentication_for('github').disabled_at).to be_present
        expect(other.authentications.find_by(provider: 'github', uid: 'uid-github').disabled_at).to be_nil
      end

      it 'returns nil when the user does not own the association' do
        expect(user.disable_external_authentication('github', 'missing')).to be_nil
      end
    end

    describe 'a late ordinary login' do
      it 'cannot re-enable a suspended association' do
        User.disable_provider('github', 'uid-github')

        expect(User.load_from_provider('github', 'uid-github')).to be_nil
        expect(authentication_for('github').reload.disabled_at).to be_present
      end

      it 'does not resurrect the login when re-adding the same provider and uid' do
        User.disable_provider('github', 'uid-github')

        user.add_provider_to_user('github', 'uid-github')

        expect(User.load_from_provider('github', 'uid-github')).to be_nil
        expect(authentication_for('github').reload.disabled_at).to be_present
      end
    end

    describe 'approved recovery' do
      before { User.disable_provider('github', 'uid-github') }

      it '.reactivate_provider restores the suspended login' do
        User.reactivate_provider('github', 'uid-github')

        expect(authentication_for('github').reload.disabled_at).to be_nil
        expect(User.load_from_provider('github', 'uid-github')).to eq user
      end

      it '#reactivate_external_authentication restores the suspended login' do
        user.reactivate_external_authentication('github', 'uid-github')

        expect(authentication_for('github').reload.disabled_at).to be_nil
        expect(User.load_from_provider('github', 'uid-github')).to eq user
      end

      it 'returns nil when no association matches the recovery request' do
        expect(User.reactivate_provider('github', 'unknown-uid')).to be_nil
      end
    end

    describe 'end-to-end notification sequence with synthetic receipts' do
      let(:github_receipt) { { provider: 'github', uid: 'uid-github', event: 'account_suspended' } }
      let(:google_receipt) { { provider: 'google', uid: 'uid-google', event: 'account_suspended' } }

      def process(receipt)
        User.disable_provider(receipt[:provider], receipt[:uid])
      end

      it 'applies two provider receipts while retaining records and password login' do
        process(github_receipt)
        process(google_receipt)

        expect(User.load_from_provider('github', 'uid-github')).to be_nil
        expect(User.load_from_provider('google', 'uid-google')).to be_nil
        expect(Authentication.count).to eq 2
        expect(User.authenticate('gizmo@example.com', 'secret')).to eq user
      end

      it 'treats a duplicate suspension notification as idempotent' do
        process(github_receipt)
        github_timestamp = authentication_for('github').reload.disabled_at

        process(github_receipt) # duplicate notification

        expect(authentication_for('github').reload.disabled_at).to eq github_timestamp
        expect(Authentication.count).to eq 2
      end

      it 'restores only the association that goes through the approved flow' do
        process(github_receipt)
        process(google_receipt)

        User.reactivate_provider('github', 'uid-github')

        expect(User.load_from_provider('github', 'uid-github')).to eq user
        expect(User.load_from_provider('google', 'uid-google')).to be_nil
      end
    end
  end
end
