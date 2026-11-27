# frozen_string_literal: true

require 'spec_helper'

describe User, :active_record do
  context 'with external_grants submodule' do
    before(:all) do
      MigrationHelper.migrate("#{Rails.root}/db/migrate/external")
      MigrationHelper.migrate("#{Rails.root}/db/migrate/external_grants")

      sorcery_reload!([:external, :external_grants])
      sorcery_model_property_set(:authentications_class, Authentication)
      sorcery_model_property_set(:grants_class, ExternalGrant)
    end

    after(:all) do
      MigrationHelper.rollback("#{Rails.root}/db/migrate/external_grants")
      MigrationHelper.rollback("#{Rails.root}/db/migrate/external")
    end

    let(:user) { create_new_external_user(:example) }

    describe '.scope_covers?' do
      it 'covers when the granted scope includes the required entries' do
        expect(Sorcery::Model::Submodules::ExternalGrants.scope_covers?('profile admin:console', 'admin:console')).to be true
      end

      it 'does not cover when an entry is missing' do
        expect(Sorcery::Model::Submodules::ExternalGrants.scope_covers?('profile', 'admin:console')).to be false
      end

      it 'always covers a blank required scope' do
        expect(Sorcery::Model::Submodules::ExternalGrants.scope_covers?(nil, nil)).to be true
      end

      it 'accepts arrays on both sides' do
        expect(Sorcery::Model::Submodules::ExternalGrants.scope_covers?(%w[profile admin:console], ['admin:console'])).to be true
      end
    end

    describe '#register_external_grant' do
      it 'creates an unconfirmed grant' do
        grant = user.register_external_grant('example', :admin_console, 'profile admin:console')

        expect(grant).to be_persisted
        expect(user.external_grant_status('example', :admin_console)).to eq 'unconfirmed'
      end

      it 'keeps the status when the scope is unchanged' do
        user.register_external_grant('example', :admin_console, 'profile admin:console')
        user.confirm_external_grant('example', :admin_console)

        user.register_external_grant('example', :admin_console, 'profile admin:console')

        expect(user.external_grant_status('example', :admin_console)).to eq 'granted'
      end

      it 'sends the grant back to unconfirmed when the scope changed' do
        user.register_external_grant('example', :admin_console, 'profile admin:console')
        user.confirm_external_grant('example', :admin_console)

        user.register_external_grant('example', :admin_console, 'profile admin:console extra')

        expect(user.external_grant_status('example', :admin_console)).to eq 'unconfirmed'
      end

      it 'returns false and keeps the persisted state when the update fails' do
        user.register_external_grant('example', :admin_console, 'profile admin:console')
        user.confirm_external_grant('example', :admin_console)

        allow_any_instance_of(ExternalGrant).to receive(:save).and_raise(ActiveRecord::RecordNotSaved) # rubocop:disable RSpec/AnyInstance

        expect(user.register_external_grant('example', :admin_console, 'profile admin:console extra')).to be false
        expect(user.external_grant_status('example', :admin_console)).to eq 'granted'
      end
    end

    describe '#confirm_external_grant and #stop_external_grant' do
      it 'transitions the grant between granted and stopped' do
        user.register_external_grant('example', :admin_console, 'profile admin:console')

        expect(user.confirm_external_grant('example', :admin_console)).to be_truthy
        expect(user.external_grant_status('example', :admin_console)).to eq 'granted'

        expect(user.stop_external_grant('example', :admin_console)).to be_truthy
        expect(user.external_grant_status('example', :admin_console)).to eq 'stopped'
      end

      it 'returns false when no grant exists' do
        expect(user.confirm_external_grant('example', :admin_console)).to be false
        expect(user.stop_external_grant('example', :admin_console)).to be false
      end
    end

    describe '#external_grant_allows?' do
      it 'is true only for granted grants whose scope covers the required one' do
        user.register_external_grant('example', :admin_console, 'profile admin:console')

        expect(user.external_grant_allows?('example', :admin_console, 'admin:console')).to be false

        user.confirm_external_grant('example', :admin_console)

        expect(user.external_grant_allows?('example', :admin_console, 'admin:console')).to be true
        expect(user.external_grant_allows?('example', :admin_console, 'admin:other')).to be false

        user.stop_external_grant('example', :admin_console)

        expect(user.external_grant_allows?('example', :admin_console, 'admin:console')).to be false
      end

      it 'is false when no grant exists' do
        expect(user.external_grant_allows?('example', :admin_console)).to be false
      end
    end
  end
end
