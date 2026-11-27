# frozen_string_literal: true

require 'spec_helper'

describe User, :active_record do
  context 'with reset_password token lifecycle policy' do
    before(:all) do
      MigrationHelper.migrate("#{Rails.root}/db/migrate/reset_password")
      described_class.reset_column_information
    end

    after(:all) do
      MigrationHelper.rollback("#{Rails.root}/db/migrate/reset_password")
    end

    let(:policy_class) { Sorcery::Model::ResetPasswordTokenPolicy }
    let(:generations) do
      [
        { id: 'gen-2026-10', secret: 'first-generation-secret' },
        { id: 'gen-2026-11', secret: 'second-generation-secret' }
      ]
    end

    def build_policy(**options)
      policy_class.new(generations: generations, **options)
    end

    before(:all) do
      sorcery_reload!([:reset_password], reset_password_mailer: SorceryMailer, reset_password_expiration_period: 3600)
    end

    after do
      User.reset_password_token_policy = nil
      User.sorcery_config.reset_password_expiration_period = 3600
      sorcery_reload!([:reset_password], reset_password_mailer: SorceryMailer)
    end

    it 'keeps the legacy plain-token flow when no policy is configured' do
      user = create_new_user
      user.deliver_reset_password_instructions!

      expect(user.reset_password_token).not_to include('rp1.')
      expect(User.load_from_reset_password_token(user.reset_password_token)).to eq user
    end

    it 'issues tokens signed by the current generation' do
      User.reset_password_token_policy = build_policy(current: 'gen-2026-11')
      user = create_new_user
      user.deliver_reset_password_instructions!

      expect(user.reset_password_token_generation).to eq 'gen-2026-11'
      expect(User.load_from_reset_password_token(user.reset_password_token)).to eq user
    end

    it 'accepts tokens from a generation in its grace period' do
      sorcery_model_property_set(:reset_password_time_between_emails, 0)
      policy = build_policy(current: 'gen-2026-10')
      User.reset_password_token_policy = policy
      user = create_new_user
      user.deliver_reset_password_instructions!
      old_token = user.reset_password_token

      policy.rotate!('gen-2026-11', grace_period: 300)
      user.deliver_reset_password_instructions!
      new_token = user.reset_password_token

      expect(new_token).not_to eq old_token
      expect(user.reset_password_token_generation).to eq 'gen-2026-11'

      user.update(reset_password_token: old_token)
      expect(User.load_from_reset_password_token(old_token)).to eq user
    end

    it 'stops accepting a generation once its grace period ends' do
      policy = build_policy(current: 'gen-2026-10')
      User.reset_password_token_policy = policy
      user = create_new_user
      user.deliver_reset_password_instructions!
      old_token = user.reset_password_token

      policy.rotate!('gen-2026-11', grace_period: 0.05)
      Timecop.travel(Time.now.in_time_zone + 0.2) do
        expect(User.load_from_reset_password_token(old_token)).to be_nil
        failure = nil
        User.load_from_reset_password_token(old_token) { |_, reason| failure = reason }
        expect(failure).to eq :token_retired
      end
    end

    it 'rejects tokens signed by an unknown generation' do
      User.reset_password_token_policy = build_policy(current: 'gen-2026-11')
      user = create_new_user

      expect(User.load_from_reset_password_token('rp1.gen-2099.abc.def')).to be_nil
      expect(user.reset_password_token_generation).to be_nil
    end

    it 'rejects a token whose signature does not match' do
      User.reset_password_token_policy = build_policy(current: 'gen-2026-11')
      user = create_new_user
      user.generate_reset_password_token!
      tampered = user.reset_password_token.sub(/.$/, 'x')

      failure = nil
      User.load_from_reset_password_token(tampered) { |_, reason| failure = reason }

      expect(failure).to eq :invalid_signature
    end

    it 'rejects a token before revealing that its generation is retired' do
      policy = build_policy(current: 'gen-2026-10')
      User.reset_password_token_policy = policy
      user = create_new_user
      user.generate_reset_password_token!
      valid = user.reset_password_token
      policy.rotate!('gen-2026-11')

      forged = valid.sub(/.$/, valid.end_with?('a') ? 'b' : 'a')
      expect(policy.resolve(forged).status).to eq :invalid_signature
      expect(policy.resolve(valid).status).to eq :token_retired
    end

    it 'rejects an invalid configuration instead of silently switching generations' do
      expect do
        policy_class.new(generations: generations, current: 'gen-2099')
      end.to raise_error(policy_class::Error, /unknown current generation/)
    end

    it 'accepts a single generation specification hash' do
      policy = policy_class.new(generations: { id: 'gen-2026-11', secret: 'second-generation-secret' })

      expect(policy.generation_ids).to eq ['gen-2026-11']
      expect(policy.current_id).to eq 'gen-2026-11'
    end

    it 'admits legacy records only when explicitly allowed' do
      policy = build_policy(current: 'gen-2026-11', admit_legacy: false)
      User.reset_password_token_policy = policy
      user = create_new_user
      user.update(reset_password_token: 'legacy-mail-token')

      failure = nil
      User.load_from_reset_password_token('legacy-mail-token') { |_, reason| failure = reason }
      expect(failure).to eq :legacy_not_admitted

      policy.admit_legacy = true
      expect(User.load_from_reset_password_token('legacy-mail-token')).to eq user
    end

    it 'stops admitting legacy records after the legacy window closes' do
      policy = build_policy(current: 'gen-2026-11', admit_legacy: true,
                            legacy_admitted_until: Time.now.in_time_zone + 0.05)
      User.reset_password_token_policy = policy
      user = create_new_user
      user.update(reset_password_token: 'legacy-mail-token')

      Timecop.travel(Time.now.in_time_zone + 0.2) do
        expect(User.load_from_reset_password_token('legacy-mail-token')).to be_nil
      end
    end

    it 'records issuance per generation without exposing the token' do
      policy = build_policy(current: 'gen-2026-11')
      User.reset_password_token_policy = policy
      user = create_new_user
      user.deliver_reset_password_instructions!

      current_entry = User.reset_password_token_registry.find { |entry| entry[:id] == 'gen-2026-11' }
      expect(current_entry[:issued_count]).to eq 1
      expect(current_entry[:state]).to eq :active
      expect(current_entry[:current]).to be true

      serialized = User.reset_password_token_registry.inspect + User.reset_password_token_diagnostics.inspect
      expect(serialized).not_to include(user.reset_password_token)
      expect(serialized).not_to include('first-generation-secret')
      expect(serialized).not_to include('second-generation-secret')
    end

    it 'records a token-free rejection diagnostic' do
      User.reset_password_token_policy = build_policy(current: 'gen-2026-11')
      User.load_from_reset_password_token('rp1.gen-2099.missing.signature')

      diagnostics = User.reset_password_token_diagnostics
      rejection = diagnostics.find { |entry| entry[:event] == :lookup_rejected }

      expect(rejection[:reason]).to eq :unknown_generation
      expect(diagnostics.inspect).not_to include('missing')
    end

    it 'does not issue or register when the persistence update fails' do
      policy = build_policy(current: 'gen-2026-11')
      User.reset_password_token_policy = policy
      user = create_new_user
      user.update(reset_password_token: 'previous-token')

      allow(user.sorcery_adapter).to receive(:update_attributes).and_return(false)

      expect(user.generate_reset_password_token!).to be false
      expect(user.reset_password_token).to eq 'previous-token'
      expect(policy.registry.find { |entry| entry[:id] == 'gen-2026-11' }[:issued_count]).to eq 0
      expect(policy.diagnostics.last).to include(event: :issue_failed, reason: :storage_failed)
    end

    it 'restores the previous token when persistence raises' do
      policy = build_policy(current: 'gen-2026-11')
      User.reset_password_token_policy = policy
      user = create_new_user
      user.update(reset_password_token: 'previous-token')

      allow(user.sorcery_adapter).to receive(:update_attributes).and_raise(ActiveRecord::StatementInvalid, 'disk full')

      expect(user.generate_reset_password_token!).to be false
      expect(user.reset_password_token).to eq 'previous-token'
      expect(policy.diagnostics.last).to include(event: :issue_failed, reason: :storage_failed)
      expect(policy.diagnostics.last.inspect).not_to include('previous-token')
    end

    it 'leaves the email unsent when issuance fails' do
      policy = build_policy(current: 'gen-2026-11')
      User.reset_password_token_policy = policy
      user = create_new_user

      allow(user).to receive(:generate_reset_password_token!).and_return(false)

      expect { user.deliver_reset_password_instructions! }.not_to change(ActionMailer::Base.deliveries, :size)
    end

    it 'uses two explicitly in-use generations while only the current one issues' do
      policy = policy_class.new(
        generations: [
          { id: 'gen-2026-10', secret: 'first-generation-secret', state: :pending },
          { id: 'gen-2026-11', secret: 'second-generation-secret' }
        ],
        current: 'gen-2026-11'
      )
      User.reset_password_token_policy = policy

      old_policy = build_policy(current: 'gen-2026-10')
      old_issuance = old_policy.build_issuance
      User.reset_password_token_policy = policy
      user = create_new_user
      user.update(reset_password_token: old_issuance.credential)

      expect(User.load_from_reset_password_token(old_issuance.credential)).to eq user
      expect(policy.build_issuance.generation_id).to eq 'gen-2026-11'
    end

    it 'keeps generation ids when keyed hashes carry state' do
      policy = policy_class.new(
        generations: {
          'gen-2026-10' => { secret: 'first-generation-secret', state: :pending },
          'gen-2026-11' => { secret: 'second-generation-secret' }
        },
        current: 'gen-2026-11'
      )

      expect(policy.generation_ids).to eq %w[gen-2026-10 gen-2026-11]
      expect(policy.registry.find { |entry| entry[:id] == 'gen-2026-10' }[:state]).to eq :pending
      expect(policy.build_issuance.generation_id).to eq 'gen-2026-11'
    end

    it 'returns a usable old-generation issuance when rotated mid-flight' do
      policy = build_policy(current: 'gen-2026-10')
      User.reset_password_token_policy = policy

      issuance = policy.rotate_with_retiring_issuance!('gen-2026-11', grace_period: 60)

      expect(issuance.generation_id).to eq 'gen-2026-10'
      expect(policy.current_id).to eq 'gen-2026-11'
      expect(policy.build_issuance.generation_id).to eq 'gen-2026-11'
    end

    it 'allows exactly one redemption of an admitted legacy token' do
      policy = build_policy(current: 'gen-2026-11', admit_legacy: true)
      User.reset_password_token_policy = policy
      user = create_new_user
      user.update(reset_password_token: 'legacy-mail-token')

      expect(User.load_from_reset_password_token('legacy-mail-token')).to eq user
      User.load_from_reset_password_token('legacy-mail-token') { |_, reason| @second_failure = reason }
      expect(@second_failure).to eq :legacy_already_used
    end

    it 'accepts a generation map and admits explicitly listed legacy tokens' do
      policy = policy_class.new(generations: { 'gen-2026-11' => 'second-generation-secret' },
                                admit_legacy: ['historical-mail-token'])
      User.reset_password_token_policy = policy
      user = create_new_user
      user.update(reset_password_token: 'historical-mail-token')

      expect(User.load_from_reset_password_token('historical-mail-token')).to eq user
      expect(policy.generation_ids).to eq ['gen-2026-11']

      policy.admit_legacy = true
      expect(User.load_from_reset_password_token('historical-mail-token')).to be_nil
      expect(User.load_from_reset_password_token('other-legacy-token')).to be_nil
    end

    it 'uses the generation active at issuance time when the policy is refreshed mid-flight' do
      policy = build_policy(current: 'gen-2026-10')
      User.reset_password_token_policy = policy
      user = create_new_user

      issuance = policy.build_issuance
      expect(issuance.generation_id).to eq 'gen-2026-10'

      policy.rotate!('gen-2026-11')
      user.update(reset_password_token: issuance.credential)

      expect(User.load_from_reset_password_token(issuance.credential)).to be_nil
      expect(policy.registry.find { |entry| entry[:id] == 'gen-2026-10' }[:state]).to eq :retired
    end

    it 'rotates from the old generation to the new generation' do
      policy = build_policy(current: 'gen-2026-10')
      User.reset_password_token_policy = policy

      policy.rotate!('gen-2026-11')

      expect(policy.current_id).to eq 'gen-2026-11'
      old_entry = policy.registry.find { |entry| entry[:id] == 'gen-2026-10' }
      expect(old_entry[:state]).to eq :retired
      expect(policy.diagnostics.map { |entry| entry[:event] }).to include(:rotated)
    end
  end
end
