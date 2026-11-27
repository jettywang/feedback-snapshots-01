# frozen_string_literal: true

require 'spec_helper'

# Regression coverage for temporary (magic) login used by support to restore a
# customer's ordinary access while another browser window is finishing an
# independent confirmation.
#
# The scenario is driven entirely through sorcery's model API plus small,
# explicit collaborators defined below:
#   * MagicLoginMailboxFake - a fake mailbox, no real email delivery,
#   * Timecop - a controllable clock for token and confirmation expiry,
#   * ConfirmationCoordinator - server-side confirmation registry with
#     observation points (call counters) that binds every confirmation to the
#     session which started it,
#   * MagicLoginRecovery - one-time consumer of the temporary credential that
#     rebuilds a fresh ordinary session,
#   * SensitiveAction - a business action that runs only for a session holding
#     its own fresh confirmation.
describe 'magic login session rebuild and one-time credential consumption', :active_record do
  # Mailbox fake: the magic login email is captured instead of being sent.
  class MagicLoginMailboxFake
    attr_reader :deliveries

    def initialize
      @deliveries = []
    end

    def deliver_magic_login_email(user, token)
      @deliveries << { email: user.email, token: token, sent_at: Time.now.in_time_zone }
    end

    def last_token
      @deliveries.last.fetch(:token)
    end
  end

  # In-memory server-side session store. Each browser window owns a distinct
  # session id and an isolated data hash, mirroring separate cookie jars.
  class SessionStore
    def initialize
      @data = {}
      @sequence = 0
    end

    def open!
      @sequence += 1
      id = "session-#{@sequence}"
      @data[id] = { user_id: nil, confirmation_id: nil, restored: false }
      id
    end

    def [](id)
      @data.fetch(id)
    end

    def exists?(id)
      @data.key?(id)
    end

    # Rebuilds the recovery session after the temporary credential is exchanged:
    # a brand new id is issued (session fixation safety) and no confirmation is
    # carried over, because recovery restores ordinary access only.
    def rebuild!(recovery_session_id)
      record = @data.delete(recovery_session_id)
      @sequence += 1
      new_id = "session-#{@sequence}"
      @data[new_id] = {
        user_id: record[:user_id],
        confirmation_id: nil,
        restored: true
      }
      new_id
    end
  end

  # Server-side confirmation registry with observation points. A confirmation
  # is bound to the session that started it and can never be attached to a
  # different (for example, rebuilt) session.
  class ConfirmationCoordinator
    attr_reader :start_count, :complete_count, :attach_attempts, :rejections

    def initialize(ttl: 60)
      @ttl = ttl
      @records = {}
      @sequence = 0
      @start_count = 0
      @complete_count = 0
      @attach_attempts = 0
      @rejections = 0
    end

    def start!(session_id, user_id)
      @start_count += 1
      @sequence += 1
      confirmation_id = "confirmation-#{@sequence}"
      @records[confirmation_id] = {
        session_id: session_id,
        user_id: user_id,
        status: :pending,
        started_at: Time.now.in_time_zone
      }
      confirmation_id
    end

    # Completes a confirmation only when it still belongs to the calling
    # session. A completion arriving from a stale window after the session was
    # rebuilt is rejected, so it can never attach to the rebuilt session.
    def complete!(session_id, confirmation_id)
      @attach_attempts += 1
      record = @records[confirmation_id]
      if record.nil? || record[:session_id] != session_id ||
         record[:status] != :pending || expired?(record)
        @rejections += 1
        return false
      end

      record[:status] = :confirmed
      record[:confirmed_at] = Time.now.in_time_zone
      @complete_count += 1
      true
    end

    def confirmed_for?(session_id, confirmation_id)
      record = @records[confirmation_id]
      !record.nil? && record[:session_id] == session_id && record[:status] == :confirmed
    end

    protected

    attr_reader :records

    private

    def expired?(record)
      Time.now.in_time_zone - record[:started_at] > @ttl
    end
  end

  # Deliberately broken double: it completes a confirmation without verifying
  # the owning session and re-binds it to whichever session calls in. This lets
  # an old window attach its confirmation to the rebuilt session. It exists to
  # prove the regression assertions actually fail on the vulnerable behaviour.
  class CrossSessionConfirmationDouble < ConfirmationCoordinator
    def complete!(session_id, confirmation_id)
      @attach_attempts += 1
      record = records[confirmation_id]
      if record.nil? || record[:status] != :pending
        @rejections += 1
        return false
      end

      record[:status] = :confirmed
      record[:confirmed_at] = Time.now.in_time_zone
      record[:session_id] = session_id
      @complete_count += 1
      true
    end
  end

  # One-time consumer of the temporary credential. The user is loaded through
  # sorcery's magic login token API, then the token is cleared inside a
  # transaction with a locked re-read so two exchanges cannot both consume it.
  # The consumption count moves only when a real token is exchanged.
  class MagicLoginRecovery
    attr_reader :consumption_count, :rejection_count

    def initialize(user_class, sessions)
      @user_class = user_class
      @sessions = sessions
      @consumption_count = 0
      @rejection_count = 0
    end

    def call(session_id, token)
      user = nil
      failure = nil
      @user_class.load_from_magic_login_token(token) do |loaded_user, load_failure|
        user = loaded_user
        failure = load_failure
      end

      if user.nil?
        @rejection_count += 1
        return { ok: false, reason: failure || :invalid_token }
      end

      consumed = false
      ActiveRecord::Base.transaction do
        locked = @user_class.sorcery_adapter.find(user.id)
        stored_token = locked.magic_login_token
        if stored_token.blank? || stored_token != token
          @rejection_count += 1
          raise ActiveRecord::Rollback
        end

        locked.clear_magic_login_token!
        @consumption_count += 1
        @sessions[session_id][:user_id] = locked.id.to_s
        consumed = true
      end

      if consumed
        { ok: true, user_id: @sessions[session_id][:user_id], session_id: @sessions.rebuild!(session_id) }
      else
        { ok: false, reason: :already_consumed }
      end
    end
  end

  # Broken recovery double: it trusts the token lookup alone and never verifies
  # that the stored token is still present, so a spent credential can be
  # exchanged again. Used to prove the one-time consumption assertion fails.
  class ReusableCredentialRecoveryDouble < MagicLoginRecovery
    def call(session_id, token)
      user = @user_class.sorcery_adapter.find_by_token(
        @user_class.sorcery_config.magic_login_token_attribute_name, token
      )
      return { ok: false, reason: :user_not_found } unless user

      # Vulnerable: no locked re-read, no stored-token check, no clear.
      @consumption_count += 1
      @sessions[session_id][:user_id] = user.id.to_s
      { ok: true, user_id: user.id.to_s, session_id: @sessions.rebuild!(session_id) }
    end
  end

  # Sensitive business action. It runs only for a session holding a confirmation
  # bound to itself; every allowed and denied call is observed via counters.
  class SensitiveAction
    attr_reader :business_call_count, :denial_count

    def initialize(sessions, confirmations)
      @sessions = sessions
      @confirmations = confirmations
      @business_call_count = 0
      @denial_count = 0
    end

    def call(session_id)
      session = @sessions[session_id]
      confirmation_id = session[:confirmation_id]
      allowed = confirmation_id &&
                @confirmations.confirmed_for?(session_id, confirmation_id)

      unless allowed
        @denial_count += 1
        return { ok: false, reason: :confirmation_required }
      end

      @business_call_count += 1
      { ok: true, user_id: session[:user_id] }
    end
  end

  def build_user
    User.create!(
      username: 'support-customer',
      email: 'customer@example.test',
      password: 'secret'
    )
  end

  def issue_temporary_credential(user, mailbox)
    user.generate_magic_login_token!
    mailbox.deliver_magic_login_email(user, user.reload.magic_login_token)
    mailbox.last_token
  end

  # Shared end-to-end scenario. The old window starts a confirmation, support
  # recovers ordinary access through the temporary credential mid-confirmation,
  # the stale confirmation then completes, the rebuilt session attempts a
  # sensitive action, the credential is replayed, and finally a new window runs
  # its own independent confirmation.
  def run_scenario(confirmations, recovery_class: MagicLoginRecovery)
    sessions = SessionStore.new
    mailbox = MagicLoginMailboxFake.new
    recovery = recovery_class.new(User, sessions)
    sensitive_action = SensitiveAction.new(sessions, confirmations)

    user = build_user
    token = issue_temporary_credential(user, mailbox)

    old_window = sessions.open!
    sessions[old_window][:user_id] = user.id.to_s
    old_confirmation = confirmations.start!(old_window, user.id.to_s)
    sessions[old_window][:confirmation_id] = old_confirmation

    recovery_window = sessions.open!
    recovery_result = recovery.call(recovery_window, token)
    rebuilt_window = recovery_result[:session_id]

    # The old window finishes its confirmation during the recovery callback and
    # the browser submits it against the rebuilt session, which never started
    # that confirmation. A secure coordinator rejects the cross-session attach;
    # the broken double re-binds and accepts it.
    stale_completion = confirmations.complete!(rebuilt_window, old_confirmation)
    if stale_completion
      sessions[rebuilt_window][:confirmation_id] = old_confirmation
    end

    rebuilt_sensitive_before = sensitive_action.call(rebuilt_window)
    replay_result = recovery.call(sessions.open!, token)

    new_window = sessions.open!
    sessions[new_window][:user_id] = user.id.to_s
    new_confirmation = confirmations.start!(new_window, user.id.to_s)
    sessions[new_window][:confirmation_id] = new_confirmation
    new_completion = confirmations.complete!(new_window, new_confirmation)
    new_sensitive_result = sensitive_action.call(new_window)

    {
      sessions: sessions, mailbox: mailbox, recovery: recovery,
      sensitive_action: sensitive_action, confirmations: confirmations, user: user,
      old_window: old_window, recovery_window: recovery_window,
      rebuilt_window: rebuilt_window, new_window: new_window,
      old_confirmation: old_confirmation, new_confirmation: new_confirmation,
      recovery_result: recovery_result, replay_result: replay_result,
      stale_completion: stale_completion, new_completion: new_completion,
      rebuilt_sensitive_before: rebuilt_sensitive_before,
      new_sensitive_result: new_sensitive_result
    }
  end

  # The three reusable security properties, shared by the happy path and by the
  # broken-double mutation checks.
  def expect_one_time_credential(result)
    expect(result[:mailbox].deliveries.size).to eq 1
    expect(result[:mailbox].deliveries.first[:email]).to eq 'customer@example.test'
    expect(result[:recovery].consumption_count).to eq 1
    expect(result[:recovery_result][:ok]).to be true
    expect(result[:replay_result][:ok]).to be false
    expect(result[:user].reload.magic_login_token).to be_nil
  end

  def expect_session_rebuild_and_isolation(result)
    expect(result[:recovery_result][:session_id]).not_to eq result[:recovery_window]
    expect(result[:sessions].exists?(result[:recovery_window])).to be false
    expect(result[:sessions].exists?(result[:old_window])).to be true
    expect(result[:sessions][result[:rebuilt_window]][:user_id]).to eq result[:user].id.to_s
    expect(result[:sessions][result[:rebuilt_window]][:restored]).to be true
    expect(result[:sessions][result[:rebuilt_window]][:confirmation_id]).to be_nil
    expect(result[:stale_completion]).to be false
    expect(result[:confirmations].rejections).to eq 1
    expect(
      result[:confirmations].confirmed_for?(result[:rebuilt_window], result[:old_confirmation])
    ).to be false
    expect(result[:rebuilt_sensitive_before]).to eq({ ok: false, reason: :confirmation_required })
  end

  def expect_independent_new_window_confirmation(result)
    expect(result[:new_completion]).to be true
    expect(result[:confirmations].start_count).to eq 2
    expect(result[:confirmations].complete_count).to eq 1
    expect(result[:new_sensitive_result]).to eq({ ok: true, user_id: result[:user].id.to_s })
    expect(result[:sensitive_action].business_call_count).to eq 1
    expect(result[:sensitive_action].denial_count).to eq 1
  end

  before(:all) do
    MigrationHelper.migrate("#{Rails.root}/db/migrate/magic_login")
    User.reset_column_information
    sorcery_reload!([:magic_login])
  end

  after(:all) do
    MigrationHelper.rollback("#{Rails.root}/db/migrate/magic_login")
    User.reset_column_information
  end

  before do
    User.sorcery_adapter.delete_all
  end

  after do
    User.sorcery_config.reset!
  end

  context 'with a session-scoped confirmation coordinator' do
    let(:result) { run_scenario(ConfirmationCoordinator.new) }

    it 'issues the temporary credential to the fake mailbox and consumes it once' do
      expect_one_time_credential(result)
      expect(result[:recovery].rejection_count).to eq 1
      expect(result[:replay_result][:reason]).to eq :user_not_found
    end

    it 'rebuilds an ordinary session that the old window confirmation cannot attach to' do
      expect_session_rebuild_and_isolation(result)
    end

    it 'keeps the sensitive action denied until the new window confirms independently' do
      expect_independent_new_window_confirmation(result)
    end

    it 'rejects a confirmation that the controllable clock has expired' do
      coordinator = ConfirmationCoordinator.new(ttl: 60)
      sessions = result[:sessions]
      window = sessions.open!
      confirmation = coordinator.start!(window, result[:user].id.to_s)

      Timecop.travel(Time.now.in_time_zone + 120.seconds) do
        expect(coordinator.complete!(window, confirmation)).to be false
      end
      expect(coordinator.rejections).to eq 1
    end
  end

  context 'with a broken double that reuses the old window confirmation' do
    let(:result) { run_scenario(CrossSessionConfirmationDouble.new) }

    it 'fails the session isolation and independent-confirmation assertions' do
      isolation_failure = nil
      begin
        expect_session_rebuild_and_isolation(result)
      rescue RSpec::Expectations::ExpectationNotMetError => e
        isolation_failure = e
      end
      expect(isolation_failure).to be_a(RSpec::Expectations::ExpectationNotMetError)

      independent_failure = nil
      begin
        expect_independent_new_window_confirmation(result)
      rescue RSpec::Expectations::ExpectationNotMetError => e
        independent_failure = e
      end
      expect(independent_failure).to be_a(RSpec::Expectations::ExpectationNotMetError)

      # Concrete vulnerable behaviour the double introduces.
      expect(result[:stale_completion]).to be true
      expect(result[:confirmations].rejections).to eq 0
      expect(result[:rebuilt_sensitive_before]).to eq({ ok: true, user_id: result[:user].id.to_s })
      expect(result[:sensitive_action].business_call_count).to eq 2
    end

    it 'still leaves the one-time credential property intact, showing the guards are separate' do
      expect_one_time_credential(result)
    end
  end

  context 'with a broken double that allows credential reuse' do
    let(:result) do
      run_scenario(ConfirmationCoordinator.new, recovery_class: ReusableCredentialRecoveryDouble)
    end

    it 'fails the one-time credential assertion because the spent token is replayed' do
      credential_failure = nil
      begin
        expect_one_time_credential(result)
      rescue RSpec::Expectations::ExpectationNotMetError => e
        credential_failure = e
      end
      expect(credential_failure).to be_a(RSpec::Expectations::ExpectationNotMetError)

      expect(result[:recovery].consumption_count).to eq 2
      expect(result[:replay_result][:ok]).to be true
    end

    it 'does not weaken the separate confirmation boundary' do
      expect_session_rebuild_and_isolation(result)
      expect_independent_new_window_confirmation(result)
    end
  end
end
