# frozen_string_literal: true

require "webauthn/backup_attributes"

module WebAuthn
  class BackupPolicy
    Decision = Struct.new(:approved_actions, :basis, :writable, keyword_init: true) do
      def writable?
        writable != false
      end
    end

    attr_reader :daily_actions, :sensitive_actions, :legacy_actions

    def initialize(daily_actions: [:login], sensitive_actions: [:financial], legacy_actions: [:login])
      @daily_actions = normalize_actions(daily_actions)
      @sensitive_actions = normalize_actions(sensitive_actions)
      @legacy_actions = normalize_actions(legacy_actions)
    end

    def registration(attributes, requested_actions: nil)
      decide(attributes, requested_actions, phase: :registration)
    end

    def migration(attributes, requested_actions: nil)
      decide(attributes, requested_actions, phase: :migration)
    end

    def authentication(stored:, observed:, requested_actions: nil)
      actions = requested_action_set(requested_actions)

      if eligibility_mismatch?(stored, observed)
        return build_decision([], :eligibility_mismatch, writable: false)
      end

      if stored.unknown_eligibility? || !stored.trusted_source?
        return build_decision(actions & legacy_actions, :legacy_daily_policy)
      end

      if stored.device_bound?
        approved = actions & daily_actions
        approved |= actions & sensitive_actions

        build_decision(approved, :device_bound_authentication)
      else
        basis = stored.state == observed.state ? :backup_state_unchanged : :backup_state_changed

        build_decision(actions & daily_actions, basis)
      end
    end

    def next_attributes(stored:, observed:)
      return stored if eligibility_mismatch?(stored, observed)

      BackupAttributes.new(
        eligible: stored.eligible,
        state: observed.state,
        source: stored.source
      )
    end

    def all_actions
      (daily_actions + sensitive_actions + legacy_actions).uniq
    end

    private

    def decide(attributes, requested_actions, phase:)
      actions = requested_action_set(requested_actions)
      approved = actions & legacy_actions

      if attributes.unknown_eligibility?
        basis = :"legacy_#{phase}"
      elsif attributes.device_bound? && attributes.trusted_source?
        approved = actions & daily_actions
        approved |= actions & sensitive_actions
        basis = :"device_bound_#{phase}"
      elsif attributes.syncable?
        approved = actions & daily_actions
        basis = :"synced_#{phase}"
      else
        basis = :"untrusted_#{phase}"
      end

      build_decision(approved, basis)
    end

    def eligibility_mismatch?(stored, observed)
      stored.known_eligibility? &&
        observed.known_eligibility? &&
        stored.eligible != observed.eligible
    end

    def requested_action_set(requested_actions)
      actions = requested_actions.nil? ? all_actions : requested_actions
      normalize_actions(actions)
    end

    def normalize_actions(actions)
      Array(actions).map(&:to_sym).uniq.freeze
    end

    def build_decision(actions, basis, writable: true)
      Decision.new(
        approved_actions: normalize_actions(actions),
        basis: basis,
        writable: writable
      )
    end
  end
end
