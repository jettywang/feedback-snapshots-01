# frozen_string_literal: true

module WebAuthn
  class BackupAttributes
    TRUSTED_SOURCES = [:registration, :migration, :u2f_migration].freeze

    attr_reader :eligible, :state, :source

    def self.from_credential(credential, source:)
      new(
        eligible: credential.backup_eligible?,
        state: credential.backed_up?,
        source: source
      )
    end

    def initialize(eligible:, state:, source:)
      unless [true, false, nil].include?(eligible)
        raise ArgumentError, "eligible must be true, false or nil"
      end

      unless [true, false, nil].include?(state)
        raise ArgumentError, "state must be true, false or nil"
      end

      if eligible == false && state == true
        raise ArgumentError, "state cannot be true when eligibility is false"
      end

      @eligible = eligible
      @state = state
      @source = source&.to_sym
      freeze
    end

    def known_eligibility?
      !eligible.nil?
    end

    def unknown_eligibility?
      eligible.nil?
    end

    def device_bound?
      eligible == false
    end

    def syncable?
      eligible == true
    end

    def backed_up?
      state == true
    end

    def trusted_source?
      TRUSTED_SOURCES.include?(source)
    end

    def ==(other)
      other.is_a?(BackupAttributes) &&
        other.eligible == eligible &&
        other.state == state &&
        other.source == source
    end
  end
end
