# frozen_string_literal: true

module WebAuthn
  class BackupReceipt
    attr_reader :approved_actions, :version, :basis

    def initialize(approved_actions:, version:, basis:)
      @approved_actions = approved_actions.map(&:to_sym).freeze
      @version = version
      @basis = basis&.to_sym
      freeze
    end

    def approved?
      !approved_actions.empty?
    end

    def approved_action?(action)
      approved_actions.include?(action.to_sym)
    end

    def to_h
      {
        approved_actions: approved_actions,
        version: version,
        basis: basis
      }
    end
  end
end
