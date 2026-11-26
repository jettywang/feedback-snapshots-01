# frozen_string_literal: true

module TicketService
  # In-memory audit trail for permit checks. Every entry records which
  # tenant the principal belongs to and which claim layer the decision
  # was based on, so reviewers can see exactly what took effect.
  class AuditLog
    Entry = Struct.new(:at, :tenant, :provider, :uid, :name, :operation, :status, :layer, :key, :actual) do
      def to_h
        {
          at: at, tenant: tenant, provider: provider, uid: uid, name: name,
          operation: operation, status: status, layer: layer, key: key, actual: actual
        }
      end
    end

    attr_reader :entries

    def initialize
      @entries = []
    end

    def record(decision:, provider:, uid:, name:)
      entry = Entry.new(
        Time.now.utc, decision.tenant, provider, uid, name,
        decision.operation, decision.status, decision.layer, decision.key, decision.actual
      )
      @entries << entry
      entry
    end
  end
end
