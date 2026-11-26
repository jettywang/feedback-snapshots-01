# frozen_string_literal: true

module TicketService
  # Registry of operation policies. A policy is the ONLY thing that may
  # decide which claim source (auth hash layer + key) is approved to
  # satisfy an operation for a given tenant. Merging user profile fields
  # with extra claims can never widen or replace an approval registered
  # here.
  class PolicyRegistry
    Policy = Struct.new(:tenant, :operation, :layer, :key, :value) do
      def to_h
        { tenant: tenant, operation: operation, layer: layer, key: key, value: value }
      end
    end

    def initialize
      @policies = {}
    end

    # Approve exactly one claim source for (tenant, operation).
    #
    # layer: which auth hash layer the claim must come from (:info or :extra)
    # key:   the claim key inside that layer
    # value: the claim value required for the permit to be granted
    def register(tenant:, operation:, layer:, key:, value:)
      unless %i[info extra].include?(layer.to_sym)
        raise ArgumentError, "layer must be :info or :extra, got #{layer.inspect}"
      end

      @policies[[tenant.to_s, operation.to_sym]] =
        Policy.new(tenant.to_s, operation.to_sym, layer.to_sym, key.to_s, value)
      self
    end

    # Returns the approved Policy for (tenant, operation), or nil when no
    # source has been approved — in which case the permit is unobtainable.
    def policy_for(tenant:, operation:)
      @policies[[tenant.to_s, operation.to_sym]]
    end
  end
end
