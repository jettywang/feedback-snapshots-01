# frozen_string_literal: true

module TicketService
  # Optional view over an OmniAuth auth hash that answers "may this
  # principal perform this operation?". It never reads the merged profile:
  # every check goes through the PolicyRegistry and then reads the claim
  # from the exact approved layer of the auth hash, so a same-named key in
  # the other layer (or a lucky merge order) cannot stand in for an
  # approved source.
  class PermissionView
    # Result of a single permit check. +status+ is one of:
    #   :granted               - approved source present and matching
    #   :denied_claim_missing  - approved layer has no such key
    #   :denied_claim_mismatch - approved layer's key holds a different value
    #   :unavailable_no_policy - tenant/operation has no approved source at all
    Decision = Struct.new(:operation, :tenant, :status, :layer, :key, :expected, :actual) do
      def granted?
        status == :granted
      end

      def to_h
        {
          operation: operation, tenant: tenant, status: status,
          layer: layer, key: key, expected: expected, actual: actual
        }
      end
    end

    attr_reader :auth_hash, :tenant

    def initialize(auth_hash, tenant:, registry:)
      @auth_hash = auth_hash
      @tenant = tenant.to_s
      @registry = registry
    end

    def decision(operation)
      policy = @registry.policy_for(tenant: tenant, operation: operation)
      unless policy
        return Decision.new(operation.to_sym, tenant, :unavailable_no_policy, nil, nil, nil, nil)
      end

      layer_hash = auth_hash[policy.layer.to_s] || auth_hash[policy.layer]
      actual = layer_hash[policy.key] if layer_hash.is_a?(Hash)

      status =
        if actual.nil?
          :denied_claim_missing
        elsif actual == policy.value
          :granted
        else
          :denied_claim_mismatch
        end

      Decision.new(operation.to_sym, tenant, status, policy.layer, policy.key, policy.value, actual)
    end

    def granted?(operation)
      decision(operation).granted?
    end
  end
end
