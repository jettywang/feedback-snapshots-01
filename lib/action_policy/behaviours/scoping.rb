# frozen_string_literal: true

require "action_policy/scope_contract"

module ActionPolicy
  module Behaviours
    # Adds `authorized_scop` method to behaviour
    module Scoping
      # Apply scope to the target of the specified type.
      #
      # NOTE: policy lookup consists of the following steps:
      #   - first, check whether `with` option is present
      #   - secondly, try to infer policy class from `target` (non-raising lookup)
      #   - use `implicit_authorization_target` if none of the above works.
      #
      # When `contract: true` is passed, the result is wrapped into
      # an ActionPolicy::ScopeContract recording the authorized scope
      # it was derived from (see ActionPolicy::ScopeContract).
      def authorized_scope(target, type: nil, as: :default, scope_options: nil, contract: false, **options)
        options[:context] && (options[:context] = authorization_context.merge(options[:context]))

        policy = policy_for(record: target, allow_nil: true, **options)
        policy ||= policy_for(record: implicit_authorization_target!, **options)

        type ||= authorization_scope_type_for(policy, target)
        name = as

        scoped = Authorizer.scopify(target, policy, type:, name:, scope_options:)

        return scoped unless contract

        ScopeContract.authorize(scoped, policy: policy.class, type: type, name: name)
      end

      # For backward compatibility
      alias_method :authorized, :authorized_scope

      # Infer scope type for target if none provided.
      # Raises an exception if type couldn't be inferred.
      def authorization_scope_type_for(policy, target)
        policy.resolve_scope_type(target)
      end
    end
  end
end
