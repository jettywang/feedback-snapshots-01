# frozen_string_literal: true

require "action_policy/ext/policy_cache_key"

module ActionPolicy
  module Utils
    # Builds a stable identity for an authorization context.
    #
    # Unlike a values-only key, this representation includes the context keys
    # and keeps an absent entry distinct from an explicit `nil`. Both are
    # required to avoid reusing a decision (and, thus, an identity) across
    # different authorization contexts.
    module ContextCacheKey
      using ActionPolicy::Ext::PolicyCacheKey

      module_function

      def call(context)
        context
          .map { |key, value| "#{key}=#{value._policy_cache_key(use_object_id: true)}" }
          .sort
          .join(".")
      end
    end
  end
end
