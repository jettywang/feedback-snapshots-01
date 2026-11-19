# frozen_string_literal: true

module ActionPolicy
  module PerThreadCache # :nodoc:
    CACHE_KEY = "action_policy.per_thread_cache"

    class << self
      attr_writer :enabled

      def enabled?() = @enabled == true

      def fetch(key)
        return yield unless enabled?

        store = (Thread.current[CACHE_KEY] ||= {})

        return store[key] if store.key?(key)

        store[key] = yield
      end

      def clear_all
        Thread.current[CACHE_KEY] = {}
      end

      # Runs the block with a fresh, isolated per-thread store and
      # restores the previous one (or discards the store) when the block
      # finishes, even if an exception is raised.
      #
      # Use it to bound an authorization context (e.g. a single background job
      # or a nested call): policies built inside the block are re-used within
      # it, but cannot leak to subsequent operations on the same long-lived
      # thread.
      #
      # Returns the block's result.
      def with_cache
        return yield unless enabled?

        previous_store = Thread.current[CACHE_KEY]
        Thread.current[CACHE_KEY] = {}

        begin
          yield
        ensure
          Thread.current[CACHE_KEY] = previous_store
        end
      end
    end

    # Turn off by default in test env
    self.enabled = !(ENV["RAILS_ENV"] == "test" || ENV["RACK_ENV"] == "test")
  end

  module Behaviours
    # Per-thread memoization for policies.
    #
    # Used by `policy_for` to re-use policy object for records.
    #
    # For long-lived objects (e.g. background worker threads) bound the
    # memoization to an operation with `ActionPolicy::PerThreadCache.with_cache`
    # so the store is reclaimed when the operation ends, or call
    # `ActionPolicy::PerThreadCache.clear_all` to wipe the whole thread store.
    module ThreadMemoized
      class << self
        def prepended(base)
          base.prepend InstanceMethods
        end

        alias_method :included, :prepended
      end

      module InstanceMethods # :nodoc:
        def policy_for(record:, context: nil, resolved_context: nil, cache_key: nil, **opts)
          resolved_context ||= policy_for_context(context)
          cache_key ||= policy_for_cache_key(record:, context: resolved_context, **opts)

          __policy_thread_memoize__(cache_key) { super(record:, **opts, resolved_context:, cache_key:) }
        end
      end

      def __policy_thread_memoize__(cache_key)
        ActionPolicy::PerThreadCache.fetch(cache_key) { yield }
      end
    end
  end
end
