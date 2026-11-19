# frozen_string_literal: true

require "action_policy/utils/context_cache_key"

module ActionPolicy
  # Tracks the trusted authorization context of the authorization in progress.
  #
  # A policy can declare a context key as `trusted: true`, which means its value
  # must be provided by the trusted ingress (a controller, channel, job, etc.)
  # rather than derived by another policy.
  #
  # The frame is opened when a rule is applied (or a scope is applied) to a
  # policy that has an authorization context. Policies created inside the frame
  # are _derived_: they may only forward the exact trusted values from the
  # frame. A missing trusted key fails closed and is never inherited from an
  # earlier authorization or a memoized policy.
  #
  # The frame is fiber-local (`Thread#[]`), so concurrent authorizations cannot
  # observe each other's provenance.
  module TrustedContext # :nodoc:
    STORAGE_KEY = :__action_policy_trusted_context__

    class << self
      # Opens a frame for the given policy (unless an authorization is already
      # in progress). Policies without an authorization context don't open a
      # frame, so their nested resolutions aren't constrained.
      def with_policy_context(policy)
        return yield unless policy.respond_to?(:action_policy_trusted_context)

        with_ingress(policy.action_policy_trusted_context) { yield }
      end

      # Opens the trusted frame for the duration of the block. Nested calls keep
      # the frame of the authorization that initiated them.
      def with_ingress(context, &block)
        return yield if active?

        Thread.current[STORAGE_KEY] = (context || {}).dup.freeze

        begin
          block.call
        ensure
          Thread.current[STORAGE_KEY] = nil
        end
      end

      def active? = !Thread.current[STORAGE_KEY].nil?

      def context = Thread.current[STORAGE_KEY] || {}

      # A memoization scope that separates derived resolutions from the
      # ingress one (and from resolutions made under another trusted context).
      # Returns nil when no authorization is in progress.
      def scope = active? ? "d/#{Utils::ContextCacheKey.call(context)}" : nil

      # Ensures the trusted keys declared by a derived policy are only forwarded
      # with the exact values provided for the current authorization.
      def validate!(authorization_targets, params)
        return unless active?

        trusted_context = context

        authorization_targets.each do |id, opts|
          next unless opts[:trusted]

          if params.key?(id)
            value = params[id]

            # An explicit nil can only mirror an already absent identity; it
            # can't drop a real one (the constructor enforces nilability).
            next if value.nil? && trusted_context[id].nil?
            next if trusted_context.key?(id) && trusted_context[id] == value

            raise UntrustedAuthorizationContext.new(id)
          end

          # An absent required identity must fail; it must never be inherited
          # from the frame or from a previously memoized policy.
          next if opts[:optional]

          raise AuthorizationContextMissing, id
        end
      end

      # The subset of the given values that is trusted at the current point.
      #
      # At the ingress, every provided value is trusted. For a derived policy,
      # only values that match the current frame remain trusted, so an
      # intermediate policy can't launder a value it added itself.
      def trusted_values(params)
        frame = Thread.current[STORAGE_KEY]
        return params.dup.freeze if frame.nil?

        params.each_with_object({}) do |(key, value), trusted|
          trusted[key] = value if frame.key?(key) && frame[key] == value
        end.freeze
      end

      def clear!
        Thread.current[STORAGE_KEY] = nil
      end
    end
  end
end
