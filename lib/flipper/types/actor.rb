module Flipper
  module Types
    class Actor < Type
      def self.wrappable?(actor)
        return false if actor.nil?
        actor.respond_to?(:flipper_id)
      end

      attr_reader :actor

      # Public: The absolute Time at which this grant expires, if any.
      attr_reader :expires_at

      # Public: The number of seconds from grant time at which this grant
      # expires, if any. Resolved by the adapter that enforces expiration.
      attr_reader :expires_in

      def initialize(actor, expires_at: nil, expires_in: nil)
        raise ArgumentError, 'actor cannot be nil' if actor.nil?

        unless actor.respond_to?(:flipper_id)
          raise ArgumentError, "#{actor.inspect} must respond to flipper_id, but does not"
        end

        if expires_at && expires_in
          raise ArgumentError, 'pass either expires_at or expires_in, not both'
        end

        if expires_in && !expires_in.is_a?(Numeric)
          raise ArgumentError, "expires_in must be a number of seconds, but was #{expires_in.inspect}"
        end

        @actor = actor
        @value = actor.flipper_id.to_s
        @expires_at = expires_at
        @expires_in = expires_in
      end

      # Public: Does this actor carry an expiration?
      def expiration?
        !@expires_at.nil? || !@expires_in.nil?
      end

      def respond_to?(*args)
        super || @actor.respond_to?(*args)
      end

      if RUBY_VERSION >= '3.0'
        def method_missing(name, *args, **kwargs, &block)
          @actor.send name, *args, **kwargs, &block
        end
      else
        def method_missing(name, *args, &block)
          @actor.send name, *args, &block
        end
      end
    end
  end
end
