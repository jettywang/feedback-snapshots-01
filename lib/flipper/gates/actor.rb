module Flipper
  module Gates
    class Actor < Gate
      # Internal: The name of the gate. Used for instrumentation, etc.
      def name
        :actor
      end

      # Internal: Name converted to value safe for adapter.
      def key
        :actors
      end

      def data_type
        :set
      end

      def enabled?(value)
        !value.empty?
      end

      # Internal: Checks if the gate is open for an actor.
      #
      # Returns true if gate open for actor, false if not.
      def open?(context)
        return false unless context.actors?

        enabled_actors = context.values.actors
        return false if enabled_actors.empty?

        # The actor gate only counts actors whose grant has not expired. An
        # adapter may expose expired grants (until they are reaped); they must
        # never open the gate.
        expirations = context.values.actor_expirations
        # No expiring grants at all: skip the per-actor metadata hash lookups.
        if expirations.nil? || expirations.empty?
          context.actors.any? { |actor| enabled_actors.include?(actor.value) }
        else
          context.actors.any? do |actor|
            enabled_actors.include?(actor.value) &&
              !context.values.actor_expired?(actor.value)
          end
        end
      end

      def wrap(actor)
        Types::Actor.wrap(actor)
      end

      def protects?(actor)
        Types::Actor.wrappable?(actor)
      end
    end
  end
end
