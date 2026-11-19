require "flipper/dsl"
require "flipper/adapters/actor_expiration"

module Flipper
  # Public: A Flipper DSL for integrations that let operator-approved actors
  # expire. It is the same as Flipper.new, except the adapter is wrapped so
  # actor grants can carry expires_at / expires_in and be reaped later.
  #
  #   flipper = Flipper::Managed.new(Flipper::Adapters::Memory.new)
  #   flipper.enable_actor :pilot, employee, expires_in: 3600
  #   flipper.reap_expired_actors(:pilot)
  #
  # Boolean, group, percentage, and expression gates keep their usual
  # behavior. Expiration only affects the actor gate.
  class Managed < DSL
    # Public: The wrapper that owns actor expiration metadata.
    attr_reader :expiration_adapter

    def initialize(adapter, clock: nil, **options)
      @expiration_adapter = if adapter.is_a?(Adapters::ActorExpiration)
        adapter.tap { |existing| existing.clock = clock if clock }
      else
        # An adapter that already enforces expiration (such as Memory) keeps
        # its native metadata and clock. Layering another wrapper would give
        # one grant two independent expiration times.
        if adapter.actor_expiration?
          if clock && adapter.respond_to?(:clock=)
            adapter.clock = clock
            adapter
          elsif clock
            Adapters::ActorExpiration.new(adapter, clock: clock)
          else
            adapter
          end
        else
          Adapters::ActorExpiration.new(adapter, clock: clock)
        end
      end

      super(@expiration_adapter, options)
    end
  end

  # Public: Build a Flipper::Managed DSL. See Flipper::Managed.
  def self.managed(adapter, clock: nil, **options)
    Managed.new(adapter, clock: clock, **options)
  end
end
