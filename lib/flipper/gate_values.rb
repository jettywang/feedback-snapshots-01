require 'set'
require 'flipper/typecast'

module Flipper
  class GateValues
    attr_reader :boolean
    attr_reader :actors
    attr_reader :groups
    attr_reader :expression
    attr_reader :percentage_of_actors
    attr_reader :percentage_of_time

    # Public: Expiration metadata for actor grants, keyed by the actor's
    # flipper_id. Missing actor IDs are grants without an expiration.
    attr_reader :actor_expirations

    # Public: The Time at which actor expirations should be evaluated. Adapters
    # that support expiration pass their clock time; otherwise wall clock time
    # is used.
    attr_reader :actor_expiration_now

    def initialize(adapter_values = nil, actor_expirations: nil, actor_expiration_now: nil, **keyword_values)
      adapter_values ||= keyword_values
      if actor_expirations
        adapter_values = adapter_values.merge(actor_expirations: actor_expirations)
      end
      if actor_expiration_now
        adapter_values = adapter_values.merge(actor_expiration_now: actor_expiration_now)
      end

      @boolean = Typecast.to_boolean(adapter_values[:boolean])
      @actors = Typecast.to_set(adapter_values[:actors])
      @groups = Typecast.to_set(adapter_values[:groups])
      @expression = adapter_values[:expression]
      @percentage_of_actors = Typecast.to_number(adapter_values[:percentage_of_actors])
      @percentage_of_time = Typecast.to_number(adapter_values[:percentage_of_time])
      @actor_expirations = normalize_expirations(adapter_values[:actor_expirations])
      @actor_expiration_now = adapter_values[:actor_expiration_now] || Time.now
    end

    # Public: The expiration Time for an actor, if one is recorded.
    def actor_expires_at(actor_or_id)
      actor_id = actor_or_id.respond_to?(:value) ? actor_or_id.value : actor_or_id
      actor_expirations[actor_id.to_s]
    end

    # Public: Has this actor's grant expired at the evaluation time?
    def actor_expired?(actor_or_id)
      expires_at = actor_expires_at(actor_or_id)
      expires_at ? expires_at <= actor_expiration_now : false
    end

    def eql?(other)
      self.class.eql?(other.class) &&
        boolean == other.boolean &&
        actors == other.actors &&
        groups == other.groups &&
        actor_expirations == other.actor_expirations &&
        expression == other.expression &&
        percentage_of_actors == other.percentage_of_actors &&
        percentage_of_time == other.percentage_of_time
    end
    alias_method :==, :eql?

    private

    def normalize_expirations(expirations)
      return {} if expirations.nil? || expirations.empty?

      normalized = {}
      expirations.each do |actor_id, expires_at|
        normalized[actor_id.to_s] = Typecast.to_time(expires_at)
      end
      normalized
    end
  end
end
