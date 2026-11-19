require "flipper/adapters/wrapper"

module Flipper
  module Adapters
    # Public: Adapter wrapper that gives actor grants an expiration. It works
    # with any adapter, keeps normal boolean, group, percentage, and
    # expression gates unchanged, and leaves expired actor grants in the
    # wrapped adapter until #reap_expired_actors removes them.
    #
    # Expiration metadata is held by this wrapper. Pass a shared +expirations+
    # Hash if several wrapper instances in one process should see the same
    # metadata. Expired entries stop opening the actor gate immediately; only
    # an explicit reap deletes the stored grant.
    class ActorExpiration < Wrapper
      # Public: The clock callable. Defaults to wall clock time.
      attr_reader :clock

      # Public: The Hash of feature key => {actor_id => expires_at}.
      attr_reader :expirations

      def initialize(adapter, clock: nil, expirations: nil)
        super(adapter)
        @clock = clock
        @expirations = expirations || {}
        @lock = Mutex.new
      end

      # Public: Replace the clock. Accepts a callable, an object with #now, or
      # a Time. Expiration checks and reaping share it.
      def clock=(value)
        @lock.synchronize { @clock = value }
      end

      # Public: The wrapper always supports actor expiration.
      def actor_expiration?
        true
      end

      # Public: Expiration metadata for the feature's actor grants, keyed by
      # flipper_id. Expired grants stay here until they are reaped.
      def actor_expirations(feature)
        @lock.synchronize { copy_expirations(feature.key) }
      end

      # Public: The wrapper's notion of now, shared by checks and reaping.
      # The clock may be a callable, an object with #now, or a Time.
      def now
        source = @clock
        return Time.now unless source

        if source.respond_to?(:call)
          source.call
        elsif source.respond_to?(:now)
          source.now
        else
          Typecast.to_time(source)
        end
      end

      def get(feature)
        with_expirations(feature.key, @adapter.get(feature))
      end

      def get_multi(features)
        result = @adapter.get_multi(features)
        features.each do |feature|
          result[feature.key] = with_expirations(feature.key, result[feature.key])
        end
        result
      end

      def get_all(**kwargs)
        result = @adapter.get_all(**kwargs)
        result.keys.each do |key|
          result[key] = with_expirations(key, result[key])
        end
        result
      end

      def enable(feature, gate, thing)
        @lock.synchronize do
          result = @adapter.enable(feature, gate, storage_thing(gate, thing))

          if actor_gate?(gate)
            record_expiration(feature, thing, now) if result
          elsif gate.data_type == :boolean && result
            # Enabling everyone clears the other gates, so it also clears
            # their actor expirations.
            @expirations.delete(feature.key)
          end

          result
        end
      end

      def disable(feature, gate, thing)
        @lock.synchronize do
          if actor_gate?(gate)
            # Only forget metadata if the grant is really gone from storage.
            # Adapters may refuse writes; don't silently lose the expiry.
            removed = @adapter.disable(feature, gate, storage_thing(gate, thing))
            forget_expiration(feature, thing) if removed
            removed
          else
            @expirations.delete(feature.key) if gate.data_type == :boolean
            @adapter.disable(feature, gate, thing)
          end
        end
      end

      def clear(feature)
        @lock.synchronize do
          @adapter.clear(feature).tap { @expirations.delete(feature.key) }
        end
      end

      def remove(feature)
        @lock.synchronize do
          @adapter.remove(feature).tap { @expirations.delete(feature.key) }
        end
      end

      # Public: Export the flags with expiration metadata. The default
      # Wrapper#export would delegate to the wrapped adapter and lose the
      # metadata this wrapper owns.
      def export(format: :json, version: 1)
        Flipper::Exporter.build(format: format, version: version).call(self)
      end

      # Public: Import flags and expiration metadata. Expirations are taken
      # from the export's get_all snapshot, then the wrapped adapter imports
      # the gates themselves.
      def import(source)
        source_adapter = self.class.from(source)
        snapshot = source_adapter.get_all
        imported_expirations = snapshot.each_with_object({}) do |(feature_key, gates), result|
          expirations = gates[:actor_expirations]
          next if expirations.nil? || expirations.empty?

          result[feature_key] = expirations.each_with_object({}) do |(actor_id, expires_at), normalized|
            normalized[actor_id.to_s] = Typecast.to_time(expires_at)
          end
        end

        @lock.synchronize do
          result = @adapter.import(source)
          @expirations = imported_expirations if result
          result
        end
      end

      # Public: Remove actor grants whose expiration has passed at +now+.
      # Each grant is removed only while it still has the expiration that was
      # observed at the start of this call, so an approval extended during
      # the reap is kept.
      #
      # Returns an Array of [feature_key, actor_id] pairs removed.
      def reap_expired_actors(now: nil, feature: nil)
        now ||= self.now

        # Snapshot before reaping. A grant extended after this snapshot has a
        # different current expiration below and is left alone.
        snapshot = @lock.synchronize do
          keys = feature ? [feature.key] : @expirations.keys.to_a
          keys.each_with_object({}) do |key, copy|
            values = @expirations[key]
            copy[key] = values.dup if values
          end
        end

        @lock.synchronize do
          snapshot.each_with_object([]) do |(feature_key, observed), removed|
            expirations = @expirations[feature_key]
            next unless expirations

            actor_feature = Flipper::Feature.new(feature_key, @adapter)
            actors = @adapter.get(actor_feature)[:actors] || Set.new

            observed.each do |actor_id, observed_expires_at|
              next unless observed_expires_at <= now

              current_expires_at = expirations[actor_id]
              next unless current_expires_at == observed_expires_at
              next unless actors.include?(actor_id)

              @adapter.disable(actor_feature, Flipper::Gates::Actor.new,
                               Flipper::Types::Actor.new(Flipper::Actor.new(actor_id)))
              expirations.delete(actor_id)
              removed << [feature_key, actor_id]
            end

            @expirations.delete(feature_key) if expirations.empty?
          end
        end
      end

      private

      def actor_gate?(gate)
        gate.is_a?(Flipper::Gates::Actor)
      end

      def record_expiration(feature, actor, now)
        actor_expirations = (@expirations[feature.key] ||= {})

        unless actor.respond_to?(:expiration?) && actor.expiration?
          actor_expirations.delete(actor.value.to_s)
          @expirations.delete(feature.key) if actor_expirations.empty?
          return
        end

        expires_at = if actor.expires_at
          Typecast.to_time(actor.expires_at)
        else
          (now + actor.expires_in).utc
        end

        actor_expirations[actor.value.to_s] = expires_at
      end

      def forget_expiration(feature, actor)
        actor_expirations = @expirations[feature.key]
        return unless actor_expirations

        actor_expirations.delete(actor.value.to_s)
        @expirations.delete(feature.key) if actor_expirations.empty?
      end

      def copy_expirations(feature_key)
        (@expirations[feature_key] || {}).dup
      end

      def with_expirations(feature_key, gate_values)
        return gate_values unless gate_values.respond_to?(:merge)

        expirations = @lock.synchronize { copy_expirations(feature_key) }
        return gate_values if expirations.empty?

        gate_values.merge(actor_expirations: expirations)
      end

      # Private: The wrapped adapter stores the actor ID only. This wrapper
      # owns expiration metadata and its clock.
      def storage_thing(gate, thing)
        return thing unless actor_gate?(gate)
        return thing unless thing.respond_to?(:expiration?) && thing.expiration?

        Flipper::Types::Actor.new(thing.actor)
      end
    end
  end
end
