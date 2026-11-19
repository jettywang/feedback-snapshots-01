require "flipper/adapter"
require "flipper/typecast"

module Flipper
  module Adapters
    # Public: Adapter for storing everything in memory.
    # Useful for tests/specs.
    class Memory
      include ::Flipper::Adapter

      # Private: Shared frozen config for unknown features. Gate values
      # returned by get are treated as read-only.
      DEFAULT_CONFIG = default_config.each_value(&:freeze).freeze

      # Public
      def initialize(source = nil, threadsafe: true, clock: nil)
        @source = Typecast.features_hash(source)
        @lock = Mutex.new if threadsafe
        @sync_version = nil
        @actor_expirations = {}
        @clock = clock

        # A get_all snapshot carries expiration metadata next to the gates.
        # Keep it out of @source so it never becomes a gate value.
        extract_actor_expirations(@source).each do |feature_key, expirations|
          @actor_expirations[feature_key] = expirations
        end
      end

      # Public: Does this adapter support per-actor expiration? Memory does,
      # so tests and local development can exercise expiration end to end.
      def actor_expiration?
        true
      end

      # Public: Expiration metadata for actor grants on a feature, keyed by
      # flipper_id. Entries are kept after expiration until they are reaped,
      # so storage can be inspected.
      def actor_expirations(feature)
        raise ArgumentError, '#actor_expirations requires a feature' if feature.nil?

        synchronize { (@actor_expirations[feature.key] || {}).dup }
      end

      # Public: Remove actor grants whose expiration has passed at now, but
      # only if the expiration is still the one observed when this call began.
      # Returns the [feature_key, actor_id] pairs removed. Each removal is
      # checked again under the same lock as enable/disable, so a grant
      # extended after the snapshot is never removed by a stale reap.
      def reap_expired_actors(now: nil, feature: nil)
        now ||= self.now

        # Snapshot outside the write lock. A concurrent extension then changes
        # the current expiration and the removal check below skips it.
        snapshot = synchronize do
          expired_feature_keys(feature).each_with_object({}) do |feature_key, copy|
            values = @actor_expirations[feature_key]
            copy[feature_key] = values.dup if values
          end
        end

        synchronize do
          snapshot.each_with_object([]) do |(feature_key, observed), removed|
            expirations = @actor_expirations[feature_key]
            actors = @source[feature_key] && @source[feature_key][:actors]
            next unless expirations && actors

            observed.each do |actor_id, observed_expires_at|
              next unless observed_expires_at <= now

              current_expires_at = expirations[actor_id]
              next unless current_expires_at == observed_expires_at
              next unless actors.include?(actor_id)

              actors.delete(actor_id)
              expirations.delete(actor_id)
              removed << [feature_key, actor_id]
            end

            @actor_expirations.delete(feature_key) if expirations.empty?
          end
        end
      end

      # Public: The clock used for expiration checks, computed expirations and
      # reaping. Replace it with a callable in tests to use a fake clock.
      def clock
        @clock ||= -> { Time.now }
      end

      def clock=(value)
        synchronize { @clock = value }
      end

      def now
        source = clock
        if source.respond_to?(:call)
          source.call
        elsif source.respond_to?(:now)
          source.now
        else
          Typecast.to_time(source)
        end
      end

      # Public
      def sync_version
        synchronize { @sync_version }
      end

      # Public
      def sync_version=(version)
        synchronize { @sync_version = version }
      end

      # Public: The set of known features.
      def features
        synchronize { @source.keys }.to_set
      end

      # Public: Adds a feature to the set of known features.
      def add(feature)
        synchronize { @source[feature.key] ||= default_config }
        true
      end

      # Public: Removes a feature from the set of known features and clears
      # all the values for the feature.
      def remove(feature)
        synchronize do
          @source.delete(feature.key)
          @actor_expirations.delete(feature.key)
        end
        true
      end

      # Public: Clears all the gate values for a feature.
      def clear(feature)
        synchronize do
          @source[feature.key] = default_config
          @actor_expirations.delete(feature.key)
        end
        true
      end

      # Public
      def get(feature)
        synchronize { @source[feature.key] } || DEFAULT_CONFIG
      end

      def get_multi(features)
        synchronize do
          result = {}
          features.each do |feature|
            result[feature.key] = @source[feature.key] || DEFAULT_CONFIG
          end
          result
        end
      end

      def get_all(**kwargs)
        synchronize do
          result = Typecast.features_hash(@source)
          @actor_expirations.each do |feature_key, expirations|
            next if expirations.empty?
            next unless result.key?(feature_key)

            result[feature_key][:actor_expirations] = expirations.dup
          end
          result
        end
      end

      # Public
      def enable(feature, gate, thing)
        synchronize do
          @source[feature.key] ||= default_config

          case gate.data_type
          when :boolean
            @source[feature.key] = default_config
            @source[feature.key][gate.key] = thing.value.to_s
            @actor_expirations.delete(feature.key)
          when :integer
            @source[feature.key][gate.key] = thing.value.to_s
          when :set
            @source[feature.key][gate.key] << thing.value.to_s
            record_actor_expiration(feature, gate, thing)
          when :json
            @source[feature.key][gate.key] = thing.value
          else
            raise "#{gate} is not supported by this adapter yet"
          end

          true
        end
      end

      # Public
      def disable(feature, gate, thing)
        synchronize do
          @source[feature.key] ||= default_config

          case gate.data_type
          when :boolean
            @source[feature.key] = default_config
            @actor_expirations.delete(feature.key)
          when :integer
            @source[feature.key][gate.key] = thing.value.to_s
          when :set
            @source[feature.key][gate.key].delete thing.value.to_s
            forget_actor_expiration(feature, gate, thing)
          when :json
            @source[feature.key].delete(gate.key)
          else
            raise "#{gate} is not supported by this adapter yet"
          end

          true
        end
      end

      # Public
      def inspect
        attributes = [
          'name=:memory',
          "source=#{@source.inspect}",
        ]
        "#<#{self.class.name}:#{object_id} #{attributes.join(', ')}>"
      end

      # Public: a more efficient implementation of import for this adapter.
      # Keeps the current flags if the source's are an older sync version.
      def import(source)
        adapter = self.class.from(source)
        get_all = Typecast.features_hash(adapter.get_all)
        expirations = extract_actor_expirations(get_all)
        version = adapter.sync_version

        synchronize do
          unless version&.older_than?(@sync_version)
            @source.replace(get_all)
            @actor_expirations = expirations
            @sync_version = version if version
          end
        end

        true
      end

      private

      # Private: Record an actor grant's expiration, replacing any earlier one.
      # Only the actor gate carries expiration metadata.
      def record_actor_expiration(feature, gate, thing)
        return unless gate.is_a?(Flipper::Gates::Actor)
        actor_expirations = (@actor_expirations[feature.key] ||= {})

        unless thing.respond_to?(:expiration?) && thing.expiration?
          actor_expirations.delete(thing.value.to_s)
          @actor_expirations.delete(feature.key) if actor_expirations.empty?
          return
        end

        actor_expirations[thing.value.to_s] = expiration_for(thing)
      end

      def expiration_for(thing)
        if thing.expires_at
          Typecast.to_time(thing.expires_at)
        else
          (now + thing.expires_in).utc
        end
      end

      # Private: Remove expiration metadata when the grant itself is removed.
      def forget_actor_expiration(feature, gate, thing)
        return unless gate.is_a?(Flipper::Gates::Actor)

        actor_expirations = @actor_expirations[feature.key]
        return unless actor_expirations

        actor_expirations.delete(thing.value.to_s)
        @actor_expirations.delete(feature.key) if actor_expirations.empty?
      end

      # Private: Remove expiration metadata from an imported features hash so
      # it never becomes a gate value, and normalize the times for storage.
      def extract_actor_expirations(get_all)
        get_all.each_with_object({}) do |(feature_key, gates), result|
          expirations = gates.delete(:actor_expirations)
          next if expirations.nil? || expirations.empty?

          result[feature_key] = expirations.each_with_object({}) do |(actor_id, expires_at), normalized|
            normalized[actor_id.to_s] = Typecast.to_time(expires_at)
          end
        end
      end

      def expired_feature_keys(feature)
        if feature
          [feature.key]
        else
          @source.keys
        end
      end

      def synchronize(&block)
        if @lock
          @lock.synchronize(&block)
        else
          block.call
        end
      end
    end
  end
end
