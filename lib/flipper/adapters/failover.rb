require 'set'
require 'flipper/typecast'
require 'flipper/instrumenters/noop'

module Flipper
  module Adapters
    class Failover
      include ::Flipper::Adapter

      # Public: The name of the event instrumented when a read cannot be served
      # by the primary adapter and degrades to the secondary or a safe value.
      InstrumentationName = "failover_degraded.#{InstrumentationNamespace}".freeze

      # Public: Build a new failover instance.
      #
      # primary   - The primary flipper adapter.
      # secondary - The secondary flipper adapter which services reads when
      #             the primary adapter is unavailable.
      # options   - Hash of options:
      #             :dual_write - Boolean, whether to update secondary when
      #                           primary is updated
      #             :errors - Array of exception types for which to failover
      #             :critical_features - Array of feature keys (String or
      #                           Symbol) that must fail closed. When a read of
      #                           one of these features cannot reach the
      #                           primary, its safe value is returned instead of
      #                           the secondary's possibly stale snapshot.
      #             :safe_value - Hash of gate values returned for every
      #                           critical feature when the primary read fails.
      #                           Defaults to all gates disabled. Pass false or
      #                           nil for the same. A Hash is merged over the
      #                           adapter's default config, so gates not
      #                           mentioned stay disabled.
      #             :safe_values - Hash of feature key to gate values. Takes
      #                           precedence over :safe_value for that feature.
      #                           Every key must also be in :critical_features.
      #             :instrumenter - What to use to instrument degraded reads.
      #
      # Critical features model money-flow switches that must not keep running
      # from a stale snapshot. Ordinary features still fail over to the
      # secondary and keep their allowed values. Every read tries the primary
      # first, so once it recovers its actual values are used again, including
      # the sync version it reports.

      attr_reader :primary, :secondary

      def initialize(primary, secondary, options = {})
        @primary = primary
        @secondary = secondary

        @dual_write = options.fetch(:dual_write, false)
        @errors = Array(options.fetch(:errors, [ StandardError ]))
        @instrumenter = options.fetch(:instrumenter, Instrumenters::Noop)

        @critical_features = normalize_critical_features(options.fetch(:critical_features, []))
        @safe_value = normalize_safe_value(options.fetch(:safe_value, nil), :safe_value)
        @safe_values = normalize_safe_values(options.fetch(:safe_values, {}))
      end

      def adapter_stack
        "#{name}(primary: #{@primary.adapter_stack}, secondary: #{@secondary.adapter_stack})"
      end

      def read_only?
        @primary.read_only? || (@dual_write && @secondary.read_only?)
      end

      # Public: The Set of feature keys that must fail closed.
      attr_reader :critical_features

      # Public: Is this feature protected by a critical safe value?
      def critical_feature?(feature)
        @critical_features.include?(key_for(feature))
      end

      # Public: The gate values returned for a critical feature when the
      # primary cannot be read. Returns a fresh Hash so callers cannot change
      # the configured safe value.
      def safe_config_for(feature)
        duplicate_config(@safe_values.fetch(key_for(feature), @safe_value))
      end

      def features
        @primary.features
      rescue *@errors => error
        instrument_degraded(error, :features, @critical_features.to_a, :secondary_snapshot)
        @secondary.features | @critical_features
      end

      def get(feature)
        @primary.get(feature)
      rescue *@errors => error
        if critical_feature?(feature)
          instrument_degraded(error, :get, [key_for(feature)], :critical_safe_value)
          safe_config_for(feature)
        else
          instrument_degraded(error, :get, [], :secondary_snapshot)
          @secondary.get(feature)
        end
      end

      def get_multi(features)
        @primary.get_multi(features)
      rescue *@errors => error
        degraded_get_multi(features, error)
      end

      def get_all(**kwargs)
        @primary.get_all(**kwargs)
      rescue *@errors => error
        instrument_degraded(error, :get_all, @critical_features.to_a, :secondary_snapshot)
        degraded_snapshot(@secondary.get_all(**kwargs))
      end

      def sync_version
        @primary.sync_version
      rescue *@errors
        @secondary.sync_version
      end

      def sync_version=(version)
        @primary.sync_version = version
        @secondary.sync_version = version if @dual_write
      end

      def add(feature)
        @primary.add(feature).tap do
          @secondary.add(feature) if @dual_write
        end
      end

      def remove(feature)
        @primary.remove(feature).tap do
          @secondary.remove(feature) if @dual_write
        end
      end

      def clear(feature)
        @primary.clear(feature).tap do
          @secondary.clear(feature) if @dual_write
        end
      end

      def enable(feature, gate, thing)
        @primary.enable(feature, gate, thing).tap do
          @secondary.enable(feature, gate, thing) if @dual_write
        end
      end

      def disable(feature, gate, thing)
        @primary.disable(feature, gate, thing).tap do
          @secondary.disable(feature, gate, thing) if @dual_write
        end
      end

      private

      def degraded_get_multi(features, error)
        critical = features.select { |feature| critical_feature?(feature) }
        fallback = features.reject { |feature| critical_feature?(feature) }

        instrument_degraded(
          error,
          :get_multi,
          critical.map { |feature| key_for(feature) },
          fallback.map { |feature| key_for(feature) },
        )

        fallback_result = fallback.empty? ? {} : @secondary.get_multi(fallback)
        features.each_with_object({}) do |feature, result|
          result[feature.key] = if critical_feature?(feature)
            safe_config_for(feature)
          else
            fallback_result[feature.key]
          end
        end
      end

      # Keeps ordinary stale values but replaces every critical value with its
      # safe value. Configured critical features are included even when the
      # stale snapshot does not know them, so a complete preload cannot later
      # supply the adapter default in their place.
      def degraded_snapshot(fallback)
        result = {}
        fallback.each do |key, gates|
          result[key] = critical_key?(key) ? safe_config_for(key) : gates
        end
        @critical_features.each do |key|
          result[key] = safe_config_for(key) unless result.key?(key)
        end
        result
      end

      def normalize_critical_features(features)
        unless features.is_a?(Array) || features.is_a?(Set) || features.is_a?(String) || features.is_a?(Symbol)
          raise ArgumentError, ":critical_features must be an Array of feature keys"
        end

        Array(features).map(&:to_s).to_set
      end

      def normalize_safe_value(value, option_name)
        case value
        when nil, false
          default_config
        when Hash
          build_safe_config(value, option_name)
        else
          raise ArgumentError, "#{option_name} must be false, nil or a Hash of gate values"
        end
      end

      def normalize_safe_values(values)
        unless values.is_a?(Hash)
          raise ArgumentError, ":safe_values must be a Hash of feature key to gate values"
        end

        values.each_with_object({}) do |(feature_key, value), result|
          key = feature_key.to_s
          unless @critical_features.include?(key)
            raise ArgumentError, ":safe_values contains #{key.inspect}, which is not in :critical_features"
          end

          result[key] = normalize_safe_value(value, "safe_values[#{key.inspect}]")
        end
      end

      def build_safe_config(values, option_name)
        config = default_config
        values.each do |gate_key, gate_value|
          key = gate_key.to_sym
          unless config.key?(key)
            raise ArgumentError, "#{option_name} contains unknown gate #{gate_key.inspect}"
          end

          if key == :boolean
            gate_value = nil if gate_value == false
          elsif key == :expression && gate_value.is_a?(Flipper::Expression)
            gate_value = gate_value.value
          end

          config[key] = gate_value
        end

        Typecast.features_hash('__safe_value__' => config).fetch('__safe_value__')
      end

      def duplicate_config(config)
        config.each_with_object({}) do |(gate_key, gate_value), result|
          result[gate_key] = case gate_value
          when Set, Array, Hash, String
            gate_value.dup
          else
            gate_value
          end
        end
      end

      def critical_key?(key)
        @critical_features.include?(key.to_s)
      end

      def key_for(feature)
        feature.respond_to?(:key) ? feature.key.to_s : feature.to_s
      end

      def instrument_degraded(error, operation, critical_keys, fallback)
        @instrumenter.instrument(InstrumentationName, {
          operation: operation,
          reason: :primary_unavailable,
          error_class: error.class.name,
          critical_feature_keys: critical_keys,
          fallback: fallback,
        })
      end
    end
  end
end
