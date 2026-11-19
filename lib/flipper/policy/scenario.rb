require 'set'
require 'flipper/typecast'

module Flipper
  module Policy
    # Public: A named, in-memory gate configuration for one or more features.
    #
    # A scenario is the "existing or planned gate combination" an approver wants
    # to inspect. It is just data copied into a fresh Memory adapter during the
    # preflight; building a scenario never touches a live adapter.
    #
    # Examples
    #
    #   scenario = Flipper::Policy::Scenario.new(:planned) do |s|
    #     s.feature :billing,
    #       groups: [:pilot],
    #       actors: ["User;7"],
    #       expression: { "Equal" => [{ "Property" => ["plan"] }, "pro"] },
    #       percentage_of_actors: 25
    #   end
    class Scenario
      attr_reader :name, :features

      def initialize(name)
        @name = name
        @features = {}
        yield self if block_given?
      end

      # Public: Declare the gates for a feature. Every option is optional; only
      # the provided gates are set. Unknown gate keys raise so a typo cannot be
      # mistaken for a real configuration.
      def feature(name, **gates)
        config = Flipper::Adapters::Memory::DEFAULT_CONFIG.each_with_object({}) do |(key, default), memo|
          memo[key] = default.is_a?(Set) ? Set.new : default
        end

        gates.each do |gate, value|
          unless config.key?(gate)
            raise ArgumentError, "unknown gate #{gate.inspect} for feature #{name.inspect}"
          end
          config[gate] = coerce(gate, value)
        end

        @features[name.to_s] = config
        self
      end

      # Public: Build a throwaway Memory adapter holding exactly this scenario.
      # The expression is stored as raw data, so a scenario may carry an unknown
      # expression (a function this Flipper cannot build) without raising.
      def build_adapter
        Flipper::Adapters::Memory.new(deep_dup_features)
      end

      def inspect
        "#<#{self.class.name} name=#{name.inspect} features=#{@features.keys.inspect}>"
      end

      private

      def coerce(gate, value)
        case gate
        when :boolean
          value.nil? ? nil : Typecast.to_boolean(value).to_s
        when :actors, :groups
          Array(value).map { |item| item.to_s }.to_set
        when :expression
          value
        when :percentage_of_actors, :percentage_of_time
          value.nil? ? nil : Typecast.to_number(value).to_s
        else
          value
        end
      end

      def deep_dup_features
        @features.each_with_object({}) do |(name, config), memo|
          memo[name] = config.each_with_object({}) do |(key, value), feature_memo|
            feature_memo[key] = value.is_a?(Set) ? Set.new(value) : deep_dup(value)
          end
        end
      end

      def deep_dup(value)
        case value
        when Hash then value.transform_values { |child| deep_dup(child) }
        when Array then value.map { |child| deep_dup(child) }
        else value
        end
      end
    end
  end
end
