require 'flipper/instrumentation/gate_classification'

module Flipper
  module Instrumenters
    # Public: Wraps another instrumenter and removes person or customer
    # identifiers from event payloads before any subscriber sees them.
    #
    # Feature decisions are untouched. Only the monitoring payload is reduced
    # to a small allowlist of low-sensitivity fields:
    #
    #   feature_name  - the flag being checked
    #   feature_names - flags touched by a multi-feature adapter operation
    #   operation     - what happened (enabled?, enable, get, ...)
    #   adapter_name  - the storage adapter involved
    #   result        - a boolean result, when the operation has one
    #   gate_name     - a bounded gate category (:actor, :group, :none, ...)
    #
    # Actor identifiers, things, adapter result values, and exception messages
    # are intentionally omitted because any of them can contain person or
    # customer identifiers.
    #
    #   instrumenter = Flipper::Instrumenters::LowSensitivity.new(ActiveSupport::Notifications)
    #   flipper = Flipper.new(adapter, instrumenter: instrumenter)
    #
    class LowSensitivity
      # Internal: Payload hash that discards disallowed keys on write. Passing
      # this downstream means even instrumenters that add exception details or
      # duplicate the payload cannot leak those values to subscribers.
      class Payload < Hash
        ALLOWED_KEYS = Set[
          :feature_name,
          :feature_names,
          :operation,
          :adapter_name,
          :result,
          :gate_name,
        ].freeze

        def []=(key, value)
          return value unless ALLOWED_KEYS.include?(key)
          return value if key == :result && value != true && value != false

          super
        end
        alias_method :store, :[]=

        def merge!(other)
          other.each { |key, value| self[key] = value }
          self
        end
        alias_method :update, :merge!

        def replace(other)
          clear
          merge!(other)
          self
        end
      end

      # Public: The wrapped instrumenter.
      attr_reader :instrumenter

      # Public: Wrap an instrumenter so its subscribers only see low-sensitivity
      # data. Returns an already-wrapped instrumenter as-is.
      def self.wrap(instrumenter)
        return instrumenter if instrumenter.is_a?(self)
        new(instrumenter)
      end

      # Public: Return the instrumenter beneath any LowSensitivity wrappers.
      def self.unwrap(instrumenter)
        instrumenter = instrumenter.instrumenter while instrumenter.is_a?(self)
        instrumenter
      end

      def initialize(instrumenter)
        @instrumenter = instrumenter
      end

      def instrument(name, payload = {})
        if block_given?
          delivered = Payload.new.merge!(payload)
          instrumenter.instrument(name, delivered) do |inner_payload|
            begin
              yield inner_payload
            ensure
              # Result and gate are known only after the operation.
              safe = sanitize(inner_payload)
              inner_payload.replace(safe) if inner_payload.respond_to?(:replace)
              # Wrappers outside this one (Cloud telemetry, for example) keep
              # their own reference to the payload they were handed or to the
              # payload they passed in. Update both to the same allowlisted
              # view so neither can retain identifiers.
              delivered.replace(safe)
              payload.replace(safe) if payload.respond_to?(:replace) && !payload.frozen?
            end
          end
        else
          instrumenter.instrument(name, sanitize(payload))
        end
      end

      private

      def sanitize(payload)
        safe = {}

        safe[:feature_name] = payload[:feature_name] if payload.key?(:feature_name)
        safe[:feature_names] = payload[:feature_names].map(&:to_s) if payload[:feature_names]
        safe[:operation] = payload[:operation] if payload.key?(:operation)
        safe[:adapter_name] = payload[:adapter_name] if payload.key?(:adapter_name)
        safe[:result] = payload[:result] if boolean_result?(payload)
        safe[:gate_name] = gate_category(payload) if gate_category_needed?(payload)

        safe
      end

      def boolean_result?(payload)
        payload[:result] == true || payload[:result] == false
      end

      # Enabled checks always get a category, even when denied and no gate
      # could report one, so subscribers can group every decision consistently.
      # A check that raised has no boolean result and is not a decision.
      def gate_category_needed?(payload)
        (payload[:operation] == :enabled? && boolean_result?(payload)) || payload.key?(:gate_name)
      end

      def gate_category(payload)
        if payload[:operation] == :enabled?
          Flipper::Instrumentation::GateClassification.for_check(payload[:gate_name], payload[:result])
        else
          Flipper::Instrumentation::GateClassification.category(payload[:gate_name])
        end
      end
    end
  end
end
