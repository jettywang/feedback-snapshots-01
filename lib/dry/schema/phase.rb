# frozen_string_literal: true

require "dry/schema/constants"

module Dry
  module Schema
    # Ordered processing phases used to authorize sensitive callbacks
    #
    # Every core step belongs to a phase. Callbacks inherit the phase of the step
    # they are attached to, except `after(:rule_applier)` callbacks which run in
    # the `:finalization` phase.
    #
    # @see Step
    # @see Diagnostics
    #
    # @api public
    module Phase
      # Processing phases in execution order
      #
      # @return [Array<Symbol>]
      #
      # @api public
      ORDER = %i[keys filter coercion validation finalization].freeze

      # Phase ranks, used to order diagnostics
      #
      # @api private
      RANKS = ORDER.each_with_index.to_h.freeze

      # Core steps mapped to their phase
      #
      # @api private
      STEP_PHASES = {
        key_validator: :keys,
        key_coercer: :keys,
        filter_schema: :filter,
        value_coercer: :coercion,
        rule_applier: :validation
      }.freeze

      # Steps whose after callbacks run during finalization
      #
      # @api private
      FINALIZATION_STEPS = %i[rule_applier].freeze

      module_function

      # Return the phase for a step
      #
      # @param [Symbol] type The step type (`:core`, `:before` or `:after`)
      # @param [Symbol] name The core step the callback is attached to
      #
      # @return [Symbol]
      #
      # @api private
      def for(type:, name:)
        parent = STEP_PHASES.fetch(name)

        if type.equal?(:after) && FINALIZATION_STEPS.include?(name)
          :finalization
        else
          parent
        end
      end

      # Return the rank of a phase
      #
      # @param [Symbol] phase
      #
      # @return [Integer]
      #
      # @raise [ArgumentError] when the phase is unknown
      #
      # @api public
      def rank(phase)
        RANKS.fetch(phase) do
          raise ::ArgumentError,
            "Unknown phase #{phase.inspect}. Available phases: #{ORDER.inspect}"
        end
      end

      # Check if a phase is known
      #
      # @param [Symbol] phase
      #
      # @return [Boolean]
      #
      # @api public
      def known?(phase)
        RANKS.key?(phase)
      end

      # Return a validated phase
      #
      # @param [Symbol] phase
      #
      # @return [Symbol]
      #
      # @raise [ArgumentError] when the phase is unknown
      #
      # @api public
      def fetch!(phase)
        return phase if known?(phase)

        raise ::ArgumentError, "Unknown phase #{phase.inspect}. Available phases: #{ORDER.inspect}"
      end

      # Normalize a processor permit into the list of granted phases
      #
      # Permits are cumulative: authorizing a phase authorizes every phase
      # before it. `true` and `:all` grant every phase.
      #
      # @param [nil, false, true, Symbol, Array<Symbol>] permit
      #
      # @return [Array<Symbol>] granted phases in execution order
      #
      # @raise [ArgumentError] when a phase is unknown
      #
      # @api public
      def normalize_permit(permit)
        requested =
          case permit
          when nil, false
            EMPTY_ARRAY
          when true, :all
            [ORDER.last]
          when ::Symbol
            [fetch!(permit)]
          when ::Array
            permit.map { |phase| fetch!(phase) }
          else
            raise ::ArgumentError,
              "+permit+ must be nil, true, :all, a phase name, or an array of phase names"
          end

        return EMPTY_ARRAY if requested.empty?

        highest = requested.map { |phase| rank(phase) }.max

        ORDER[0..highest]
      end

      # Check if a permit covers a phase
      #
      # @param [Array<Symbol>, nil, true, Symbol] permit A normalized or raw permit
      # @param [Symbol] phase
      #
      # @return [Boolean]
      #
      # @api public
      def permit_covers?(permit, phase)
        granted = permit.is_a?(::Array) ? permit : normalize_permit(permit)

        granted.include?(phase)
      end
    end
  end
end
