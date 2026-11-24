# frozen_string_literal: true

require "dry/initializer"
require "dry/schema/constants"
require "dry/schema/phase"
require "dry/schema/phase_failure"

module Dry
  module Schema
    # Steps for the Dry::Schema::Processor
    #
    # There are 5 main steps:
    #
    #   1. `key_validator` - Validate input keys (optional, when `validate_keys` is on)
    #   2. `key_coercer` - Prepare input hash using a key map
    #   3. `filter_schema` - Apply pre-coercion filtering rules
    #      (optional step, used only when `filter` was used)
    #   4. `value_coercer` - Apply value coercions based on type specifications
    #   5. `rule_applier` - Apply rules
    #
    # Steps and callbacks run in phase order. A callback may declare a `permit:`
    # phase; such a callback only runs when the processor was called with a
    # permit covering that phase and no earlier action already failed. Missing
    # permits skip the callback and mark the result non-deliverable.
    #
    # @see Processor
    # @see Diagnostics
    #
    # @api public
    class ProcessorSteps
      extend ::Dry::Initializer

      option :steps, default: -> { EMPTY_HASH.dup }
      option :before_steps, default: -> { EMPTY_HASH.dup }
      option :after_steps, default: -> { EMPTY_HASH.dup }

      # Executes steps and callbacks in order
      #
      # @param [Result] result
      # @param [Object] permit Optional phase permit granted by the caller
      #
      # @return [Result]
      #
      # @api public
      def call(result, permit: nil)
        diagnostics = Diagnostics.new(permit: permit)
        granted = Phase.normalize_permit(permit)
        halted = false

        STEPS_IN_ORDER.each do |name|
          callbacks_for(name).each do |step, type|
            halted = run_step(
              result, step, type: type, granted: granted, diagnostics: diagnostics
            )
            break if halted
          end

          break if halted
        end

        result.diagnostics = diagnostics
        diagnostics.finish!(result, halted: halted)
        result
      end

      # @api private
      def rule_applier
        @rule_applier ||= steps[:rule_applier].executor
      end

      # @api private
      def key_map
        @key_map ||= self[:key_coercer].executor.key_map
      end

      # @api private
      def type_schema
        @type_schema ||= steps[:value_coercer].executor.type_schema
      end

      # Returns step by name
      #
      # @param [Symbol] name The step name
      #
      # @api public
      def [](name)
        steps[name]
      end

      # Sets step by name
      #
      # @param [Symbol] name The step name
      #
      # @api public
      def []=(name, value)
        steps[name] = Step.new(type: :core, name: name, executor: value)
      end

      # Add passed block after the mentioned step
      #
      # @param [Symbol] name The step name
      # @param [Symbol, nil] permit Phase permit required to run the callback
      #
      # @return [ProcessorSteps]
      #
      # @api public
      def after(name, permit: nil, &block)
        after_steps[name] ||= EMPTY_ARRAY.dup
        after_steps[name] << Step.new(type: :after, name: name, executor: block, permit: permit)
        after_steps[name].sort_by!(&:path)
        self
      end

      # Add passed block before the mentioned step
      #
      # @param [Symbol] name The step name
      # @param [Symbol, nil] permit Phase permit required to run the callback
      #
      # @return [ProcessorSteps]
      #
      # @api public
      def before(name, permit: nil, &block)
        before_steps[name] ||= EMPTY_ARRAY.dup
        before_steps[name] << Step.new(type: :before, name: name, executor: block, permit: permit)
        before_steps[name].sort_by!(&:path)
        self
      end

      # Stacks callback steps and returns new ProcessorSteps instance
      #
      # @param [ProcessorSteps] other
      #
      # @return [ProcessorSteps]
      #
      # @api public
      def merge(other)
        ProcessorSteps.new(
          before_steps: merge_callbacks(before_steps, other.before_steps),
          after_steps: merge_callbacks(after_steps, other.after_steps)
        )
      end

      # @api private
      def merge_callbacks(left, right)
        left.merge(right) do |_key, oldval, newval|
          (oldval + newval).sort_by(&:path)
        end
      end

      # @api private
      def import_callbacks(path, other)
        other.before_steps.each do |name, callback_steps|
          before_steps[name] ||= []
          before_steps[name]
            .concat(callback_steps.map { |step| step.scoped(path) }).sort_by!(&:path)
        end

        other.after_steps.each do |name, callback_steps|
          after_steps[name] ||= []
          after_steps[name]
            .concat(callback_steps.map { |step| step.scoped(path) }).sort_by!(&:path)
        end
      end

      private

      # @api private
      def callbacks_for(name)
        core = steps[name]
        list = []

        before_steps[name]&.each { |step| list << [step, :before] }
        list << [core, :core] unless core.nil?
        after_steps[name]&.each { |step| list << [step, :after] }

        list
      end

      # Runs a single step, gating sensitive steps and recording diagnostics
      #
      # @return [Boolean] true when processing must stop
      #
      # @api private
      def run_step(result, step, type:, granted:, diagnostics:)
        sensitive = step.sensitive?
        phase = step.phase

        if sensitive && !Phase.permit_covers?(granted, step.permit)
          record_skip(diagnostics, step, type, phase, reason: :permit)
          return false
        end

        if sensitive && result.failure?
          record_skip(diagnostics, step, type, phase, reason: :precondition)
          return false
        end

        action = Diagnostics::Action.new(
          kind: action_kind(type),
          step: step.name,
          phase: phase,
          type: type,
          path: step.path.keys,
          sensitive: sensitive
        )
        diagnostics.record(action)

        errors_before = result.result_ast.size
        step.(result)
        record_errors(diagnostics, step, phase, result, errors_before)

        false
      rescue PhaseFailure => e
        action&.fail!(e.message)
        diagnostics.fail!(
          phase: phase, step: step.name, error: e.message, output: result.output
        )
        true
      rescue StandardError => e
        action&.fail!(e.message)
        diagnostics.fail!(
          phase: phase, step: step.name, error: e.message, output: result.output
        )
        raise
      end

      # @api private
      def record_skip(diagnostics, step, type, phase, reason:)
        diagnostics.record(
          Diagnostics::Action.new(
            kind: action_kind(type),
            step: step.name,
            phase: phase,
            type: type,
            path: step.path.keys,
            sensitive: true,
            skip_reason: reason
          )
        )
      end

      # @api private
      def record_errors(diagnostics, step, phase, result, errors_before)
        errors = result.result_ast[errors_before..] || EMPTY_ARRAY
        return if errors.empty?

        diagnostics.current_action&.fail!("#{errors.size} validation error(s)")

        diagnostics.fail!(
          phase: phase,
          step: step.name,
          error: "#{errors.size} validation error(s)",
          errors: errors,
          output: result.output
        )
      end

      # @api private
      def action_kind(type)
        type.equal?(:core) ? :step : :callback
      end
    end
  end
end
