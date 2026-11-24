# frozen_string_literal: true

require "dry/schema/phase"

module Dry
  module Schema
    # Per-call report explaining which actions ran, which phase failed, and
    # whether the result may be delivered
    #
    # A {Diagnostics} instance is attached to every {Result} returned by
    # {Processor#call}. It records:
    #
    # - every core step and callback that ran, in execution order
    # - sensitive callbacks skipped because a permit was missing or because an
    #   earlier phase already failed
    # - the first failure and the phase it belongs to
    # - the partial output captured when processing stopped
    #
    # @see Processor#call
    # @see Result#diagnostics
    #
    # @api public
    class Diagnostics
      # A single action considered during processing
      #
      # @api public
      class Action
        # @return [Symbol] `:step` for core steps, `:callback` for injected callbacks
        attr_reader :kind

        # @return [Symbol] core step name the action belongs to
        attr_reader :step

        # @return [Symbol] phase in which the action ran
        attr_reader :phase

        # @return [Symbol] `:before`, `:core` or `:after`
        attr_reader :type

        # @return [Array<Symbol>] nested path the action was scoped to
        attr_reader :path

        # @return [Boolean] true when the action required a permit
        attr_reader :sensitive

        # @return [Symbol, nil] why a sensitive action was skipped
        #   (`:permit` or `:precondition`)
        attr_reader :skip_reason

        # @return [String, nil] error message when the action failed
        attr_reader :error

        # @api private
        def initialize(
          kind:, step:, phase:, type:, path: EMPTY_ARRAY, sensitive: false,
          skip_reason: nil, error: nil
        )
          @kind = kind
          @step = step
          @phase = phase
          @type = type
          @path = path
          @sensitive = sensitive
          @skip_reason = skip_reason
          @error = error
        end

        # @api public
        def sensitive?
          sensitive
        end

        # @api public
        def skipped?
          !skip_reason.nil?
        end

        # Check if the action ran and failed
        #
        # @return [Boolean]
        #
        # @api public
        def failed?
          !skipped? && !error.nil?
        end

        # Check if the action ran without failing
        #
        # @return [Boolean]
        #
        # @api public
        def performed?
          !skipped? && error.nil?
        end

        # Mark the action as failed
        #
        # @api private
        def fail!(message)
          @error = message
          self
        end

        # @api public
        def to_h
          {
            kind: kind,
            step: step,
            phase: phase,
            type: type,
            path: path,
            sensitive: sensitive,
            skipped: skipped?,
            skip_reason: skip_reason,
            error: error
          }
        end

        # @api private
        def inspect
          "#<#{self.class.name} #{to_h.map { |(key, value)| "#{key}=#{value.inspect}" }.join(" ")}>"
        end
      end

      # @return [Object] raw permit passed to the processor
      attr_reader :permit

      # @return [Array<Action>] actions in execution order, including skipped ones
      attr_reader :actions

      # @return [Array<Hash>] failures in execution order
      attr_reader :failures

      # @return [Symbol, nil] phase of the first failure
      attr_reader :failed_phase

      # @return [String, nil] error message of the first failure
      attr_reader :error

      # @return [Hash] output captured at the first failure, or the final output
      #   when processing succeeded
      attr_reader :partial_output

      # @return [Hash] output as it stands after the pipeline stopped
      attr_reader :final_output

      # @api private
      def initialize(permit: nil)
        @permit = permit
        @actions = EMPTY_ARRAY.dup
        @failures = EMPTY_ARRAY.dup
        @failed_phase = nil
        @error = nil
        @partial_output = EMPTY_HASH.dup
        @final_output = EMPTY_HASH.dup
        @finished = false
        @halted = false
      end

      # @api private
      def record(action)
        actions << action
        action
      end

      # Return the most recently recorded action
      #
      # @api private
      def current_action
        actions.last
      end

      # Record a failure
      #
      # The first failure also snapshots the output produced up to that point.
      #
      # @api private
      def fail!(phase:, step:, error:, errors: EMPTY_ARRAY, output: nil)
        if failed_phase.nil?
          @failed_phase = phase
          @error = error
          @partial_output = snapshot(output) || @partial_output
        end

        failures << {phase: phase, step: step, error: error, errors: errors}
      end

      # Record how processing ended and capture the partial output
      #
      # @api private
      def finish!(result, halted: false)
        @final_output = snapshot(result.output) || EMPTY_HASH

        if failed_phase.nil?
          @partial_output = @final_output
        end

        @halted = halted
        @finished = true
      end

      # Check if processing finished normally without any failure
      #
      # @return [Boolean]
      #
      # @api public
      def success?
        @finished && !@halted && failed_phase.nil?
      end

      # Check if processing stopped early because an action failed
      #
      # @return [Boolean]
      #
      # @api public
      def halted?
        @halted
      end

      # Check if any phase failed
      #
      # @return [Boolean]
      #
      # @api public
      def failed?
        !failed_phase.nil?
      end

      # Check if the result may be delivered
      #
      # A result is deliverable only when processing completed, no phase failed,
      # and every sensitive action actually ran. A skipped sensitive callback
      # makes the result non-deliverable even when validation itself passed.
      #
      # @return [Boolean]
      #
      # @api public
      def deliverable?
        success? && skipped.empty?
      end

      # Return the first failure as a hash
      #
      # @return [Hash, nil]
      #
      # @api public
      def first_failure
        failures.first
      end

      # Return the phase of the first failure
      #
      # @return [Symbol, nil]
      #
      # @api public
      def first_failure_phase
        first_failure&.fetch(:phase)
      end

      # Return actions that actually ran, including the one that failed
      #
      # @return [Array<Action>]
      #
      # @api public
      def performed
        actions.reject(&:skipped?)
      end

      # Return actions skipped because a permit was missing or a precondition failed
      #
      # @return [Array<Action>]
      #
      # @api public
      def skipped
        actions.select(&:skipped?)
      end

      # Return the action that failed
      #
      # @return [Action, nil]
      #
      # @api public
      def failed_action
        actions.find(&:failed?)
      end

      # Return phases in which every action ran successfully
      #
      # A phase with a skipped callback or a failed action is not completed.
      #
      # @return [Array<Symbol>]
      #
      # @api public
      def completed_phases
        actions
          .group_by(&:phase)
          .select { |_phase, phase_actions| phase_actions.all?(&:performed?) }
          .keys
          .sort_by { |phase| Phase.rank(phase) }
      end

      # Return the last phase reached, whether completed or failed
      #
      # @return [Symbol, nil]
      #
      # @api public
      def last_phase
        actions.last&.phase
      end

      # Group recorded failures by phase
      #
      # @return [Hash<Symbol, Array<String>>]
      #
      # @api public
      def errors_by_phase
        failures.each_with_object(EMPTY_HASH.dup) do |failure, hash|
          (hash[failure[:phase]] ||= EMPTY_ARRAY.dup) << failure[:error]
        end
      end

      # @api public
      def to_h
        {
          permit: permit,
          success: success?,
          halted: halted?,
          actions: actions.map(&:to_h),
          failures: failures,
          first_failure: first_failure,
          performed: performed.map(&:to_h),
          skipped: skipped.map(&:to_h),
          completed_phases: completed_phases,
          last_phase: last_phase,
          errors_by_phase: errors_by_phase,
          partial_output: partial_output,
          final_output: final_output,
          deliverable: deliverable?
        }
      end

      # @api public
      def inspect
        "#<#{self.class.name} failed_phase=#{failed_phase.inspect} deliverable=#{deliverable?} " \
          "actions=#{actions.size}>"
      end

      private

      # Shallow copy of an output hash, used to keep a snapshot
      #
      # @api private
      def snapshot(output)
        output.is_a?(::Hash) ? output.dup : nil
      end
    end
  end
end
