# frozen_string_literal: true

module Grape
  class Entity
    # Internal, opt-in audit trail for the role-based visibility decisions made
    # while rendering an entity.
    #
    # The trace never participates in a visibility decision. It only records the
    # outcome of conditions that were evaluated as part of the normal rendering
    # pass, so a second pass (or re-running any user supplied condition) is never
    # needed to produce an explanation. Conditions skipped because an earlier
    # condition already rejected the exposure, or because the key was filtered
    # out via +:only+/+:except+, are recorded as +:not_executed+, preserving the
    # short-circuiting behavior.
    class DecisionTrace
      ConditionDecision = Struct.new(:kind, :inverse, :result, :status, :source_location, keyword_init: true)
      ExposureResult = Struct.new(:field, :entity_class, :outcome, :conditions, :source_location, keyword_init: true)

      attr_reader :exposure_results

      def initialize
        @exposure_results = []
        @evaluated_conditions = 0
      end

      # Records the visibility decision for one exposure. Each condition is
      # evaluated at most once; remaining conditions are marked
      # +:not_executed+ as soon as a condition rejects the exposure or the key
      # is filtered out.
      #
      # @return [Boolean] whether the exposure is visible, identical to what
      #   +Exposure::Base#should_expose?+ returns without a trace.
      def record(exposure, entity, options)
        key_returned = exposure.should_return_key?(options)
        decisions = exposure.conditions.map do |condition|
          if key_returned
            met = condition.met?(entity, options)
            @evaluated_conditions += 1
            key_returned = met
            build_condition_decision(condition, met)
          else
            build_condition_decision(condition, nil, :not_executed)
          end
        end

        outcome = key_returned ? :visible : :hidden
        @exposure_results << ExposureResult.new(
          field: exposure.key(entity),
          entity_class: entity.class,
          outcome: outcome,
          conditions: decisions,
          source_location: exposure.source_location
        )
        outcome == :visible
      end

      def for_field(field)
        field = field.to_sym
        @exposure_results.find { |result| result.field == field }
      end

      # Read-only explanation of every recorded decision. Building it does not
      # evaluate any condition, so calling it never runs user code again.
      def explain(field = nil)
        results = field ? @exposure_results.select { |result| result.field == field.to_sym } : @exposure_results
        results.map { |result| explanation_for(result) }
      end

      # Counters proving how often user supplied conditions actually ran.
      def counters
        condition_statuses = @exposure_results.flat_map { |result| result.conditions.map(&:status) }
        {
          evaluated_conditions: @evaluated_conditions,
          met_conditions: condition_statuses.count(:met),
          unmet_conditions: condition_statuses.count(:unmet),
          not_executed_conditions: condition_statuses.count(:not_executed),
          visible_fields: @exposure_results.count { |result| result.outcome == :visible },
          hidden_fields: @exposure_results.count { |result| result.outcome == :hidden }
        }
      end

      private

      def build_condition_decision(condition, met, status = nil)
        ConditionDecision.new(
          kind: condition.class.name.split('::').last,
          inverse: condition.inversed?,
          result: met,
          status: status || (met ? :met : :unmet),
          source_location: condition.source_location
        )
      end

      def explanation_for(result)
        {
          field: result.field,
          entity: result.entity_class.name || result.entity_class.to_s,
          outcome: result.outcome,
          declared_at: format_location(result.source_location),
          conditions: result.conditions.map { |decision| explanation_for_condition(decision) }
        }
      end

      def explanation_for_condition(decision)
        {
          kind: decision.kind,
          inverse: decision.inverse,
          result: decision.result,
          status: decision.status,
          declared_at: format_location(decision.source_location)
        }
      end

      def format_location(location)
        location&.to_s
      end
    end
  end
end
