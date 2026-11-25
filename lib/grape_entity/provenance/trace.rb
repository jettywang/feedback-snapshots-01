# frozen_string_literal: true

module Grape
  class Entity
    module Provenance
      # A Trace collects raw observations made while rendering a single entity
      # instance. It is written to by the instrumentation prepends and read
      # once, when the immutable Receipt is built.
      #
      # Three distinct kinds of observation are kept apart on purpose:
      #   * :adopted   - the exposure produced a value that reached the output
      #   * :condition - the exposure was evaluated but a condition failed, so
      #                  it never produced output (a "condition-only" candidate)
      #   * :formatter - a formatter proc actually executed for an adopted field
      class Trace
        attr_reader :condition_checks, :adoptions, :formatter_runs

        def initialize
          @condition_checks = []
          @adoptions = []
          @formatter_runs = []
          @seen_conditions = Set.new
          @seen_adoptions = Set.new
        end

        def record_condition(claim_id, met:, path:)
          signature = [claim_id, path]
          return if @seen_conditions.include?(signature)

          @seen_conditions.add(signature)
          @condition_checks << { claim_id: claim_id, met: met, path: path.dup }
        end

        def record_adoption(claim_id, path:, value:, kind:, nesting:)
          signature = [claim_id, path]
          return if @seen_adoptions.include?(signature)

          @seen_adoptions.add(signature)
          @adoptions << {
            claim_id: claim_id,
            path: path.dup,
            value: value,
            kind: kind,
            nesting: nesting
          }
        end

        def record_formatter_run(claim_id, formatter_name:, formatter_kind:)
          @formatter_runs << {
            claim_id: claim_id,
            formatter_name: formatter_name,
            formatter_kind: formatter_kind
          }
        end
      end
    end
  end
end
