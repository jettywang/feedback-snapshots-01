require 'set'

module Flipper
  module Policy
    # Public: The read-only findings for one feature inside one scenario.
    class FeatureReport
      attr_reader :feature, :scenario, :state, :matched_employee_ids,
                  :total_employees, :open_gates, :unknown_dependencies,
                  :added_employee_ids

      def initialize(feature:, scenario:, state:, matched_employee_ids:,
                     total_employees:, open_gates:, unknown_dependencies:,
                     added_employee_ids:)
        @feature = feature
        @scenario = scenario
        @state = state
        @matched_employee_ids = matched_employee_ids
        @total_employees = total_employees
        @open_gates = open_gates
        @unknown_dependencies = unknown_dependencies
        @added_employee_ids = added_employee_ids
      end

      # Public: True when this combination reaches every modeled employee.
      def full_rollout?
        !matched_employee_ids.empty? && matched_employee_ids.size == total_employees
      end

      # Public: True when at least one employee is newly enabled relative to the
      # baseline. Without a baseline there is nothing to diff, so this is false.
      def expands?
        !@added_employee_ids.nil? && !@added_employee_ids.empty?
      end

      def has_unknowns?
        !@unknown_dependencies.empty?
      end

      def matched_count
        @matched_employee_ids.size
      end

      # Public: A plain-language explanation an approver can read without
      # knowing Flipper's gate internals.
      def explain
        audience = if full_rollout?
          "every employee (#{total_employees} of #{total_employees})"
        elsif matched_count.zero?
          "no modeled employee"
        else
          "#{matched_count} of #{total_employees} employees"
        end

        lines = ["[#{@scenario}] #{@feature}: #{@state} - opens to #{audience}"]
        lines << "  deterministic gates: #{@open_gates.empty? ? 'none' : @open_gates.join(', ')}"

        unless @matched_employee_ids.empty?
          lines << "  matched: #{@matched_employee_ids.join(', ')}"
        end

        if expands?
          lines << "  newly added vs baseline: #{@added_employee_ids.join(', ')}"
        end

        @unknown_dependencies.each do |dependency|
          lines << "  UNKNOWN (approver decides): #{dependency.explain}"
        end

        lines.join("\n")
      end

      def to_h
        {
          feature: @feature,
          scenario: @scenario,
          state: @state,
          full_rollout: full_rollout?,
          matched_employee_ids: @matched_employee_ids,
          matched_count: matched_count,
          total_employees: @total_employees,
          open_gates: @open_gates,
          added_employee_ids: @added_employee_ids,
          unknown_dependencies: @unknown_dependencies.map(&:to_h),
        }
      end
    end

    # Public: The full set of findings for every feature across every scenario.
    # It only describes what would happen; it carries no ability to change a
    # flag (see Preflight, which evaluates through a ReadOnly adapter).
    class Report
      attr_reader :scenario_names, :feature_reports, :roster

      def initialize(roster:, feature_reports:, scenario_names:)
        @roster = roster
        @feature_reports = feature_reports
        @scenario_names = scenario_names
      end

      # Public: Fetch the FeatureReport for a scenario/feature pair.
      def for_feature(scenario_name, feature_name)
        @feature_reports.dig(scenario_name.to_s, feature_name.to_s)
      end

      # Public: All feature reports that would reach the entire roster.
      def full_rollouts
        all_reports.select(&:full_rollout?)
      end

      # Public: All feature reports that add at least one employee vs baseline.
      def expansions
        all_reports.select(&:expands?)
      end

      # Public: All feature reports that leave an unresolved dependency.
      def with_unknowns
        all_reports.select(&:has_unknowns?)
      end

      def all_reports
        @feature_reports.values.flat_map(&:values)
      end
      alias_method :each, :all_reports

      def to_h
        @feature_reports.transform_values do |features|
          features.transform_values(&:to_h)
        end
      end

      # Public: Human-readable, approval-oriented rendering of every finding.
      def to_text
        header = "Policy preflight (read-only) - roster of #{roster.size} employee(s)"
        body = all_reports.map(&:explain).join("\n\n")
        "#{header}\n#{body}\n"
      end
      alias_method :to_s, :to_text
    end
  end
end
