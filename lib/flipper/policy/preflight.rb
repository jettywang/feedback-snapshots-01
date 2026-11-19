require 'set'
require 'flipper/adapters/read_only'
require 'flipper/policy/employee'
require 'flipper/policy/roster'
require 'flipper/policy/scenario'
require 'flipper/policy/unknown_dependency'
require 'flipper/policy/report'

module Flipper
  module Policy
    # Public: A read-only auditor for trial/rollout gate combinations.
    #
    # The preflight takes an employee roster and one or more in-memory
    # scenarios (the current configuration and any planned ones), then reports
    # who each combination would reach and which configurations would broaden a
    # pilot toward all employees. Everything runs against a throwaway
    # Flipper::Adapters::Memory wrapped in Flipper::Adapters::ReadOnly, so no
    # live gate is ever read for writing or changed.
    #
    # Anything the preflight cannot resolve (unknown expression functions,
    # missing employee properties, unregistered groups, probabilistic time
    # rollouts, actors absent from the roster) is reported as an
    # UnknownDependency for the approver instead of being guessed.
    class Preflight
      # Internal: Gate names that have a fixed, per-employee answer. The time
      # gate is handled separately because it is probabilistic.
      DETERMINISTIC_GATE_ORDER = %i[
        boolean expression actor percentage_of_actors group
      ].freeze

      def initialize(roster, groups: nil)
        @roster = roster
        @local_groups = build_local_groups(groups)
      end

      # Public: Run the preflight over the given scenarios.
      #
      # scenarios - one Scenario or an Array of them.
      # baseline  - optional Scenario treated as the current configuration; the
      #             report lists the employees each scenario would newly add.
      #
      # Returns a Flipper::Policy::Report.
      def check(scenarios, baseline: nil)
        scenarios = Array(scenarios)
        baseline_matches = baseline ? matched_ids_by_feature(baseline) : {}

        feature_reports = scenarios.each_with_object({}) do |scenario, memo|
          memo[scenario.name.to_s] = evaluate_scenario(scenario, baseline, baseline_matches)
        end

        Report.new(
          roster: @roster,
          feature_reports: feature_reports,
          scenario_names: scenarios.map { |scenario| scenario.name.to_s }
        )
      end

      private

      def build_local_groups(groups)
        (groups || {}).each_with_object({}) do |(name, block), memo|
          memo[name.to_s] = Flipper::Types::Group.new(name, &block)
        end
      end

      def evaluate_scenario(scenario, baseline, baseline_matches)
        flipper = read_only_flipper(scenario)

        scenario.features.each_with_object({}) do |(feature_name, _config), memo|
          feature = flipper.feature(feature_name)
          values = feature.gate_values

          unknowns = detect_unknowns(feature_name, values)
          matched, open_gates = resolve_audience(feature, values)
          added = baseline ? added_employees(feature_name, matched, baseline_matches) : nil

          memo[feature_name] = FeatureReport.new(
            feature: feature_name,
            scenario: scenario.name.to_s,
            state: feature.state,
            matched_employee_ids: matched.sort,
            total_employees: @roster.size,
            open_gates: open_gates.to_a.sort,
            unknown_dependencies: unknowns,
            added_employee_ids: added&.sort
          )
        end
      end

      def read_only_flipper(scenario)
        adapter = Flipper::Adapters::ReadOnly.new(scenario.build_adapter)
        Flipper.new(adapter, memoize: false)
      end

      # Internal: Returns [matched_id_set, open_gate_set] using only gates with
      # a deterministic answer. The probabilistic time gate never contributes
      # ids here; its 100% extreme is treated as a full open, matching Flipper.
      def resolve_audience(feature, values)
        matched = Set.new
        open_gates = Set.new

        @roster.each do |employee|
          actor = Flipper::Types::Actor.new(employee)
          context = Flipper::FeatureCheckContext.new(
            feature_name: feature.name,
            values: values,
            actors: [actor]
          )

          gate_name = first_open_gate(feature, context, values)
          next if gate_name.nil?

          matched << employee.flipper_id
          open_gates << gate_name
        end

        [matched, open_gates]
      end

      def first_open_gate(feature, context, values)
        feature.gates.each do |gate|
          case gate.name
          when :percentage_of_time
            return gate.name if values.percentage_of_time >= 100
          when :group
            return gate.name if group_gate_open?(context)
          else
            return gate.name if gate.open?(context)
          end
        end
        nil
      end

      def group_gate_open?(context)
        context.values.groups.any? do |name|
          group = @local_groups[name] || (Flipper.group(name) if Flipper.group_exists?(name))
          next false if group.nil?

          context.actors.any? { |actor| group.match?(actor, context) }
        end
      end

      def detect_unknowns(feature_name, values)
        unknowns = []
        unknowns.concat(unknown_functions(feature_name, values.expression))
        unknowns.concat(missing_properties(feature_name, values.expression))
        unknowns.concat(unregistered_groups(feature_name, values.groups))
        unknowns.concat(probabilistic_time(feature_name, values.percentage_of_time))
        unknowns.concat(unmodeled_actors(feature_name, values.actors))
        unknowns
      end

      def unknown_functions(feature_name, expression)
        expression_function_names(expression).reject do |name|
          Flipper::Expressions.const_defined?(name, false)
        end.uniq.map do |name|
          UnknownDependency.new(kind: :unknown_function, detail: name, feature: feature_name)
        end
      end

      def missing_properties(feature_name, expression)
        referenced_properties(expression).uniq.reject do |property|
          @roster.all? { |employee| employee.flipper_properties.key?(property.to_s) }
        end.map do |property|
          UnknownDependency.new(kind: :missing_property, detail: property, feature: feature_name)
        end
      end

      def unregistered_groups(feature_name, groups)
        groups.reject { |name| known_group?(name) }.map do |name|
          UnknownDependency.new(kind: :unregistered_group, detail: name, feature: feature_name)
        end
      end

      def probabilistic_time(feature_name, percentage_of_time)
        if percentage_of_time.positive? && percentage_of_time < 100
          [UnknownDependency.new(
            kind: :percentage_of_time,
            detail: percentage_of_time,
            feature: feature_name
          )]
        else
          []
        end
      end

      def unmodeled_actors(feature_name, actors)
        @roster.missing_ids(actors).map do |flipper_id|
          UnknownDependency.new(kind: :unmodeled_actor, detail: flipper_id, feature: feature_name)
        end
      end

      def known_group?(name)
        @local_groups.key?(name) || Flipper.group_exists?(name)
      end

      # Internal: Every function node name appearing anywhere in an expression
      # tree. Leaf constants (strings/numbers/booleans) are not function nodes.
      def expression_function_names(node, names = [])
        case node
        when Hash
          node.each do |name, args|
            names << name.to_s
            Array(args).each { |child| expression_function_names(child, names) }
          end
        when Array
          node.each { |child| expression_function_names(child, names) }
        end
        names
      end

      def referenced_properties(node, properties = [])
        case node
        when Hash
          node.each do |name, args|
            if name.to_s == "Property"
              properties << Array(args).first.to_s
            else
              Array(args).each { |child| referenced_properties(child, properties) }
            end
          end
        when Array
          node.each { |child| referenced_properties(child, properties) }
        end
        properties
      end

      def matched_ids_by_feature(scenario)
        flipper = read_only_flipper(scenario)
        scenario.features.each_with_object({}) do |(feature_name, _config), memo|
          values = flipper.feature(feature_name).gate_values
          memo[feature_name] = resolve_audience(flipper.feature(feature_name), values).first
        end
      end

      def added_employees(feature_name, matched, baseline_matches)
        baseline_set = baseline_matches[feature_name] || Set.new
        (matched - baseline_set).to_a
      end
    end
  end
end
