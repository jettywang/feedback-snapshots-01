require 'set'

module Flipper
  module Instrumentation
    # Internal: Maps gate names to a small, stable set of labels that are safe
    # to use in monitoring. Unknown and custom gates collapse into :other so a
    # new gate can never create an unbounded or sensitive metric label.
    module GateClassification
      # The gate category for a check that no gate allowed.
      NONE = :none

      # The gate category for a gate this version does not know about.
      OTHER = :other

      KNOWN = Set[
        :boolean,
        :actor,
        :group,
        :percentage_of_actors,
        :percentage_of_time,
        :expression,
      ].freeze

      # Public: Returns the stable category for a gate name.
      def self.category(gate_name)
        name = gate_name.to_sym if gate_name.respond_to?(:to_sym)
        KNOWN.include?(name) ? name : OTHER
      end

      # Public: Returns the category that decided a feature check. A denied
      # check has no open gate, so it is counted as :none.
      def self.for_check(gate_name, result)
        result ? category(gate_name) : NONE
      end
    end
  end
end
