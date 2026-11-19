require 'flipper'
require 'flipper/policy/employee'
require 'flipper/policy/roster'
require 'flipper/policy/scenario'
require 'flipper/policy/unknown_dependency'
require 'flipper/policy/report'
require 'flipper/policy/preflight'

module Flipper
  module Policy
    # Public: Convenience constructor for an employee roster.
    def self.roster(employees = [])
      Roster.new(employees)
    end

    # Public: Convenience constructor for a gate scenario.
    def self.scenario(name, &block)
      Scenario.new(name, &block)
    end

    # Public: Convenience constructor for a read-only preflight.
    def self.preflight(roster, groups: nil)
      Preflight.new(roster, groups: groups)
    end
  end
end
