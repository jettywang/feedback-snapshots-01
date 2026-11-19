begin
  require 'bundler/setup'
rescue Bundler::GemNotFound
  # Allow running without a fully installed bundle (e.g. a minimal checkout).
  $LOAD_PATH.unshift(File.expand_path('../lib', __dir__))
end
require 'flipper/policy'

# A read-only "preflight" for the unreleased billing flow. The trial switch is
# the same flag that gates the new flow, so approvers need to see which gate
# combinations would widen the pilot toward all employees.
#
# Everything below is constructed in memory and evaluated through a
# Flipper::Adapters::ReadOnly adapter: no live feature is read for writing or
# changed.

roster = Flipper::Policy.roster([
  Flipper::Policy::Employee.new('User;1', plan: 'pro',  team: 'finance'),
  Flipper::Policy::Employee.new('User;2', plan: 'pro',  team: 'sales'),
  Flipper::Policy::Employee.new('User;3', plan: 'free', team: 'sales'),
  Flipper::Policy::Employee.new('User;4', plan: 'free', team: 'finance'),
])

# Groups are passed in as plain blocks so the preflight never mutates the
# global Flipper group registry.
preflight = Flipper::Policy.preflight(roster, groups: {
  pilot: ->(actor) { actor['team'] == 'finance' },
})

# The configuration currently in production: a single hand-picked employee.
current = Flipper::Policy.scenario(:current) do |s|
  s.feature :billing, actors: ['User;1']
end

# Planned trial: pilot group + plan expression + a percentage-of-actors ramp.
planned = Flipper::Policy.scenario(:planned) do |s|
  s.feature :billing,
    groups: [:pilot],
    expression: { 'Equal' => [{ 'Property' => ['plan'] }, 'pro'] },
    percentage_of_actors: 50
end

# An expression that references a function this Flipper release does not have.
# The preflight cannot decide who it covers, so it is left to the approver.
unknown = Flipper::Policy.scenario(:unknown_expression) do |s|
  s.feature :billing,
    expression: { 'UnreleasedGate' => [{ 'Property' => ['plan'] }] }
end

# Flipping the boolean turns the trial into an all-employee rollout.
full = Flipper::Policy.scenario(:full_open) do |s|
  s.feature :billing, boolean: true
end

report = preflight.check([planned, unknown, full], baseline: current)
puts report.to_text

puts 'Configurations that reach the entire roster:'
report.full_rollouts.each do |result|
  puts "  - #{result.scenario}/#{result.feature}"
end

puts "\nDecisions left to the approver:"
report.with_unknowns.each do |result|
  result.unknown_dependencies.each do |dependency|
    puts "  - #{result.scenario}/#{dependency.feature}: #{dependency.explain}"
  end
end
