# frozen_string_literal: true

# Prints the reproducible call table behind the 404-triage convention in
# diagnostics/README.md and self-checks the expectations each row makes.
#
#   .feedback/bundle-env exec ruby -Ilib diagnostics/not_found_triage.rb
#
# Exits 0 when every scenario answers as expected, 1 otherwise.

require_relative 'synthetic_mounts'

# expected_allow: :confirmed means an Allow header must be present (its
# value is printed, not pinned), :unconfirmed means none may be present.
SCENARIOS = [
  { name: 'unregistered path',            method: 'GET',     path: '/v1/nope',           token: 'ops-alice',
    expect: { status: 404, allow: :unconfirmed, terminal: %r{router:no_candidate} } },
  { name: 'unregistered version (path)',  method: 'GET',     path: '/v9/ledger',         token: 'ops-alice',
    expect: { status: 404, allow: :unconfirmed, terminal: %r{router:no_candidate} } },
  { name: 'version rejected (param)',     method: 'GET',     path: '/reports?apiver=v9', token: 'ops-alice',
    expect: { status: 404, allow: :unconfirmed, terminal: %r{version:rejected} } },
  { name: 'hidden, operator token',       method: 'GET',     path: '/v1/ledger/hidden',  token: 'ops-alice',
    expect: { status: 404, allow: :unconfirmed, terminal: %r{identity:denied} } },
  { name: 'hidden, anonymous',            method: 'GET',     path: '/v1/ledger/hidden',  token: nil,
    expect: { status: 404, allow: :unconfirmed, terminal: %r{identity:denied} } },
  { name: 'hidden on mount B, operator',  method: 'GET',     path: '/reports/hidden?apiver=v2', token: 'ops-alice',
    expect: { status: 404, allow: :unconfirmed, terminal: %r{identity:denied} } },
  { name: 'method not supported',         method: 'POST',    path: '/v1/ledger',         token: 'ops-alice',
    expect: { status: 405, allow: :confirmed, terminal: %r{method:method_not_allowed} } },
  { name: 'auto-OPTIONS',                 method: 'OPTIONS', path: '/v1/ledger',         token: 'ops-alice',
    expect: { status: 204, allow: :confirmed, terminal: %r{method:auto_options} } },
  { name: 'hidden path, unsupported method', method: 'POST', path: '/v1/ledger/hidden',  token: 'ops-alice',
    expect: { status: 404, allow: :unconfirmed, terminal: %r{identity:denied} } },
  { name: 'hidden path, method, root',    method: 'POST',    path: '/v1/ledger/hidden',  token: 'root-admin',
    expect: { status: 405, allow: :confirmed, terminal: %r{method:method_not_allowed} } },
  { name: 'hidden, authorized root',      method: 'GET',     path: '/v1/ledger/hidden',  token: 'root-admin',
    expect: { status: 200, allow: :unconfirmed, terminal: %r{endpoint:executed} } },
  { name: 'public, operator token',       method: 'GET',     path: '/v1/ledger',         token: 'ops-alice',
    expect: { status: 200, allow: :unconfirmed, terminal: %r{endpoint:executed} } },
  { name: 'public on mount B',            method: 'GET',     path: '/reports?apiver=v2', token: 'ops-alice',
    expect: { status: 200, allow: :unconfirmed, terminal: %r{endpoint:executed} } }
].freeze

def check(scenario, result)
  expect = scenario[:expect]
  failures = []
  failures << "status #{result.status} != #{expect[:status]}" unless result.status == expect[:status]
  allow_ok = expect[:allow] == :confirmed ? !result.allow.nil? : result.allow.nil?
  failures << "Allow #{result.allow.inspect} violates #{expect[:allow]}" unless allow_ok
  failures << "terminal #{result.terminal_stage.inspect} !~ #{expect[:terminal]}" unless result.terminal_stage.match?(expect[:terminal])
  failures
end

results = SCENARIOS.map { |scenario| [scenario, Diagnostics.call(scenario[:method], scenario[:path], token: scenario[:token])] }

puts '== Grape 404 triage -- reproducible call table =='
puts 'stack: PublicFacade -> HeaderCascade -> [MountProbe(LedgerAPI v1/path), MountProbe(ReportsAPI v2/param)]'
puts
header = format('%-2s %-32s %-38s %-6s %-22s %s', '#', 'scenario', 'request', 'ext', 'Allow (public)', 'terminal internal stage')
puts header
puts '-' * header.length
results.each_with_index do |(scenario, result), index|
  request = "#{scenario[:method]} #{scenario[:path]}"
  request += " [token=#{scenario[:token]}]" if scenario[:token]
  external = "#{result.status} #{result.body}"
  allow = result.allow || 'unconfirmed'
  puts format('%-2d %-32s %-38s %-6s %-22s %s', index + 1, scenario[:name], request, external, allow, result.terminal_stage)
end

puts
puts '== internal event traces (never leaves the process) =='
results.each_with_index do |(scenario, result), index|
  puts
  puts "#{index + 1}. #{scenario[:name]} -- #{scenario[:method]} #{scenario[:path]} -> #{result.status}"
  result.events.each do |event|
    puts format('   [%-7s] %-8s %-18s %s', event[:mount], event[:stage], event[:event], event[:detail])
  end
end

failures = results.flat_map do |scenario, result|
  check(scenario, result).map { |failure| "#{scenario[:name]}: #{failure}" }
end
puts
if failures.empty?
  puts "self-check: #{results.size}/#{results.size} scenarios as expected"
  exit 0
else
  puts 'self-check FAILED:'
  failures.each { |failure| puts "  - #{failure}" }
  exit 1
end
