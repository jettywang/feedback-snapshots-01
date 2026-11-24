#!/usr/bin/env ruby
# frozen_string_literal: true

# Local congestion scenario for Elastic::Transport congestion protection.
#
# Run with the pinned local bundle:
#   .feedback/bundle-env exec ruby examples/congestion_scenario.rb
#
# The clock is fake (CongestionControl::FakeClock), so the whole failure,
# boundary, probe, resurrection and quota-recovery timeline is deterministic
# and finishes instantly. The script self-checks every number and exits 1 if
# any reconciliation fails.

$LOAD_PATH.unshift File.expand_path('../lib', __dir__)
require 'elastic-transport'

T = Elastic::Transport::Transport
C = T::CongestionControl

CHECKS = []
def check(label, actual, expected)
  ok = actual == expected
  CHECKS << ok
  printf "  %<mark>s %<label>s (got %<actual>s)%<expected>s\n",
         mark: ok ? 'PASS' : 'FAIL', label: label, actual: actual.inspect,
         expected: ok ? '' : " expected #{expected.inspect}"
end

# A transport with two real connections and a scripted pinned node.
class ScenarioTransport
  include T::Base
  attr_accessor :pinned

  def __build_connection(host, _options = {}, _block = nil)
    T::Connections::Connection.new(
      host: host,
      connection: Object.new,
      clock: congestion_control&.clock,
      options: { resurrect_timeout: 0 }
    )
  end

  def get_connection(options = {})
    pinned || super
  end
end

clock = C::FakeClock.new(0.0)
cc = C.new(
  clock: clock,
  total_retry_limit: 2, total_retry_refill_interval: 4.0,
  per_node_limit: 3,   node_refill_interval: 1.0,
  discovery_limit: 1,   discovery_refill_interval: 10.0,
  resurrection_limit: 1, resurrection_refill_interval: 5.0,
  probe_limit: 1,       probe_refill_interval: 2.0
)

hosts = [{ host: '10.0.0.1', port: 9200 }, { host: '10.0.0.2', port: 9200 }]
transport = ScenarioTransport.new(
  hosts: hosts.map(&:dup),
  options: { retry_on_failure: 2, congestion_control: cc }
)
a = transport.connections.all.find { |c| c.host[:host] == '10.0.0.1' }
b = transport.connections.all.find { |c| c.host[:host] == '10.0.0.2' }
key_a = cc.node_key(a)
key_b = cc.node_key(b)
ok_response = T::Response.new(200, '{}', 'content-type' => 'application/json')

puts '== Partial congestion: node A is down, node B is healthy =='
puts "   A=#{key_a}  B=#{key_b}"

# --- Group A: one request pinned to A -> 1 initial + 2 retries ----------
transport.pinned = a
attempts_a = 0
begin
  transport.perform_request('GET', 'orders/_search') do
    attempts_a += 1
    raise Errno::ECONNREFUSED
  end
rescue T::Error
  # expected after the retry budget is exhausted
end

puts '[t=0] group A (failed node) reaches both boundaries'
check('A HTTP attempts (1 + 2 retries)', attempts_a, 3)
check('total-retry tokens spent', cc.ledger.consumed(:total_retry), 2)
check('node-A quota spent', cc.ledger.consumed(:node, scope: key_a), 3)
check('total-retry remaining', cc.remaining(:total_retry), 0)
check('node-A remaining', cc.remaining(:node, node: key_a), 0)
combined = cc.peek_retry(key_a)
check('next A retry allowed?', combined.allowed?, false)
printf "       combined retry resumes in %.1fs (node needs 1s, global budget 4s)\n",
       combined.retry_after

# --- Background probe #1 (small probe budget) --------------------------
probe1 = transport.probe_dead_connections! { false }
check('probe #1 result', probe1.first[:result], :unreachable)

# --- Discovery budget ---------------------------------------------------
plain_sniffer = Object.new
plain_sniffer.define_singleton_method(:hosts) { hosts.map(&:dup) }
transport.sniffer = plain_sniffer
transport.reload_connections!
transport.reload_connections! # immediately rejected by the 1-token budget
check('discovery tokens spent after 2 calls', cc.ledger.consumed(:discovery), 1)

# --- Group B: three healthy queries hit the node boundary ---------------
transport.pinned = b
3.times { transport.perform_request('GET', 'orders/_search') { ok_response } }
check('node-B quota spent by 3 queries', cc.ledger.consumed(:node, scope: key_b), 3)
fourth_ran = false
begin
  transport.perform_request('GET', 'orders/_search') { fourth_ran = true; ok_response }
rescue T::CongestionLimitExceeded => e
  check('4th B query retry_after', e.retry_after, 1.0)
end
check('4th B query was blocked before I/O', fourth_ran, false)

# --- t=1: B quota recycles one token -> normal query continues -----------
clock.advance(1.0)
result = transport.perform_request('GET', 'orders/_search') { ok_response }
check('B query at t=1 status', result.status, 200)
check('node-B recycled tokens at t=1', cc.ledger.recycled(:node, scope: key_b), 1)
check('node-B total spent after resume', cc.ledger.consumed(:node, scope: key_b), 4)
puts '       -> healthy node B continues exactly at fake t=1.0s'

# --- t=2: probe budget recycles; probe #2 succeeds; resurrection --------
clock.advance(1.0)
probe2 = transport.probe_dead_connections! { true }
check('probe #2 result at t=2', probe2.first[:result], :reachable)
check('probe tokens spent on A', cc.ledger.consumed(:probe, scope: key_a), 2)
check('probe tokens recycled', cc.ledger.recycled(:probe), 1)

transport.resurrect_dead_connections!
check('node A alive after resurrection', a.dead?, false)
check('resurrection tokens spent on A', cc.ledger.consumed(:resurrection, scope: key_a), 1)

extra = cc.reserve(:resurrection, node: key_a)
check('second resurrection at t=2 allowed?', extra.allowed?, false)
check('resurrection wait', extra.retry_after, 3.0)
clock.advance(3.0) # t=5
check('resurrection token recycled at t=5', cc.remaining(:resurrection), 1)

clock.advance(5.0) # t=10
check('discovery token recycled at t=10', cc.remaining(:discovery), 1)

puts
puts '== Cost reconciliation for the failed node A =='
puts '   active retries : 3 node-quota + 2 total-retry tokens'
puts "   probes         : #{cc.ledger.consumed(:probe, scope: key_a)} tokens (one failed t=0, one reachable t=2)"
puts "   resurrection   : #{cc.ledger.consumed(:resurrection, scope: key_a)} token"
puts "   discovery      : #{cc.ledger.consumed(:discovery)} token spent (small global budget)"
puts '   healthy node B : blocked at t=0 boundary, resumed at fake t=1.0s on quota recovery'
puts
cc.report($stdout)
puts

if CHECKS.all?
  puts "ALL #{CHECKS.size} CHECKS PASSED"
  exit 0
else
  puts "#{CHECKS.count(false)} CHECK(S) FAILED"
  exit 1
end
