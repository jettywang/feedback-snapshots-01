# Licensed to Elasticsearch B.V. under one or more contributor
# license agreements. See the NOTICE file distributed with
# this work for additional information regarding copyright
# ownership. Elasticsearch B.V. licenses this file to you under
# the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.

require 'test_helper'

class Elastic::Transport::Transport::CongestionControlTest < Minitest::Test
  C = Elastic::Transport::Transport::CongestionControl
  FakeClock = C::FakeClock
  Response = Elastic::Transport::Transport::Response
  CongestionLimitExceeded = Elastic::Transport::Transport::CongestionLimitExceeded

  def setup
    @clock = FakeClock.new(0.0)
  end

  def build_control(**options)
    C.new({ clock: @clock }.merge(options))
  end

  # ------------------------------------------------------------------
  # Token buckets / fake clock
  # ------------------------------------------------------------------

  def test_buckets_start_full_and_spend_tokens
    cc = build_control(total_retry_limit: 2, per_node_limit: 3)
    assert_equal 2, cc.remaining(:total_retry)
    assert_equal 3, cc.remaining(:node, node: 'a:9200')

    assert cc.reserve_retry('a:9200').allowed?
    assert cc.reserve_retry('a:9200').allowed?
    refute cc.reserve_retry('a:9200').allowed?
    assert_equal 0, cc.remaining(:total_retry)
  end

  def test_quota_recycles_one_token_per_interval_on_fake_clock
    cc = build_control(per_node_limit: 2, node_refill_interval: 1.0)
    cc.reserve_dispatch('a')
    cc.reserve_dispatch('a')
    assert_equal 0, cc.remaining(:node, node: 'a')

    denied = cc.reserve_dispatch('a')
    assert denied.denied?
    assert_in_delta 1.0, denied.retry_after, 0.001

    @clock.advance(0.9)
    assert cc.reserve_dispatch('a').denied?, 'boundary is inclusive of the full interval'

    @clock.advance(0.1)
    assert cc.reserve_dispatch('a').allowed?, 'one token is restored exactly at t=1'
    assert_equal 0, cc.remaining(:node, node: 'a')
    assert_equal 1, cc.ledger.recycled(:node, scope: 'a')
  end

  def test_advance_helper_refills_eagerly
    cc = build_control(probe_limit: 1, probe_refill_interval: 2.0)
    assert cc.reserve(:probe).allowed?
    refute cc.reserve(:probe).allowed?
    cc.advance(2.0)
    assert cc.reserve(:probe).allowed?
  end

  # ------------------------------------------------------------------
  # Simultaneous total + node enforcement
  # ------------------------------------------------------------------

  def test_retry_requires_both_total_and_node_quota
    cc = build_control(total_retry_limit: 5, per_node_limit: 1)
    assert cc.reserve_dispatch('a').allowed? # initial attempt takes the only node token

    decision = cc.reserve_retry('a')
    assert decision.denied?
    # Total budget must be untouched when the combined gate fails.
    assert_equal 5, cc.remaining(:total_retry)
    assert_equal 0, cc.remaining(:node, node: 'a')
  end

  def test_retry_gate_is_atomic_when_node_empty_but_total_has_tokens
    cc = build_control(total_retry_limit: 2, per_node_limit: 1)
    cc.reserve_retry('a') # consumes one total + the only node token
    before = cc.ledger.entries.size

    refute cc.reserve_retry('a').allowed?
    assert_equal 1, cc.remaining(:total_retry), 'no total token consumed on rejection'
    assert_equal before + 1, cc.ledger.entries.size, 'only the denial event is recorded'
    assert_equal 1, cc.ledger.denials(:total_retry)
  end

  def test_other_node_keeps_independent_quota
    cc = build_control(total_retry_limit: 10, per_node_limit: 1)
    cc.reserve_dispatch('a')
    cc.reserve_dispatch('a') rescue nil
    refute cc.reserve_dispatch('a').allowed?
    assert cc.reserve_dispatch('b').allowed?, 'healthy node quota is isolated'
  end

  def test_bang_method_raises_with_retry_after
    cc = build_control(total_retry_limit: 0)
    error = assert_raises(CongestionLimitExceeded) { cc.reserve_retry!('a') }
    assert_kind_of Elastic::Transport::Transport::Error, error
    assert error.retry_after
  end

  # ------------------------------------------------------------------
  # Auxiliary budgets + ledger
  # ------------------------------------------------------------------

  def test_auxiliary_budgets_are_small_and_recover
    cc = build_control(
      discovery_limit: 1, discovery_refill_interval: 10,
      resurrection_limit: 1, resurrection_refill_interval: 5,
      probe_limit: 1, probe_refill_interval: 2
    )

    assert cc.reserve(:discovery).allowed?
    assert cc.reserve(:resurrection, node: 'a').allowed?
    assert cc.reserve(:probe, node: 'a').allowed?
    refute cc.reserve(:discovery).allowed?
    refute cc.reserve(:resurrection, node: 'a').allowed?
    refute cc.reserve(:probe, node: 'a').allowed?

    @clock.advance(2) # probe interval
    assert cc.reserve(:probe, node: 'a').allowed?
    refute cc.reserve(:resurrection, node: 'a').allowed?
    refute cc.reserve(:discovery).allowed?

    @clock.advance(3) # t=5, resurrection interval
    assert cc.reserve(:resurrection, node: 'a').allowed?
    refute cc.reserve(:discovery).allowed?

    @clock.advance(5) # t=10, discovery interval
    assert cc.reserve(:discovery).allowed?
    assert cc.reserve(:probe, node: 'a').allowed?
  end

  def test_probe_can_also_charge_node_quota_atomically
    cc = build_control(probe_limit: 5, per_node_limit: 1)
    cc.reserve_dispatch('a')
    decision = cc.reserve(:probe, node: 'a', charge_node_quota: true)
    assert decision.denied?
    assert_equal 5, cc.remaining(:probe), 'probe token not spent when node quota rejects'
  end

  def test_ledger_tracks_consumption_and_recycling
    cc = build_control(probe_limit: 1, probe_refill_interval: 2)
    cc.reserve(:probe)
    @clock.advance(2)
    cc.reserve(:probe)

    assert_equal 2, cc.ledger.consumed(:probe)
    assert_equal 1, cc.ledger.recycled(:probe)
    totals = cc.ledger.totals[:probe]
    assert_equal 2, totals[:consumed]
    assert_equal 1, totals[:recycled]
  end

  def test_node_key_normalizes_connection_and_hash
    assert_equal '10.0.0.1:9200', C.node_key(host: '10.0.0.1', port: 9200)
    conn = stub(host: { host: 'h', port: 9300 })
    assert_equal 'h:9300', C.node_key(conn)
    assert_equal 'node-1', C.node_key('node-1')
  end

  def test_client_builds_congestion_control_from_hash_and_accepts_instance
    clock = FakeClock.new
    client = Elastic::Transport::Client.new(
      hosts: ['http://127.0.0.1:9200'],
      congestion_control: { per_node_limit: 5, clock: clock }
    )
    assert_kind_of C, client.transport.congestion_control
    assert_equal 5, client.transport.congestion_control.limit(:node)
    assert_same clock, client.transport.congestion_control.clock

    instance = build_control
    client2 = Elastic::Transport::Client.new(
      hosts: ['http://127.0.0.1:9200'], congestion_control: instance
    )
    assert_same instance, client2.transport.congestion_control
  end

  # ------------------------------------------------------------------
  # Transport integration
  # ------------------------------------------------------------------

  class HarnessTransport
    include Elastic::Transport::Transport::Base
    attr_accessor :pinned

    def __build_connection(host, _options = {}, _block = nil)
      Elastic::Transport::Transport::Connections::Connection.new(
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

  HOSTS = [
    { host: '10.0.0.1', port: 9200 },
    { host: '10.0.0.2', port: 9200 }
  ].freeze

  def build_transport(control = nil, **options)
    control ||= build_control
    HarnessTransport.new(
      hosts: HOSTS.map(&:dup),
      options: { retry_on_failure: 2, congestion_control: control }.merge(options)
    )
  end

  def connection(transport, host)
    transport.connections.all.find { |c| c.host[:host] == host }
  end

  def ok_response
    Response.new(200, '{}', 'content-type' => 'application/json')
  end

  def test_disabled_by_default_keeps_unlimited_retries
    transport = HarnessTransport.new(
      hosts: HOSTS.map(&:dup),
      options: { retry_on_failure: true }
    )
    transport.pinned = connection(transport, '10.0.0.1')
    assert_nil transport.congestion_control
    calls = 0
    assert_raises Elastic::Transport::Transport::Error do
      transport.perform_request('GET', '/') do
        calls += 1
        raise Errno::ECONNREFUSED
      end
    end
    assert_equal 4, calls, '1 initial + DEFAULT_MAX_RETRIES retries unchanged'
  end

  def test_total_retry_budget_stops_the_retry_storm
    cc = build_control(total_retry_limit: 1, per_node_limit: 10)
    transport = build_transport(cc)
    a = connection(transport, '10.0.0.1')
    transport.pinned = a
    calls = 0

    error = assert_raises(CongestionLimitExceeded) do
      transport.perform_request('GET', '/') do
        calls += 1
        raise Errno::ECONNREFUSED
      end
    end
    assert error.retry_after
    # initial attempt + one budgeted retry; the second retry is rejected.
    assert_equal 2, calls
    assert_equal 1, cc.ledger.consumed(:total_retry)
  end

  def test_node_quota_blocks_dispatch_at_boundary
    cc = build_control(per_node_limit: 1, total_retry_limit: 5)
    transport = build_transport(cc)
    b = connection(transport, '10.0.0.2')
    transport.pinned = b

    transport.perform_request('GET', '/') { ok_response }
    calls = 0
    assert_raises(CongestionLimitExceeded) do
      transport.perform_request('GET', '/') do
        calls += 1
        ok_response
      end
    end
    assert_equal 0, calls, 'block must not run once node quota is empty'
  end

  def test_reload_connections_charges_discovery_budget
    cc = build_control(discovery_limit: 1, discovery_refill_interval: 10)
    transport = build_transport(cc)
    transport.sniffer.stubs(:hosts).returns(HOSTS.map(&:dup))

    transport.reload_connections!
    assert_equal 1, cc.ledger.consumed(:discovery)

    transport.reload_connections!
    assert_equal 1, cc.ledger.consumed(:discovery), 'second reload is skipped, not charged'
    assert_equal 1, cc.ledger.denials(:discovery)

    @clock.advance(10)
    transport.reload_connections!
    assert_equal 2, cc.ledger.consumed(:discovery)
    assert_equal 1, cc.ledger.recycled(:discovery)
  end

  def test_resurrect_pass_charges_budget_and_revives_eligible_node
    cc = build_control(resurrection_limit: 1, resurrection_refill_interval: 5)
    transport = build_transport(cc)
    a = connection(transport, '10.0.0.1')
    a.dead!
    assert a.dead?
    @clock.advance(1.0) # strict dead_since comparison needs t > 0

    transport.resurrect_dead_connections!
    refute a.dead?, 'resurrect_timeout=0 + fake clock makes it eligible'
    assert_equal 1, cc.ledger.consumed(:resurrection)

    # No dead connections left, so a second pass spends nothing.
    transport.resurrect_dead_connections!
    assert_equal 1, cc.ledger.consumed(:resurrection)
  end

  def test_probe_cycle_spends_probe_budget_and_reports_outcomes
    cc = build_control(probe_limit: 1, probe_refill_interval: 2)
    transport = build_transport(cc)
    a = connection(transport, '10.0.0.1')
    a.dead!

    first = transport.probe_dead_connections! { |_c| false }
    assert_equal :unreachable, first.first[:result]
    assert a.dead?

    second = transport.probe_dead_connections! { |_c| true }
    assert_equal :skipped, second.first[:result], 'small probe budget exhausted'

    @clock.advance(2)
    third = transport.probe_dead_connections! { |_c| true }
    assert_equal :reachable, third.first[:result]
    assert a.dead?, 'reachable probe does not return node to pool without resurrection'
    assert_equal 2, cc.ledger.consumed(:probe)
    assert_equal 1, cc.ledger.recycled(:probe)
  end

  def test_probe_block_exception_is_reported_unreachable_not_raised
    cc = build_control(probe_limit: 2)
    transport = build_transport(cc)
    a = connection(transport, '10.0.0.1')
    a.dead!

    results = transport.probe_dead_connections! { raise Errno::ECONNREFUSED }
    assert_equal :unreachable, results.first[:result]
    assert a.dead?
    assert_equal 1, cc.ledger.consumed(:probe)
  end

  def test_background_probe_tick_records_cycles_and_history
    cc = build_control(probe_limit: 1, probe_refill_interval: 2)
    transport = build_transport(cc)
    a = connection(transport, '10.0.0.1')
    a.dead!

    prober = Elastic::Transport::Transport::BackgroundProbe.new(transport) { |_c| false }
    results = prober.tick
    assert_equal :unreachable, results.first[:result]
    assert_equal 1, prober.cycles
    assert_equal 1, prober.history.size

    # Budget exhausted: the next tick records a skipped node, no extra spend.
    skipped = prober.tick
    assert_equal :skipped, skipped.first[:result]
    assert_equal 2, prober.cycles
    assert_equal 2, prober.history.size
    assert_equal 1, cc.ledger.consumed(:probe), 'skipped tick spends no token'

    @clock.advance(2)
    prober2 = Elastic::Transport::Transport::BackgroundProbe.new(transport) { |_c| true }
    assert_equal :reachable, prober2.tick.first[:result]
    assert_equal 2, cc.ledger.consumed(:probe)
  end

  # ------------------------------------------------------------------
  # The requested local-congestion scenario with the fake clock.
  # ------------------------------------------------------------------

  def test_local_congestion_two_groups_hit_the_quota_boundary
    report = StringIO.new
    line = ->(text = '') { report.puts text }

    clock = FakeClock.new(0.0)
    cc = C.new(
      clock: clock,
      total_retry_limit: 2,
      total_retry_refill_interval: 4.0,
      per_node_limit: 3,
      node_refill_interval: 1.0,
      discovery_limit: 1,
      discovery_refill_interval: 10.0,
      resurrection_limit: 1,
      resurrection_refill_interval: 5.0,
      probe_limit: 1,
      probe_refill_interval: 2.0
    )
    transport = build_transport(cc)
    node_a = connection(transport, '10.0.0.1')
    node_b = connection(transport, '10.0.0.2')
    key_a = cc.node_key(node_a)
    key_b = cc.node_key(node_b)

    line.call '== Local congestion scenario (fake clock, two nodes) =='
    line.call "node A=#{key_a} (fails), node B=#{key_b} (healthy)"

    # ---- Group A: one pinned request performs 1 initial + 2 retries ----
    transport.pinned = node_a
    attempts_a = 0
    assert_raises Elastic::Transport::Transport::Error do
      transport.perform_request('GET', 'orders/_search') do
        attempts_a += 1
        raise Errno::ECONNREFUSED
      end
    end

    assert_equal 3, attempts_a
    assert_equal 2, cc.ledger.consumed(:total_retry)
    assert_equal 3, cc.ledger.consumed(:node, scope: key_a)
    assert_equal 0, cc.remaining(:total_retry)
    assert_equal 0, cc.remaining(:node, node: key_a)
    assert node_a.dead?
    line.call "[t=0] group A: #{attempts_a} attempts; total-retry 2/2 used; node-A quota 3/3 used"

    # A further simultaneous retry gate is rejected by BOTH empty buckets.
    blocked = cc.peek_retry(key_a)
    refute blocked.allowed?
    line.call "[t=0] next A retry blocked; retry_after=#{blocked.retry_after.round(2)}s"

    # ---- First background probe of the failed node (small budget) ----
    probe1 = transport.probe_dead_connections! { |_c| false }
    assert_equal :unreachable, probe1.first[:result]
    line.call "[t=0] probe #1 against A: unreachable (probe budget spent=1)"

    # ---- Discovery/reload uses its own small budget too ----
    transport.sniffer.stubs(:hosts).returns(HOSTS.map(&:dup))
    transport.reload_connections!
    transport.reload_connections! # immediately rejected by the 1-token budget
    assert_equal 1, cc.ledger.consumed(:discovery)
    assert_equal 1, cc.ledger.denials(:discovery)
    line.call '[t=0] discovery reload spent 1 token; immediate reload rejected (recovery at t=10)'

    # ---- Group B: three healthy queries reach their node boundary ----
    transport.pinned = node_b
    3.times { transport.perform_request('GET', 'orders/_search') { ok_response } }
    assert_equal 3, cc.ledger.consumed(:node, scope: key_b)
    assert_equal 0, cc.remaining(:node, node: key_b)

    fourth = nil
    assert_raises(CongestionLimitExceeded) do
      transport.perform_request('GET', 'orders/_search') do
        fourth = :called
        ok_response
      end
    end
    assert_nil fourth
    b_wait = cc.retry_after(:node, node: key_b)
    assert_in_delta 1.0, b_wait, 0.001
    line.call "[t=0] group B: 3 queries used node-B quota 3/3; 4th query waits #{b_wait.round(2)}s"

    # ---- t=1: node quota recycles one token, B continues ----
    clock.advance(1.0)
    result = transport.perform_request('GET', 'orders/_search') { ok_response }
    assert_equal 200, result.status
    assert_equal 4, cc.ledger.consumed(:node, scope: key_b) # 3 + 1
    assert_equal 1, cc.ledger.recycled(:node, scope: key_b)
    line.call '[t=1] node-B quota recycled 1 token -> next normal query SUCCEEDS and drains it'

    # ---- t=2: probe budget recycles, second probe succeeds, resurrect ----
    clock.advance(1.0)
    probe2 = transport.probe_dead_connections! { |_c| true }
    assert_equal :reachable, probe2.first[:result]
    assert_equal 2, cc.ledger.consumed(:probe)
    assert_equal 1, cc.ledger.recycled(:probe)
    line.call '[t=2] probe budget recycled 1 token; probe #2 against A: reachable'

    transport.resurrect_dead_connections!
    refute node_a.dead?
    assert_equal 1, cc.ledger.consumed(:resurrection)
    line.call '[t=2] resurrection budget spent 1; node A returned to the pool'

    # Resurrection budget is at its boundary; recovery lands at t=5.
    extra = cc.reserve(:resurrection, node: key_a)
    assert extra.denied?
    assert_in_delta 3.0, extra.retry_after, 0.001
    clock.advance(3.0) # t=5
    assert_equal 1, cc.remaining(:resurrection), 'one resurrection token recycled at t=5'
    assert_equal 1, cc.ledger.recycled(:resurrection)
    line.call '[t=5] resurrection budget recycled 1 token (recovery recorded)'

    # ---- t=10: discovery budget recycles and one reload is allowed ----
    clock.advance(5.0) # t=10
    transport.reload_connections!
    assert_equal 2, cc.ledger.consumed(:discovery)
    assert_equal 1, cc.ledger.recycled(:discovery)
    line.call '[t=10] discovery budget recycled 1 token; reload allowed again'

    # ---- Reconcile the cost of the failed node's probe + resurrection ----
    probe_spent = cc.ledger.consumed(:probe, scope: key_a)
    resurrect_spent = cc.ledger.consumed(:resurrection, scope: key_a)
    discovery_spent = cc.ledger.consumed(:discovery)
    assert_equal 2, probe_spent
    assert_equal 1, resurrect_spent
    assert_equal 2, discovery_spent
    line.call "COST CHECK failed node A: probes=#{probe_spent} tokens, " \
              "resurrection=#{resurrect_spent} token; discovery=#{discovery_spent} tokens total"
    line.call '           retries on A also consumed 3 node quota + 2 total-retry tokens'
    line.call 'RESUME CHECK healthy node B continued at fake t=1.00s, independent of A'

    line.call ''
    cc.report(report)
    puts report.string
  end
end
