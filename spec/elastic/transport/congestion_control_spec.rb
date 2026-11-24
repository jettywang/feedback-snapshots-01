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

# Intentionally requires the gem directly (not spec_helper) so the congestion
# suite stays runnable in minimal environments without the Curb gem.
require 'elastic-transport'

RSpec.describe Elastic::Transport::Transport::CongestionControl do
  CC = Elastic::Transport::Transport::CongestionControl

  let(:clock) { CC::FakeClock.new(0.0) }
  let(:cc) do
    CC.new(
      clock: clock,
      total_retry_limit: 2,
      per_node_limit: 3,
      probe_limit: 1,
      probe_refill_interval: 2.0
    )
  end

  it 'starts every bucket full' do
    expect(cc.remaining(:total_retry)).to eq(2)
    expect(cc.remaining(:node, node: 'a:9200')).to eq(3)
  end

  it 'enforces total retry and node quota together atomically' do
    expect(cc.reserve_dispatch('a').allowed?).to be(true)
    expect(cc.reserve_retry('a').allowed?).to be(true)
    expect(cc.reserve_retry('a').allowed?).to be(true)

    decision = cc.reserve_retry('a')
    expect(decision).to be_denied
    # node cap 3 = 1 dispatch + 2 retries, total cap 2 consumed
    expect(cc.remaining(:node, node: 'a')).to eq(0)
    expect(cc.remaining(:total_retry)).to eq(0)
  end

  it 'does not spend the global budget when the node quota is empty' do
    tight = CC.new(clock: clock, total_retry_limit: 5, per_node_limit: 1)
    tight.reserve_retry('a')
    expect(tight.reserve_retry('a')).to be_denied
    expect(tight.remaining(:total_retry)).to eq(4)
  end

  it 'keeps node quotas isolated from a failed peer' do
    cc.reserve_dispatch('a')
    2.times { cc.reserve_dispatch('a') }
    expect(cc.reserve_dispatch('a')).to be_denied
    expect(cc.reserve_dispatch('b')).to be_allowed
  end

  it 'recycles tokens on the fake clock and records it in the ledger' do
    cc.reserve(:probe)
    expect(cc.reserve(:probe)).to be_denied
    clock.advance(2.0)
    expect(cc.reserve(:probe)).to be_allowed
    expect(cc.ledger.consumed(:probe)).to eq(2)
    expect(cc.ledger.recycled(:probe)).to eq(1)
  end

  it 'raises CongestionLimitExceeded with retry_after from bang methods' do
    tight = CC.new(clock: clock, total_retry_limit: 0)
    expect { tight.reserve_retry!('a') }.to raise_error(
      Elastic::Transport::Transport::CongestionLimitExceeded
    )
  end

  describe Elastic::Transport::Transport::Base do
    class SpecCongestionTransport
      include Elastic::Transport::Transport::Base
      attr_accessor :pinned

      def __build_connection(host, _options = {}, _block = nil)
        Elastic::Transport::Transport::Connections::Connection.new(
          host: host, connection: Object.new,
          clock: congestion_control&.clock,
          options: { resurrect_timeout: 0 }
        )
      end

      def get_connection(options = {})
        pinned || super
      end
    end

    let(:hosts) { [{ host: '10.0.0.1', port: 9200 }, { host: '10.0.0.2', port: 9200 }] }
    let(:transport) do
      SpecCongestionTransport.new(
        hosts: hosts.map(&:dup),
        options: { retry_on_failure: 2, congestion_control: cc }
      )
    end
    let(:node_a) { transport.connections.all.find { |c| c.host[:host] == '10.0.0.1' } }
    let(:ok) do
      # No JSON content-type on purpose: congestion accounting is independent
      # of response parsing and this keeps the example environment minimal.
      Elastic::Transport::Transport::Response.new(200, 'OK')
    end

    it 'consumes both budgets exactly at the combined boundary and stops' do
      transport.pinned = node_a
      calls = 0
      expect do
        transport.perform_request('GET', '/') do
          calls += 1
          raise Errno::ECONNREFUSED
        end
      end.to raise_error(Elastic::Transport::Transport::Error)
      expect(calls).to eq(3) # 1 initial + 2 budgeted retries
      key = cc.node_key(node_a)
      expect(cc.remaining(:total_retry)).to eq(0)
      expect(cc.remaining(:node, node: key)).to eq(0)
      # any further retry is refused by the combined gate
      expect(cc.peek_retry(key)).to be_denied
    end

    it 'raises CongestionLimitExceeded when the retry budget is smaller than max_retries' do
      tight = CC.new(clock: clock, total_retry_limit: 1, per_node_limit: 10)
      tight_transport = SpecCongestionTransport.new(
        hosts: hosts.map(&:dup),
        options: { retry_on_failure: 5, congestion_control: tight }
      )
      node = tight_transport.connections.all.first
      tight_transport.pinned = node
      calls = 0
      expect do
        tight_transport.perform_request('GET', '/') do
          calls += 1
          raise Errno::ECONNREFUSED
        end
      end.to raise_error(Elastic::Transport::Transport::CongestionLimitExceeded)
      expect(calls).to eq(2)
    end

    it 'blocks a node at its quota boundary and resumes after fake-time refill' do
      node_b = transport.connections.all.find { |c| c.host[:host] == '10.0.0.2' }
      transport.pinned = node_b
      3.times { transport.perform_request('GET', '/') { ok } }
      expect { transport.perform_request('GET', '/') { ok } }
        .to raise_error(Elastic::Transport::Transport::CongestionLimitExceeded)
      clock.advance(1.0)
      expect(transport.perform_request('GET', '/') { ok }.status).to eq(200)
    end

    it 'meters probes and resurrection against the failed node' do
      node_a.dead!
      expect(transport.probe_dead_connections! { false }.first[:result]).to eq(:unreachable)
      clock.advance(2.0)
      expect(transport.probe_dead_connections! { true }.first[:result]).to eq(:reachable)
      clock.advance(1.0)
      transport.resurrect_dead_connections!
      expect(node_a.dead?).to be(false)
      key = cc.node_key(node_a)
      expect(cc.ledger.consumed(:probe, scope: key)).to eq(2)
      expect(cc.ledger.consumed(:resurrection, scope: key)).to eq(1)
    end
  end
end
