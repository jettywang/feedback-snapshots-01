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

module Elastic
  module Transport
    module Transport
      # Periodically runs the budgeted probe cycle over dead connections.
      #
      # The probe cadence and volume are ultimately capped by the
      # `:probe` budget of the transport's {CongestionControl}; every probe is
      # recorded in its ledger. Tests and local scenarios drive {#tick} with a
      # {CongestionControl::FakeClock} instead of using a real thread.
      #
      # @example Deterministic (fake clock)
      #   prober = BackgroundProbe.new(transport) { |c| fake_backend.up?(c) }
      #   clock.advance(2)
      #   prober.tick
      #
      # @example Real background thread
      #   prober = BackgroundProbe.new(transport, interval: 30) do |c|
      #     transport.__probe_http?(c)
      #   end
      #   prober.start!
      #   # ...
      #   prober.stop!
      #
      class BackgroundProbe
        DEFAULT_INTERVAL = 30 # seconds

        attr_reader :transport, :interval, :cycles, :history

        # @param transport [Object] a transport including {Base}
        # @param interval  [Float] real-thread sleep interval in seconds
        # @param probe     [Proc]  block given a connection, truthy = reachable
        def initialize(transport, interval: DEFAULT_INTERVAL, &probe)
          raise ArgumentError, 'A probe block is required' unless block_given?

          @transport = transport
          @interval = interval
          @probe = probe
          @cycles = 0
          @history = []
          @mutex = Mutex.new
          @thread = nil
          @running = false
        end

        # Run one probe cycle now. Safe to call repeatedly from tests.
        #
        # @return [Array<Hash>] results from {Base#probe_dead_connections!}
        def tick
          results = @transport.probe_dead_connections!(&@probe)
          @mutex.synchronize do
            @cycles += 1
            @history.concat(results)
          end
          results
        end
        alias run_cycle tick

        # Start a daemon thread that runs {#tick} every `interval` seconds.
        #
        # @return [self]
        def start!
          @mutex.synchronize do
            return self if @thread&.alive?

            @running = true
            @thread = Thread.new do
              while @running
                sleep(@interval)
                break unless @running

                tick
              end
            end
          end
          self
        end

        # Stop the background thread.
        #
        # @return [self]
        def stop!
          thread = @mutex.synchronize do
            @running = false
            @thread
          end
          if thread
            thread.wakeup if thread.status == 'sleep'
            thread.join(2) rescue nil # rubocop:disable Style/RescueModifier
          end
          @mutex.synchronize { @thread = nil }
          self
        end

        def running?
          @mutex.synchronize { @running && @thread&.alive? }
        end
      end
    end
  end
end
