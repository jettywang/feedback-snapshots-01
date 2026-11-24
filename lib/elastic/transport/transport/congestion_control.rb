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
      # Configurable congestion protection ("quota" / token budgets).
      #
      # A node that has become unreachable used to make the client retry in an
      # unbounded loop, spending attempts against the dead node and the shared
      # retry budget. {CongestionControl} keeps two independent limits that are
      # enforced together before every retry:
      #
      # * a **total retry budget** shared by the whole transport, and
      # * a **node-level quota** for the specific connection.
      #
      # Discovery (sniff/reload), dead-connection resurrection and background
      # probes each get their own small budget so they can still happen, but
      # cannot amplify a failure. Every token spent ("consumed") and every
      # token restored by the clock ("recycled") is written to a {Ledger}.
      #
      # Time comes from an injectable `clock`, which makes the whole mechanism
      # deterministic in tests: pass a {FakeClock} and advance it manually.
      #
      # @example Enable with limits
      #   cc = Elastic::Transport::Transport::CongestionControl.new(
      #     total_retry_limit: 4,
      #     per_node_limit: 6,
      #     discovery_limit: 1,
      #     resurrection_limit: 1,
      #     probe_limit: 2,
      #     refill_interval: 1.0,
      #     refill_amount: 1
      #   )
      #   Elastic::Client.new(congestion_control: cc)
      #
      class CongestionControl
        TOTAL_RETRY  = :total_retry
        NODE         = :node
        DISCOVERY    = :discovery
        RESURRECTION = :resurrection
        PROBE        = :probe

        # Budgets that are intentionally small and independent of traffic.
        AUX_CATEGORIES = [DISCOVERY, RESURRECTION, PROBE].freeze
        CATEGORIES     = [TOTAL_RETRY, NODE, *AUX_CATEGORIES].freeze

        DEFAULT_LIMITS = {
          TOTAL_RETRY  => 3,
          NODE         => 10,
          DISCOVERY    => 1,
          RESURRECTION => 1,
          PROBE        => 1
        }.freeze

        DEFAULT_REFILL_INTERVAL = 1.0
        DEFAULT_REFILL_AMOUNT   = 1

        LIMIT_KEY_ALIASES = {
          TOTAL_RETRY => %i[total_retry_limit total_retry_budget total_retry_quota
                            retry_budget total_retries max_total_retries],
          NODE => %i[per_node_limit per_node_quota per_node_budget node_limit
                     node_quota node_budget max_retries_per_node],
          DISCOVERY => %i[discovery_limit discovery_budget discovery_quota
                          sniff_limit sniff_budget],
          RESURRECTION => %i[resurrection_limit resurrection_budget resurrection_quota
                             resurrect_limit resurrect_budget],
          PROBE => %i[probe_limit probe_budget probe_quota background_probe_limit
                      background_probe_budget]
        }.freeze

        # The result of every reservation attempt.
        Decision = Struct.new(:allowed, :category, :scope, :amount,
                              :remaining, :retry_after, :reason,
                              keyword_init: true) do
          def allowed?
            allowed == true
          end

          def denied?
            !allowed?
          end

          # Seconds until `amount` tokens are available; 0 when allowed.
          def retry_after_seconds
            retry_after.to_f
          end
        end

        # A monotonic-ish wall clock wrapper (Time is the default clock).
        class SystemClock
          def now
            ::Time.now
          end
        end

        # Deterministic clock for specs and local congestion scenarios.
        #
        # `#now` is a Float number of fake seconds; use {#advance} to move time.
        class FakeClock
          attr_reader :now

          def initialize(start = 0.0)
            @mutex = Mutex.new
            @now = start.to_f
          end

          def advance(seconds)
            @mutex.synchronize { @now += seconds.to_f }
          end
          alias tick advance

          def travel(to)
            @mutex.synchronize { @now = to.to_f }
          end
        end

        # One refillable token bucket with stepped recovery.
        #
        # Every `refill_interval` seconds the bucket recovers `refill_amount`
        # tokens, capped at `capacity`. Recovery is computed lazily against the
        # injected clock, so no background thread is needed.
        class Bucket
          attr_reader :category, :scope, :capacity, :refill_amount,
                      :refill_interval, :tokens, :last_refill_at

          def initialize(category:, capacity:, clock:, scope: nil,
                         refill_amount: DEFAULT_REFILL_AMOUNT,
                         refill_interval: DEFAULT_REFILL_INTERVAL,
                         ledger: nil)
            @category = category
            @scope = scope
            @capacity = capacity
            @tokens = capacity
            @refill_amount = refill_amount
            @refill_interval = refill_interval
            @clock = clock
            @ledger = ledger
            @last_refill_at = clock.now
          end

          def exhausted?
            tokens <= 0
          end

          # Recover tokens due at `now` and write recycle entries. Returns the
          # number of tokens actually restored.
          def refill!(now = @clock.now)
            return 0 unless refill_interval.positive?
            return 0 if @tokens >= @capacity

            periods = ((now - @last_refill_at) / @refill_interval).floor
            return 0 if periods <= 0

            @last_refill_at += periods * @refill_interval
            restored = [periods * @refill_amount, @capacity - @tokens].min
            return 0 if restored <= 0

            @tokens += restored
            @ledger&.record(
              :recycle,
              category: @category, scope: @scope, amount: restored,
              at: now, remaining: @tokens
            )
            restored
          end

          def can_take?(amount = 1)
            @tokens >= amount
          end

          def take!(amount, now:, detail: nil, scope: nil)
            @tokens -= amount
            @ledger&.record(
              :consume,
              category: @category, scope: scope || @scope, amount: amount,
              at: now, remaining: @tokens, detail: detail
            )
          end

          # Fake seconds until `amount` tokens can be taken (0 if available).
          def retry_after(amount = 1, now = @clock.now)
            return 0.0 if @tokens >= amount
            return Float::INFINITY unless refill_interval.positive? && refill_amount.positive?

            periods_needed = ((amount - @tokens) / refill_amount.to_f).ceil
            ready_at = @last_refill_at + (periods_needed * refill_interval)
            [ready_at - now, 0.0].max
          end

          def snapshot
            {
              category: @category,
              scope: @scope,
              capacity: @capacity,
              tokens: @tokens,
              refill_amount: @refill_amount,
              refill_interval: @refill_interval,
              last_refill_at: @last_refill_at
            }
          end
        end

        # Append-only audit trail of consumed and recycled quota.
        class Ledger
          Entry = Struct.new(:seq, :at, :type, :category, :scope,
                             :amount, :remaining, :detail, keyword_init: true)

          attr_reader :entries

          def initialize
            @mutex = Mutex.new
            @entries = []
            @seq = 0
          end

          def record(type, category:, amount:, at:, scope: nil, remaining: nil, detail: nil)
            @mutex.synchronize do
              @seq += 1
              @entries << Entry.new(
                seq: @seq, at: at.to_f, type: type.to_sym,
                category: category.to_sym, scope: scope&.to_s,
                amount: amount, remaining: remaining, detail: detail&.to_s
              )
            end
          end

          def consumed(category = nil, scope: nil)
            sum(:consume, category, scope)
          end

          def recycled(category = nil, scope: nil)
            sum(:recycle, category, scope)
          end

          def denied(category = nil, scope: nil)
            @mutex.synchronize do
              select_entries(:deny, category, scope).sum { |e| e.amount || 0 }
            end
          end

          def denials(category = nil, scope: nil)
            @mutex.synchronize do
              select_entries(:deny, category, scope).size
            end
          end

          def events(type = nil)
            @mutex.synchronize do
              type ? @entries.select { |e| e.type == type.to_sym } : @entries.dup
            end
          end

          # Nested totals for assertions and reporting.
          def totals
            @mutex.synchronize do
              result = {}
              @entries.each do |e|
                bucket = (result[e.category] ||= { consumed: 0, recycled: 0, denied: 0, denials: 0 })
                case e.type
                when :consume then bucket[:consumed] += e.amount
                when :recycle then bucket[:recycled] += e.amount
                when :deny
                  bucket[:denied] += e.amount || 0
                  bucket[:denials] += 1
                end
              end
              result
            end
          end

          def report(io = StringIO.new)
            io.puts 'QUOTA LEDGER (consumed / recycled / denied)'
            totals.sort.each do |category, values|
              io.puts format(
                '  %-13<cat>s consumed=%<used>d recycled=%<back>d ' \
                'denied=%<denied>d (%<count>d rejection%<plural>s)',
                cat: category, used: values[:consumed], back: values[:recycled],
                denied: values[:denied], count: values[:denials],
                plural: values[:denials] == 1 ? '' : 's'
              )
            end
            io
          end

          private

          # Caller holds the ledger mutex when this runs.
          def sum(type, category, scope)
            @mutex.synchronize do
              select_entries(type, category, scope).sum { |e| e.amount || 0 }
            end
          end

          def select_entries(type, category, scope)
            @entries.select do |e|
              e.type == type &&
                (category.nil? || e.category == category.to_sym) &&
                (scope.nil? || e.scope == scope.to_s)
            end
          end
        end

        attr_reader :clock, :ledger

        # @param config [Hash] congestion settings (see class docs).
        def initialize(config = {})
          @config = symbolize(config || {})
          @clock = build_clock(@config[:clock])
          @mutex = Mutex.new
          @ledger = @config[:ledger] || Ledger.new
          @buckets = {}
          @node_buckets = {}
          # Prime the global/auxiliary buckets at the clock's start so their
          # refill anchors are deterministic; node buckets are created lazily.
          [TOTAL_RETRY, *AUX_CATEGORIES].each { |category| simple_bucket(category) }
        end

        # Normalize a connection/host/string into a stable node scope.
        def self.node_key(connection_or_key)
          case connection_or_key
          when nil then 'default'
          when String, Symbol, Numeric then connection_or_key.to_s
          when Hash then host_key(connection_or_key)
          else
            if connection_or_key.respond_to?(:host)
              host = safe_host(connection_or_key)
              key = host_key(host) if host
              return key if key
            end
            connection_or_key.class.name.to_s + '@' + connection_or_key.object_id.to_s(16)
          end
        rescue StandardError
          'unknown-node'
        end

        def self.safe_host(connection)
          connection.host
        rescue StandardError
          nil
        end

        def self.host_key(host)
          return nil unless host.respond_to?(:[])

          name = host[:host] || host['host'] || host[:name] || host['name'] ||
                 host[:hostname] || host['hostname']
          return nil unless name

          port = host[:port] || host['port']
          attributes = host[:attributes] || host['attributes']
          suffix = attributes && !attributes.empty? ? "##{attributes.hash.to_s(16)}" : ''
          port ? "#{name}:#{port}#{suffix}" : name.to_s
        end

        def node_key(connection_or_key)
          self.class.node_key(connection_or_key)
        end

        # Reserve quota for the first (or only) dispatch to a node. Only the
        # node-level quota applies here; retry budget is spent in {#reserve_retry}.
        def reserve_dispatch(node, amount: 1)
          key = node_key(node)
          @mutex.synchronize do
            bucket = node_bucket(key)
            reserve_from(bucket, amount, category: NODE, scope: key)
          end
        end
        alias reserve_request reserve_dispatch

        def reserve_dispatch!(node, amount: 1)
          bang!(reserve_dispatch(node, amount: amount))
        end

        # Atomically reserve one retry: BOTH the total retry budget and the
        # target node quota must have room. Neither bucket is touched when the
        # combined reservation is rejected.
        def reserve_retry(node, amount: 1)
          key = node_key(node)
          @mutex.synchronize do
            total = simple_bucket(TOTAL_RETRY)
            node_bucket = node_bucket(key)
            total.refill!
            node_bucket.refill!

            if total.can_take?(amount) && node_bucket.can_take?(amount)
              total.take!(amount, now: now, detail: 'retry')
              node_bucket.take!(amount, now: now, detail: 'retry')
              Decision.new(
                allowed: true, category: TOTAL_RETRY, scope: key,
                amount: amount, remaining: node_bucket.tokens,
                reason: 'retry allowed'
              )
            else
              retry_after = [
                total.retry_after(amount, now),
                node_bucket.retry_after(amount, now)
              ].max
              deny(TOTAL_RETRY, key, amount, node_bucket.tokens, retry_after,
                    'total retry budget or node quota exhausted')
            end
          end
        end

        def reserve_retry!(node, amount: 1)
          bang!(reserve_retry(node, amount: amount))
        end

        # Reserve one of the small auxiliary budgets
        # (`:discovery`, `:resurrection` or `:probe`).
        #
        # When `charge_node`/`charge_node_quota` is set, the node quota is
        # checked and debited atomically as well (useful when a probe performs
        # real network I/O against the node).
        def reserve(category, node: nil, amount: 1, charge_node: false,
                    charge_node_quota: false)
          category = category.to_sym
          raise ArgumentError, "unknown congestion category: #{category}" unless CATEGORIES.include?(category)

          key = node ? node_key(node) : nil
          charge_node ||= charge_node_quota
          @mutex.synchronize do
            bucket = simple_bucket(category)
            target = charge_node && key ? node_bucket(key) : nil
            bucket.refill!
            target&.refill!

            if bucket.can_take?(amount) && (target.nil? || target.can_take?(amount))
              bucket.take!(amount, now: now, detail: category.to_s, scope: key)
              target&.take!(amount, now: now, detail: category.to_s)
              Decision.new(
                allowed: true, category: category, scope: key,
                amount: amount,
                remaining: target ? target.tokens : bucket.tokens,
                reason: "#{category} budget allowed"
              )
            else
              retry_after = [
                bucket.retry_after(amount, now),
                target&.retry_after(amount, now)
              ].compact.max.to_f
              deny(category, key, amount, bucket.tokens, retry_after,
                   "#{category} budget exhausted")
            end
          end
        end

        def reserve!(category, **kwargs)
          bang!(reserve(category, **kwargs))
        end

        # Peek whether a retry would currently be allowed without spending it.
        def retry_allowed?(node, amount: 1)
          peek_retry(node, amount: amount).allowed?
        end

        # Non-mutating counterpart of {#reserve_retry}.
        def peek_retry(node, amount: 1)
          key = node_key(node)
          @mutex.synchronize do
            total = simple_bucket(TOTAL_RETRY)
            node_bucket = node_bucket(key)
            total.refill!
            node_bucket.refill!
            allowed = total.can_take?(amount) && node_bucket.can_take?(amount)
            retry_after = [
              total.retry_after(amount, now),
              node_bucket.retry_after(amount, now)
            ].max
            Decision.new(
              allowed: allowed, category: TOTAL_RETRY, scope: key,
              amount: amount, remaining: node_bucket.tokens,
              retry_after: allowed ? 0.0 : retry_after,
              reason: allowed ? 'retry available' : 'retry budget exhausted'
            )
          end
        end

        # Recover every bucket against the current clock and record recycling.
        def refill!
          @mutex.synchronize do
            all_buckets.each { |bucket| bucket.refill! }
          end
        end

        def now
          @clock.now
        end

        def advance(seconds)
          raise ArgumentError, 'clock does not support advancing' unless @clock.respond_to?(:advance)

          @clock.advance(seconds)
          refill!
          now
        end

        # Seconds until one token of `category`/node scope is available.
        def retry_after(category = TOTAL_RETRY, node: nil, amount: 1)
          @mutex.synchronize do
            bucket = category == NODE || node ? node_bucket(node_key(node)) : simple_bucket(category.to_sym)
            bucket.refill!
            bucket.retry_after(amount, now)
          end
        end

        def remaining(category, node: nil)
          @mutex.synchronize do
            bucket = resolve_bucket(category, node)
            bucket.refill!
            bucket.tokens
          end
        end

        def limit(category, node: nil)
          @mutex.synchronize { resolve_bucket(category, node).capacity }
        end

        def snapshot
          @mutex.synchronize do
            {
              at: now,
              buckets: all_buckets.map(&:snapshot),
              totals: @ledger.totals
            }
          end
        end

        def report(io = $stdout)
          snapshot
          @ledger.report(io)
          io
        end

        private

        def resolve_bucket(category, node)
          category = category.to_sym
          if category == NODE || node
            node_bucket(node_key(node))
          else
            simple_bucket(category)
          end
        end

        def bang!(decision)
          return decision if decision.allowed?

          raise CongestionLimitExceeded.new(
            "#{decision.reason} (scope=#{decision.scope || decision.category}, " \
            "retry_after=#{decision.retry_after_seconds}s)",
            retry_after: decision.retry_after
          )
        end

        def reserve_from(bucket, amount, category:, scope:)
          bucket.refill!
          if bucket.can_take?(amount)
            bucket.take!(amount, now: now, detail: 'dispatch')
            Decision.new(allowed: true, category: category, scope: scope,
                         amount: amount, remaining: bucket.tokens,
                         reason: "#{category} quota allowed")
          else
            deny(category, scope, amount, bucket.tokens,
                 bucket.retry_after(amount, now), "#{category} quota exhausted")
          end
        end

        def deny(category, scope, amount, remaining, retry_after, reason)
          @ledger.record(:deny, category: category, scope: scope,
                         amount: amount, at: now, remaining: remaining)
          Decision.new(allowed: false, category: category, scope: scope,
                       amount: amount, remaining: remaining,
                       retry_after: retry_after, reason: reason)
        end

        def all_buckets
          @buckets.values + @node_buckets.values
        end

        def simple_bucket(category)
          @buckets[category] ||= build_bucket(category, nil)
        end

        def node_bucket(key)
          @node_buckets[key] ||= build_bucket(NODE, key)
        end

        def build_bucket(category, scope)
          limit = integer_config(limit_keys(category), DEFAULT_LIMITS[category])
          refill_amount = integer_config(
            ["#{category}_refill_amount".to_sym, :refill_amount],
            DEFAULT_REFILL_AMOUNT
          )
          refill_interval = numeric_config(
            ["#{category}_refill_interval".to_sym, :refill_interval],
            DEFAULT_REFILL_INTERVAL
          )

          budgets = @config[:budgets] || @config[:quotas] || {}
          override = budgets[category] || budgets[category.to_s]
          if override.is_a?(Hash)
            limit = override.fetch(:limit) { override[:capacity] || override['limit'] || override['capacity'] || limit }
            refill_amount = override[:refill_amount] || override['refill_amount'] || refill_amount
            refill_interval = override[:refill_interval] || override['refill_interval'] || refill_interval
          elsif override
            limit = override
          end

          Bucket.new(
            category: category, scope: scope, capacity: limit.to_i,
            clock: @clock, refill_amount: refill_amount.to_i,
            refill_interval: refill_interval.to_f, ledger: @ledger
          )
        end

        def limit_keys(category)
          [category, *(LIMIT_KEY_ALIASES[category] || [])]
        end

        def integer_config(keys, default)
          value = first_config(keys)
          value.nil? ? default : value.to_i
        end

        def numeric_config(keys, default)
          value = first_config(keys)
          value.nil? ? default : value.to_f
        end

        def first_config(keys)
          Array(keys).each do |key|
            return @config[key] if @config.key?(key)
            return @config[key.to_s] if @config.key?(key.to_s)
          end
          nil
        end

        def symbolize(hash)
          hash.each_with_object({}) do |(key, value), memo|
            memo[key.to_sym] = value.is_a?(Hash) ? symbolize(value) : value
          end
        end

        def build_clock(clock)
          case clock
          when nil then SystemClock.new
          when Proc then ProcClock.new(clock)
          else
            clock.respond_to?(:now) ? clock : ProcClock.new(clock)
          end
        end

        # Adapter for a Proc/lambda returning the current time.
        class ProcClock
          def initialize(callable)
            @callable = callable
          end

          def now
            @callable.call
          end
        end
      end

      # Naming alias: the feature is "congestion protection"; the class is the
      # quota/budget implementation.
      CongestionProtection = CongestionControl
    end
  end
end
