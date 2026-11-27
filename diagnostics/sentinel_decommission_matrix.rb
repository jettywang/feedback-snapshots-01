# frozen_string_literal: true

# Re-runnable diagnostic matrix for Sentinel decommissioning questions.
#
# It exercises the real RedisClient::SentinelConfig resolution/caching code and
# the real RedisClient#ensure_connected retry loop, but substitutes an in-memory
# driver for sockets. Every dial, cache transition, ROLE check and retry decision
# is recorded with the sample address it used.
#
# Usage:
#   ruby -Ilib diagnostics/sentinel_decommission_matrix.rb --list
#   ruby -Ilib diagnostics/sentinel_decommission_matrix.rb --all
#   ruby -Ilib diagnostics/sentinel_decommission_matrix.rb --scenario role_change_rebuild
#   ruby -Ilib diagnostics/sentinel_decommission_matrix.rb --all --format json
#   ruby -Ilib diagnostics/sentinel_decommission_matrix.rb --all --verify

require "redis_client"
require "json"
require "optparse"

module SentinelDiagnostic
  NAME = "cache"
  SAMPLE_KEY = "retained:sample"
  SAMPLE_VALUE = "retained-sample"
  WRITE_COMMANDS = %w[SET SETEX PSETEX APPEND INCR DECR DEL UNLINK EXPIRE MSET].freeze

  # Documentation-only TEST-NET addresses. The diagnostic never opens a socket.
  ADDRESSES = {
    S1: ["192.0.2.10", 26379],
    S2: ["192.0.2.11", 26379],
    X: ["198.51.100.20", 6379],
    Y: ["203.0.113.30", 6379],
  }.freeze

  class Log
    attr_reader :events

    def initialize
      @events = []
      @phase = :setup
    end

    def phase(name)
      @phase = name
      record(:phase, name: name)
    end

    def record(type, **data)
      @events << { seq: @events.size + 1, phase: @phase, type: type, **data }
      @events.last
    end

    def where(type, phase: nil)
      selected = @events.select { |event| event[:type] == type }
      phase ? selected.select { |event| event[:phase] == phase } : selected
    end
  end

  class Endpoint
    attr_reader :host, :port
    attr_accessor :role

    def initialize(host, port, role: nil)
      @host = host
      @port = port
      @role = role
      @down = false
      @failures = Hash.new { |hash, key| hash[key] = [] }
    end

    def down=(value)
      @down = value
    end

    def down?
      @down
    end

    def enqueue_failure(command, mode)
      @failures[command.to_s.upcase] << mode
    end

    def take_failure(command)
      @failures[command.to_s.upcase]&.shift
    end

    def on_failure(command, &block)
      (@failure_hooks ||= Hash.new { |hash, key| hash[key] = [] })[command.to_s.upcase] << block
    end

    def run_failure_hooks(command)
      (@failure_hooks && @failure_hooks[command.to_s.upcase])&.each(&:call)
    end
  end

  class SentinelNode < Endpoint
    def initialize(host, port, network)
      super(host, port)
      @network = network
    end

    def call(command, timeout:, protocol:, config:, retry_attempt:)
      SentinelDiagnostic.log.record(
        :command, kind: :sentinel, node: @network.label(host, port),
        host: host, port: port, command: command
      )
      name = Array(command).first.to_s.upcase
      return "OK" unless name == "SENTINEL"

      sentinel_command(command, protocol)
    end

    private

    def sentinel_command(command, protocol)
      case command[1].to_s.downcase
      when "get-master-addr-by-name"
        host, port = @network.master
        [host, port.to_s]
      when "sentinels"
        @network.sentinels.map do |endpoint|
          pair = { "ip" => endpoint.host, "port" => endpoint.port.to_s }
          protocol == 2 ? pair.to_a.flatten(1) : pair
        end
      when "replicas"
        @network.replicas.map do |endpoint|
          pair = { "ip" => endpoint.host, "port" => endpoint.port.to_s, "flags" => endpoint.role.to_s }
          protocol == 2 ? pair.to_a.flatten(1) : pair
        end
      else
        "OK"
      end
    end
  end

  class RedisNode < Endpoint
    def initialize(host, port, network, role:)
      super(host, port, role: role)
      @network = network
      @data = Hash.new { |hash, key| hash[key] = SAMPLE_VALUE }
    end

    def call(command, timeout:, protocol:, config:, retry_attempt:)
      SentinelDiagnostic.log.record(
        :command, kind: :business, node: @network.label(host, port),
        host: host, port: port, command: command
      )
      name = Array(command).first.to_s.upcase
      mode = take_failure(name)
      if mode
        SentinelDiagnostic.log.record(:command_failure, node: @network.label(host, port), command: name, mode: mode)
        run_failure_hooks(name)
        raise_failure(mode, config, retry_attempt)
      end

      if @role == :slave && WRITE_COMMANDS.include?(name)
        SentinelDiagnostic.log.record(:readonly_rejection, node: @network.label(host, port), command: name)
        error = RedisClient::ReadOnlyError.new(
          "READONLY You can't write against a read only replica.", "READONLY"
        )
        error._set_config(config)
        error._set_retry_attempt(retry_attempt)
        raise error
      end

      case name
      when "ROLE"
        if @role == :master
          ["master", 0, []]
        else
          ["slave", @network.master[0], @network.master[1], "connected", 0]
        end
      when "PING"
        "PONG"
      when "GET"
        @data[command[1]]
      when "SET"
        @data[command[1]] = command[2]
        "OK"
      else
        "OK"
      end
    end

    private

    def raise_failure(mode, config, retry_attempt)
      error = case mode
      when :timeout
        RedisClient::ReadTimeoutError.with_config("simulated read timeout at #{host}:#{port}", config)
      when :reset
        RedisClient::ConnectionError.with_config("simulated connection reset at #{host}:#{port}", config)
      else
        raise ArgumentError, "unknown failure mode: #{mode.inspect}"
      end
      error._set_retry_attempt(retry_attempt)
      raise error
    end
  end

  class Network
    attr_reader :sentinels, :nodes, :replicas

    def initialize(log, sentinels: %i[S1])
      @log = log
      @sentinels = []
      @nodes = {}
      @master_key = nil
      @replicas = []
      sentinels.each { |key| add_sentinel(key) }
    end

    def add_sentinel(key)
      host, port = ADDRESSES.fetch(key)
      endpoint = SentinelNode.new(host, port, self)
      endpoint.define_singleton_method(:key) { key }
      @sentinels << endpoint
      endpoint
    end

    def add_node(key, role:)
      host, port = ADDRESSES.fetch(key)
      endpoint = RedisNode.new(host, port, self, role: role)
      endpoint.define_singleton_method(:key) { key }
      @nodes[[host, port]] = endpoint
      endpoint
    end

    def master=(key)
      @master_key = key
      @master = ADDRESSES.fetch(key)
    end

    def master
      @master || ADDRESSES.fetch(@master_key)
    end

    def replicas=(keys)
      @replicas = keys.map { |key| @nodes.fetch(ADDRESSES.fetch(key)) }
    end

    def label(host, port)
      target = endpoint(host, port)
      target&.key&.to_s || "?"
    end

    def endpoint(host, port)
      @sentinels.find { |candidate| candidate.host == host && candidate.port == port } ||
        @nodes[[host, port]]
    end

    def node(key)
      @nodes.fetch(ADDRESSES.fetch(key))
    end

    def dial(config, connection_id:)
      host = config.host
      port = config.port
      target = endpoint(host, port)
      kind = if @sentinels.include?(target)
        :sentinel
      elsif target
        :business
      else
        :unknown
      end
      @log.record(
        :dial, kind: kind, node: label(host, port), host: host, port: port,
        connection: connection_id, config: config.class.name,
        client: config.custom[:client]
      )
      unless target
        raise RedisClient::CannotConnectError.with_config("no endpoint at #{host}:#{port}", config)
      end
      if target.down?
        raise RedisClient::CannotConnectError.with_config("simulated refusal at #{host}:#{port}", config)
      end
      target
    end
  end

  class MemoryConnection
    include RedisClient::ConnectionMixin

    def initialize(config, connect_timeout:, read_timeout:, write_timeout:)
      super(config)
      @network = config.custom.fetch(:network)
      @connect_timeout = connect_timeout
      @read_timeout = read_timeout
      @write_timeout = write_timeout
      @queue = []
      @open = false
      connect
    end

    def connect
      @server_key = config.server_key
      @endpoint = @network.dial(config, connection_id: object_id)
      @open = true
      true
    end

    def connected?
      @open
    end

    def close
      @open = false
      @queue.clear
      super
    end

    def read_timeout=(timeout)
      @read_timeout = timeout
    end

    def write_timeout=(timeout)
      @write_timeout = timeout
    end

    def write(command)
      @queue << command
    end

    def write_multi(commands)
      @queue.concat(commands)
    end

    def read(timeout)
      command = @queue.shift
      raise connection_error("no command buffered") unless command

      @endpoint.call(
        command,
        timeout: timeout,
        protocol: config.protocol,
        config: config,
        retry_attempt: @retry_attempt
      )
    end

    def measure_round_trip_delay
      call(["PING"], @read_timeout)
      0.0
    end
  end

  module SentinelConfigProbe
    def reset
      SentinelDiagnostic.log.record(:cache_reset)
      super
    end

    def check_role!(role)
      SentinelDiagnostic.log.record(
        :role_check, host: host, port: port, node: SentinelDiagnostic.current_node(host, port),
        expected: @role, actual: role
      )
      super
    rescue RedisClient::FailoverError => error
      SentinelDiagnostic.log.record(
        :role_check_failed, host: host, port: port, node: SentinelDiagnostic.current_node(host, port),
        expected: @role, actual: role, error: error.class.name
      )
      raise
    end

    def retry_connecting?(attempt, error)
      decision = super
      SentinelDiagnostic.log.record(
        :retry_decision, attempt: attempt, error: error.class.name,
        retry: decision, cache_reset: !error.is_a?(RedisClient::TimeoutError)
      )
      decision
    end

    private

    def config
      SentinelDiagnostic.log.record(:cache_lookup, hit: resolved?)
      resolved = super
      SentinelDiagnostic.log.record(:cache_lookup_result, node: SentinelDiagnostic.current_node(resolved.host, resolved.port))
      resolved
    end

    def resolve_master
      resolved = super
      SentinelDiagnostic.log.record(
        :cache_store, host: resolved.host, port: resolved.port,
        node: SentinelDiagnostic.current_node(resolved.host, resolved.port)
      )
      resolved
    end

    def sentinel_client(sentinel_config)
      previous = @sentinels[sentinel_config]
      reused = !previous.nil?
      if reused
        SentinelDiagnostic.log.record(
          :discovery_reuse, host: sentinel_config.host, port: sentinel_config.port,
          node: SentinelDiagnostic.current_node(sentinel_config.host, sentinel_config.port),
          client: previous.object_id
        )
      end
      client = super
      SentinelDiagnostic.log.record(
        :discovery_open, host: sentinel_config.host, port: sentinel_config.port,
        node: SentinelDiagnostic.current_node(sentinel_config.host, sentinel_config.port),
        client: client.object_id
      )
      client
    end
  end

  class << self
    attr_reader :log

    def log=(log)
      @log = log
    end

    attr_accessor :current_network

    def current_node(host, port)
      @current_network ? @current_network.label(host, port) : "?"
    end
  end

  RedisClient::SentinelConfig.prepend(SentinelConfigProbe)

  RedisClient.register_driver(:memory_diagnostic) do
    MemoryConnection
  end

  class Scenario
    attr_reader :name, :description, :expectations, :result, :log

    def initialize(name, description:, expectations: {}, sentinels: %i[S1], protocol: 3, &block)
      @name = name
      @description = description
      @expectations = expectations
      @sentinels = sentinels
      @protocol = protocol
      @block = block
    end

    attr_reader :protocol

    def resp2_variant
      self.class.new(
        :"#{@name}_resp2",
        description: "RESP2 copy of #{@name}: #{@description}",
        expectations: @expectations,
        sentinels: @sentinels,
        protocol: 2,
        &@block
      )
    end

    def run
      SentinelDiagnostic.log = Log.new
      SentinelDiagnostic.log.phase(:setup)
      network = Network.new(SentinelDiagnostic.log, sentinels: @sentinels)
      SentinelDiagnostic.current_network = network
      @log = SentinelDiagnostic.log
      @result = @block.call(network, @protocol)
      @log.phase(:done)
      self
    ensure
      SentinelDiagnostic.current_network = nil
    end

    def events
      @log.events
    end

    def dials(phase: nil, kind: nil)
      list = @log.where(:dial, phase: phase)
      list = list.select { |event| event[:kind] == kind } if kind
      list
    end

    def business_dials
      dials(kind: :business).map { |event| event[:node].to_sym }
    end

    def sentinel_dials
      dials(kind: :sentinel).map { |event| event[:node].to_sym }
    end

    def role_checks
      @log.where(:role_check)
    end

    def role_failures
      @log.where(:role_check_failed)
    end

    def retry_decisions
      @log.where(:retry_decision)
    end

    def demotion_seq
      event = @log.where(:demotion).first
      event && event[:seq]
    end

    def business_dials_to(node, after_seq: nil)
      list = @log.where(:dial).select { |event| event[:kind] == :business && event[:node] == node }
      list = list.select { |event| event[:seq] > after_seq } if after_seq
      list
    end

    def summary
      {
        business_dials: business_dials,
        sentinel_dials: sentinel_dials,
        role_checks: role_checks.map { |event| "#{event[:node]}:#{event[:actual]}/#{event[:expected]}" },
        role_failures: role_failures.map do |event|
          "#{event[:node]}:#{event[:actual]} expected #{event[:expected]}"
        end,
        client_dials: dials(kind: :business).group_by { |event| event[:client] || "default" }.transform_values do |events|
          events.map { |event| event[:node].to_sym }
        end,
        readonly_rejections: @log.where(:readonly_rejection).map { |event| event[:node].to_sym },
        retries: retry_decisions.map do |event|
          "attempt=#{event[:attempt]} #{short_error(event[:error])} " \
            "retry=#{event[:retry]} reset=#{event[:cache_reset]}"
        end,
        cache: collapse(@log.where(:cache_lookup).map { |event| event[:hit] ? "hit" : "miss" }),
        cache_stores: @log.where(:cache_store).map { |event| event[:node].to_sym },
        discovery_reuse: @log.where(:discovery_reuse).map { |event| event[:node].to_sym },
        final: @result,
      }
    end

    def verify!
      @expectations.filter_map do |key, expected|
        actual = summary.fetch(key)
        "#{key}: expected #{expected.inspect}, got #{actual.inspect}" unless actual == expected
      end
    end

    private

    def collapse(values)
      values.chunk_while { |left, right| left == right }.map(&:first)
    end

    def short_error(name)
      name.split("::").last
    end
  end

  class << self
    def build_config(network, reconnect_attempts:, timeout: 0.05, client: nil, protocol: 3, idle_timeout: 30.0)
      RedisClient.sentinel(
        name: NAME,
        sentinels: network.sentinels.map { |sentinel| { host: sentinel.host, port: sentinel.port } },
        role: :master,
        driver: :memory_diagnostic,
        custom: { network: network, client: client }.compact,
        timeout: timeout,
        reconnect_attempts: reconnect_attempts,
        protocol: protocol,
        idle_timeout: idle_timeout,
      )
    end

    def attempt
      { value: yield, error: nil, message: nil }
    rescue RedisClient::Error => error
      { value: nil, error: error.class.name, message: error.message }
    end

    def prime(network, config)
      log.phase(:resolve)
      client = config.new_client
      outcome = attempt { client.call("SET", SAMPLE_KEY, SAMPLE_VALUE) }
      raise "priming failed: #{outcome.inspect}" if outcome[:error]

      client
    end

    def demote(network, from:, to:)
      log.phase(:demotion)
      network.node(from).role = :slave
      network.node(to).role = :master
      network.master = to
      network.replicas = [from]
      log.record(:demotion, node: from.to_s, new_master: to.to_s)
    end

    def scenario_definitions
      @scenario_definitions ||= []
    end

    def scenario(name, description:, expectations: {}, sentinels: %i[S1], &block)
      scenario_definitions << Scenario.new(
        name, description: description, expectations: expectations, sentinels: sentinels, &block
      )
    end

    def scenario_matrix
      scenario_definitions.flat_map do |scenario|
        [scenario, scenario.resp2_variant]
      end
    end

    def scenarios
      if @expanded
        @expanded
      else
        @expanded = scenario_matrix
      end
    end
  end
end

SentinelDiagnostic.scenario(
  :reset_sentinel_down_transient,
  description: "The cached X is still master but a transient connection reset is reported while every " \
    "Sentinel is down. The reset discards a healthy cache entry, rediscovery cannot reach Sentinel, " \
    "and a recoverable command fails without redialing X.",
  expectations: {
    business_dials: %i[X],
    sentinel_dials: %i[S1 S1 S1],
    role_checks: ["X:master/master"],
    role_failures: [],
    cache_stores: %i[X],
    final: {
      value: nil,
      error: "RedisClient::ConnectionError",
      message: "No sentinels available",
    },
  }
) do |network, protocol = 3|
  network.master = :X
  network.add_node(:X, role: :master)
  network.add_node(:Y, role: :slave)

  config = SentinelDiagnostic.build_config(network, reconnect_attempts: 1, protocol: protocol)
  client = SentinelDiagnostic.prime(network, config)
  network.node(:X).enqueue_failure("GET", :reset)

  network.sentinels.each { |sentinel| sentinel.down = true }
  SentinelDiagnostic.log.phase(:transient_reset)
  SentinelDiagnostic.attempt { client.call("GET", SentinelDiagnostic::SAMPLE_KEY) }
end

SentinelDiagnostic.scenario(
  :multi_sentinel_reorder,
  description: "With S1 and S2 listed, resolution reaches S1 first. When S1 is down, the next " \
    "resolution tries S2 and reorders it to the front for later use.",
  sentinels: %i[S1 S2],
  expectations: {
    business_dials: %i[X X Y],
    sentinel_dials: %i[S1 S1 S1 S2],
    role_checks: ["X:master/master", "X:slave/master", "Y:master/master"],
    role_failures: ["X:slave expected master"],
    cache_stores: %i[X Y],
    final: { value: SentinelDiagnostic::SAMPLE_VALUE, error: nil, message: nil },
  }
) do |network, protocol = 3|
  network.master = :X
  network.add_node(:X, role: :master)
  network.add_node(:Y, role: :slave)

  config = SentinelDiagnostic.build_config(network, reconnect_attempts: 1, protocol: protocol)
  client = SentinelDiagnostic.prime(network, config)

  SentinelDiagnostic.demote(network, from: :X, to: :Y)
  network.sentinels.first.down = true
  SentinelDiagnostic.log.phase(:rebuild)
  SentinelDiagnostic.log.record(:client_close)
  client.close
  SentinelDiagnostic.attempt { client.call("GET", SentinelDiagnostic::SAMPLE_KEY) }
end

SentinelDiagnostic.scenario(
  :idle_ping_succeeds_on_stale_replica,
  description: "An idle socket is revalidated with PING. A demoted replica still answers PONG, so " \
    "the stale socket is kept and the following read succeeds with no ROLE check and no dial.",
  expectations: {
    business_dials: %i[X],
    sentinel_dials: %i[S1],
    role_checks: ["X:master/master"],
    role_failures: [],
    cache_stores: %i[X],
    final: { value: SentinelDiagnostic::SAMPLE_VALUE, error: nil, message: nil },
  }
) do |network, protocol = 3|
  network.master = :X
  network.add_node(:X, role: :master)
  network.add_node(:Y, role: :slave)

  config = SentinelDiagnostic.build_config(
    network, reconnect_attempts: 0, protocol: protocol, idle_timeout: 0.0
  )
  client = SentinelDiagnostic.prime(network, config)

  SentinelDiagnostic.demote(network, from: :X, to: :Y)
  SentinelDiagnostic.log.phase(:idle_revalidation)
  SentinelDiagnostic.attempt { client.call("GET", SentinelDiagnostic::SAMPLE_KEY) }
end

SentinelDiagnostic.scenario(
  :idle_ping_times_out_then_role_fails,
  description: "An idle socket's revalidation PING times out. The client reconnects to cached X, " \
    "the ROLE check rejects the demoted node, and the retry reaches Y. Here the idle path does " \
    "surface the role change, but only because PING failed.",
  expectations: {
    business_dials: %i[X X Y],
    sentinel_dials: %i[S1 S1],
    role_checks: ["X:master/master", "X:slave/master", "Y:master/master"],
    role_failures: ["X:slave expected master"],
    cache_stores: %i[X Y],
    final: { value: SentinelDiagnostic::SAMPLE_VALUE, error: nil, message: nil },
  }
) do |network, protocol = 3|
  network.master = :X
  network.add_node(:X, role: :master)
  network.add_node(:Y, role: :slave)

  config = SentinelDiagnostic.build_config(
    network, reconnect_attempts: 1, protocol: protocol, idle_timeout: 0.0
  )
  client = SentinelDiagnostic.prime(network, config)
  network.node(:X).enqueue_failure("PING", :timeout)

  SentinelDiagnostic.demote(network, from: :X, to: :Y)
  SentinelDiagnostic.log.phase(:idle_revalidation)
  SentinelDiagnostic.attempt { client.call("GET", SentinelDiagnostic::SAMPLE_KEY) }
end

SentinelDiagnostic.scenario(
  :cached_rebuild,
  description: "Discovery already cached Y; the business socket is closed and rebuilt. " \
    "Only the cached master address is dialed.",
  expectations: {
    business_dials: %i[Y Y],
    sentinel_dials: %i[S1],
    role_checks: ["Y:master/master", "Y:master/master"],
    role_failures: [],
    cache_stores: %i[Y],
    final: { value: SentinelDiagnostic::SAMPLE_VALUE, error: nil, message: nil },
  }
) do |network, protocol = 3|
  network.master = :Y
  network.add_node(:Y, role: :master)
  network.add_node(:X, role: :slave)

  config = SentinelDiagnostic.build_config(network, reconnect_attempts: 0, protocol: protocol)
  client = SentinelDiagnostic.prime(network, config)

  SentinelDiagnostic.log.phase(:rebuild)
  SentinelDiagnostic.log.record(:client_close)
  client.close
  SentinelDiagnostic.attempt { client.call("GET", SentinelDiagnostic::SAMPLE_KEY) }
end

SentinelDiagnostic.scenario(
  :role_change_rebuild,
  description: "Discovery cached X before failover. X is now a replica and Y is master. " \
    "Rebuild dials cached X first, ROLE rejects it, then Sentinel is re-queried for Y.",
  expectations: {
    business_dials: %i[X X Y],
    sentinel_dials: %i[S1 S1],
    role_checks: ["X:master/master", "X:slave/master", "Y:master/master"],
    role_failures: ["X:slave expected master"],
    cache_stores: %i[X Y],
    final: { value: SentinelDiagnostic::SAMPLE_VALUE, error: nil, message: nil },
  }
) do |network, protocol = 3|
  network.master = :X
  network.add_node(:X, role: :master)
  network.add_node(:Y, role: :slave)

  config = SentinelDiagnostic.build_config(network, reconnect_attempts: 1, protocol: protocol)
  client = SentinelDiagnostic.prime(network, config)

  SentinelDiagnostic.demote(network, from: :X, to: :Y)
  SentinelDiagnostic.log.phase(:rebuild)
  SentinelDiagnostic.log.record(:client_close)
  client.close
  SentinelDiagnostic.attempt { client.call("GET", SentinelDiagnostic::SAMPLE_KEY) }
end

SentinelDiagnostic.scenario(
  :timeout_keeps_cache,
  description: "A read timeout is reported first. TimeoutError does NOT reset the cached master, " \
    "so the retry dials cached X again and then fails its ROLE check with no attempts left.",
  expectations: {
    business_dials: %i[X X],
    sentinel_dials: %i[S1],
    role_checks: ["X:master/master", "X:slave/master"],
    role_failures: ["X:slave expected master"],
    cache_stores: %i[X],
    final: {
      value: nil,
      error: "RedisClient::FailoverError",
      message: "Expected to connect to a master, but the server is a replica",
    },
  }
) do |network, protocol = 3|
  network.master = :X
  network.add_node(:X, role: :master)
  network.add_node(:Y, role: :slave)

  config = SentinelDiagnostic.build_config(network, reconnect_attempts: 1, protocol: protocol)
  client = SentinelDiagnostic.prime(network, config)
  network.node(:X).enqueue_failure("GET", :timeout)

  SentinelDiagnostic.demote(network, from: :X, to: :Y)
  SentinelDiagnostic.log.phase(:timeout_retry)
  SentinelDiagnostic.attempt { client.call("GET", SentinelDiagnostic::SAMPLE_KEY) }
end

SentinelDiagnostic.scenario(
  :reset_rediscovers,
  description: "A connection reset is reported first. It resets the cached master, so the retry " \
    "queries Sentinel and dials the new master Y directly.",
  expectations: {
    business_dials: %i[X Y],
    sentinel_dials: %i[S1 S1],
    role_checks: ["X:master/master", "Y:master/master"],
    role_failures: [],
    cache_stores: %i[X Y],
    final: { value: SentinelDiagnostic::SAMPLE_VALUE, error: nil, message: nil },
  }
) do |network, protocol = 3|
  network.master = :X
  network.add_node(:X, role: :master)
  network.add_node(:Y, role: :slave)

  config = SentinelDiagnostic.build_config(network, reconnect_attempts: 1, protocol: protocol)
  client = SentinelDiagnostic.prime(network, config)
  network.node(:X).enqueue_failure("GET", :reset)

  SentinelDiagnostic.demote(network, from: :X, to: :Y)
  SentinelDiagnostic.log.phase(:reset_retry)
  SentinelDiagnostic.attempt { client.call("GET", SentinelDiagnostic::SAMPLE_KEY) }
end

SentinelDiagnostic.scenario(
  :role_reported_before_timeout,
  description: "Swap pair, run A: cached X was demoted while the socket was closed. The rebuild's " \
    "ROLE check reports the mismatch first, resetting the cache and redialing Y; a command timeout " \
    "on Y is reported second and only re-dials cached Y, so X is dialed exactly once after demotion.",
  expectations: {
    business_dials: %i[X X Y Y],
    sentinel_dials: %i[S1 S1],
    role_checks: ["X:master/master", "X:slave/master", "Y:master/master", "Y:master/master"],
    role_failures: ["X:slave expected master"],
    cache_stores: %i[X Y],
    final: { value: SentinelDiagnostic::SAMPLE_VALUE, error: nil, message: nil },
  }
) do |network, protocol = 3|
  network.master = :X
  network.add_node(:X, role: :master)
  network.add_node(:Y, role: :slave)

  config = SentinelDiagnostic.build_config(network, reconnect_attempts: 2, protocol: protocol)
  client = SentinelDiagnostic.prime(network, config)
  network.node(:Y).enqueue_failure("GET", :timeout)

  SentinelDiagnostic.demote(network, from: :X, to: :Y)
  SentinelDiagnostic.log.phase(:rebuild)
  SentinelDiagnostic.log.record(:client_close)
  client.close
  SentinelDiagnostic.attempt { client.call("GET", SentinelDiagnostic::SAMPLE_KEY) }
end

SentinelDiagnostic.scenario(
  :timeout_reported_before_role,
  description: "Swap pair, run B: the only role evidence predates the demotion, so a command " \
    "timeout is reported first and keeps the cache. The demotion lands before the retry, which dials " \
    "stale X again and only then gets the ROLE mismatch.",
  expectations: {
    business_dials: %i[X X Y],
    sentinel_dials: %i[S1 S1],
    role_checks: ["X:master/master", "X:slave/master", "Y:master/master"],
    role_failures: ["X:slave expected master"],
    cache_stores: %i[X Y],
    final: { value: SentinelDiagnostic::SAMPLE_VALUE, error: nil, message: nil },
  }
) do |network, protocol = 3|
  network.master = :X
  network.add_node(:X, role: :master)
  network.add_node(:Y, role: :slave)

  config = SentinelDiagnostic.build_config(network, reconnect_attempts: 2, protocol: protocol)
  client = SentinelDiagnostic.prime(network, config)
  network.node(:X).enqueue_failure("GET", :timeout)

  SentinelDiagnostic.log.phase(:timeout_then_failover)
  network.node(:X).on_failure("GET") do
    SentinelDiagnostic.demote(network, from: :X, to: :Y)
  end
  SentinelDiagnostic.attempt { client.call("GET", SentinelDiagnostic::SAMPLE_KEY) }
end

SentinelDiagnostic.scenario(
  :live_connection_not_rechecked,
  description: "X is demoted while the business socket stays open. The command succeeds against X, " \
    "no ROLE check happens and no new dial or Sentinel query is made.",
  expectations: {
    business_dials: %i[X],
    sentinel_dials: %i[S1],
    role_checks: ["X:master/master"],
    role_failures: [],
    cache_stores: %i[X],
    final: { value: SentinelDiagnostic::SAMPLE_VALUE, error: nil, message: nil },
  }
) do |network, protocol = 3|
  network.master = :X
  network.add_node(:X, role: :master)
  network.add_node(:Y, role: :slave)

  config = SentinelDiagnostic.build_config(network, reconnect_attempts: 0, protocol: protocol)
  client = SentinelDiagnostic.prime(network, config)

  SentinelDiagnostic.demote(network, from: :X, to: :Y)
  SentinelDiagnostic.log.phase(:live_connection)
  SentinelDiagnostic.attempt { client.call("GET", SentinelDiagnostic::SAMPLE_KEY) }
end

SentinelDiagnostic.scenario(
  :two_clients_converge,
  description: "Client A resolves after failover and reconnects from cached Y; client B resolved before " \
    "failover, hits the ROLE change on X, rediscovers, and also ends on Y.",
  expectations: {
    business_dials: %i[X Y Y X Y],
    sentinel_dials: %i[S1 S1 S1],
    role_checks: ["X:master/master", "Y:master/master", "Y:master/master", "X:slave/master", "Y:master/master"],
    role_failures: ["X:slave expected master"],
    cache_stores: %i[X Y Y],
    client_dials: { "A" => %i[Y Y], "B" => %i[X X Y] },
    final: {
      clients: {
        "A" => { value: SentinelDiagnostic::SAMPLE_VALUE, error: nil, message: nil },
        "B" => { value: SentinelDiagnostic::SAMPLE_VALUE, error: nil, message: nil },
      },
    },
  }
) do |network, protocol = 3|
  network.master = :X
  network.add_node(:X, role: :master)
  network.add_node(:Y, role: :slave)

  config_b = SentinelDiagnostic.build_config(network, reconnect_attempts: 1, client: "B", protocol: protocol)
  client_b = SentinelDiagnostic.prime(network, config_b)

  SentinelDiagnostic.demote(network, from: :X, to: :Y)

  config_a = SentinelDiagnostic.build_config(network, reconnect_attempts: 0, client: "A", protocol: protocol)
  client_a = SentinelDiagnostic.prime(network, config_a)

  SentinelDiagnostic.log.phase(:reconnect)
  SentinelDiagnostic.log.record(:client_close, client: "A")
  SentinelDiagnostic.log.record(:client_close, client: "B")
  client_a.close
  client_b.close

  outcome_a = SentinelDiagnostic.attempt { client_a.call("GET", SentinelDiagnostic::SAMPLE_KEY) }
  outcome_b = SentinelDiagnostic.attempt { client_b.call("GET", SentinelDiagnostic::SAMPLE_KEY) }
  { clients: { "A" => outcome_a, "B" => outcome_b } }
end

SentinelDiagnostic.scenario(
  :live_replica_readonly_rejected,
  description: "The business socket stays open across demotion. A read still succeeds from the stale " \
    "replica (no ROLE check), but a write is rejected with READONLY and only then reconnects to Y.",
  expectations: {
    business_dials: %i[X Y],
    sentinel_dials: %i[S1 S1],
    role_checks: ["X:master/master", "Y:master/master"],
    role_failures: [],
    cache_stores: %i[X Y],
    readonly_rejections: %i[X],
    final: {
      read: { value: SentinelDiagnostic::SAMPLE_VALUE, error: nil, message: nil },
      write: { value: "OK", error: nil, message: nil },
    },
  }
) do |network, protocol = 3|
  network.master = :X
  network.add_node(:X, role: :master)
  network.add_node(:Y, role: :slave)

  config = SentinelDiagnostic.build_config(network, reconnect_attempts: 1, protocol: protocol)
  client = SentinelDiagnostic.prime(network, config)

  SentinelDiagnostic.demote(network, from: :X, to: :Y)
  SentinelDiagnostic.log.phase(:live_replica)

  read = SentinelDiagnostic.attempt { client.call("GET", SentinelDiagnostic::SAMPLE_KEY) }
  write = SentinelDiagnostic.attempt { client.call("SET", SentinelDiagnostic::SAMPLE_KEY, "post-demotion") }
  { read: read, write: write }
end

SentinelDiagnostic.scenario(
  :cached_rebuild_sentinel_down,
  description: "Sentinel S1 is down, but discovery is already cached at current master Y. " \
    "A closed business socket is rebuilt from cache without needing Sentinel.",
  expectations: {
    business_dials: %i[Y Y],
    sentinel_dials: %i[S1],
    role_checks: ["Y:master/master", "Y:master/master"],
    role_failures: [],
    cache_stores: %i[Y],
    final: { value: SentinelDiagnostic::SAMPLE_VALUE, error: nil, message: nil },
  }
) do |network, protocol = 3|
  network.master = :Y
  network.add_node(:Y, role: :master)
  network.add_node(:X, role: :slave)

  config = SentinelDiagnostic.build_config(network, reconnect_attempts: 0, protocol: protocol)
  client = SentinelDiagnostic.prime(network, config)

  network.sentinels.first.down = true
  SentinelDiagnostic.log.phase(:sentinel_down)
  SentinelDiagnostic.log.record(:client_close)
  client.close
  SentinelDiagnostic.attempt { client.call("GET", SentinelDiagnostic::SAMPLE_KEY) }
end

SentinelDiagnostic.scenario(
  :role_change_sentinel_down,
  description: "Sentinel S1 is down and the cached X has been demoted. ROLE rejects X, the cache is " \
    "reset, but rediscovery cannot reach any Sentinel, so the rebuild fails.",
  expectations: {
    business_dials: %i[X X],
    sentinel_dials: %i[S1 S1 S1],
    role_checks: ["X:master/master", "X:slave/master"],
    role_failures: ["X:slave expected master"],
    cache_stores: %i[X],
    final: {
      value: nil,
      error: "RedisClient::ConnectionError",
      message: "No sentinels available",
    },
  }
) do |network, protocol = 3|
  network.master = :X
  network.add_node(:X, role: :master)
  network.add_node(:Y, role: :slave)

  config = SentinelDiagnostic.build_config(network, reconnect_attempts: 1, protocol: protocol)
  client = SentinelDiagnostic.prime(network, config)

  SentinelDiagnostic.demote(network, from: :X, to: :Y)
  network.sentinels.first.down = true
  SentinelDiagnostic.log.phase(:rebuild)
  SentinelDiagnostic.log.record(:client_close)
  client.close
  SentinelDiagnostic.attempt { client.call("GET", SentinelDiagnostic::SAMPLE_KEY) }
end

module SentinelDiagnostic
  module Renderer
    module_function

    def table(scenarios)
      lines = []
      lines << "Sentinel decommission diagnostic matrix"
      lines << "Sample addresses: " + ADDRESSES.map { |key, (host, port)| "#{key}=#{host}:#{port}" }.join("  ")
      lines << ""
      scenarios.each do |scenario|
        summary = scenario.summary
        lines << "== #{scenario.name} =="
        lines << scenario.description
        lines << "  business dials : #{summary[:business_dials].join(' -> ')}"
        lines << "  sentinel dials : #{summary[:sentinel_dials].join(' -> ')}"
        lines << "  role checks    : #{summary[:role_checks].join(', ')}"
        lines << "  role failures  : #{summary[:role_failures].empty? ? '-' : summary[:role_failures].join(', ')}"
        lines << "  retries        : #{summary[:retries].empty? ? '-' : summary[:retries].join(' | ')}"
        lines << "  cache          : #{summary[:cache].join(' -> ')}"
        lines << "  cache stores   : #{summary[:cache_stores].empty? ? '-' : summary[:cache_stores].join(', ')}"
        unless summary[:discovery_reuse].empty?
          lines << "  discovery reuse: #{summary[:discovery_reuse].join(', ')} " \
            "(client object reused, socket still redialed)"
        end
        unless summary[:client_dials].empty?
          summary[:client_dials].each do |client, nodes|
            label = client == "default" ? "" : " #{client}"
            lines << "  client#{label} dials : #{nodes.join(' -> ')}"
          end
        end
        unless summary[:readonly_rejections].empty?
          lines << "  readonly reject: #{summary[:readonly_rejections].join(', ')}"
        end
        lines << "  result         : #{format_result(summary[:final])}"
        if scenario.demotion_seq
          after = scenario.business_dials_to("X", after_seq: scenario.demotion_seq)
          lines << "  X dials after demotion: #{after.empty? ? 'none' : after.size}"
        end
        lines << ""
      end
      lines.join("\n")
    end

    def format_result(result)
      if result.key?(:clients)
        return result[:clients].map { |name, outcome| "#{name}=#{format_result(outcome)}" }.join("  ")
      end
      if result.key?(:read) || result.key?(:write)
        parts = []
        parts << "read=#{format_result(result[:read])}" if result.key?(:read)
        parts << "write=#{format_result(result[:write])}" if result.key?(:write)
        return parts.join("  ")
      end
      return "value=#{result[:value].inspect}" if result[:error].nil?

      "#{result[:error]}: #{result[:message]}"
    end
  end
end

def run_cli
  options = { format: :table, verify: false }
  parser = OptionParser.new do |opts|
    opts.banner = "Usage: ruby -Ilib diagnostics/sentinel_decommission_matrix.rb [options]"
    opts.on("--all", "Run the whole matrix (default)") { options[:all] = true }
    opts.on("--list", "List scenario names") { options[:list] = true }
    opts.on("--scenario NAME", "Run one scenario") { |name| options[:scenario] = name }
    opts.on("--protocol VERSION", Integer, "3 (default) or 2 for RESP2 variants") { |version| options[:protocol] = version }
    opts.on("--format FORMAT", "table or json") { |format| options[:format] = format.to_sym }
    opts.on("--verify", "Assert each scenario's recorded dials/roles") { options[:verify] = true }
    opts.on("-h", "--help", "Show help") do
      puts opts
      exit
    end
  end
  parser.parse!

  if options[:list]
    SentinelDiagnostic.scenarios.each do |scenario|
      puts "#{scenario.name}: #{scenario.description}"
    end
    exit
  end

  all_scenarios = SentinelDiagnostic.scenarios
  if options[:scenario]
    found = all_scenarios.find { |scenario| scenario.name == options[:scenario].to_sym }
    abort "Unknown scenario: #{options[:scenario]}" unless found
    selected = [found]
  elsif options[:protocol] == 2
    selected = all_scenarios.select { |scenario| scenario.protocol == 2 }
  else
    selected = all_scenarios.select { |scenario| scenario.protocol == 3 }
  end

  selected.each(&:run)

  if options[:verify]
    failures = selected.flat_map do |scenario|
      scenario.verify!.map { |failure| "#{scenario.name}: #{failure}" }
    end
    if failures.empty?
      puts "verified #{selected.size} scenario(s)"
    else
      puts failures.join("\n")
      exit 1
    end
  end

  case options[:format]
  when :json
    payload = selected.map do |scenario|
      {
        name: scenario.name,
        description: scenario.description,
        summary: scenario.summary,
        events: scenario.events,
      }
    end
    puts JSON.pretty_generate(payload)
  else
    puts SentinelDiagnostic::Renderer.table(selected)
  end
  end


run_cli if $PROGRAM_NAME == __FILE__
