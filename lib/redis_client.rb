# frozen_string_literal: true

require "redis_client/version"
require "redis_client/command_builder"
require "redis_client/url_config"
require "redis_client/config"
require "redis_client/pid_cache"
require "redis_client/sentinel_config"
require "redis_client/middlewares"

class RedisClient
  @driver_definitions = {}
  @drivers = {}

  @default_driver = nil

  class << self
    def register_driver(name, &block)
      @driver_definitions[name] = block
    end

    def driver(name)
      return name if name.is_a?(Class)

      name = name.to_sym
      unless @driver_definitions.key?(name)
        raise ArgumentError, "Unknown driver #{name.inspect}, expected one of: `#{@driver_definitions.keys.inspect}`"
      end

      @drivers[name] ||= @driver_definitions[name]&.call
    end

    def default_driver
      unless @default_driver
        @driver_definitions.each_key do |name|
          if @default_driver = driver(name)
            break
          end
        rescue LoadError
        end
      end
      @default_driver
    end

    def default_driver=(name)
      @default_driver = driver(name)
    end

    def now
      Process.clock_gettime(Process::CLOCK_MONOTONIC)
    end

    def now_ms
      Process.clock_gettime(Process::CLOCK_MONOTONIC, :float_millisecond)
    end
  end

  register_driver :ruby do
    require "redis_client/ruby_connection"
    RubyConnection
  end

  module Common
    attr_reader :config, :id, :nodes
    attr_accessor :connect_timeout, :read_timeout, :write_timeout

    def initialize(
      config,
      id: config.id,
      connect_timeout: config.connect_timeout,
      read_timeout: config.read_timeout,
      write_timeout: config.write_timeout
    )
      @config = config
      @id = id&.to_s
      @connect_timeout = connect_timeout
      @read_timeout = read_timeout
      @write_timeout = write_timeout
      @command_builder = config.command_builder
      @pid = PIDCache.pid
      @nodes = [self].freeze
    end

    def timeout=(timeout)
      @connect_timeout = @read_timeout = @write_timeout = timeout
    end

    def node_for(_key)
      self
    end

    def nodes_for(*keys)
      keys.flatten!
      { self => keys }
    end
  end

  module HasConfig
    attr_reader :config

    def _set_config(config)
      @config = config
    end

    def message
      return super unless config&.resolved?

      "#{super} (#{config.server_url})"
    end
  end

  module Retriable
    def _set_retry_attempt(retry_attempt)
      @retry_attempt = retry_attempt
    end

    def retry_attempt
      @retry_attempt || 0
    end

    def retriable?
      !!@retry_attempt
    end

    def final?
      !@retry_attempt
    end
  end

  module Final
    def _set_retry_attempt(_retry_attempt)
    end

    def retry_attempt
      0
    end

    def retriable?
      false
    end

    def final?
      true
    end
  end

  # Tracks the two independent halves of a batch exchange: the write side and
  # the read side. Drivers that perform their own I/O should flag
  # `write = :started` right before the first byte may leave the socket, so a
  # failure before that point is reported as retryable instead of pending.
  class BatchProgress
    attr_accessor :write, :received_count
    attr_reader :results

    def initialize(commands, results: nil)
      @write = :not_started
      @received_count = 0
      @results = results || Array.new(commands.size)
    end

    def record_result(index, result)
      @results[index] = result
      @received_count = index + 1
    end
  end

  module HasBatchProgress
    attr_reader :batch_progress

    def _set_batch_progress(progress) # :nodoc:
      @batch_progress = progress
    end
  end

  class Error < StandardError
    include HasConfig
    include Retriable
    include HasBatchProgress

    attr_reader :next_error

    def self.with_config(message, config = nil)
      error = new(message)
      error._set_config(config)
      error
    end

    def _set_next_error(error) # :nodoc:
      @next_error = error
    end
  end

  ProtocolError = Class.new(Error)
  UnsupportedServer = Class.new(Error)

  ConnectionError = Class.new(Error)
  CannotConnectError = Class.new(ConnectionError)

  FailoverError = Class.new(ConnectionError)

  TimeoutError = Class.new(ConnectionError)
  ReadTimeoutError = Class.new(TimeoutError)
  WriteTimeoutError = Class.new(TimeoutError)
  CheckoutTimeoutError = Class.new(TimeoutError)

  module HasCommand
    attr_reader :command

    def _set_command(command)
      @command = command
    end
  end

  module HasCode
    attr_reader :code

    def initialize(message = nil, code = nil)
      super(message)
      @code = code
    end
  end

  # Returned by `pipelined` and `multi` when `result_status: true` is passed.
  #
  # `#results` keeps the normal structure: for a pipeline it is the array of
  # replies, for a transaction it is the array returned by `EXEC`. On top of
  # that, the wrapper records two independent facts:
  #
  # * how far the write got (`#write_completed?`, `#write_started?`), and
  # * how many replies were parsed (`#receive_completed?`, `#received_count`).
  #
  # From those facts the caller can tell which results are usable
  # (`#available_results`), which commands are safe to retry because they were
  # never sent (`#retryable_commands`), and which commands may have been
  # applied without a confirmed reply (`#pending_confirmation`).
  #
  # For transactions the reply to `EXEC` is the only evidence that the queued
  # commands ran. Until that reply is parsed every queued command is reported as
  # pending confirmation, even when `MULTI` and `QUEUED` replies were received.
  class BatchResult
    include Enumerable

    # Nothing was written, every command can safely be retried.
    RETRYABLE = :retryable
    # Some or all commands may have been applied, but their replies were not
    # parsed. The caller must verify those commands before retrying them.
    PENDING_CONFIRMATION = :pending_confirmation
    # Every reply was parsed and no command error was returned.
    COMPLETE = :complete
    # Every reply was parsed, but at least one was a server-side error.
    # `#results` exposes those errors as elements.
    FAILED = :failed
    # A transaction was discarded because `EXEC` returned nil (for example a
    # watched key changed). No command was applied and the caller can retry the
    # transaction from scratch.
    ABORTED = :aborted

    attr_reader :results, :status, :exception, :commands, :received_count, :write_status

    def results=(results)
      @results = results
    end

    def expected_replies
      @expected_replies || @commands.size
    end

    def expected_replies=(count)
      @expected_replies = count
    end

    # Build a status wrapper for a batch that completed successfully.
    def self.complete(results, commands:, transaction: false, received_count: nil)
      new(
        results,
        status: COMPLETE,
        commands: commands,
        transaction: transaction,
        received_count: received_count || (results ? results.size : 0),
        write_status: :complete,
      )
    end

    # Build a status wrapper for a batch whose replies were all parsed, but
    # where at least one entry is a `CommandError`. The parsed replies stay
    # available under `#results`.
    def self.failed(results, commands:, transaction: false, received_count: nil)
      new(
        results,
        status: FAILED,
        commands: commands,
        transaction: transaction,
        received_count: received_count || (results ? results.size : 0),
        write_status: :complete,
      )
    end

    # A transaction discarded by `EXEC` returning nil: every reply was parsed,
    # but no command was applied. `received_count` and `expected_replies` refer
    # to the full MULTI/.../EXEC batch, even though `#commands` only lists the
    # queued commands that have a result slot.
    def self.aborted(commands:, received_count: commands.size)
      result = new(
        nil,
        status: ABORTED,
        commands: commands,
        transaction: true,
        received_count: received_count,
        write_status: :complete,
      )
      result.expected_replies = received_count
      result
    end

    # Build a status wrapper for a batch interrupted by an error. The status is
    # derived from the two independent progress counters: a request that never
    # started writing is retryable, anything else must be verified.
    def self.interrupted(progress, commands:, exception:, transaction: false)
      write = progress.write

      if write == :not_started
        status = RETRYABLE
        results = []
        received_count = 0
      elsif transaction
        # `MULTI`/`QUEUED` acknowledgements are not command results, so an
        # interrupted transaction has no usable results at all.
        status = PENDING_CONFIRMATION
        results = []
        received_count = 0
      elsif progress.received_count >= commands.size
        results = progress.results
        status = results.any? { |result| result.is_a?(CommandError) } ? FAILED : COMPLETE
        received_count = progress.received_count
      else
        status = PENDING_CONFIRMATION
        results = progress.results
        received_count = progress.received_count
      end

      new(
        results,
        status: status,
        commands: commands,
        transaction: transaction,
        exception: exception,
        received_count: received_count,
        write_status: write,
      )
    end

    def initialize(
      results,
      status:,
      commands:,
      transaction: false,
      exception: nil,
      received_count: nil,
      write_status: nil
    )
      @results = results
      @status = status
      @commands = commands
      @transaction = transaction
      @exception = exception
      @received_count = received_count || 0
      @write_status = write_status
    end

    # True when every reply was parsed, regardless of command errors. An
    # aborted transaction also parsed every reply, but applied nothing.
    def complete?
      @status == COMPLETE || @status == FAILED || @status == ABORTED
    end

    def success?
      @status == COMPLETE
    end

    def failed?
      @status == FAILED
    end

    def aborted?
      @status == ABORTED
    end

    def retryable?
      @status == RETRYABLE || @status == ABORTED
    end

    def pending_confirmation?
      @status == PENDING_CONFIRMATION
    end
    alias_method :partial?, :pending_confirmation?

    def needs_verification?
      pending_confirmation?
    end

    def transaction?
      @transaction
    end

    # Whether every command reached the socket. Judged independently from
    # reply parsing: a batch can be fully written but only partially read.
    def write_completed?
      @write_status == :complete
    end

    # `:not_started`, `:started` (a transfer was attempted) or `:complete`.
    def write_started?
      @write_status == :started || @write_status == :complete
    end

    # Whether every reply was parsed.
    def receive_completed?
      @received_count >= expected_replies
    end

    # Replies that were actually parsed. Always empty for an interrupted
    # transaction, because partial `MULTI`/`QUEUED` acknowledgements do not
    # confirm any command. An aborted transaction has no results at all.
    def available_results
      return [] if transaction? && (pending_confirmation? || aborted?)

      return [] unless @results

      @results.first(@received_count)
    end
    alias_method :confirmed_results, :available_results

    # Indexes whose result is usable, following the order of `#results`.
    def available_indexes
      return [] if transaction? && (pending_confirmation? || aborted?)

      0...@received_count
    end

    # Commands that may have been applied without a confirmed reply.
    def pending_confirmation
      return [] unless pending_confirmation?

      @commands[@received_count..-1] || []
    end
    alias_method :pending_commands, :pending_confirmation

    # Indexes whose outcome needs to be verified by the caller.
    def pending_indexes
      return [] unless pending_confirmation?

      (@received_count...@commands.size)
    end

    # Commands that are safe to retry because nothing was written.
    def retryable_commands
      return [] unless retryable?

      @commands
    end

    # The commands represented by `#results`, excluding MULTI/EXEC.
    def transaction_commands
      @commands
    end

    def [](index)
      @results && @results[index]
    end

    def size
      @results ? @results.size : 0
    end

    def to_a
      @results
    end

    def each(&block)
      @results&.each(&block)
    end

    def ==(other)
      other.is_a?(BatchResult) ? @results == other.results : @results == other
    end

    def deconstruct
      @results
    end

    def inspect
      "#<#{self.class.name} status=#{@status.inspect} received=#{@received_count}/#{@commands.size} " \
        "write=#{@write_status.inspect} transaction=#{@transaction}>"
    end
  end

  class CommandError < Error
    include HasCommand
    include HasCode
    include Final

    class << self
      def parse(error_message)
        code = if error_message.start_with?("ERR Error running script")
          # On older redis servers script errors are nested.
          # So we need to parse some more.
          if (match = error_message.match(/:\s-([A-Z]+) /))
            match[1]
          end
        end
        code ||= error_message.split(' ', 2).first
        klass = ERRORS.fetch(code, self)
        klass.new(error_message.strip, code.freeze)
      end
    end
  end

  AuthenticationError = Class.new(CommandError)
  PermissionError = Class.new(CommandError)
  WrongTypeError = Class.new(CommandError)
  OutOfMemoryError = Class.new(CommandError)
  NoScriptError = Class.new(CommandError)

  ReadOnlyError = Class.new(ConnectionError)
  ReadOnlyError.include(HasCommand)
  ReadOnlyError.include(HasCode)

  MasterDownError = Class.new(ConnectionError)
  MasterDownError.include(HasCommand)
  MasterDownError.include(HasCode)

  CommandError::ERRORS = {
    "WRONGPASS" => AuthenticationError,
    "NOPERM" => PermissionError,
    "READONLY" => ReadOnlyError,
    "MASTERDOWN" => MasterDownError,
    "WRONGTYPE" => WrongTypeError,
    "OOM" => OutOfMemoryError,
    "NOSCRIPT" => NoScriptError,
  }.freeze

  class << self
    def config(**kwargs)
      Config.new(client_implementation: self, **kwargs)
    end

    def sentinel(**kwargs)
      SentinelConfig.new(client_implementation: self, **kwargs)
    end

    def ring(*clients, **options)
      clients.flatten!
      require "redis_client/hash_ring" unless defined?(HashRing)
      HashRing.new(clients, **options)
    end

    def new(arg = nil, **kwargs)
      if arg.is_a?(Config::Common)
        super
      else
        super(config(**(arg || {}), **kwargs))
      end
    end

    def register(middleware)
      Middlewares.include(middleware)
    end
  end

  include Common

  def initialize(config, **)
    super
    @middlewares = config.middlewares_stack.new(self)
    @raw_connection = nil
    @disable_reconnection = false
    @retry_attempt = nil
  end

  def inspect
    id_string = " id=#{id}" if id
    "#<#{self.class.name} #{config.server_url}#{id_string}>"
  end

  def server_url
    config.server_url
  end

  def id
    config.id
  end

  def timeout
    config.read_timeout
  end

  def idle_timeout
    config.idle_timeout
  end

  def db
    config.db
  end

  def host
    config.host unless config.path
  end

  def port
    config.port unless config.path
  end

  def path
    config.path
  end

  def username
    config.username
  end

  def password
    config.password
  end

  def size
    1
  end

  def with(_options = nil)
    yield self
  end
  alias_method :then, :with

  def timeout=(timeout)
    super
    @raw_connection&.read_timeout = timeout
    @raw_connection&.write_timeout = timeout
  end

  def read_timeout=(timeout)
    super
    @raw_connection&.read_timeout = timeout
  end

  def write_timeout=(timeout)
    super
    @raw_connection&.write_timeout = timeout
  end

  def pubsub
    sub = PubSub.new(ensure_connected, @command_builder)
    @raw_connection = nil
    sub
  end

  def measure_round_trip_delay
    ensure_connected do |connection|
      @middlewares.call(["PING"], config) do
        connection.measure_round_trip_delay
      end
    end
  end

  def call(*command, **kwargs)
    command = @command_builder.generate(command, kwargs)
    result = ensure_connected do |connection|
      @middlewares.call(command, config) do
        connection.call(command, nil)
      end
    end

    if block_given?
      yield result
    else
      result
    end
  end

  def call_v(command)
    command = @command_builder.generate(command)
    result = ensure_connected do |connection|
      @middlewares.call(command, config) do
        connection.call(command, nil)
      end
    end

    if block_given?
      yield result
    else
      result
    end
  end

  def call_once(*command, **kwargs)
    command = @command_builder.generate(command, kwargs)
    result = ensure_connected(retryable: false) do |connection|
      @middlewares.call(command, config) do
        connection.call(command, nil)
      end
    end

    if block_given?
      yield result
    else
      result
    end
  end

  def call_once_v(command)
    command = @command_builder.generate(command)
    result = ensure_connected(retryable: false) do |connection|
      @middlewares.call(command, config) do
        connection.call(command, nil)
      end
    end

    if block_given?
      yield result
    else
      result
    end
  end

  def blocking_call(timeout, *command, **kwargs)
    command = @command_builder.generate(command, kwargs)
    error = nil
    result = ensure_connected do |connection|
      @middlewares.call(command, config) do
        connection.call(command, timeout)
      end
    rescue ReadTimeoutError => error
      break
    end

    if error
      raise error
    elsif block_given?
      yield result
    else
      result
    end
  end

  def blocking_call_v(timeout, command)
    command = @command_builder.generate(command)
    error = nil
    result = ensure_connected do |connection|
      @middlewares.call(command, config) do
        connection.call(command, timeout)
      end
    rescue ReadTimeoutError => error
      break
    end

    if error
      raise error
    elsif block_given?
      yield result
    else
      result
    end
  end

  def scan(*args, **kwargs, &block)
    unless block_given?
      return to_enum(__callee__, *args, **kwargs)
    end

    args = @command_builder.generate(["SCAN", 0] + args, kwargs)
    scan_list(1, args, &block)
  end

  def sscan(key, *args, **kwargs, &block)
    unless block_given?
      return to_enum(__callee__, key, *args, **kwargs)
    end

    args = @command_builder.generate(["SSCAN", key, 0] + args, kwargs)
    scan_list(2, args, &block)
  end

  def hscan(key, *args, **kwargs, &block)
    unless block_given?
      return to_enum(__callee__, key, *args, **kwargs)
    end

    args = @command_builder.generate(["HSCAN", key, 0] + args, kwargs)
    scan_pairs(2, args, &block)
  end

  def zscan(key, *args, **kwargs, &block)
    unless block_given?
      return to_enum(__callee__, key, *args, **kwargs)
    end

    args = @command_builder.generate(["ZSCAN", key, 0] + args, kwargs)
    scan_pairs(2, args, &block)
  end

  def connected?
    @raw_connection&.revalidate
  end

  def close
    @raw_connection&.close
    self
  end

  def disable_reconnection(&block)
    ensure_connected(retryable: false, &block)
  end

  def pipelined(exception: true, result_status: false)
    pipeline = Pipeline.new(@command_builder)
    yield pipeline

    if pipeline._size == 0
      result = []
      return result_status ? BatchResult.complete(result, commands: []) : result
    end

    commands = pipeline._commands

    # When status evidence is requested, never let the connection layer retry
    # the batch: a retry would hide the interrupted exchange and could re-apply
    # commands whose fate is unknown. Command errors are also returned as
    # elements rather than raised, so every outcome stays inspectable.
    retryable = result_status ? false : pipeline._retryable?
    raise_on_error = exception && !result_status
    begin
      results = ensure_connected(retryable: retryable) do |connection|
        @middlewares.call_pipelined(commands, config) do
          connection.call_pipelined(commands, pipeline._timeouts, exception: raise_on_error)
        end
      end
    rescue ConnectionError, ProtocolError => error
      raise unless result_status

      progress = error.batch_progress || BatchProgress.new(commands)
      return pipeline._coerce_batch!(BatchResult.interrupted(progress, commands: commands, exception: error))
    end

    if result_status
      final_results = pipeline._coerce_status!(results)

      batch = if final_results && final_results.any? { |result| result.is_a?(CommandError) }
        BatchResult.failed(final_results, commands: commands)
      else
        BatchResult.complete(final_results, commands: commands)
      end

      batch
    else
      pipeline._coerce!(results)
    end
  end

  def multi(watch: nil, result_status: false, &block)
    transaction = nil

    begin
      results = if watch
        # WATCH is stateful, so we can't reconnect if it's used, the whole transaction
        # has to be redone.
        ensure_connected(retryable: false) do |connection|
          call("WATCH", *watch)
          begin
            if transaction = build_transaction(&block)
              commands = transaction._commands
              call_pipelined_for(connection, commands, transaction, exception: !result_status)
            else
              call("UNWATCH")
              []
            end
          rescue
            call("UNWATCH") if connected? && watch
            raise
          end
        end
      else
        transaction = build_transaction(&block)
        if transaction._empty?
          []
        else
          commands = transaction._commands
          # Status mode must not silently retry a transaction: if the EXEC reply
          # was lost the commands may already have been applied.
          retryable = result_status ? false : transaction._retryable?
          ensure_connected(retryable: retryable) do |connection|
            call_pipelined_for(connection, commands, transaction, exception: !result_status)
          end
        end
      end
    rescue ConnectionError, ProtocolError => error
      raise unless result_status && transaction

      progress = error.batch_progress || BatchProgress.new(transaction._commands)
      return BatchResult.interrupted(
        progress,
        commands: transaction.transaction_commands,
        exception: error,
        transaction: true,
      )
    end

    return [] unless transaction
    return transaction._coerce!(results) unless result_status

    transaction._batch_result(results)
  end

  # Runs a transaction's MULTI/.../EXEC batch and records the progress on the
  # transaction so an interrupted exchange can be reported afterwards. Returns
  # the reply to `EXEC` (the last item of the batch). In status mode command
  # errors are not raised, so the caller can inspect the per-command outcome.
  def call_pipelined_for(connection, commands, transaction, exception: true)
    @middlewares.call_pipelined(commands, config) do
      progress = BatchProgress.new(commands)
      transaction._set_progress(progress)
      connection._set_batch_progress(progress)
      connection.call_pipelined(commands, nil, exception: exception)
    end.last
  end

  class PubSub
    def initialize(raw_connection, command_builder)
      @raw_connection = raw_connection
      @command_builder = command_builder
    end

    def call(*command, **kwargs)
      raw_connection.write(@command_builder.generate(command, kwargs))
      nil
    end

    def call_v(command)
      raw_connection.write(@command_builder.generate(command))
      nil
    end

    def close
      @raw_connection&.close
      @raw_connection = nil # PubSub can't just reconnect
      self
    end

    def next_event(timeout = nil)
      unless raw_connection
        raise ConnectionError, "Connection was closed or lost"
      end

      raw_connection.read(timeout)
    rescue ReadTimeoutError
      nil
    end

    private

    attr_reader :raw_connection
  end

  class Multi
    def initialize(command_builder)
      @command_builder = command_builder
      @size = 0
      @commands = []
      @blocks = nil
      @retryable = true
    end

    def call(*command, **kwargs, &block)
      command = @command_builder.generate(command, kwargs)
      (@blocks ||= [])[@commands.size] = block if block_given?
      @commands << command
      nil
    end

    def call_v(command, &block)
      command = @command_builder.generate(command)
      (@blocks ||= [])[@commands.size] = block if block_given?
      @commands << command
      nil
    end

    def call_once(*command, **kwargs, &block)
      command = @command_builder.generate(command, kwargs)
      @retryable = false
      (@blocks ||= [])[@commands.size] = block if block_given?
      @commands << command
      nil
    end

    def call_once_v(command, &block)
      command = @command_builder.generate(command)
      @retryable = false
      (@blocks ||= [])[@commands.size] = block if block_given?
      @commands << command
      nil
    end

    def _commands
      @commands
    end

    def _blocks
      @blocks
    end

    def _size
      @commands.size
    end

    def _empty?
      @commands.size <= 2
    end

    def _timeouts
      nil
    end

    def _retryable?
      @retryable
    end

    def _coerce!(results)
      results&.each_with_index do |result, index|
        if result.is_a?(CommandError)
          result._set_command(@commands[index + 1])
          raise result
        end

        if @blocks && block = @blocks[index + 1]
          results[index] = block.call(result)
        end
      end

      results
    end

    # Status mode keeps command errors as elements instead of raising, so the
    # caller can inspect every command's outcome (and the batch status).
    def _coerce_status!(results)
      results&.each_with_index do |result, index|
        if result.is_a?(CommandError)
          result._set_command(@commands[index + 1])
          next
        end

        if @blocks && block = @blocks[index + 1]
          results[index] = block.call(result)
        end
      end

      results
    end

    def _progress
      @progress
    end

    def _set_progress(progress)
      @progress = progress
    end

    # Build the status wrapper for a completed transaction. `EXEC` returns
    # `nil` when the transaction was aborted (e.g. a watched key changed); that
    # is a confirmed outcome, not an interrupted exchange. An interrupted
    # exchange instead surfaces the progress recorded by the connection.
    # Command errors inside the EXEC reply are reported as a failed batch
    # instead of raising, so the caller still receives the per-command outcome.
    def _batch_result(results)
      progress = @progress

      if results.nil?
        if progress && progress.received_count >= @commands.size
          # Every reply, including `EXEC` returning nil, was parsed.
          return BatchResult.aborted(
            commands: transaction_commands,
            received_count: progress.received_count,
          )
        end

        return BatchResult.interrupted(
          progress || BatchProgress.new(@commands),
          commands: transaction_commands,
          exception: nil,
          transaction: true,
        )
      end

      if results.is_a?(CommandError)
        # The `EXEC` reply itself was an error (e.g. an ACL error). It stands
        # for the whole transaction, so it is the single failed entry.
        results._set_command(["EXEC"])
        return BatchResult.failed([results], commands: [], transaction: true)
      end

      coerced = _coerce_status!(results)
      failed = coerced.any? { |result| result.is_a?(CommandError) }

      if failed
        BatchResult.failed(coerced, commands: transaction_commands, transaction: true)
      else
        BatchResult.complete(coerced, commands: transaction_commands, transaction: true)
      end
    end

    def transaction_commands
      @commands[1..-2] || []
    end
  end

  class Pipeline < Multi
    def initialize(_command_builder)
      super
      @timeouts = nil
    end

    def blocking_call(timeout, *command, **kwargs, &block)
      command = @command_builder.generate(command, kwargs)
      @timeouts ||= []
      @timeouts[@commands.size] = timeout
      (@blocks ||= [])[@commands.size] = block if block_given?
      @commands << command
      nil
    end

    def blocking_call_v(timeout, command, &block)
      command = @command_builder.generate(command)
      @timeouts ||= []
      @timeouts[@commands.size] = timeout
      (@blocks ||= [])[@commands.size] = block if block_given?
      @commands << command
      nil
    end

    def _timeouts
      @timeouts
    end

    def _empty?
      @commands.empty?
    end

    def _coerce!(results)
      return results unless results

      @blocks&.each_with_index do |block, index|
        if block
          results[index] = block.call(results[index])
        end
      end

      results
    end

    def _coerce_status!(results)
      return results unless results

      @blocks&.each_with_index do |block, index|
        if block
          results[index] = block.call(results[index])
        end
      end

      results
    end

    # Apply the configured blocks to the replies that were actually parsed and
    # return the batch with those transformed results. Entries that were never
    # received stay as `nil` placeholders.
    def _coerce_batch!(batch)
      results = batch.results
      received = batch.received_count
      @blocks&.each_with_index do |block, index|
        if block && index < received && results
          results[index] = block.call(results[index])
        end
      end
      batch
    end
  end

  private

  def build_transaction
    transaction = Multi.new(@command_builder)
    transaction.call("MULTI")
    yield transaction
    transaction.call("EXEC")
    transaction
  end

  def scan_list(cursor_index, command, &block)
    cursor = 0
    while cursor != "0"
      command[cursor_index] = cursor
      cursor, elements = call(*command)
      elements.each(&block)
    end
    nil
  end

  def scan_pairs(cursor_index, command)
    cursor = 0
    while cursor != "0"
      command[cursor_index] = cursor
      cursor, elements = call(*command)

      index = 0
      size = elements.size
      while index < size
        yield elements[index], elements[index + 1]
        index += 2
      end
    end
    nil
  end

  def ensure_connected(retryable: true)
    close if !config.inherit_socket && @pid != PIDCache.pid

    if @disable_reconnection
      @raw_connection.retry_attempt = nil
      if block_given?
        yield @raw_connection
      else
        @raw_connection
      end
    elsif retryable
      tries = 0
      connection = nil
      preferred_error = nil
      begin
        @retry_attempt = config.retriable?(tries) ? tries : nil
        connection = raw_connection
        if block_given?
          result = yield connection
          @last_used_at = RedisClient.now
          result
        else
          connection
        end
      rescue ConnectionError, ProtocolError => error
        preferred_error ||= error
        close

        if error.is_a?(CircuitBreaker::OpenCircuitError)
          raise preferred_error
        else
          preferred_error = error
        end

        if !@disable_reconnection && config.retry_connecting?(tries, error)
          tries += 1
          retry
        else
          raise preferred_error
        end
      end
    else
      previous_disable_reconnection = @disable_reconnection
      connection = ensure_connected
      begin
        @disable_reconnection = true
        @raw_connection.retry_attempt = nil
        result = yield connection
        @last_used_at = RedisClient.now
        result
      rescue ConnectionError, ProtocolError
        close
        raise
      ensure
        @disable_reconnection = previous_disable_reconnection
      end
    end
  end

  def raw_connection
    if @raw_connection.nil? || !@raw_connection.revalidate
      connect
    end

    if config.idle_timeout && (@last_used_at + config.idle_timeout) < RedisClient.now
      @middlewares.call(["PING"], config) do
        @raw_connection.call(["PING"], nil)
      rescue ConnectionError, ProtocolError
        close
        connect
      end
    end

    @raw_connection.retry_attempt = @retry_attempt
    @raw_connection
  end

  def connect
    @pid = PIDCache.pid

    if @raw_connection&.revalidate
      @middlewares.connect(config) do
        @raw_connection.reconnect
      end
    else
      @raw_connection = @middlewares.connect(config) do
        config.driver.new(
          config,
          connect_timeout: connect_timeout,
          read_timeout: read_timeout,
          write_timeout: write_timeout,
        )
      end
    end
    @last_used_at = RedisClient.now
    @raw_connection.retry_attempt = @retry_attempt

    prelude = config.connection_prelude.dup

    if id
      prelude << ["CLIENT", "SETNAME", id]
    end

    if config.sentinel?
      prelude << ["ROLE"]
    end

    unless prelude.empty?
      results = @middlewares.call_pipelined(prelude, config) do
        @raw_connection.call_pipelined(prelude, nil, exception: false)
      end

      results.each do |result|
        # CLIENT SETINFO is unsupported on Redis < 7.2. The pipeline drained all responses before raising,
        # so if that's the only error, the socket is healthy: keep it.
        if result.is_a?(CommandError) && !(result.command[0] == "CLIENT" && result.command[1] == "SETINFO")
          raise result
        end
      end

      if config.sentinel?
        config.check_role!(results.last.first)
      end
    end
  rescue FailoverError, CannotConnectError => error
    @raw_connection&.close
    error._set_config(config)
    raise error
  rescue ConnectionError => error
    @raw_connection&.close
    connect_error = CannotConnectError.with_config(error.message, config)
    connect_error.set_backtrace(error.backtrace)
    raise connect_error
  rescue CommandError => error
    @raw_connection&.close

    if error.command&.first == "HELLO" && error.message.match?(/ERR unknown command/)
      raise UnsupportedServer,
        "redis-client requires Redis 6+ with HELLO command available (#{config.server_url})", cause: error
    else
      raise
    end
  end
end

require "redis_client/pooled"
require "redis_client/circuit_breaker"

RedisClient.default_driver
