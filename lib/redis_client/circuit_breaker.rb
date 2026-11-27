# frozen_string_literal: true

class RedisClient
  class CircuitBreaker
    module Middleware
      def connect(config)
        config.circuit_breaker.protect { super }
      end

      def call(_command, config)
        config.circuit_breaker.protect { super }
      end

      def call_pipelined(_commands, config)
        config.circuit_breaker.protect { super }
      end
    end

    OpenCircuitError = Class.new(CannotConnectError)

    attr_reader :error_timeout, :error_threshold, :error_threshold_timeout, :success_threshold
    attr_reader :state, :generation, :successes, :last_error

    def error_count
      @lock.synchronize { @errors.size }
    end

    def initialize(error_threshold:, error_timeout:, error_threshold_timeout: error_timeout, success_threshold: 0)
      @error_threshold = Integer(error_threshold)
      @error_threshold_timeout = Float(error_threshold_timeout)
      @error_timeout = Float(error_timeout)
      @success_threshold = Integer(success_threshold)
      @errors = []
      @successes = 0
      @state = :closed
      @generation = 0
      @lock = Mutex.new
    end

    def protect
      if @state == :open
        refresh_state
      end

      # Snapshot the probe window the command enters in. A command that is still
      # in flight when the window changes must not have its result applied to the
      # new window.
      entry_generation = @generation
      entry_state = @state

      case entry_state
      when :open
        raise OpenCircuitError, "Too many connection errors happened recently"
      when :closed
        begin
          yield
        rescue ConnectionError => error
          record_error(entry_generation, error)
          raise
        end
      when :half_open
        begin
          result = yield
          record_success(entry_generation)
          result
        rescue ConnectionError => error
          record_error(entry_generation, error)
          raise
        end
      else
        raise "[BUG] RedisClient::CircuitBreaker unexpected @state (#{entry_state.inspect}})"
      end
    end

    private

    def refresh_state
      now = RedisClient.now
      @lock.synchronize do
        return unless @state == :open

        if @errors.last < (now - @error_timeout)
          if @success_threshold > 0
            @state = :half_open
            @successes = 0
          else
            @errors.clear
            @state = :closed
          end
          @generation += 1
        end
      end
    end

    def record_error(entry_generation, error = nil)
      now = RedisClient.now
      expiry = now - @error_threshold_timeout
      @lock.synchronize do
        # The window this command entered has already ended; keep the failure
        # observable (it is re-raised to the caller) but do not let it drive a
        # state transition or pollute the new window's counters.
        if entry_generation != @generation
          @last_error = error
          return
        end

        if @state == :closed
          @errors.reject! { |t| t < expiry }
        end
        @errors << now
        @last_error = error
        @successes = 0
        if @state == :half_open || (@state == :closed && @errors.size >= @error_threshold)
          @state = :open
          @generation += 1
        end
      end
    end

    def record_success(entry_generation)
      @lock.synchronize do
        # A success from a previous, already closed window cannot close the
        # current half-open probe.
        return unless entry_generation == @generation
        return unless @state == :half_open

        @successes += 1
        if @successes >= @success_threshold
          @errors.clear
          @state = :closed
          @generation += 1
        end
      end
    end
  end
end
