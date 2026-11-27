# frozen_string_literal: true

require "test_helper"

class RedisClient
  class CircuitBreakerTest < RedisClientTestCase
    include ClientTestHelper

    def setup
      super
      @circuit_breaker = CircuitBreaker.new(
        error_threshold: 3,
        error_threshold_timeout: 2,
        success_threshold: 2,
        error_timeout: 1,
      )
    end

    def test_open_circuit_after_consecutive_errors
      open_circuit @circuit_breaker
      assert_open @circuit_breaker
    end

    def test_track_errors_during_error_threshold_window
      assert_closed @circuit_breaker
      (@circuit_breaker.error_threshold - 1).times do
        record_error @circuit_breaker
      end

      travel(@circuit_breaker.error_threshold_timeout - 0.01) do
        record_error @circuit_breaker
        assert_open @circuit_breaker
      end
    end

    def test_allow_use_after_the_errors_timedout
      open_circuit @circuit_breaker
      assert_open @circuit_breaker

      travel(@circuit_breaker.error_threshold_timeout) do
        assert_closed(@circuit_breaker)
      end
    end

    def test_reopen_immediately_when_half_open
      open_circuit @circuit_breaker
      assert_open @circuit_breaker

      travel(@circuit_breaker.error_timeout) do
        record_error(@circuit_breaker)
        assert_open(@circuit_breaker)
      end
    end

    def test_close_fully_after_success_threshold_is_reached
      open_circuit @circuit_breaker
      assert_open @circuit_breaker

      travel(@circuit_breaker.error_timeout) do
        @circuit_breaker.success_threshold.times do
          assert_closed(@circuit_breaker)
        end

        record_error(@circuit_breaker)
        assert_closed(@circuit_breaker)
      end
    end

    def test_in_flight_failure_belongs_to_the_window_it_entered
      with_fake_clock do |clock|
        breaker = build_breaker
        driver = ControllableDriver.new([
          [:parked, :fail], # A enters while closed
          :fail, :fail, :fail, # E1-E3 trip the breaker while A is in flight
        ])

        command_a = async_invoke(breaker, driver, "A")
        wait_until { driver.sent_order == ["A"] }
        assert_equal :closed, breaker.state

        3.times { |i| record_invoke(breaker, driver, "E#{i + 1}") }
        assert_open breaker
        assert_equal 1, breaker.generation
        assert_equal 3, breaker.error_count

        # A's failure lands after the window switched: it is re-raised...
        driver.release("A")
        error = assert_raises CannotConnectError do
          command_a.value
        end
        assert_equal "boom-A", error.message

        # ...but it does not feed the new (open) window, while its diagnostic
        # remains observable.
        assert_equal 3, breaker.error_count
        assert_equal 1, breaker.generation
        assert_equal :open, breaker.state
        assert_equal "boom-A", breaker.last_error.message
        assert_equal %w[A E1 E2 E3], driver.sent_order
      end
    end

    def test_open_window_rejects_and_then_allows_a_single_probe
      with_fake_clock do |clock|
        breaker = build_breaker
        driver = ControllableDriver.new([[:parked, :ok]])
        trip(breaker)

        # While open the command is rejected before reaching the driver.
        assert_raises CircuitBreaker::OpenCircuitError do
          invoke(breaker, driver, "B")
        end
        refute driver.sent_order.include?("B")

        clock.advance(breaker.error_timeout + 0.01)
        command_b = async_invoke(breaker, driver, "B")
        wait_until { driver.sent_order.include?("B") }

        assert_equal :half_open, breaker.state
        assert_equal 2, breaker.generation

        driver.release("B")
        assert_equal "OK-B", command_b.value
        assert_equal 1, breaker.successes
        assert_equal :half_open, breaker.state
      end
    end

    def test_half_open_uses_the_fresh_failure_and_ignores_the_stale_success
      with_fake_clock do |clock|
        breaker = build_breaker
        # Outcomes are consumed in call order: B (parked), C (parked), F (fail).
        driver = ControllableDriver.new([
          [:parked, :ok], # B: first half-open probe
          [:parked, :ok], # C: second probe, held back until F reopens the circuit
          :fail, # F: fresh probe failure that reopens the circuit
        ])
        move_to_half_open(breaker, clock, driver, "B")
        assert_equal 1, breaker.successes

        command_c = async_invoke(breaker, driver, "C")
        wait_until { driver.sent_order == %w[B C] }

        # F, not C, drives the reopen.
        record_invoke(breaker, driver, "F")
        assert_equal :open, breaker.state
        assert_equal 3, breaker.generation
        assert_equal 0, breaker.successes

        # C's success now belongs to the window it entered, not the open window.
        driver.release("C")
        assert_equal "OK-C", command_c.value
        assert_equal :open, breaker.state
        assert_equal 3, breaker.generation
        assert_equal 0, breaker.successes
        assert_equal %w[B C F], driver.sent_order
      end
    end

    def test_recovery_closes_the_window_and_the_normal_threshold_resumes
      with_fake_clock do |clock|
        breaker = build_breaker
        driver = ControllableDriver.new([:ok, :ok, :fail])
        open_then_wait_for_half_open(breaker, clock)

        assert_equal "OK-P1", invoke(breaker, driver, "P1")
        assert_equal :half_open, breaker.state
        assert_equal 1, breaker.successes

        assert_equal "OK-P2", invoke(breaker, driver, "P2")
        assert_equal :closed, breaker.state
        assert_equal 3, breaker.generation
        assert_equal 0, breaker.error_count

        record_invoke(breaker, driver, "N1")
        assert_equal :closed, breaker.state
        assert_equal 1, breaker.error_count
      end
    end

    def test_connection_retry_keeps_the_underlying_error_observable
      breaker = build_breaker
      attempts = 0

      breaker.error_threshold.times do
        assert_raises CannotConnectError do
          breaker.protect do
            attempts += 1
            raise CannotConnectError, "connection refused"
          end
        end
      end

      assert_open breaker
      assert_equal breaker.error_threshold, attempts
      assert_equal "connection refused", breaker.last_error.message

      assert_raises CircuitBreaker::OpenCircuitError do
        breaker.protect { :never_sent }
      end
      assert_equal "connection refused", breaker.last_error.message
    end

    private

    def build_breaker
      CircuitBreaker.new(
        error_threshold: 3,
        error_threshold_timeout: 1000,
        success_threshold: 2,
        error_timeout: 1,
      )
    end

    def trip(breaker)
      breaker.error_threshold.times do
        assert_raises CannotConnectError do
          breaker.protect { raise CannotConnectError, "trip" }
        end
      end
      assert_open breaker
    end

    def open_then_wait_for_half_open(breaker, clock)
      trip(breaker)
      clock.advance(breaker.error_timeout + 0.01)
      # Simulate the timeout having flipped the window without consuming a probe
      # slot, so the driver fully owns the next two probe results.
      breaker.instance_variable_set(:@state, :half_open)
      breaker.instance_variable_set(:@generation, breaker.generation + 1)
      breaker.instance_variable_set(:@successes, 0)
      assert_equal :half_open, breaker.state
      assert_equal 0, breaker.successes
    end

    def move_to_half_open(breaker, clock, driver, parked_name)
      trip(breaker)
      clock.advance(breaker.error_timeout + 0.01)
      command = async_invoke(breaker, driver, parked_name)
      wait_until { breaker.state == :half_open }
      driver.release(parked_name)
      command.value
    end

    def invoke(breaker, driver, name)
      breaker.protect { driver.call([name]) }
    end

    def async_invoke(breaker, driver, name)
      Thread.new { invoke(breaker, driver, name) }.tap do |thread|
        thread.report_on_exception = false
      end
    end

    def record_invoke(breaker, driver, name)
      assert_raises ConnectionError do
        invoke(breaker, driver, name)
      end
    end

    def wait_until
      deadline = Time.now + 1
      loop do
        result = yield
        return result if result
        raise "wait_until condition was not satisfied" if Time.now > deadline
        Thread.pass
      end
    end

    def with_fake_clock(start = 100.0)
      clock = FakeClock.new(start)
      original_now = RedisClient.singleton_class.instance_method(:now)
      RedisClient.define_singleton_method(:now) { clock.now }
      begin
        yield clock
      ensure
        RedisClient.define_singleton_method(:now, original_now)
      end
    end

    class FakeClock
      attr_reader :now

      def initialize(start)
        @now = start.to_f
      end

      def advance(seconds)
        @now += seconds
      end
    end

    class ControllableDriver
      attr_reader :sent_order

      def initialize(outcomes)
        @outcomes = outcomes
        @sent_order = []
        @gates = {}
        @mutex = Mutex.new
      end

      def release(name)
        gate(name) << :go
      end

      def call(command)
        name = command.first
        spec = @mutex.synchronize do
          outcome = @outcomes.shift
          @sent_order << name
          outcome
        end

        gate(name).pop if spec.is_a?(Array) && spec.first == :parked
        status = spec.is_a?(Array) ? spec.last : spec

        if status == :ok
          "OK-#{name}"
        else
          raise CannotConnectError, "boom-#{name}"
        end
      end

      private

      def gate(name)
        @mutex.synchronize { @gates[name] ||= Queue.new }
      end
    end

    def assert_open(circuit_breaker)
      assert_raises CircuitBreaker::OpenCircuitError do
        circuit_breaker.protect do
          # noop
        end
      end
    end

    def assert_closed(circuit_breaker)
      assert_equal(:result, circuit_breaker.protect { :result })
    end

    def open_circuit(circuit_breaker)
      circuit_breaker.error_threshold.times do
        record_error(circuit_breaker)
      end
    end

    def record_error(circuit_breaker)
      assert_raises CannotConnectError do
        circuit_breaker.protect do
          raise CannotConnectError, "Oh no!"
        end
      end
    end
  end
end
