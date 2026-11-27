# frozen_string_literal: true

# Self contained: exercises client side capabilities against the in-memory
# RecordingDriver (test/support/driver.rb) without opening a real connection.
require "redis_client"
require "minitest/autorun"
require_relative "../support/driver"

class RedisClient
  class CapabilitiesTest < Minitest::Test
    SECRET = "super-secret-token".freeze

    def setup
      RecordingDriver.reset!
      @client = RedisClient.new(
        host: "redis.example.test",
        protocol: 2,
        idle_timeout: nil,
        driver: :recording,
      )
    end

    def test_permitted_transaction_is_sent_and_receipt_records_every_command
      RecordingDriver.respond_with("EXEC", ["OK", "value"])

      receipt = nil
      result = @client.with_capabilities(%w[MULTI SET GET EXEC]) do |redis, checkout_receipt|
        receipt = checkout_receipt
        redis.multi do |tx|
          tx.call("SET", "session:1", SECRET)
          tx.call("GET", "session:1")
        end
      end

      assert_equal ["OK", "value"], result

      # The driver really received the whole framed transaction.
      assert_equal(
        [
          ["MULTI"],
          ["SET", "session:1", SECRET],
          ["GET", "session:1"],
          ["EXEC"],
        ],
        recorded_commands,
      )

      # The borrow receipt accounts for the whole accepted batch, framing included.
      assert_equal %w[MULTI SET GET EXEC], receipt.approved
      assert_empty receipt.denied
    end

    def test_non_compliant_batch_is_rejected_as_a_whole_before_sending
      receipt = nil
      error = assert_raises(CapabilityDeniedError) do
        @client.with_capabilities(%w[GET MGET]) do |redis, checkout_receipt|
          receipt = checkout_receipt
          redis.pipelined do |pipeline|
            pipeline.call("GET", "session:1")
            pipeline.call("SET", "session:1", SECRET)
            pipeline.call("MGET", "session:1", "session:2")
          end
        end
      end

      # Only the command name leaks, the private argument never does.
      assert_equal "SET", error.command_name
      refute_includes error.message, SECRET
      refute_includes error.message, "session:1"

      # Nothing from the rejected batch reached the driver.
      assert_empty recorded_commands

      assert_equal %w[SET], receipt.denied
      assert_empty receipt.approved
    end

    def test_later_read_only_checkout_is_independent_and_reuses_the_connection
      @client.with_capabilities(%w[MULTI SET GET EXEC]) do |redis, _receipt|
        redis.multi do |tx|
          tx.call("SET", "counter", "1")
        end
      end
      open_after_write = RecordingDriver.open_connections

      RecordingDriver.respond_with("GET", "1")
      receipt = nil
      value = @client.with_capabilities(%w[GET]) do |redis, checkout_receipt|
        receipt = checkout_receipt
        redis.call("GET", "counter")
      end

      assert_equal "1", value
      assert_equal [["GET", "counter"]], recorded_commands.last(1)
      assert_equal %w[GET], receipt.approved
      assert_empty receipt.denied

      # The same physical connection serves both scopes.
      assert_equal open_after_write, RecordingDriver.open_connections

      # The read-only scope genuinely cannot write.
      error = assert_raises(CapabilityDeniedError) do
        @client.with_capabilities(%w[GET]) do |redis, _receipt|
          redis.call("SET", "counter", "2", SECRET)
        end
      end
      assert_equal "SET", error.command_name
      refute_includes error.message, SECRET
      refute_includes recorded_commands, ["SET", "counter", "2", SECRET]
    end

    def test_pooled_borrows_each_get_their_own_scope_on_a_shared_connection
      RecordingDriver.respond_with("GET", "cached")
      pool = RedisClient.config(
        host: "redis.example.test",
        protocol: 2,
        idle_timeout: nil,
        driver: :recording,
      ).new_pool(size: 1)

      reader_receipt = nil
      value = pool.with_capabilities(%w[GET]) do |redis, receipt|
        reader_receipt = receipt
        redis.call("GET", "key")
      end

      assert_equal "cached", value
      assert_equal %w[GET], reader_receipt.approved

      writer_receipt = nil
      pool.with_capabilities(%w[SET]) do |redis, receipt|
        writer_receipt = receipt
        redis.call("SET", "key", SECRET)
      end

      assert_equal %w[SET], writer_receipt.approved
      assert_equal 1, RecordingDriver.open_connections

      # A pooled caller without capabilities is not constrained.
      assert_nil pool.with { |redis| redis.capability_receipt }
    ensure
      pool&.close
    end

    def test_custom_callable_policy_only_ever_sees_command_names
      seen = []
      policy = ->(command_name) { seen << command_name; command_name.start_with?("P") }
      capabilities = Capabilities.new(policy)

      receipt = nil
      @client.with_capabilities(capabilities) do |redis, checkout_receipt|
        receipt = checkout_receipt
        assert_equal "PONG", redis.call("PING", SECRET)
      end

      assert_equal %w[PING], receipt.approved
      assert_equal %w[PING], seen
      refute_includes seen.join, SECRET

      error = assert_raises(CapabilityDeniedError) do
        @client.with_capabilities(policy) do |redis, _receipt|
          redis.call("GET", SECRET)
        end
      end
      assert_equal "GET", error.command_name
      refute_includes error.message, SECRET
    end

    def test_all_scope_and_unscoped_client_allow_every_command
      receipt = nil
      @client.with_capabilities(:all) do |redis, checkout_receipt|
        receipt = checkout_receipt
        redis.call("FLUSHDB", "ASYNC")
      end
      assert_equal %w[FLUSHDB], receipt.approved

      @client.call("CONFIG", "GET", "maxmemory")
      assert_nil @client.capability_receipt
    end

    def test_symbol_command_names_and_block_form_policy
      @client.with_capabilities(%i[get set]) do |redis, receipt|
        redis.call(:set, "k", "v")
        redis.call("GET", "k")
        assert_equal %w[SET GET], receipt.approved
      end

      caps = Capabilities.new { |name| name == "PING" }
      @client.with_capabilities(caps) { |redis, _| redis.call("PING") }
    end

    def test_invalid_scope_raises_argument_error
      assert_raises(ArgumentError) { Capabilities.new("GET") }
      assert_raises(ArgumentError) { Capabilities.new(["GET"]) { } }
    end

    private

    def recorded_commands
      RecordingDriver.recorded_commands
    end
  end
end
