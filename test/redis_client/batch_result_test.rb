# frozen_string_literal: true

unless defined?(RedisClientTestCase)
  require "redis_client"
  require "minitest/autorun"

  class RedisClientTestCase < Minitest::Test
  end
end

class RedisClient
  class BatchResultTest < RedisClientTestCase
    # A driver that records the batch it received and can be stopped at
    # specific points to reproduce a connection loss.
    class ScriptedConnection
      include RedisClient::ConnectionMixin

      attr_accessor :connect_timeout, :read_timeout, :write_timeout
      attr_reader :writes, :reads

      def initialize(config, **)
        super(config)
        connect
        @writes = []
        @reads = 0
        @replies = []
        @fail_write = nil
        @fail_after_reads = nil
      end

      def connected?
        true
      end

      def close
        super
      end

      def connect
        @server_key = config.server_key
        true
      end

      def script(replies: [], fail_write: nil, fail_after_reads: nil)
        @replies = replies
        @fail_write = fail_write
        @fail_after_reads = fail_after_reads
        self
      end

      def write_multi(commands)
        @writes << commands
        if @fail_write == :before_send
          @fail_write = nil
          raise connection_error("connection lost before send")
        end

        batch_write_started!

        if @fail_write == :during_send
          @fail_write = nil
          raise connection_error("connection lost during send")
        end
      end

      def write(command)
        @writes << command
        if @fail_write == :before_send
          @fail_write = nil
          raise connection_error("connection lost before send")
        end
      end

      def read(_timeout)
        if @fail_after_reads && @reads >= @fail_after_reads
          @fail_after_reads = nil
          raise connection_error("connection lost while reading")
        end

        value = @replies.fetch(@reads, "OK")
        @reads += 1
        value
      end
    end

    module ScriptedDriver
      def self.new(config, **timeouts)
        ($scripted_connection = ScriptedConnection.new(config, **timeouts))
      end
    end

    def setup
      super
      RedisClient.register_driver(:scripted) { ScriptedDriver }
      @client = RedisClient.config(driver: :scripted, protocol: 2, reconnect_attempts: 0).new_client
    end

    def teardown
      @client.close
      super
    end

    def script(**kwargs)
      client.send(:ensure_connected).script(**kwargs)
      self
    end

    def client
      @client
    end

    def pipeline(result_status: true, exception: true, &block)
      client.pipelined(result_status: result_status, exception: exception, &block)
    end

    def transaction(result_status: true, &block)
      client.multi(result_status: result_status, &block)
    end

    def test_complete_pipeline_keeps_original_structure
      script(replies: ["OK", 2])
      result = pipeline do |p|
        p.call("SET", "foo", "bar")
        p.call("INCR", "counter")
      end

      assert_equal ["OK", 2], result.results
      assert result.complete?
      assert result.success?
      assert result.write_completed?
      assert result.receive_completed?
      assert_equal ["OK", 2], result.available_results
      assert_empty result.pending_confirmation
      refute result.retryable?
    end

    def test_default_pipeline_returns_plain_array
      script(replies: ["OK", 2])
      assert_equal ["OK", 2], client.pipelined { |p| p.call("SET", "foo"); p.call("INCR", "counter") }
    end

    def test_failure_before_send_is_retryable
      script(fail_write: :before_send)
      result = pipeline do |p|
        p.call("SET", "foo", "1")
        p.call("SET", "bar", "2")
      end

      assert result.retryable?
      refute result.write_started?
      refute result.write_completed?
      assert_equal 0, result.received_count
      assert_empty result.available_results
      assert_equal [["SET", "foo", "1"], ["SET", "bar", "2"]], result.retryable_commands
    end

    def test_failure_after_first_reply_is_pending_confirmation
      script(replies: ["OK"], fail_after_reads: 1)
      result = pipeline do |p|
        p.call("SET", "foo", "1")
        p.call("SET", "bar", "2")
      end

      assert result.pending_confirmation?
      assert result.write_completed?
      refute result.receive_completed?
      assert_equal 1, result.received_count
      assert_equal ["OK"], result.available_results
      assert_equal [[0, "OK"]], result.available_indexes.map { |i| [i, result.results[i]] }
      assert_equal [["SET", "bar", "2"]], result.pending_confirmation
      assert_equal [1], result.pending_indexes.to_a
      assert_empty result.retryable_commands
      assert_nil result[1]
    end

    def test_pipeline_command_error_kept_as_element_in_status_mode
      error = RedisClient::CommandError.new("ERR unknown command")
      error._set_command(["NOPE"])
      script(replies: [error, "OK"])
      result = pipeline do |p|
        p.call("NOPE")
        p.call("SET", "foo", "1")
      end

      assert result.complete?
      assert result.failed?
      assert_instance_of RedisClient::CommandError, result.results[0]
      assert_equal [["NOPE"], ["SET", "foo", "1"]], result.commands
    end

    # The transaction is only confirmed by the EXEC reply. MULTI and QUEUED
    # acknowledgements are not results.
    def test_transaction_lost_before_exec_has_no_available_results
      script(replies: ["OK", "QUEUED", "QUEUED"], fail_after_reads: 3)
      result = transaction do |t|
        t.call("SET", "foo", "1")
        t.call("INCR", "counter")
      end

      assert result.pending_confirmation?
      assert result.transaction?
      assert result.write_completed?
      assert_equal 0, result.received_count
      assert_empty result.available_results
      assert_equal [["SET", "foo", "1"], ["INCR", "counter"]], result.pending_confirmation
    end

    def test_transaction_failure_before_send_is_retryable
      script(fail_write: :before_send)
      result = transaction do |t|
        t.call("SET", "foo", "1")
        t.call("INCR", "counter")
      end

      assert result.retryable?
      refute result.write_started?
      assert_equal [["SET", "foo", "1"], ["INCR", "counter"]], result.retryable_commands
    end

    def test_complete_transaction
      script(replies: ["OK", "QUEUED", "QUEUED", ["OK", 1]])
      result = transaction do |t|
        t.call("SET", "foo", "1")
        t.call("INCR", "counter")
      end

      assert result.success?
      assert result.transaction?
      assert_equal ["OK", 1], result.results
      assert_equal ["OK", 1], result.available_results
    end

    def test_aborted_transaction_is_retryable
      script(replies: ["OK", "QUEUED", "QUEUED", nil])
      result = transaction do |t|
        t.call("SET", "foo", "1")
        t.call("INCR", "counter")
      end

      assert result.aborted?
      assert result.retryable?
      assert result.complete?
      assert_nil result.results
      assert_equal [["SET", "foo", "1"], ["INCR", "counter"]], result.retryable_commands
    end

    def test_status_mode_disables_automatic_retry
      client = RedisClient.config(driver: :scripted, protocol: 2, reconnect_attempts: 2).new_client
      client.send(:ensure_connected).script(replies: ["OK"], fail_after_reads: 1)

      result = client.pipelined(result_status: true) do |p|
        p.call("SET", "foo", "1")
        p.call("SET", "bar", "2")
      end

      assert result.pending_confirmation?
      assert_equal 1, client.send(:ensure_connected).reads
      client.close
    end

    def test_pipeline_blocks_apply_in_status_mode
      script(replies: [2, 3])
      result = pipeline do |p|
        p.call("INCR", "a") { |value| value * 10 }
        p.call("INCR", "b")
      end

      assert_equal [20, 3], result.results
      assert result.success?
    end

    def test_transaction_exec_error_is_failed_batch
      error = RedisClient::CommandError.new("ACL denied")
      script(replies: ["OK", "QUEUED", error])
      result = transaction { |t| t.call("SET", "foo", "1") }

      assert result.failed?
      assert_instance_of RedisClient::CommandError, result.results.first
    end

    def test_following_regular_command_succeeds_after_interrupted_batch
      script(fail_write: :during_send)
      result = pipeline { |p| p.call("SET", "foo", "1") }
      assert result.pending_confirmation?

      client.send(:ensure_connected).script(replies: ["PONG"])
      assert_equal "PONG", client.call("PING")
    end
  end
end
