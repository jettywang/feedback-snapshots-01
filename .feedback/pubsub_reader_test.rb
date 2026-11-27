# frozen_string_literal: true

# Drives the restricted subscription view with a recording connection so that
# the actually exposed capabilities are asserted from recorded commands and
# observed responses, without needing a live Redis server.
require "redis_client"
require "minitest/autorun"

class PubSubReaderTest < Minitest::Test
  # Connection double that records every management command written to the
  # server and serves queued notification events on read.
  class RecordingConnection
    attr_reader :written_commands, :close_count

    def initialize(events = [])
      @written_commands = []
      @close_count = 0
      @event_queue = events.dup
    end

    def write(command)
      @written_commands << command
      nil
    end

    def read(timeout = nil)
      event = @event_queue.shift
      raise RedisClient::ReadTimeoutError, "no more events" unless event

      event
    end

    def close
      @close_count += 1
      nil
    end
  end

  def setup
    @connection = RecordingConnection.new(
      [
        ["subscribe", "mychannel", 1],
        ["message", "mychannel", "event-0"],
      ],
    )
    @pubsub = RedisClient::PubSub.new(@connection, RedisClient::CommandBuilder)
  end

  def test_recorded_driver_records_the_management_command
    @pubsub.call("SUBSCRIBE", "mychannel")

    assert_equal [["SUBSCRIBE", "mychannel"]], @connection.written_commands
  end

  def test_reader_receives_notifications_recorded_on_the_connection
    reader = @pubsub.reader

    assert_equal ["subscribe", "mychannel", 1], reader.next_event
    assert_equal ["message", "mychannel", "event-0"], reader.next_event
    assert_nil reader.next_event(0.01)
  end

  def test_reader_closing_ends_only_its_own_reading
    reader = @pubsub.reader
    assert_same reader, reader.close
    assert reader.closed?

    error = assert_raises(RedisClient::ConnectionError) { reader.next_event }
    assert_match(/closed/, error.message)
    # The owning subscription connection is untouched: no close reached it.
    assert_equal 0, @connection.close_count
    # The manager keeps reading from the same, still-open subscription.
    assert_equal ["subscribe", "mychannel", 1], @pubsub.next_event
  end

  def test_other_readers_are_unaffected_when_one_reader_closes
    first_reader = @pubsub.reader
    second_reader = @pubsub.reader

    first_reader.close

    refute second_reader.closed?
    assert_equal ["subscribe", "mychannel", 1], second_reader.next_event
    assert_equal 0, @connection.close_count
  end

  def test_manager_still_owns_full_subscription_management
    @pubsub.call("SUBSCRIBE", "mychannel")
    @pubsub.call_v(["UNSUBSCRIBE"])

    assert_equal [["SUBSCRIBE", "mychannel"], ["UNSUBSCRIBE"]], @connection.written_commands

    assert_same @pubsub, @pubsub.close
    assert_equal 1, @connection.close_count
  end

  def test_reader_cannot_issue_commands_even_though_the_manager_can
    reader = @pubsub.reader

    assert_raises(NoMethodError) { reader.call("SUBSCRIBE", "hack") }
    assert_raises(NoMethodError) { reader.call_v(["SUBSCRIBE", "hack"]) }
    # Nothing reached the connection: the restricted view cannot manage
    # subscriptions, proven by the recorded command stream staying empty.
    assert_empty @connection.written_commands
  end

  def test_reader_close_does_not_reach_the_connection_pool_owned_connection
    reader = @pubsub.reader
    reader.close

    # Only an explicit manager close shuts the shared connection down.
    assert_equal 0, @connection.close_count
    @pubsub.close
    assert_equal 1, @connection.close_count
  end

  def test_reader_loses_reading_once_the_manager_closes_the_connection
    reader = @pubsub.reader
    @pubsub.close

    assert_raises(RedisClient::ConnectionError) { reader.next_event }
    refute reader.closed?
  end
end
