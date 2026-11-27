# frozen_string_literal: true

require "test_helper"

class RedisClient
  class PubSubReaderTest < RedisClientTestCase
    # Connection double recording the commands the manager writes and serving
    # queued notification events on read, so capabilities are verified from the
    # actual command stream rather than from method names.
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
        raise ReadTimeoutError, "no more events" unless event

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
      @pubsub = PubSub.new(@connection, CommandBuilder)
    end

    def test_management_commands_are_recorded_through_the_full_pubsub
      @pubsub.call("SUBSCRIBE", "mychannel")
      @pubsub.call_v(["UNSUBSCRIBE"])

      assert_equal [["SUBSCRIBE", "mychannel"], ["UNSUBSCRIBE"]], @connection.written_commands
    end

    def test_reader_receives_notifications_recorded_on_the_connection
      reader = @pubsub.reader

      assert_equal ["subscribe", "mychannel", 1], reader.next_event
      assert_equal ["message", "mychannel", "event-0"], reader.next_event
      assert_nil reader.next_event(0.01)
    end

    def test_reader_close_ends_only_its_own_reading
      reader = @pubsub.reader
      assert_same reader, reader.close
      assert reader.closed?

      assert_raises(ConnectionError) { reader.next_event }
      assert_equal 0, @connection.close_count
      assert_equal ["subscribe", "mychannel", 1], @pubsub.next_event
    end

    def test_closing_one_reader_does_not_affect_another_reader
      first_reader = @pubsub.reader
      second_reader = @pubsub.reader

      first_reader.close

      refute second_reader.closed?
      assert_equal ["subscribe", "mychannel", 1], second_reader.next_event
      assert_equal 0, @connection.close_count
    end

    def test_reader_cannot_manage_subscriptions
      reader = @pubsub.reader

      refute_respond_to reader, :call
      refute_respond_to reader, :call_v
      assert_raises(NoMethodError) { reader.call("SUBSCRIBE", "hack") }
      assert_raises(NoMethodError) { reader.call_v(["SUBSCRIBE", "hack"]) }
      assert_empty @connection.written_commands
    end

    def test_only_the_manager_close_shuts_down_the_shared_connection
      reader = @pubsub.reader
      reader.close

      assert_equal 0, @connection.close_count

      assert_same @pubsub, @pubsub.close
      assert_equal 1, @connection.close_count
    end

    def test_reader_stops_reading_once_the_manager_closes_the_connection
      reader = @pubsub.reader
      @pubsub.close

      assert_raises(ConnectionError) { reader.next_event }
      refute reader.closed?
    end
  end
end
