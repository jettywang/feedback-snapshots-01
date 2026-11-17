require 'common'
require 'net/ssh/connection/session'

module Connection
  # Exercises the channel pending-output flow-control contract end to end
  # through a real Connection::Session, over a pausable in-memory transport.
  # Everything is driven deterministically (explicit preprocess passes and
  # scripted server packets); no sleeps are involved.
  class TestChannelFlowControl < NetSSHTest
    include Net::SSH::Connection::Constants

    # A fully in-memory transport. Outbound messages are recorded as parsed
    # frames on +wire+ immediately, unless paused, in which case they queue
    # in +outbound+ until #resume! flushes them in order. Inbound (server to
    # client) packets are scripted via #<<.
    class PausableTransport
      attr_reader :wire, :outbound, :socket

      def initialize
        @socket = Object.new
        @incoming = []
        @outbound = []
        @wire = []
        @paused = false
      end

      def logger
        nil
      end

      def host
        "flow-control.test"
      end

      def closed?
        false
      end

      def pause!
        @paused = true
      end

      def resume!
        @paused = false
        flush!
      end

      def flush!
        @wire << Net::SSH::Packet.new(@outbound.shift.to_s) until @outbound.empty?
      end

      def enqueue_message(msg)
        @outbound << msg
        flush! unless @paused
      end

      # Scripts a packet arriving from the server.
      def <<(packet)
        @incoming << packet
      end

      def poll_message
        @incoming.shift
      end
    end

    attr_reader :transport, :session

    def setup
      @transport = PausableTransport.new
      @session = Net::SSH::Connection::Session.new(@transport, {})
    end

    def teardown
      assert_equal [], transport.outbound, "expected all outbound messages to be flushed"
    end

    # Opens two channels and confirms them with the server: the "blocked"
    # channel gets a tiny window (16 bytes, 8-byte packets) that the server
    # never replenishes until told to; the "interactive" channel gets a
    # comfortable window.
    def open_channels(blocked_window: 16, blocked_packet: 8, interactive_window: 64, interactive_packet: 8)
      blocked = session.open_channel
      interactive = session.open_channel

      transport << P(:byte, CHANNEL_OPEN_CONFIRMATION, :long, blocked.local_id,
                     :long, 100, :long, blocked_window, :long, blocked_packet)
      transport << P(:byte, CHANNEL_OPEN_CONFIRMATION, :long, interactive.local_id,
                     :long, 200, :long, interactive_window, :long, interactive_packet)
      session.preprocess

      [blocked, interactive]
    end

    # Outgoing channel frames address the channel by its remote id, so
    # frames are matched by the channel's remote_id.
    def frames(type = nil, channel: nil)
      transport.wire.select do |frame|
        (type.nil? || frame.type == type) && (channel.nil? || frame[:local_id] == channel.remote_id)
      end
    end

    def data_frames(channel)
      frames(CHANNEL_DATA, channel: channel)
    end

    def test_blocked_channel_queue_is_bounded_and_never_drops_or_oversends
      blocked, = open_channels
      blocked.max_pending_output_size = 48

      payload = (0...48).map { |i| (65 + (i % 26)).chr }.join
      blocked.send_data(payload[0, 32])
      session.preprocess

      # Only the 16 bytes of remote window went out, as two 8-byte packets;
      # the server is never sent more than its advertised window.
      assert_equal 2, data_frames(blocked).length
      assert_equal payload[0, 16], data_frames(blocked).map { |f| f[:data] }.join
      assert_equal 0, blocked.remote_window_size
      assert_equal 16, blocked.pending_output_bytes

      blocked.send_data(payload[32, 16])
      assert_equal 32, blocked.pending_output_bytes
      assert blocked.writable?

      # Filling the queue exactly to the bound is still accepted, but leaves
      # no room for even one more byte.
      blocked.send_data("Z" * 16)
      assert_equal 48, blocked.pending_output_bytes
      refute blocked.writable?

      # Exceeding the bound raises and is atomic: not a single byte of the
      # rejected chunk is queued, and previously queued bytes are untouched.
      assert_raises(Net::SSH::ChannelPendingOutputLimitExceeded) do
        blocked.send_data("X" * 32)
      end
      assert_equal 48, blocked.pending_output_bytes
      assert_equal payload[16, 32] + "Z" * 16, blocked.output.to_s

      # The bound holds for the whole stalled period.
      3.times { session.preprocess }
      assert_operator blocked.pending_output_bytes, :<=, blocked.max_pending_output_size
      assert_equal 2, data_frames(blocked).length
    end

    def test_stalled_channel_does_not_starve_interactive_channel
      blocked, interactive = open_channels
      blocked.max_pending_output_size = 48

      blocked.send_data("B" * 48)
      session.preprocess
      assert_equal 32, blocked.pending_output_bytes
      assert_equal 2, data_frames(blocked).length

      # A short interaction on the other channel proceeds immediately, even
      # though the first channel sits on a full, stalled queue. Fairness is
      # proven by completed work (frames on the wire), not by timing.
      interactive.send_data("ping")
      session.preprocess
      interactive.send_data("pong")
      session.preprocess

      assert_equal %w[ping pong], data_frames(interactive).map { |f| f[:data] }
      assert_equal 2, data_frames(blocked).length,
                    "stalled channel must not emit more than its zero window allows"
    end

    def test_queued_data_outlives_close_request_until_window_reopens
      blocked, = open_channels
      blocked.max_pending_output_size = 48

      payload = (0...48).map { |i| (65 + (i % 26)).chr }.join
      blocked.send_data(payload)

      drained = 0
      blocked.on_output_drain { |_ch| drained += 1 }

      session.preprocess
      assert_equal 32, blocked.pending_output_bytes

      # EOF and close are requested while the queue is stalled: both must
      # wait for the queued data, and the queue stays inspectable.
      blocked.eof!
      blocked.close
      session.preprocess

      assert_equal 32, blocked.pending_output_bytes
      assert_equal [], frames(CHANNEL_EOF, channel: blocked)
      assert_equal [], frames(CHANNEL_CLOSE, channel: blocked)
      assert blocked.closing?
      refute blocked.local_closed?

      # The server reopens the window; the rest of the queued bytes must
      # flow in their original order, chunked by max packet, followed by
      # EOF and only then CLOSE.
      transport << P(:byte, CHANNEL_WINDOW_ADJUST, :long, blocked.local_id, :long, 64)
      session.preprocess

      sent = data_frames(blocked).map { |f| f[:data] }.join
      assert_equal payload, sent, "all queued bytes must be delivered exactly once, in order"
      assert data_frames(blocked).all? { |f| f[:data].bytesize <= 8 }
      assert_equal 0, blocked.pending_output_bytes
      assert_equal 1, drained, "on_output_drain should fire once backpressure relents"

      sequence = frames.select do |f|
        [CHANNEL_DATA, CHANNEL_EOF, CHANNEL_CLOSE].include?(f.type) && f[:local_id] == blocked.remote_id
      end.map(&:type)
      assert_equal CHANNEL_EOF, sequence[-2]
      assert_equal CHANNEL_CLOSE, sequence[-1]
      assert blocked.local_closed?
    end

    def test_pausable_transport_holds_and_releases_frames_in_order
      _, interactive = open_channels

      transport.pause!
      interactive.send_data("held-1")
      interactive.send_data("held-2")
      session.preprocess

      assert_equal [], data_frames(interactive)
      assert_equal 2, transport.outbound.length

      transport.resume!
      released = data_frames(interactive).map { |f| f[:data] }
      assert_equal "held-1held-2", released.join, "held frames must be released in original byte order"
      assert released.all? { |data| data.bytesize <= 8 }
    end

    def test_window_adjust_and_close_interleave_with_inspectable_disposition
      blocked, = open_channels
      blocked.max_pending_output_size = 48
      blocked.send_data("Q" * 40)
      session.preprocess
      assert_equal 24, blocked.pending_output_bytes

      blocked.close
      # Partial reopen: only part of the queue drains before the window
      # closes again; the remainder is still observable, and CLOSE still
      # has not been sent.
      transport << P(:byte, CHANNEL_WINDOW_ADJUST, :long, blocked.local_id, :long, 16)
      session.preprocess
      assert_equal 8, blocked.pending_output_bytes
      assert_equal [], frames(CHANNEL_CLOSE, channel: blocked)

      transport << P(:byte, CHANNEL_WINDOW_ADJUST, :long, blocked.local_id, :long, 16)
      session.preprocess
      assert_equal 0, blocked.pending_output_bytes
      assert_equal 1, frames(CHANNEL_CLOSE, channel: blocked).length
      assert_equal "Q" * 40, data_frames(blocked).map { |f| f[:data] }.join
    end
  end
end
