require_relative '../common'
require 'net/ssh/connection/session'

module Connection
  class TestKeepalive < NetSSHTest
    include Net::SSH::Connection::Constants

    INTERVAL = 10
    MAXCOUNT = 3

    def setup
      @now = 1000.0
      @sent = []
    end

    def test_defaults
      plain = Net::SSH::Connection::Session.new(transport, keepalive: true)
      assert_equal Net::SSH::Connection::Session::DEFAULT_IO_SELECT_TIMEOUT, plain.keepalive.interval
      assert_equal 3, plain.keepalive.keepalive_maxcount
      assert plain.keepalive.enabled?

      disabled = Net::SSH::Connection::Session.new(transport, keepalive: false)
      refute disabled.keepalive.enabled?
    end

    def test_persistent_silence_sends_exactly_maxcount_probes_then_times_out
      collect_sent
      session.keepalive.clock = -> { @now }

      process_at(0)
      process_at(INTERVAL)
      process_at(2 * INTERVAL)
      assert_equal MAXCOUNT, keepalive_sends
      assert_equal MAXCOUNT, session.keepalive.unresponded_count

      # the budget is exhausted, so the next due slot raises instead of
      # sending another probe
      error = assert_raises(Net::SSH::Timeout) { process_at(3 * INTERVAL) }
      assert_match(/not responding/, error.message)
      assert_equal MAXCOUNT, keepalive_sends
    end

    def test_business_events_do_not_keep_a_dead_session_alive
      collect_sent
      session.keepalive.clock = -> { @now }
      socket.stubs(:recv).returns("x")
      events = [[socket], [], []]

      process_at(0, select_returns: events)
      process_at(INTERVAL, select_returns: events)
      process_at(2 * INTERVAL, select_returns: events)
      assert_equal MAXCOUNT, keepalive_sends

      assert_raises(Net::SSH::Timeout) { process_at(3 * INTERVAL, select_returns: events) }
      assert_equal MAXCOUNT, keepalive_sends
    end

    def test_replies_are_matched_to_global_requests_in_send_order
      collect_sent
      session.keepalive.clock = -> { @now }

      process_at(0) # keepalive probe becomes the oldest pending request
      assert_equal 1, session.keepalive.unresponded_count

      user_replied = false
      session.send_global_request("testing") { |_success, _packet| user_replied = true }

      transport.return(REQUEST_SUCCESS)
      process_at(1)
      assert_equal 0, session.keepalive.unresponded_count
      refute user_replied, "the first reply belongs to the oldest request (the keepalive)"

      transport.return(REQUEST_SUCCESS)
      process_at(2)
      assert user_replied
    end

    def test_unrelated_reply_does_not_clear_an_outstanding_probe
      collect_sent
      session.keepalive.clock = -> { @now }

      user_replied = false
      session.send_global_request("testing") { |_success, _packet| user_replied = true }

      process_at(0) # keepalive probe queued behind the user request
      assert_equal 1, session.keepalive.unresponded_count

      transport.return(REQUEST_SUCCESS) # answers the user request, not the probe
      process_at(1)
      assert user_replied
      assert_equal 1, session.keepalive.unresponded_count

      transport.return(REQUEST_SUCCESS) # answers the probe
      process_at(2)
      assert_equal 0, session.keepalive.unresponded_count
    end

    def test_late_reply_to_old_probe_does_not_hide_newer_silence
      collect_sent
      session.keepalive.clock = -> { @now }

      process_at(0)
      process_at(INTERVAL)
      process_at(2 * INTERVAL)
      assert_equal MAXCOUNT, session.keepalive.unresponded_count

      # a single late reply excuses only the oldest outstanding probe; the
      # newer ones still count against the budget
      transport.return(REQUEST_SUCCESS)
      process_at(3 * INTERVAL)
      assert_equal MAXCOUNT, session.keepalive.unresponded_count

      assert_raises(Net::SSH::Timeout) { process_at(4 * INTERVAL) }
      assert_equal MAXCOUNT + 1, keepalive_sends
    end

    def test_random_wall_clock_does_not_disturb_a_healthy_session
      collect_sent
      session.keepalive.clock = -> { @now }
      # machine time jumps backwards and forwards; the keepalive schedule
      # must only follow the monotonic clock
      Time.stubs(:now).returns(Time.at(50_000), Time.at(3), Time.at(-99_999), Time.at(1_000_000))

      process_at(0) # first probe
      (1..4).each do |i|
        transport.return(REQUEST_SUCCESS)
        process_at(i * INTERVAL)
      end

      assert_equal 5, keepalive_sends
      assert_equal 1, session.keepalive.unresponded_count
    end

    def test_paused_event_loop_neither_bursts_nor_false_positives_on_resume
      collect_sent
      session.keepalive.clock = -> { @now }

      process_at(0)
      transport.return(REQUEST_SUCCESS)
      process_at(INTERVAL)
      assert_equal 2, keepalive_sends

      # the event loop is paused for a long time; on resume exactly one
      # probe is due, and the pause itself is not counted as unresponsiveness
      process_at(100 * INTERVAL)
      assert_equal 3, keepalive_sends

      transport.return(REQUEST_SUCCESS)
      process_at(101 * INTERVAL)
      assert_equal 4, keepalive_sends
    end

    def test_rekey_in_progress_defers_probing
      collect_sent
      session.keepalive.clock = -> { @now }
      transport.algorithms.stubs(:pending?).returns(true)

      process_at(0)
      process_at(INTERVAL)
      assert_equal 0, keepalive_sends

      transport.algorithms.stubs(:pending?).returns(false)
      process_at(2 * INTERVAL)
      assert_equal 1, keepalive_sends
    end

    def test_closed_session_stops_probing_and_tolerates_late_replies
      collect_sent
      session.keepalive.clock = -> { @now }

      process_at(0)
      assert_equal 1, session.keepalive.unresponded_count

      transport.stubs(:closed?).returns(true)
      process_at(INTERVAL)
      process_at(2 * INTERVAL)
      assert_equal 1, keepalive_sends

      transport.return(REQUEST_SUCCESS)
      process_at(3 * INTERVAL)
      assert_equal 0, session.keepalive.unresponded_count
    end

    def test_reply_arriving_after_timeout_is_ignored
      collect_sent
      session(keepalive_maxcount: 1).keepalive.clock = -> { @now }

      process_at(0)
      assert_raises(Net::SSH::Timeout) { process_at(INTERVAL) }
      assert_equal 0, session.keepalive.unresponded_count

      # the late reply must not resurrect or corrupt liveness state
      transport.return(REQUEST_SUCCESS)
      process_at(2 * INTERVAL)
      assert_equal 1, session.keepalive.unresponded_count
      assert_equal 2, keepalive_sends
    end

    def test_outstanding_state_distinguishes_unanswered_probes_from_confirmed_replies
      collect_sent
      session.keepalive.clock = -> { @now }

      assert_equal 0, session.keepalive.unresponded_count
      assert session.keepalive.outstanding.empty?

      process_at(0)
      assert_equal 1, session.keepalive.unresponded_count
      assert_equal 1, session.keepalive.outstanding.size

      transport.return(REQUEST_SUCCESS)
      process_at(1)
      assert_equal 0, session.keepalive.unresponded_count
      assert session.keepalive.outstanding.empty?
    end

    private

    def socket
      @socket ||= begin
        socket = Object.new
        socket.extend(Net::SSH::Transport::PacketStream)
        socket
      end
    end

    def transport
      @transport ||= MockTransport.new(socket: socket)
    end

    def session(options = {})
      @session ||= Net::SSH::Connection::Session.new(
        transport,
        { keepalive: true, keepalive_interval: INTERVAL, keepalive_maxcount: MAXCOUNT }.merge(options)
      )
    end

    # Runs one event-loop iteration with the monotonic clock at +at+.
    def process_at(at, select_returns: nil)
      @now = at
      IO.stubs(:select).returns(select_returns)
      session.process
    end

    # Records every packet the session hands to the transport instead of
    # touching the socket, so sent probes can be counted exactly.
    def collect_sent
      sent = @sent
      transport.stubs(:enqueue_message).with { |msg| sent << msg.content }
    end

    def keepalive_sends
      @sent.count(keepalive_packet)
    end

    def keepalive_packet
      P(:byte, GLOBAL_REQUEST, :string, "keepalive@openssh.com", :bool, true).content
    end
  end
end
