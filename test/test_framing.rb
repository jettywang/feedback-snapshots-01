require "common"

class FramingTest < Net::SFTP::TestCase
  include Net::SFTP::Constants::PacketTypes

  StoryResult = Struct.new(:callbacks, :process_errors, :pending_ids, :outcomes,
                           :input_length, :state, :packet_length, :remaining_events,
                           :late_send_error, :chunk_sizes, :close_sent,
                           :framing_error_input_length)

  def test_packet_sequence_outcome_is_independent_of_ssh_data_boundaries
    bytes = [attrs_frame(0, 42), status_frame(1, 0), status_frame(2, 1)].join
    baseline = run_story([bytes], request_count: 3)

    assert_empty baseline.process_errors
    assert_equal [], baseline.pending_ids
    assert_equal [[0, 0, 42], [1, 0, nil], [2, 1, nil]], baseline.callbacks
    assert_equal [[0, :complete, 0], [1, :complete, 0], [2, :complete, 1]], baseline.outcomes

    (0...bytes.bytesize).each do |split|
      chunks = [bytes.byteslice(0, split), bytes.byteslice(split, bytes.bytesize - split)]
      result = run_story(chunks, request_count: 3)

      assert_equal chunks.map(&:bytesize), result.chunk_sizes,
                   "the story did not deliver the requested cut at #{split}"
      assert_equal baseline.callbacks, result.callbacks, "callbacks differ when split at #{split}"
      assert_equal baseline.outcomes, result.outcomes, "outcomes differ when split at #{split}"
      assert_equal baseline.pending_ids, result.pending_ids, "pending requests differ when split at #{split}"
      assert_empty result.process_errors, "error when split at #{split}"
      assert_equal 0, result.input_length, "input left when split at #{split}"
    end

    result = run_story(bytes.each_char.to_a, request_count: 3)
    assert_equal [1] * bytes.bytesize, result.chunk_sizes
    assert_equal baseline.callbacks, result.callbacks, "callbacks differ for one-byte callbacks"
    assert_equal baseline.outcomes, result.outcomes, "outcomes differ for one-byte callbacks"
    assert_equal baseline.pending_ids, result.pending_ids, "pending requests differ for one-byte callbacks"
    assert_empty result.process_errors
    assert_equal 0, result.input_length
  end

  def test_empty_ssh_data_callbacks_do_not_change_the_stream_outcome
    bytes = [attrs_frame(0, 42), status_frame(1, 0)].join
    baseline = run_story([bytes], request_count: 2)
    assert_equal [[0, 0, 42], [1, 0, nil]], baseline.callbacks
    assert_equal [bytes.bytesize], baseline.chunk_sizes

    (0..bytes.bytesize).each do |split|
      chunks = [bytes.byteslice(0, split), "", bytes.byteslice(split, bytes.bytesize - split)]
      result = run_story(chunks, request_count: 2)

      assert_equal chunks.map(&:bytesize), result.chunk_sizes,
                   "the story did not deliver the empty callback at #{split}"
      assert_equal baseline.callbacks, result.callbacks, "callbacks differ with empty callback at #{split}"
      assert_equal baseline.outcomes, result.outcomes, "outcomes differ with empty callback at #{split}"
      assert_equal [], result.pending_ids, "pending requests differ with empty callback at #{split}"
      assert_empty result.process_errors
      assert_equal 0, result.input_length
    end
  end

  def test_incomplete_final_packet_leaves_the_same_pending_request_at_every_split
    bytes = [status_frame(0, 0), status_frame(1, 0)[0, 3]].join
    baseline = run_story([bytes], request_count: 2)

    assert_empty baseline.process_errors
    assert_equal [[0, 0, nil]], baseline.callbacks
    assert_equal [1], baseline.pending_ids
    assert_equal 3, baseline.input_length
    assert_nil baseline.packet_length

    (0..bytes.bytesize).each do |split|
      chunks = [bytes.byteslice(0, split), bytes.byteslice(split, bytes.bytesize - split)]
      result = run_story(chunks, request_count: 2)

      assert_equal chunks.map(&:bytesize), result.chunk_sizes,
                   "the story did not deliver the requested cut at #{split}"
      assert_empty result.process_errors, "error when split at #{split}"
      assert_equal baseline.callbacks, result.callbacks, "callbacks differ when split at #{split}"
      assert_equal baseline.pending_ids, result.pending_ids, "pending requests differ when split at #{split}"
      assert_equal 3, result.input_length, "input left when split at #{split}"
    end
  end

  def test_a_split_length_header_is_not_dispatched_until_header_and_body_arrive
    frame = attrs_frame(0, 42)

    (1..4).each do |prefix|
      result = run_story([frame.byteslice(0, prefix)], request_count: 1)

      assert_empty result.process_errors
      assert_empty result.callbacks
      assert_equal [0], result.pending_ids
      assert_equal prefix, result.input_length
      if prefix == 4
        assert_equal 17, result.packet_length
      else
        assert_nil result.packet_length
      end

      result = run_story(
        [frame.byteslice(0, prefix), frame.byteslice(prefix, frame.bytesize - prefix)],
        request_count: 1
      )
      assert_empty result.process_errors
      assert_equal [[0, 0, 42]], result.callbacks
      assert_equal [], result.pending_ids
      assert_equal 0, result.input_length
    end
  end

  def test_zero_length_packet_is_a_framing_error
    result = run_story([length_header(0)], request_count: 2, expect_close: true)
    error = only_process_error(result)

    assert_instance_of Net::SFTP::FramingError, error
    assert_equal 0, error.length
    assert_equal [], result.callbacks
    assert_equal [], result.pending_ids
    assert_equal 0, result.input_length, "data delivered after the failure was buffered"
    assert_equal :closed, result.state
    assert_equal 0, result.remaining_events
    assert result.close_sent, "the bad stream was left open for the server to keep feeding"
    result.outcomes.each do |id, exception, message|
      assert_equal [exception, message], [Net::SFTP::FramingError, error.message], "request #{id}"
    end
    assert_instance_of Net::SFTP::SessionClosedError, result.late_send_error
  end

  def test_a_bad_length_between_complete_packets_keeps_earlier_replies_and_fails_the_rest
    good = status_frame(0, 0)
    bad = length_header(0)
    later = status_frame(1, 0)

    result = run_story([good + bad + later], request_count: 2, expect_close: true)
    error = only_process_error(result)

    assert_instance_of Net::SFTP::FramingError, error
    assert_equal [[0, 0, nil]], result.callbacks
    assert_equal [], result.pending_ids
    assert_equal [0, :complete, 0], result.outcomes.first
    assert_equal [Net::SFTP::FramingError, error.message], result.outcomes.last[1..2]
    assert_equal 0, result.input_length
  end

  def test_an_oversized_length_after_a_complete_packet_keeps_the_earlier_reply_and_fails
    good = status_frame(0, 0)
    over = Net::SFTP::Session::MAX_PACKET_LENGTH + 1
    bad = length_header(over)

    result = run_story([good + bad], request_count: 2, expect_close: true)
    error = only_process_error(result)

    assert_equal over, error.length
    assert_equal [[0, 0, nil]], result.callbacks
    assert_equal [], result.pending_ids
    assert_equal 0, result.input_length
  end

  def test_declared_length_over_the_limit_is_rejected_before_payload_is_buffered
    over = Net::SFTP::Session::MAX_PACKET_LENGTH + 1
    payload = "x" * 1024

    [[length_header(over) + payload], [length_header(over), payload]].each do |chunks|
      result = run_story(chunks, request_count: 2, expect_close: true)
      error = only_process_error(result)

      assert_instance_of Net::SFTP::FramingError, error
      assert_equal over, error.length
      assert_equal [], result.callbacks
      assert_equal [], result.pending_ids
      assert_equal 4, result.framing_error_input_length,
                   "payload in the same callback was buffered before the length check"
      assert_equal 0, result.input_length, "the payload after the bad header was buffered"
      assert_equal :closed, result.state
      assert_equal 0, result.remaining_events
      assert result.close_sent, "the bad stream was left open for the server to keep feeding"
    end
  end

  def test_the_outer_limit_is_reported_before_a_protocol_item_count_check
    looks_like_name = raw(:byte, FXP_NAME, :long, 0x7fff_ffff)
    result = run_story(
      [length_header(Net::SFTP::Session::MAX_PACKET_LENGTH + 1), looks_like_name],
      request_count: 1, expect_close: true
    )
    error = only_process_error(result)

    assert_instance_of Net::SFTP::FramingError, error
    refute_match(/entries in only/, error.message)
  end

  def test_an_oversized_packet_split_across_callbacks_fails_without_buffering_the_body
    over = Net::SFTP::Session::MAX_PACKET_LENGTH + 1
    bad = length_header(over)
    result = run_story([bad.byteslice(0, 2), bad.byteslice(2, 2), "x" * 512],
                       request_count: 1, expect_close: true)

    assert_equal over, only_process_error(result).length
    assert_equal 4, result.framing_error_input_length
    assert_equal [], result.callbacks
    assert_equal [], result.pending_ids
    assert_equal 0, result.input_length
  end

  def test_declared_length_at_the_limit_is_not_rejected
    result = run_story([length_header(Net::SFTP::Session::MAX_PACKET_LENGTH)], request_count: 1)

    assert_empty result.process_errors
    assert_empty result.callbacks
    assert_equal [0], result.pending_ids
    assert_equal 4, result.input_length
    assert_equal Net::SFTP::Session::MAX_PACKET_LENGTH, result.packet_length
  end

  def test_a_packet_one_byte_under_the_limit_is_dispatched
    frame = padded_status_frame(0, 0, Net::SFTP::Session::MAX_PACKET_LENGTH - 1)
    chunks = frame.bytes.each_slice(4096).map { |slice| slice.pack("C*") }
    result = run_story(chunks, request_count: 1, server_version: 1)

    assert_empty result.process_errors
    assert_equal [[0, 0, nil]], result.callbacks
    assert_equal [], result.pending_ids
    assert_equal 0, result.input_length
  end

  def test_a_packet_of_exactly_the_limit_is_dispatched
    frame = padded_status_frame(0, 0, Net::SFTP::Session::MAX_PACKET_LENGTH)
    assert_equal Net::SFTP::Session::MAX_PACKET_LENGTH, frame.bytesize - 4

    # The mock transport buffers at most 8 KiB per SSH read, so feed the
    # maximum-size SFTP packet as several data callbacks.
    chunks = frame.bytes.each_slice(4096).map { |slice| slice.pack("C*") }
    result = run_story(chunks, request_count: 1, server_version: 1)

    assert_empty result.process_errors
    assert_equal [[0, 0, nil]], result.callbacks
    assert_equal [], result.pending_ids
    assert_equal 0, result.input_length
    assert_equal :open, result.state
  end

  def test_packets_completed_before_a_bad_length_stay_completed_and_the_rest_fail
    r0 = status_frame(0, 0)
    r1 = status_frame(1, 0)
    r2 = status_frame(2, 0)

    [0, Net::SFTP::Session::MAX_PACKET_LENGTH + 1].each do |bad_length|
      bad = length_header(bad_length)
      [
        [r0 + r1 + bad + r2],
        [r0, r1 + bad + r2],
        [r0 + r1 + bad, r2],
        [r0, r1, bad, r2]
      ].each do |chunks|
        result = run_story(chunks, request_count: 3, expect_close: true)
        error = only_process_error(result)

        assert_instance_of Net::SFTP::FramingError, error
        assert_equal bad_length, error.length
        assert_equal [[0, 0, nil], [1, 0, nil]], result.callbacks
        assert_equal [], result.pending_ids
        assert_equal [[0, :complete, 0], [1, :complete, 0]], result.outcomes.first(2)
        assert_equal [Net::SFTP::FramingError, error.message], result.outcomes.last[1..2]
        assert_equal 0, result.input_length, "the bytes after the bad header were kept"
        assert_equal :closed, result.state
        assert_equal 0, result.remaining_events
        assert result.close_sent, "the bad stream was left open for the server to keep feeding"
      end
    end
  end

  def test_trailing_bytes_shorter_than_a_packet_are_buffered_until_the_rest_arrives
    r0 = status_frame(0, 0)
    r1 = status_frame(1, 0)

    partial_header = run_story([r0 + r1.byteslice(0, 3)], request_count: 2)
    assert_empty partial_header.process_errors
    assert_equal [[0, 0, nil]], partial_header.callbacks
    assert_equal [1], partial_header.pending_ids
    assert_equal 3, partial_header.input_length
    assert_nil partial_header.packet_length

    partial_body = run_story([r0 + r1.byteslice(0, 7)], request_count: 2)
    assert_empty partial_body.process_errors
    assert_equal [[0, 0, nil]], partial_body.callbacks
    assert_equal [1], partial_body.pending_ids
    assert_equal 7, partial_body.input_length
    assert_equal 9, partial_body.packet_length

    completed = run_story(
      [r0, r1.byteslice(0, 3), r1.byteslice(3, r1.bytesize - 3)],
      request_count: 2
    )
    assert_empty completed.process_errors
    assert_equal [[0, 0, nil], [1, 0, nil]], completed.callbacks
    assert_equal [], completed.pending_ids
    assert_equal 0, completed.input_length
  end

  private

    # The session records the byte count of each SSH data callback so tests can
    # prove the story delivered the cuts they asked for rather than silently
    # coalescing them.
    def recording_session_class
      @recording_session_class ||= Class.new(Net::SFTP::Session) do
        attr_reader :received_chunk_sizes, :framing_error_input_length

        def initialize(*args)
          @received_chunk_sizes = []
          super
        end

        private

        def when_channel_data(channel, data)
          @received_chunk_sizes << data.bytesize
          super
        end

        def fail_framing!(channel, length)
          @framing_error_input_length = input.length
          super
        end
      end
    end

    def packet(type, *args)
      data = raw(*args)
      raw(:long, data.length + 1, :byte, type, :raw, data)
    end

    def attrs_frame(id, size)
      packet(FXP_ATTRS, :long, id, :long, 1, :int64, size)
    end

    def status_frame(id, code)
      packet(FXP_STATUS, :long, id, :long, code)
    end

    # A version 1 status packet padded to an exact declared length; version 1
    # parsing reads only the id and code and ignores the rest.
    def padded_status_frame(id, code, packet_length)
      data = raw(:long, id, :long, code, :raw, "x" * (packet_length - 9))
      raw(:long, packet_length, :byte, FXP_STATUS, :raw, data)
    end

    def length_header(length)
      raw(:long, length)
    end

    def only_process_error(result)
      assert_equal 1, result.process_errors.length, "expected exactly one framing error"
      result.process_errors.first
    end

    # Drives a complete session over Net::SSH::Test's in-memory SSH story.
    # +chunks+ is the SFTP byte stream cut into the pieces each CHANNEL_DATA
    # callback should carry. Returns callbacks, errors and the final
    # pending_requests state so outcomes can be compared across cuts.
    def run_story(chunks, request_count: 2, server_version: 3, expect_close: false)
      socket = Net::SSH::Test::Socket.new
      script = socket.script
      channel = script.opens_channel
      channel.sends_subsystem("sftp")
      channel.sends_packet(FXP_INIT, :long, Net::SFTP::Session::HIGHEST_PROTOCOL_VERSION_SUPPORTED)
      channel.gets_packet(FXP_VERSION, :long, server_version)
      request_count.times do |id|
        channel.sends_packet(FXP_STAT, :long, id, :string, "/p#{id}")
      end
      chunks.each { |chunk| channel.gets_data(chunk) }
      channel.sends_close if expect_close

      callbacks = []
      process_errors = []
      requests = []
      sftp = nil
      pending_ids = []
      outcomes = []
      late_send_error = nil
      input_length = nil
      state = nil
      packet_length = nil
      chunk_sizes = []

      Net::SSH::Test::Extensions::IO.with_test_extension do
        transport = Net::SSH::Transport::Session.new(
          "localhost",
          :kex => "test", :host_key => "ssh-rsa",
          :encryption => "+none", :hmac => "+none",
          :append_all_supported_algorithms => true,
          :verify_host_key => :never,
          :proxy => socket
        )
        connection = Net::SSH::Connection::Session.new(transport)
        sftp = recording_session_class.new(connection)
        sftp.connect!
        # Only the chunks that carry the test's SFTP byte stream matter; the
        # SSH version handshake does not reach when_channel_data.
        recorded_from = sftp.received_chunk_sizes.length

        request_count.times do |id|
          requests << sftp.stat("/p#{id}") do |response|
            callbacks << [response.request.id, response.code, response.data[:attrs]&.size]
          end
        end

        # The test transport only hands one scripted event to the socket per
        # poll, so keep polling after the script is empty until the buffered
        # bytes have been fed to the session as well. A fixed budget keeps an
        # incomplete final packet from being mistaken for a finished stream.
        guard = script.events.length + 8
        guard.times do
          begin
            connection.process(0) { true }
          rescue => error
            process_errors << error
          end
        end

        pending_ids = sftp.pending_requests.keys
        late_send_error = nil
        if process_errors.any?
          begin
            sftp.stat("/late")
          rescue => error
            late_send_error = error
          end
        end
        # Late bytes from a server that ignored the close must neither be
        # parsed against a fresh buffer nor be appended to it.
        sftp.send(:when_channel_data, nil, "stale") if process_errors.any?
        outcomes = requests.map do |request|
          if pending_ids.include?(request.id)
            [request.id, :pending]
          else
            begin
              request.wait
              [request.id, :complete, request.response.code]
            rescue => error
              [request.id, error.class, error.message]
            end
          end
        end
        chunk_sizes = sftp.received_chunk_sizes[recorded_from..-1] || []
        input_length = sftp.send(:input).length
        state = sftp.state
        packet_length = sftp.instance_variable_get(:@packet_length)
      end

      StoryResult.new(callbacks, process_errors, pending_ids, outcomes,
                      input_length, state, packet_length, script.events.length,
                      late_send_error, chunk_sizes,
                      !expect_close || script.events.empty?,
                      sftp.framing_error_input_length)
    end
end
