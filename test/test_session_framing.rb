require "common"

# Regression tests for the outer SFTP framing layer. A packet may arrive in
# any number of SSH channel-data callbacks, and several packets may arrive in
# one callback. These tests drive the real Net::SSH test story with raw bytes
# and compare the effects of every split point, without starting a server.
class SessionFramingTest < Net::SFTP::TestCase
  include Net::SFTP::Constants::PacketTypes

  VERSION = 3
  MAX = Net::SFTP::Session::MAX_PACKET_LENGTH

  class InMemorySSH
    include Net::SSH::Test
  end

  def test_splitting_valid_packets_does_not_change_callbacks_or_pending_requests
    bytes = status_packet(0) + status_packet(1)
    expected = run_framing(bytes, [bytes])

    assert_equal [[0, 0], [1, 0]], expected[:calls]
    assert_equal [0, 0], expected[:codes]
    assert_empty expected[:pending]
    assert_nil expected[:error]
    assert_equal 0, expected[:input_length]
    assert_nil expected[:packet_length]
    assert_equal 0, expected[:script_events]

    two_way_splits(bytes).each do |chunks|
      assert_equal expected, run_framing(bytes, chunks),
        "framing changed when split into #{chunks.map(&:bytesize).inspect} bytes"
    end

    assert_equal expected, run_framing(bytes, byte_chunks(bytes)),
      "framing changed when delivered one byte at a time"
  end

  def test_length_header_split_across_callbacks_waits_for_all_four_bytes
    1.upto(3) do |prefix_length|
      with_in_memory_sftp do |sftp, requests, calls|
        packet = status_packet(0)
        feed(sftp, packet.byteslice(0, prefix_length))

        assert_empty calls
        assert_equal [0, 1], sftp.pending_requests.keys.sort
        assert_equal prefix_length, sftp.send(:input).length
        assert_nil sftp.instance_variable_get(:@packet_length)

        feed(sftp, packet.byteslice(prefix_length, packet.bytesize - prefix_length))

        assert_equal [[0, 0]], calls
        assert_equal 0, requests[0].response.code
        assert_equal [1], sftp.pending_requests.keys
        assert_equal 0, sftp.send(:input).length
        assert_nil sftp.instance_variable_get(:@packet_length)
      end
    end
  end

  def test_zero_length_packet_is_rejected_and_fails_all_pending_requests
    header = length_header(0)
    expected = run_framing(header, [header])

    assert_empty expected[:calls]
    assert_equal [nil, nil], expected[:codes]
    assert_empty expected[:pending]
    assert_equal [[Net::SFTP::Exception, "invalid SFTP packet length 0"],
                  [Net::SFTP::Exception, "invalid SFTP packet length 0"]], expected[:failed]
    assert_equal [Net::SFTP::Exception, "invalid SFTP packet length 0"], expected[:error]
    assert_equal 0, expected[:input_length]
    assert_nil expected[:packet_length]

    two_way_splits(header).each do |chunks|
      assert_equal expected, run_framing(header, chunks),
        "empty packet handling changed when split into #{chunks.map(&:bytesize).inspect} bytes"
    end
    assert_equal expected, run_framing(header, byte_chunks(header))
  end

  def test_oversized_length_is_rejected_from_the_header_before_the_body_is_buffered
    header = length_header(MAX + 1)
    expected = run_framing(header, [header])

    assert_empty expected[:calls]
    assert_equal [nil, nil], expected[:codes]
    assert_empty expected[:pending]
    assert_equal Net::SFTP::Exception, expected[:error] && expected[:error][0]
    assert_match(/SFTP packet length #{MAX + 1} exceeds the maximum of #{MAX}/, expected[:error][1])
    refute_match(/entries/, expected[:error][1],
      "the outer frame length must be rejected by the framing layer, not by a protocol item count")
    assert_equal 0, expected[:input_length]
    assert_nil expected[:packet_length]

    two_way_splits(header).each do |chunks|
      assert_equal expected, run_framing(header, chunks),
        "oversize handling changed when split into #{chunks.map(&:bytesize).inspect} bytes"
    end
    assert_equal expected, run_framing(header, byte_chunks(header))
  end

  def test_length_at_the_limit_is_accepted_and_one_byte_more_is_not
    with_in_memory_sftp do |sftp, requests, calls|
      feed(sftp, length_header(MAX))

      assert_empty calls
      assert_equal [0, 1], sftp.pending_requests.keys.sort
      assert_equal 4, sftp.send(:input).length
      assert_equal MAX, sftp.instance_variable_get(:@packet_length)
    end

    error = run_framing(length_header(MAX + 1), [length_header(MAX + 1)])[:error]
    assert_equal Net::SFTP::Exception, error[0]
  end

  def test_incomplete_trailing_packet_is_buffered_and_not_dispatched
    first = status_packet(0)
    second = status_packet(1)

    [3, 8].each do |tail_length|
      partial = second.byteslice(0, tail_length)
      with_in_memory_sftp do |sftp, requests, calls|
        feed(sftp, first + partial)

        assert_equal [[0, 0]], calls
        assert_equal 0, requests[0].response.code
        assert_equal [1], sftp.pending_requests.keys
        assert_equal tail_length, sftp.send(:input).length

        if tail_length >= 4
          assert_equal second.bytesize - 4, sftp.instance_variable_get(:@packet_length)
        else
          assert_nil sftp.instance_variable_get(:@packet_length)
        end

        feed(sftp, second.byteslice(tail_length, second.bytesize - tail_length))

        assert_equal [[0, 0], [1, 0]], calls
        assert_empty sftp.pending_requests
        assert_equal 0, sftp.send(:input).length
        assert_nil sftp.instance_variable_get(:@packet_length)
      end
    end
  end

  def test_valid_packet_before_a_bad_frame_is_dispatched_and_the_tail_is_discarded
    [length_header(0), length_header(MAX + 1)].each do |bad_header|
      bytes = status_packet(0) + bad_header + status_packet(1)
      expected = run_framing(bytes, [bytes], :requests => 3)

      assert_equal [[0, 0]], expected[:calls]
      assert_equal [0, nil, nil], expected[:codes]
      assert_empty expected[:pending]
      assert_equal Net::SFTP::Exception, expected[:error][0]
      assert_nil expected[:failed][0]
      assert_equal expected[:error], expected[:failed][1]
      assert_equal expected[:error], expected[:failed][2]
      assert_equal 0, expected[:input_length]
      assert_nil expected[:packet_length]

      two_way_splits(bytes).each do |chunks|
        assert_equal expected, run_framing(bytes, chunks, :requests => 3),
          "bad-frame handling changed when split into #{chunks.map(&:bytesize).inspect} bytes"
      end
      assert_equal expected, run_framing(bytes, byte_chunks(bytes), :requests => 3)
    end
  end

  def test_framing_error_is_terminal_and_has_a_clear_failure_policy
    with_in_memory_sftp :requests => 3 do |sftp, requests, calls|
      error = assert_raises(Net::SFTP::Exception) do
        feed(sftp, status_packet(0) + length_header(0))
      end

      assert_equal [[0, 0]], calls
      assert requests[0].response.ok?
      refute requests[0].pending?

      [1, 2].each do |index|
        refute requests[index].pending?
        wait_error = assert_raises(Net::SFTP::Exception) { requests[index].wait }
        assert_equal error.message, wait_error.message
      end

      send_error = assert_raises(Net::SFTP::Exception) { sftp.close("another") }
      assert_same error, send_error, "a request after a framing error should raise the framing error"

      assert_empty sftp.pending_requests
      assert_equal 0, sftp.send(:input).length

      repeated = assert_raises(Net::SFTP::Exception) { sftp.channel.process }
      assert_same error, repeated, "the framing error should remain terminal for the connection"

      sftp.channel.do_data(status_packet(9))
      assert_raises(Net::SFTP::Exception) { sftp.channel.process }
      assert_equal [[0, 0]], calls, "bytes after a framing error must not be dispatched"
      assert_equal 0, sftp.send(:input).length
    end
  end

  private

    def status_packet(id, code = 0)
      Net::SSH::Buffer.from(:long, 9, :byte, FXP_STATUS, :long, id, :long, code).to_s
    end

    def length_header(length)
      [length].pack("N")
    end

    def two_way_splits(bytes)
      (1...bytes.bytesize).map do |index|
        [bytes.byteslice(0, index), bytes.byteslice(index, bytes.bytesize - index)]
      end
    end

    def byte_chunks(bytes)
      Array.new(bytes.bytesize) { |index| bytes.byteslice(index, 1) }
    end

    def feed(sftp, data)
      sftp.channel.do_data(data)
      sftp.channel.process
    end

    def with_in_memory_sftp(options = {})
      request_count = options.fetch(:requests, 2)
      ssh = InMemorySSH.new
      calls = []

      ssh.story do |script|
        channel = script.opens_channel
        channel.sends_subsystem("sftp")
        channel.sends_packet(FXP_INIT, :long, VERSION)
        channel.gets_packet(FXP_VERSION, :long, VERSION)
        request_count.times do |id|
          channel.sends_packet(FXP_CLOSE, :long, id, :string, "handle-#{id}")
        end
      end

      Net::SSH::Test::Extensions::IO.with_test_extension do
        sftp = Net::SFTP::Session.new(ssh.connection, VERSION)
        sftp.connect!
        requests = Array.new(request_count) do |id|
          sftp.close("handle-#{id}") { |response| calls << [id, response.code] }
        end
        yield sftp, requests, calls, ssh
      end
    end

    def run_framing(bytes, chunks, options = {})
      outcome = nil
      with_in_memory_sftp(options) do |sftp, requests, calls, ssh|
        error = nil
        chunks.each do |chunk|
          begin
            feed(sftp, chunk)
          rescue StandardError => e
            error = e
            break
          end
        end

        outcome = {
          :calls => calls,
          :codes => requests.map { |request| request.response && request.response.code },
          :pending => sftp.pending_requests.keys.sort,
          :failed => requests.map { |request| request_error(request) },
          :error => error && [error.class, error.message],
          :input_length => sftp.send(:input).length,
          :packet_length => sftp.instance_variable_get(:@packet_length),
          :script_events => ssh.socket.script.events.length
        }
      end
      outcome
    end

    def request_error(request)
      error = request.instance_variable_get(:@error)
      error && [error.class, error.message]
    end
end
