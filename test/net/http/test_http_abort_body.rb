# coding: US-ASCII
# frozen_string_literal: false
require 'net/http'
require 'socket'
require 'test/unit'

# Exercises Net::HTTPResponse#abort_body end to end over a local, fully
# observable transport: each connection is a UNIXSocket pair, so the test can
# see every request the client writes and every byte the server sends.
class TestNetHTTPAbortBody < Test::Unit::TestCase
  # One scripted server side of a connection. It answers successive requests
  # with the bodies given at construction, and records the raw requests.
  class Peer
    attr_reader :requests

    def initialize(socket, bodies)
      @socket = socket
      @bodies = bodies
      @requests = Queue.new
      @thread = Thread.new { run }
      @thread.report_on_exception = false
    end

    def close
      @thread.kill
      @thread.join
      @socket.close unless @socket.closed?
    end

    private

    def run
      @bodies.each do |body|
        request = read_request
        break unless request
        @requests << request
        write_response(body)
      end
    rescue IOError, SystemCallError
      # The client closed the connection early; that is expected in the
      # abort-with-remainder cases.
    end

    def read_request
      line = @socket.gets
      return nil unless line
      headers = +''
      while (header = @socket.gets)
        headers << header
        break if header == "\r\n"
      end
      line + headers
    end

    def write_response(body)
      if body.is_a?(Array) # [payload, :chunked]
        payload, = body
        @socket.write "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n" \
                      "#{payload.bytesize.to_s(16)}\r\n#{payload}\r\n0\r\n\r\n"
      else
        @socket.write "HTTP/1.1 200 OK\r\nContent-Length: #{body.bytesize}\r\n" \
                      "Connection: keep-alive\r\n\r\n#{body}"
      end
    end
  end

  # Net::HTTP with the network replaced by UNIXSocket pairs. +connections+ is
  # a queue of body lists; the nth call to #connect consumes the nth list.
  class ScriptedHTTP < Net::HTTP
    def self.with_connections(connections)
      http = allocate
      http.send(:initialize, 'example.com', 80)
      http.instance_variable_set(:@connections, connections)
      http
    end

    attr_reader :connect_count, :peers

    private

    def connect
      @connect_count += 1
      client, server = UNIXSocket.pair
      @peers << Peer.new(server, @connections.pop)
      @socket = Net::BufferedIO.new(
        client,
        read_timeout: 5,
        write_timeout: 5,
        continue_timeout: nil,
        debug_output: nil
      )
    end
  end

  def setup
    @http = nil
    @connections = Queue.new
  end

  def teardown
    @http&.peers&.each(&:close)
    @http&.finish if @http&.started?
  end

  def new_http(*connections)
    connections.each { |bodies| @connections << bodies }
    @http = ScriptedHTTP.with_connections(@connections)
    @http.instance_variable_set(:@connect_count, 0)
    @http.instance_variable_set(:@peers, [])
    @http.start
    @http
  end

  def test_abort_with_remaining_body_closes_connection_and_reconnects
    first = 'x' * 200_000
    new_http([first], %w[second])

    got = +''
    res = @http.request(Net::HTTP::Get.new('/first')) do |response|
      response.read_body do |chunk|
        got << chunk
        response.abort_body
        break
      end
    end

    assert_operator got.bytesize, :>, 0
    assert_operator got.bytesize, :<, first.bytesize
    assert_equal first[0, got.bytesize], got
    assert_false res.body_complete?
    assert_true res.body_aborted?
    assert_true @http.instance_variable_get(:@socket).closed?
    assert_equal 1, @http.connect_count

    second = @http.request(Net::HTTP::Get.new('/second'))
    assert_equal 'second', second.body
    assert_equal 2, @http.connect_count
    assert_equal 2, @http.peers.size
    assert_match(%r{\AGET /second }, @http.peers.last.requests.pop)
  end

  def test_abort_after_body_exactly_consumed_keeps_connection_reusable
    first = 'first' * 4096
    new_http([first, 'second'])

    got = +''
    res = @http.request(Net::HTTP::Get.new('/first')) do |response|
      response.read_body do |chunk|
        got << chunk
        if got.bytesize == first.bytesize
          assert_false response.abort_body
        end
      end
    end

    assert_equal first, got
    assert_true res.body_complete?
    assert_false res.body_aborted?
    assert_false @http.instance_variable_get(:@socket).closed?

    second = @http.request(Net::HTTP::Get.new('/second'))
    assert_equal 'second', second.body
    assert_equal 1, @http.connect_count,
                 'the second request must reuse the same connection'
    assert_equal 1, @http.peers.size
    assert_equal 2, @http.peers.first.requests.size
  end

  def test_abort_after_full_read_is_a_noop
    new_http(%w[body second])

    res = @http.request(Net::HTTP::Get.new('/first')) do |response|
      response.read_body
      assert_false response.abort_body
    end

    assert_true res.body_complete?
    assert_false res.body_aborted?
    assert_equal 'body', res.body

    second = @http.request(Net::HTTP::Get.new('/second'))
    assert_equal 'second', second.body
    assert_equal 1, @http.connect_count
  end

  def test_exception_in_block_is_preserved_and_connection_closed
    first = 'p' * 200_000
    new_http([first], %w[second])

    error = Class.new(StandardError).new('callback failed')
    captured = nil
    raised = assert_raise(error.class) do
      @http.request(Net::HTTP::Get.new('/first')) do |response|
        captured = response
        response.read_body do |_chunk|
          raise error
        end
      end
    end

    assert_same error, raised
    assert_same error, captured.body_exception
    assert_same error, captured.body_error
    assert_false captured.body_complete?
    assert_true captured.body_aborted?
    assert_true @http.instance_variable_get(:@socket).closed?

    second = @http.request(Net::HTTP::Get.new('/second'))
    assert_equal 'second', second.body
    assert_equal 2, @http.connect_count
  end

  def test_abort_before_reading_skips_body_and_closes_connection
    new_http(%w[payload], %w[second])

    res = @http.request(Net::HTTP::Get.new('/first')) do |response|
      assert_true response.abort_body
    end

    assert_nil res.body
    assert_false res.body_complete?
    assert_true res.body_aborted?
    assert_true @http.instance_variable_get(:@socket).closed?

    second = @http.request(Net::HTTP::Get.new('/second'))
    assert_equal 'second', second.body
    assert_equal 2, @http.connect_count
  end

  def test_abort_can_record_caller_exception_without_raising
    first = 'p' * 200_000
    new_http([first], %w[second])

    error = RuntimeError.new('credentials rejected')
    res = @http.request(Net::HTTP::Get.new('/first')) do |response|
      response.read_body do |_chunk|
        response.abort_body(error)
      end
    end

    assert_same error, res.body_exception
    assert_false res.body_complete?
    assert_true res.body_aborted?
    assert_true @http.instance_variable_get(:@socket).closed?
  end
end

class TestNetHTTPAbortBodyChunked < Test::Unit::TestCase
  def setup
    @connections = Queue.new
    @http = TestNetHTTPAbortBody::ScriptedHTTP.with_connections(@connections)
    @http.instance_variable_set(:@connect_count, 0)
    @http.instance_variable_set(:@peers, [])
  end

  def teardown
    @http.peers.each(&:close)
    @http.finish if @http.started?
  end

  def queue(*connections)
    connections.each { |bodies| @connections << bodies }
    @http.start
  end

  # Stops after the first (fully delivered) chunk, before the terminating
  # zero-length chunk and trailer. Those bytes stay unread and the connection
  # must not be reused.
  def test_abort_mid_chunked_closes_connection_without_reading_trailer
    payload = 'c' * 1000
    queue([[payload, :chunked]], %w[second])

    got = +''
    res = @http.request(Net::HTTP::Get.new('/first')) do |response|
      response.read_body do |chunk|
        got << chunk
        assert_true response.abort_body
      end
    end

    assert_equal payload, got
    assert_false res.body_complete?
    assert_true res.body_aborted?
    assert_true @http.instance_variable_get(:@socket).closed?

    second = @http.request(Net::HTTP::Get.new('/second'))
    assert_equal 'second', second.body
    assert_equal 2, @http.connect_count
  end

  def test_chunked_body_read_to_end_is_complete
    queue([['hello', :chunked], 'second'])

    res = @http.request(Net::HTTP::Get.new('/first')) do |response|
      response.read_body
      assert_false response.abort_body
    end

    assert_true res.body_complete?
    assert_false res.body_aborted?
    assert_equal 'hello', res.body

    second = @http.request(Net::HTTP::Get.new('/second'))
    assert_equal 'second', second.body
    assert_equal 1, @http.connect_count
  end
end
