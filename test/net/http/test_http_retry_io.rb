# coding: US-ASCII
# frozen_string_literal: false
#
# Tests for Net::HTTP connection retry behaviour backed by real I/O.
#
# Every case stands in for the server with the peer end of a real
# Socket.pair stream (no port binding, no fake write/read methods), so the
# byte stream and the exceptions raised on a closed connection are the same
# ones a TCP socket would produce.  The server end of each pair is driven by
# a thread that either:
#
#   * closes before reading anything, or
#   * reads the request header plus a fixed prefix of the body, then closes,
#   * reads the whole request and answers once.
#
# The recorded raw bytes of every attempt are asserted so that a future
# change to the retry policy has a concrete baseline: a non-idempotent
# request must never produce a second submission, while an idempotent retry
# must deliver its response exactly once.

require 'test/unit'
require 'net/http'
require 'socket'
require 'tempfile'

class TestNetHTTPRetryIO < Test::Unit::TestCase
  BODY = ("A".."Z").map { |c| c * 40 }.join # 1040 bytes, easy to spot in dumps
  PARTIAL_BODY_BYTES = 50
  RESPONSE = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"

  # One accepted stand-in connection.  +bytes+ holds everything the server
  # side actually received, split into header/body by the test for assertions.
  #
  # +ready_io+ is the write end of a separate pipe used as a one-shot
  # handshake for stand-ins that must finish their opening action (an
  # immediate close) before the client writes.
  class Connection
    attr_reader :bytes
    attr_accessor :server_error, :thread

    def initialize(server_io, ready_io, behavior)
      @server_io = server_io
      @ready_io = ready_io
      @behavior = behavior
      @bytes = +''
      @server_error = nil
      @thread = nil
      @signaled = false
    end

    def header
      @bytes.byteslice(0, header_end)
    end

    def body
      @bytes.byteslice(header_end, @bytes.bytesize - header_end) || +''
    end

    # Called by a behavior once the client is allowed to start writing.
    def signal_ready
      if @ready_io && !@signaled
        @ready_io.write('.')
        @ready_io.close
        @signaled = true
      end
    end

    def run
      @behavior.call(@server_io, self)
    ensure
      signal_ready
      @server_io.close unless @server_io.closed?
    end

    private

    def header_end
      sep = @bytes.index("\r\n\r\n")
      sep ? sep + 4 : @bytes.bytesize
    end
  end

  def setup
    @proxy_env = %w[http_proxy HTTP_PROXY https_proxy HTTPS_PROXY
                    no_proxy NO_PROXY].each_with_object({}) do |name, saved|
      saved[name] = ENV.delete(name)
    end
    @connections = []
    @http = Net::HTTP.new('retry-io.example')
    @http.max_retries = 1
    @http.read_timeout = 1
    @http.write_timeout = 1
    install_fake_connect
  end

  def teardown
    @connections.each do |connection|
      connection.thread.join
      assert_nil connection.server_error,
                 "stand-in server failed unexpectedly: #{connection.server_error}"
    end
    @body_file&.close!
    @proxy_env&.each { |name, value| ENV[name] = value }
  end

  # Replace the private TCP connect with one that hands Net::HTTP a real
  # BufferedIO wrapped around one end of a socket pair.  Each retry therefore
  # gets a brand new pair, exactly like a fresh TCP connection.
  def install_fake_connect
    connections = @connections
    behaviors = proc { @behaviors }
    http = @http
    http.define_singleton_method(:connect) do
      client_io, server_io = Socket.pair(:UNIX, :STREAM)
      configured = behaviors.call
      behavior = configured.fetch(connections.size, configured.last)
      if behavior.respond_to?(:needs_ready_handshake?) && behavior.needs_ready_handshake?
        ready_read, ready_write = IO.pipe
      end
      connection = Connection.new(server_io, ready_write, behavior)
      connection.thread = Thread.new do
        begin
          connection.run
        rescue => exception
          connection.server_error = exception
        ensure
          ready_write&.close
        end
      end
      connections << connection
      if ready_read
        # Wait for the stand-in to finish its opening action.  Thread.pass
        # then yields so a reply stand-in reaches its blocking read before the
        # client writes, preventing scheduler-induced truncation.
        ready_read.read(1)
        ready_read.close
        Thread.pass
      end
      @socket = Net::BufferedIO.new(
        client_io,
        read_timeout: @read_timeout,
        write_timeout: @write_timeout,
        continue_timeout: @continue_timeout,
        debug_output: @debug_output
      )
      @last_communicated = nil
    end
  end

  # Close without reading a single byte, so the client's first write fails.
  def close_before_send
    behavior = lambda do |io, connection|
      connection.signal_ready
      io.close
    end
    behavior.define_singleton_method(:needs_ready_handshake?) { true }
    behavior
  end

  # Consume the header and PARTIAL_BODY_BYTES of the body, then drop the
  # connection while the client is still writing the rest.
  def close_after_partial_body
    partial = PARTIAL_BODY_BYTES
    lambda do |io, connection|
      read_header(io, connection)
      prefix = io.read(partial)
      connection.bytes << prefix if prefix
      io.close
    end
  end

  # Read the complete request (using its Content-Length) and answer once.
  # It signals ready before reading so the client only sends once this server
  # thread exists and is about to block on read; the client keeps the socket
  # open until it reads this response, so no data can be lost.
  def read_full_and_reply
    response = RESPONSE
    behavior = lambda do |io, connection|
      connection.signal_ready
      read_header(io, connection)
      length = content_length(connection.header)
      remaining = length
      while remaining > 0
        chunk = io.read(remaining)
        break if chunk.nil?
        connection.bytes << chunk
        remaining -= chunk.bytesize
      end
      io.write(response)
    end
    behavior.define_singleton_method(:needs_ready_handshake?) { true }
    behavior
  end

  # Read the request header, briefly drain any body bytes already buffered,
  # then close without replying.  Used for a retry whose body stream was
  # consumed on the first attempt: it still advertises a Content-Length but
  # can send no body, so this stand-in must not block waiting for that body.
  def read_header_then_close
    lambda do |io, connection|
      read_header(io, connection)
      loop do
        ready, = IO.select([io], nil, nil, 0.1)
        break unless ready
        chunk = io.read_nonblock(65536, +'', exception: false)
        case chunk
        when nil, :wait_readable
          break
        else
          connection.bytes << chunk
        end
      end
      io.close
    end
  end

  def read_header(io, connection)
    until connection.bytes.end_with?("\r\n\r\n")
      char = io.read(1)
      raise EOFError, 'stand-in connection closed mid-header' if char.nil?
      connection.bytes << char
    end
  end

  def content_length(header)
    match = /\A.*\r\nContent-Length:\s*(\d+)\r\n/mi.match(header)
    match ? match[1].to_i : 0
  end

  def string_request(method)
    request = Net::HTTPGenericRequest.new(method, true, true, '/')
    request.body = BODY
    request
  end

  def stream_request(method)
    @body_file = Tempfile.new('net-http-retry-body')
    @body_file.binmode
    @body_file.write(BODY)
    @body_file.rewind
    request = Net::HTTPGenericRequest.new(method, true, true, '/')
    request.body_stream = @body_file
    request['Content-Length'] = BODY.bytesize.to_s
    request
  end

  def perform(request)
    error = nil
    response = nil
    @http.start do
      begin
        response = @http.request(request)
      rescue SystemCallError, EOFError, IOError, Net::ReadTimeout => exception
        error = exception
      end
    end
    [response, error]
  end

  def assert_single_attempt
    assert_equal 1, @connections.size,
                 'a non-idempotent request must not open a second connection'
  end

  # The request target is origin-form ("POST / ...") for a direct connection
  # and absolute-form ("POST http://host/ ...") through a proxy, so assert the
  # method and the terminating path independently.
  def assert_request_line(method, header)
    assert_match(/\A#{method} (?:\/|http:\/\/retry-io\.example\/) HTTP\/1\.1\r\n/,
                 header)
  end

  def test_post_string_body_close_before_send_does_not_retry
    @behaviors = [close_before_send]
    response, error = perform(string_request('POST'))

    assert_nil response
    assert_kind_of EOFError, error
    assert_single_attempt
    assert_predicate @connections.first.header, :empty?
    assert_predicate @connections.first.body, :empty?
  end

  def test_post_string_body_partial_write_does_not_retry
    @behaviors = [close_after_partial_body]
    response, error = perform(string_request('POST'))

    assert_nil response
    assert_kind_of EOFError, error
    assert_single_attempt
    connection = @connections.first
    assert_request_line('POST', connection.header)
    assert_equal PARTIAL_BODY_BYTES, connection.body.bytesize
    assert_equal BODY.byteslice(0, PARTIAL_BODY_BYTES), connection.body
    assert_not_equal BODY, connection.body,
                     'the one attempt must remain an incomplete submission'
  end

  def test_post_stream_body_partial_write_does_not_retry
    @behaviors = [close_after_partial_body]
    response, error = perform(stream_request('POST'))

    assert_nil response
    assert_kind_of EOFError, error
    assert_single_attempt
    connection = @connections.first
    assert_request_line('POST', connection.header)
    assert_equal PARTIAL_BODY_BYTES, connection.body.bytesize
    assert_equal BODY.byteslice(0, PARTIAL_BODY_BYTES), connection.body
  end

  def test_put_string_body_close_before_send_retries_and_answers_once
    @behaviors = [close_before_send, read_full_and_reply]
    response, error = perform(string_request('PUT'))

    assert_nil error
    assert_equal '200', response.code
    assert_equal 'ok', response.body
    assert_equal 2, @connections.size

    first, second = @connections
    assert_predicate first.header, :empty?
    assert_predicate first.body, :empty?
    assert_request_line('PUT', second.header)
    assert_equal BODY, second.body
  end

  def test_put_string_body_partial_write_retries_with_full_body_once
    @behaviors = [close_after_partial_body, read_full_and_reply]
    response, error = perform(string_request('PUT'))

    assert_nil error
    assert_equal '200', response.code
    assert_equal 'ok', response.body
    assert_equal 2, @connections.size

    first, second = @connections
    assert_request_line('PUT', first.header)
    assert_equal PARTIAL_BODY_BYTES, first.body.bytesize
    assert_equal BODY.byteslice(0, PARTIAL_BODY_BYTES), first.body
    assert_request_line('PUT', second.header)
    assert_equal BODY, second.body,
                 'a String body is rewindable, so the retry resends every byte'
  end

  def test_put_stream_body_close_before_send_retries_with_untouched_stream
    @behaviors = [close_before_send, read_full_and_reply]
    response, error = perform(stream_request('PUT'))

    assert_nil error
    assert_equal '200', response.code
    assert_equal 'ok', response.body
    assert_equal 2, @connections.size

    first, second = @connections
    assert_predicate first.header, :empty?
    assert_predicate first.body, :empty?
    assert_equal BODY, second.body,
                 'no bytes were consumed before the reset, so the retry is complete'
  end

  def test_put_stream_body_partial_write_retries_with_truncated_body
    @behaviors = [close_after_partial_body, read_header_then_close]
    request = stream_request('PUT')
    response, error = perform(request)

    # The stream is not rewound between attempts: the retry advertises the
    # original Content-Length but has no body bytes left, so the second
    # stand-in reads just the header and the client fails at EOF.  Pin this
    # behaviour so a retry-policy change (e.g. rewinding body streams) is
    # deliberate.
    assert_nil response
    assert_kind_of EOFError, error
    assert_equal 2, @connections.size

    first, second = @connections
    assert_equal PARTIAL_BODY_BYTES, first.body.bytesize
    assert_equal BODY.byteslice(0, PARTIAL_BODY_BYTES), first.body
    assert_request_line('PUT', second.header)
    assert_equal 0, second.body.bytesize,
                 'the consumed stream has no body bytes left for the retry'
    assert_equal BODY.bytesize, content_length(second.header),
                 'the retry still promises the full Content-Length'
  end
end
