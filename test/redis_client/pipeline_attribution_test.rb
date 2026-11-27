# frozen_string_literal: true

begin
  require "test_helper"
  PipelineAttributionTestCase = RedisClientTestCase
rescue LoadError
  # Allow running the regression test standalone: the full stack
  # (megatest/toxiproxy/redis-server) is not needed for these in-memory checks.
  require "minitest/autorun"
  $LOAD_PATH.unshift File.expand_path("../../lib", __dir__)
  require "redis-client"
  PipelineAttributionTestCase = Minitest::Test
end

class RedisClient
  class PipelineAttributionTest < PipelineAttributionTestCase
    # In-memory socket stand-in. Every byte handed to the driver is recorded so
    # the tests can prove the driver consumes exactly one RESP reply per
    # pipeline command and never reads past the end of its batch.
    class ScriptedIO
      attr_reader :bytes_read, :read_sizes, :bytes_written

      def initialize(payload, chunk_size: 1)
        @payload = payload.b
        @chunk_size = chunk_size
        @read_offset = 0
        @bytes_read = 0
        @read_sizes = []
        @bytes_written = 0
        @closed = false
        @eof_observed = false
      end

      def read_nonblock(maxlen, buffer = nil, exception: true)
        if @read_offset >= @payload.bytesize
          @eof_observed = true
          return nil if exception

          raise EOFError, "end of file reached"
        end

        length = [maxlen, @chunk_size, @payload.bytesize - @read_offset].min
        chunk = @payload.byteslice(@read_offset, length)
        @read_offset += length
        @bytes_read += length
        @read_sizes << length

        if buffer
          buffer.replace(chunk)
        else
          chunk
        end
      end

      def write_nonblock(string, exception: true)
        @bytes_written += string.bytesize
        string.bytesize
      end

      def drained?
        @read_offset == @payload.bytesize
      end

      # BufferedIO#eof? only consults the underlying IO once its own buffer is
      # drained; mirror a socket, where EOF is visible only after a read past
      # the last available byte.
      def eof?
        drained? && @eof_observed
      end

      def close
        @closed = true
      end

      def closed?
        @closed
      end

      # BufferedIO only reaches for to_io on #close/#closed? and readiness
      # waits; an in-memory stream has no real fd to expose.
      def to_io
        self
      end

      def wait_readable(_timeout = nil)
        true
      end

      def wait_writable(_timeout = nil)
        true
      end
    end

    # Hands out one pre-recorded RESP script per physical connection, so a
    # reconnect is observable and receives a distinct, freshly attributed reply.
    class ScriptedServer
      attr_reader :connections, :handled_ios

      def prelude?
        @prelude
      end

      # A RESP3 client always performs a HELLO connection prelude; answer it
      # with a minimal valid RESP3 map so the prelude does not consume bytes
      # that belong to the batch under test.
      PRELUDE_REPLY = "%1\r\n+server\r\n+redis\r\n"
      PRELUDE_BYTES = PRELUDE_REPLY.bytesize

      def initialize(scripts, chunk_sizes: [1], prelude: true)
        @scripts = scripts
        @chunk_sizes = chunk_sizes
        @prelude = prelude
        @connections = 0
        @handled_ios = []
      end

      def open_connection
        script = @scripts.fetch(@connections)
        chunk_size = @chunk_sizes.fetch(@connections, @chunk_sizes.last)
        payload = @prelude ? PRELUDE_REPLY + script.fetch(:reply) : script.fetch(:reply)
        io = ScriptedIO.new(payload, chunk_size: chunk_size)
        @handled_ios << io
        @connections += 1
        io
      end
    end

    class ScriptedDriver < RubyConnection
      def connect
        @server_key = config.server_key
        @io = BufferedIO.new(
          config.custom[:server].open_connection,
          read_timeout: read_timeout,
          write_timeout: write_timeout,
          chunk_size: 1,
        )
        true
      end

      def read_timeout
        @read_timeout
      end

      def write_timeout
        @write_timeout
      end
    end

    # Deliberately broken test double: it injects a mid-batch disconnect after
    # the first reply while bytes belonging to another request are still
    # buffered, then makes the replacement driver instance reuse that same
    # poisoned stream instead of opening a clean connection. A correct driver
    # must discard every byte read on the failed connection.
    class StaleBufferReusingDriver < ScriptedDriver
      @shared_io = nil

      class << self
        attr_accessor :shared_io
      end

      def self.reset!
        @shared_io = nil
      end

      def connect
        @server_key = config.server_key
        self.class.shared_io ||= BufferedIO.new(
          config.custom[:server].open_connection,
          read_timeout: read_timeout,
          write_timeout: write_timeout,
          chunk_size: 1,
        )
        @io = self.class.shared_io
        true
      end

      def read(*)
        unless @failure_injected
          @read_count ||= 0
          @read_count += 1
          if @read_count == 2
            @failure_injected = true
            raise connection_error("simulated mid-batch disconnect")
          end
        end
        super
      end

      # Keep the reused stream "open" so revalidate does not hide the leak by
      # forcing yet another brand-new connection.
      def close
        @pending_reads = 0
        nil
      end
    end

    # Six U+2010-style multibyte characters encoded as explicit UTF-8 bytes:
    # 6 characters but 18 bytes, independent of the source file's encoding.
    # The binary blob is 3 bytes with no valid character encoding at all. This
    # forces byte-based (not char-based) math throughout the read buffer.
    MULTIBYTE_VALUE = ("\xE2\x82\xAC" * 6).b
    MULTIBYTE_BYTES = MULTIBYTE_VALUE.bytesize
    MULTIBYTE_CHAR_COUNT = MULTIBYTE_VALUE.dup.force_encoding(Encoding::UTF_8).length
    # A lone continuation byte is valid as raw bytes but never valid UTF-8, so
    # the parser must keep it in BINARY encoding instead of promoting it.
    BINARY_VALUE = "\x80\x00\xFE".b
    BINARY_BYTES = BINARY_VALUE.bytesize

    def test_decoded_failed_and_pending_entries_each_have_distinct_criteria
      payload = happy_path_payload
      server = ScriptedServer.new([{ reply: payload }], prelude: true)
      client = build_client(server)

      results = client.pipelined(exception: false) do |pipeline|
        pipeline.call("INCR", "counter")
        pipeline.call("DOESNT-EXIST")
        pipeline.call("GET", "multibyte")
        pipeline.call("ECHO", "plain")
        pipeline.call("GET", "binary")
        pipeline.call("GET", "missing")
      end

      # Decoded entries: exact value, position and encoding.
      assert_equal 42, results[0]
      assert_equal MULTIBYTE_VALUE.dup.force_encoding(Encoding::UTF_8), results[2]
      assert_equal MULTIBYTE_CHAR_COUNT, results[2].length
      assert_equal MULTIBYTE_BYTES, results[2].bytesize
      assert_equal "plain", results[3]
      assert_equal BINARY_VALUE, results[4]
      assert_equal Encoding::BINARY, results[4].encoding
      refute results[4].dup.force_encoding(Encoding::UTF_8).valid_encoding?

      # Explicit failure: a CommandError attributed to its own command only,
      # without shifting the replies that follow it.
      assert_instance_of RedisClient::CommandError, results[1]
      assert_equal ["DOESNT-EXIST"], results[1].command
      assert_start_with "ERR boom", results[1].message
      refute_instance_of RedisClient::CommandError, results[0]
      refute_instance_of RedisClient::CommandError, results[2]

      # Pending entry: a null reply is a delivered value, not a missing slot.
      assert_nil results[5]
      assert_equal 6, results.size
      assert_equal 0, raw_connection_pending_reads(client)

      assert_io_drained(payload, server.handled_ios.last)
    ensure
      client&.close
    end

    def test_byte_counts_not_character_counts_hold_across_buffer_split_positions
      payload = String.new
      payload << blob(MULTIBYTE_VALUE)
      payload << blob(BINARY_VALUE)
      cut_points = [1, 2, 3, 5, 7, 16, MULTIBYTE_BYTES, MULTIBYTE_BYTES + 1, 64,
        payload.bytesize, payload.bytesize + 4096]
      cut_points.each do |chunk_size|
        server = ScriptedServer.new(
          [{ reply: payload }],
          chunk_sizes: [chunk_size],
          prelude: true,
        )
        client = build_client(server, chunk_size: chunk_size)

        results = client.pipelined(exception: false) do |pipeline|
          pipeline.call("GET", "multibyte")
          pipeline.call("GET", "binary")
        end

        assert_equal MULTIBYTE_BYTES, results[0].bytesize
        assert_equal MULTIBYTE_CHAR_COUNT, results[0].length
        assert_equal BINARY_BYTES, results[1].bytesize
        assert_io_drained(payload, server.handled_ios.last)
      ensure
        client&.close
      end
    end

    def test_command_error_does_not_shift_later_replies
      payload = String.new
      payload << "-ERR first failure\r\n"
      payload << "$3\r\nbar\r\n"
      server = ScriptedServer.new([{ reply: payload }], prelude: true)
      client = build_client(server)

      results = client.pipelined(exception: false) do |pipeline|
        pipeline.call("DOESNT-EXIST-1")
        pipeline.call("GET", "key")
      end

      assert_instance_of RedisClient::CommandError, results[0]
      assert_equal ["DOESNT-EXIST-1"], results[0].command
      assert_equal "bar", results[1]
      assert_predicate client, :connected?
      assert_io_drained(payload, server.handled_ios.last)
    ensure
      client&.close
    end

    def test_command_error_is_raised_by_default_after_draining_every_reply
      payload = "-ERR boom\r\n+OK\r\n"
      server = ScriptedServer.new([{ reply: payload }], prelude: true)
      client = build_client(server)

      error = assert_raises(RedisClient::CommandError) do
        client.pipelined do |pipeline|
          pipeline.call("DOESNT-EXIST")
          pipeline.call("SET", "key", "value")
        end
      end

      assert_equal ["DOESNT-EXIST"], error.command
      # Every reply was drained before raising, so the socket stays usable.
      assert_predicate client, :connected?
      assert_io_drained(payload, server.handled_ios.last)
    ensure
      client&.close
    end

    def test_mid_stream_eof_fails_the_pipeline_and_never_returns_partial_results
      payload = String.new
      payload << ":42\r\n"
      payload << blob(MULTIBYTE_VALUE)
      payload << "+third\r\n"
      # Every cut lands inside one of the three replies, so the driver always
      # reaches EOF while still expecting responses for the open pipeline.
      cut_points = [1, 3, 5, 8, payload.bytesize - 1]
      cut_points.each do |cut_at|
        truncated = payload.byteslice(0, cut_at)
        server = ScriptedServer.new([{ reply: truncated }], prelude: true)
        client = build_client(server)

        error = assert_raises(RedisClient::ConnectionError) do
          client.pipelined do |pipeline|
            pipeline.call("INCR", "counter")
            pipeline.call("GET", "multibyte")
            pipeline.call("ECHO", "third")
          end
        end

        assert_match(/end of file/i, error.message)
        refute_predicate client, :connected?
        assert_equal(
          ScriptedServer::PRELUDE_BYTES + cut_at,
          server.handled_ios.last.bytes_read,
        )
      ensure
        client&.close
      end
    end

    def test_reconnect_discards_stale_bytes_and_attributes_fresh_reply_to_the_retry
      fresh_payload = ":1\r\n:2\r\n"
      # The dead connection is truncated inside the second reply: the first
      # result is already decoded when the driver fails while still reading the
      # remaining responses for the batch.
      dead_payload = ":1\r\n:2\r"
      [1, 4, fresh_payload.bytesize].each do |chunk_size|
        server = ScriptedServer.new(
          [{ reply: dead_payload }, { reply: fresh_payload }],
          chunk_sizes: [chunk_size, chunk_size],
          prelude: true,
        )
        client = build_client(server, reconnect_attempts: 1, chunk_size: chunk_size)

        results = client.pipelined do |pipeline|
          pipeline.call("INCR", "a")
          pipeline.call("INCR", "b")
        end

        assert_equal [1, 2], results
        assert_equal 2, server.connections
        assert_equal ScriptedServer::PRELUDE_BYTES + fresh_payload.bytesize,
          server.handled_ios.last.bytes_read
        assert_equal ScriptedServer::PRELUDE_BYTES + dead_payload.bytesize,
          server.handled_ios.first.bytes_read
      ensure
        client&.close
      end
    end

    def test_mid_stream_eof_without_retry_surfaces_the_connection_error
      fresh_payload = ":1\r\n:2\r\n"
      dead_payload = ":1\r\n:2\r"
      server = ScriptedServer.new(
        [{ reply: dead_payload }, { reply: fresh_payload }],
        prelude: true,
      )
      client = build_client(server, reconnect_attempts: false)

      assert_raises(RedisClient::ConnectionError) do
        client.pipelined do |pipeline|
          pipeline.call("INCR", "a")
          pipeline.call("INCR", "b")
        end
      end
      refute_predicate client, :connected?
      assert_equal 1, server.connections
      assert_equal ScriptedServer::PRELUDE_BYTES + dead_payload.bytesize,
        server.handled_ios.first.bytes_read
    ensure
      client&.close
    end

    def test_real_driver_satisfies_the_reconnect_attribution_contract
      fresh_payload = ":1\r\n:2\r\n"
      dead_payload = ":1\r\n:2\r"
      server = ScriptedServer.new(
        [{ reply: dead_payload }, { reply: fresh_payload }],
        prelude: true,
      )
      client = build_client(server, reconnect_attempts: 1)

      assert_nil reconnect_attribution_violation(client, server, [1, 2], fresh_payload)
    ensure
      client&.close
    end

    def test_stale_buffer_double_is_caught_and_names_the_violated_semantic
      # Bytes 100/200 belong to a different request already sitting on the dead
      # connection; the double hands them to the retried pipeline as success.
      dead_payload = ":1\r\n:100\r\n:200\r\n"
      fresh_payload = ":1\r\n:2\r\n"
      server = ScriptedServer.new(
        [{ reply: dead_payload }, { reply: fresh_payload }],
        prelude: false,
      )
      StaleBufferReusingDriver.reset!
      client = build_client(
        server,
        reconnect_attempts: 1,
        driver: StaleBufferReusingDriver,
        prelude: false,
      )

      violation = reconnect_attribution_violation(client, server, [1, 2], fresh_payload)

      refute_nil violation
      assert_match(
        %r{reconnected pipeline must read its replies from the new connection},
        violation,
      )
      # The double never opened a second connection and surfaced stale bytes as
      # the retry's successful result.
      assert_equal 1, server.connections
      assert_match(/results: \[100, 200\]/, violation)
    ensure
      client&.close
      StaleBufferReusingDriver.reset!
    end

    private

    def happy_path_payload
      payload = String.new
      payload << ":42\r\n"
      payload << "-ERR boom\r\n"
      payload << blob(MULTIBYTE_VALUE)
      payload << "+plain\r\n"
      payload << blob(BINARY_VALUE)
      payload << "_\r\n"
      payload
    end

    def blob(value)
      "$#{value.bytesize}\r\n#{value}\r\n"
    end

    def assert_start_with(prefix, actual)
      assert actual.start_with?(prefix), "expected #{actual.inspect} to start with #{prefix.inspect}"
    end

    def build_client(server, reconnect_attempts: false, driver: ScriptedDriver, chunk_size: 1, prelude: true)
      config = RedisClient::Config.new(
        host: "scripted.example",
        port: 6379,
        protocol: 3,
        reconnect_attempts: reconnect_attempts,
        driver: driver,
        custom: { server: server },
      )
      client = RedisClient.new(config)
      unless prelude
        # The double manually models connection reuse, so no HELLO prelude may
        # consume a byte of the scripted stream.
        client.config.define_singleton_method(:connection_prelude) { [] }
      end
      client
    end

    def assert_io_drained(expected_payload, io)
      assert_equal ScriptedServer::PRELUDE_BYTES + expected_payload.bytesize, io.bytes_read
      assert_predicate io, :drained?
      assert(io.read_sizes.all? { |size| size > 0 }, "recorded a zero-length read")
    end

    def raw_connection_pending_reads(client)
      client
        .instance_variable_get(:@raw_connection)
        .instance_variable_get(:@pending_reads)
    end

    def reconnect_attribution_violation(client, server, expected_results, fresh_payload)
      results = client.pipelined do |pipeline|
        pipeline.call("INCR", "a")
        pipeline.call("INCR", "b")
      end

      prelude_bytes = server.prelude? ? ScriptedServer::PRELUDE_BYTES : 0
      fresh_io_bytes = server.handled_ios.last.bytes_read
      expected_fresh_bytes = prelude_bytes + fresh_payload.bytesize
      return if server.connections == 2 &&
        results == expected_results &&
        fresh_io_bytes == expected_fresh_bytes

      "reconnected pipeline must read its replies from the new connection, " \
        "but the driver attributed bytes from the dead connection to the retry " \
        "(connections: #{server.connections}, results: #{results.inspect}, " \
        "fresh connection bytes: #{fresh_io_bytes}/#{expected_fresh_bytes})"
    rescue RedisClient::Error => error
      "reconnected pipeline must read its replies from the new connection, " \
        "but the driver failed before draining the fresh connection " \
        "(#{error.class}: #{error.message})"
    end
  end
end
