# frozen_string_literal: true

require "redis_client/connection_mixin"

# An in-memory driver that never opens a socket. It records every command it
# actually receives, which lets tests assert what was sent on the wire after the
# client side capabilities have been enforced.
#
# Responses are scripted per command name through RecordingDriver.respond_with.
class RedisClient
  class RecordingDriver
    include ConnectionMixin

    class << self
      # Commands received by every driver instance, in transmission order.
      attr_reader :recorded_commands

      # Number of physical connections currently open.
      attr_reader :open_connections

      # Total number of connections established (including reconnects).
      attr_reader :total_connections

      def reset!
        @recorded_commands = []
        @open_connections = 0
        @total_connections = 0
        @responses = Hash.new("OK")
        @responses["GET"] = nil
        @responses["MGET"] = []
        @responses["PING"] = "PONG"
        @responses["HELLO"] = { "proto" => 2 }
        @responses["MULTI"] = "OK"
        @responses["EXEC"] = []
        @responses["DISCARD"] = "OK"
        @responses["UNWATCH"] = "OK"
        @responses["WATCH"] = "OK"
      end

      def respond_with(command_name, response)
        @responses ||= {}
        @responses[command_name.to_s.upcase] = response
      end

      def scripted_response(command)
        @responses ||= {}
        @responses.fetch(command.first.to_s.upcase, "OK")
      end

      def ssl_context(ssl_params)
        ssl_params
      end

      def track_connection!
        @open_connections += 1
        @total_connections += 1
      end

      def track_disconnection!
        @open_connections -= 1
      end
    end

    reset!

    def initialize(config, connect_timeout:, read_timeout:, write_timeout:)
      super(config)
      @connect_timeout = connect_timeout
      @read_timeout = read_timeout
      @write_timeout = write_timeout
      connect
    end

    def connected?
      !@closed
    end

    def read_timeout=(timeout)
      @read_timeout = timeout
    end

    def write_timeout=(timeout)
      @write_timeout = timeout
    end

    def connect
      @closed = false
      @server_key = @config.server_key
      self.class.track_connection!
      true
    end

    def reconnect
      close
      connect
    end

    def close
      unless @closed
        @closed = true
        self.class.track_disconnection!
      end
      super
    end

    def write(command)
      self.class.recorded_commands << command
      nil
    end

    def write_multi(commands)
      commands.each { |command| write(command) }
      nil
    end

    def read(_timeout = nil)
      @scripted_response
    end

    def call(command, timeout)
      write(command)
      @scripted_response = self.class.scripted_response(command)
      result = read(timeout)
      raise result if result.is_a?(RedisClient::Error)
      result
    end

    def call_pipelined(commands, _timeouts, exception: true)
      write_multi(commands)

      in_transaction = false
      commands.map do |command|
        name = command.first.to_s.upcase
        if name == "MULTI"
          in_transaction = true
          "OK"
        elsif name == "EXEC"
          in_transaction = false
          self.class.scripted_response(command)
        elsif in_transaction
          "QUEUED"
        else
          self.class.scripted_response(command)
        end
      end
    end

    def measure_round_trip_delay
      call(["PING"], @read_timeout)
      0
    end
  end

  register_driver :recording do
    RecordingDriver
  end
end
