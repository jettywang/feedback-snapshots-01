# frozen_string_literal: true

class RedisClient
  module ConnectionMixin
    attr_accessor :retry_attempt
    attr_reader :config

    def initialize(config)
      @pending_reads = 0
      @retry_attempt = nil
      @config = config
      @server_key = nil
    end

    def reconnect
      close
      connect
    end

    def _set_batch_progress(progress) # :nodoc:
      @batch_progress = progress
    end

    def close
      @pending_reads = 0
      nil
    end

    def revalidate
      if @pending_reads > 0 || @server_key != @config.server_key
        close
        false
      else
        connected?
      end
    end

    def call(command, timeout)
      @pending_reads += 1
      write(command)
      result = read(connection_timeout(timeout))
      @pending_reads -= 1
      if result.is_a?(Error)
        result._set_command(command)
        result._set_config(config)
        result._set_retry_attempt(@retry_attempt)
        raise result
      else
        result
      end
    end

    def call_pipelined(commands, timeouts, exception: true)
      first_error = last_error = nil

      size = commands.size
      results = Array.new(commands.size)
      progress = @batch_progress || BatchProgress.new(commands, results: results)
      results = progress.results
      @batch_progress = progress
      @pending_reads += size

      begin
        write_multi(commands)
        progress.write = :complete
      rescue Exception => error
        error._set_batch_progress(progress) if error.is_a?(Error)
        raise
      end

      begin
        size.times do |index|
          timeout = timeouts && timeouts[index]
          result = read(connection_timeout(timeout))
          @pending_reads -= 1

          # A multi/exec command can return an array of results.
          # An error from a multi/exec command is handled in Multi#_coerce!.
          if result.is_a?(Array)
            result.each do |res|
              res._set_config(config) if res.is_a?(Error)
            end
          elsif result.is_a?(Error)
            result._set_command(commands[index])
            result._set_config(config)
            result._set_retry_attempt(@retry_attempt)

            last_error&._set_next_error(result)
            first_error ||= result
            last_error = result
          end

          results[index] = result
          progress.record_result(index, result)
        end
      rescue Exception => error
        error._set_batch_progress(progress) if error.is_a?(Error)
        raise
      end

      if first_error && exception
        first_error._set_batch_progress(progress) if first_error.is_a?(Error)
        raise first_error
      else
        results
      end
    ensure
      @batch_progress = nil
    end

    # Called by drivers immediately before the first byte of a batch may
    # leave the client. Anything that fails before this point can still be
    # retried because no command was sent.
    def batch_write_started!
      @batch_progress.write = :started if @batch_progress
    end

    def connection_timeout(timeout)
      return timeout unless timeout && timeout > 0

      # Can't use the command timeout argument as the connection timeout
      # otherwise it would be very racy. So we add the regular read_timeout on top
      # to account for the network delay.
      timeout + config.read_timeout
    end

    def protocol_error(message)
      error = ProtocolError.with_config(message, config)
      error._set_retry_attempt(@retry_attempt)
      error
    end

    def connection_error(message)
      error = ConnectionError.with_config(message, config)
      error._set_retry_attempt(@retry_attempt)
      error
    end
  end
end
