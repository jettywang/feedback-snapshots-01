# Copyright 2016 Shawn Neal <sneal@sneal.net>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

require_relative 'retryable'
require_relative '../exceptions'
require_relative '../http/transport'
require_relative '../wsmv/cleanup_command'
require_relative '../wsmv/close_shell'
require_relative '../wsmv/command'
require_relative '../wsmv/command_output'
require_relative '../wsmv/receive_response_reader'
require_relative '../wsmv/create_shell'
require_relative '../wsmv/soap'

module WinRM
  module Shells
    # Base class for remote shell
    class Base
      TOO_MANY_COMMANDS = '2150859174'.freeze
      ERROR_OPERATION_ABORTED = '995'.freeze
      SHELL_NOT_FOUND = '2150858843'.freeze

      # Upper bound on the retained cleanup history so a long lived shell does
      # not accumulate one status object per command forever. The statuses for
      # a run are attached to its error before trimming can evict them.
      CLEANUP_HISTORY_LIMIT = 100

      FAULTS_FOR_RESET = [
        '2150858843', # Shell has been closed
        '2147943418', # Error reading registry key
        TOO_MANY_COMMANDS, # Maximum commands per user exceeded
      ].freeze

      include Retryable

      # Create a new Cmd shell
      # @param connection_opts [ConnectionOpts] The WinRM connection options
      # @param transport [HttpTransport] The WinRM SOAP transport
      # @param logger [Logger] The logger to log diagnostic messages to
      # @param shell_opts [Hash] Options targeted for the created shell
      def initialize(connection_opts, transport, logger, shell_opts = {})
        @connection_opts = connection_opts
        @transport = transport
        @logger = logger
        @shell_opts = shell_opts
        @cleanup_statuses = []
        @shell_handle = nil
        @lifecycle_mutex = Mutex.new
      end

      # @return [String] shell id of the currently open shell or nil if closed
      def shell_id
        handle = @lifecycle_mutex.synchronize { @shell_handle }
        handle && handle.id
      end

      # @return [Array<CleanupStatus>] outcomes of every Signal/Delete attempted
      #   by this shell, in the order they were sent
      attr_reader :cleanup_statuses

      # @return [WinRM::Output, nil] output collected by the most recent run,
      #   even when that run failed
      attr_reader :last_output

      # @return [String] uri that SOAP calls use to identify shell type
      attr_reader :shell_uri

      # @return [ConnectionOpts] connection options of the shell
      attr_reader :connection_opts

      # @return [WinRM::HTTP::HttpTransport] transport used to talk with endpoint
      attr_reader :transport

      # @return [Logger] logger used for diagnostic messages
      attr_reader :logger

      # @return [Hash] Options targeted for the created shell
      attr_reader :shell_opts

      # Runs the specified command with optional arguments
      # @param command [String] The command or executable to run
      # @param arguments [Array] The optional command arguments
      # @param block [&block] The optional callback for any realtime output
      # @yieldparam [string] standard out response text
      # @yieldparam [string] standard error response text
      # @yieldreturn [WinRM::Output] The command output
      def run(command, arguments = [], &block)
        with_command_shell(command, arguments) do |shell, cmd|
          response_reader.read_output(command_output_message(shell, cmd), &block)
        end
      end

      # Closes the shell if one is open.
      #
      # The handle is claimed before the Delete request is sent, so an explicit
      # close and the finalizer can never both release the same shell, and a
      # close racing with a reopen can never have the brand new shell deleted
      # using the previous id. The shell is forgotten before the request is
      # made, so a failed Delete does not leave an unreleasable handle behind.
      # Cleanup failures other than the protocol's "already gone" codes are
      # raised as {WinRM::CleanupError}.
      def close
        handle = take_shell_handle
        return unless handle

        release_shell_handle(handle)
      end

      # Ruby 3.1+ introduced a change where finalizers cannot allocate new threads.
      # This can raise a ThreadError when the WinRM shell cleanup tries to run in a Thread
      # during garbage collection. Previously, the gem used Thread.new in finalizers.
      #
      # Our solution preserves original behavior safely:
      # 1. Attempt cleanup in a new thread (same as before) for normal execution.
      # 2. If a ThreadError occurs specifically due to "can't alloc thread",
      #    defer cleanup to an at_exit block to ensure the shell is closed properly
      #    without crashing the program.
      # 3. Any other ThreadError is re-raised to avoid hiding unexpected issues.
      #
      # `install_finalizer` wraps the proc returned by #finalize in a claim-once
      # gate shared with explicit #close, so the finalizer and a manual close
      # never send two Delete requests and a shell that was reopened in between
      # is not touched with the stale id.
      def self.finalize(connection_opts, transport, shell_id)
        proc do
          begin
            # Attempt normal cleanup in a new thread (preserves existing behavior)
            Thread.new { close_shell(connection_opts, transport, shell_id) }
          rescue ThreadError => e
            # Only handle the specific Ruby 3.1+ GC thread allocation restriction
            raise unless e.message.include?("can't alloc thread")

            # Defer cleanup to at_exit when thread allocation is permitted
            at_exit do
              begin
                close_shell(connection_opts, transport, shell_id)
              rescue StandardError => cleanup_error
                # Warn about cleanup failures in deferred context only
                warn "[WinRM] Deferred shell cleanup failed: #{cleanup_error.class}: #{cleanup_error.message}"
              end
            end
          end
        end
      end

      # Wraps #finalize in the one-shot gate for a specific shell generation.
      # Defined at class scope so the closure never captures the shell instance
      # (which would warn "finalizer references object to be finalized").
      def self.install_finalizer(connection_opts, transport, shell_id, handle)
        release = finalize(connection_opts, transport, shell_id)
        proc do
          next unless handle.claim

          release.call
        end
      end

      protected

      def send_command(_command, _arguments)
        raise NotImplementedError
      end

      def response_reader
        raise NotImplementedError
      end

      def open_shell
        raise NotImplementedError
      end

      def out_streams
        raise NotImplementedError
      end

      def command_output_message(shell_id, command_id)
        cmd_out_opts = {
          shell_id: shell_id,
          command_id: command_id,
          shell_uri: shell_uri,
          out_streams: out_streams
        }
        WinRM::WSMV::CommandOutput.new(connection_opts, cmd_out_opts)
      end

      def with_command_shell(command, arguments = [])
        tries ||= 2
        run_statuses = []
        command_id = nil
        command_shell_id = nil

        begin
          open unless shell_id
          # Bind the command to the shell that was actually open when it was
          # sent. A concurrent reopen must not make cleanup terminate the
          # command on a different (newer) shell.
          command_shell_id = shell_id
          command_id = send_command(command, arguments)
          logger.debug("[WinRM] creating command_id: #{command_id} on shell_id #{command_shell_id}")
          result = yield command_shell_id, command_id
          @last_output = result if result.is_a?(WinRM::Output)
          result
        rescue WinRMWSManFault => e
          # Stop the command on the shell that created it before a retry can
          # move to a different shell.
          if command_id
            run_statuses << cleanup_command(command_id, command_shell_id)
            command_id = nil
          end
          raise unless retryable_command_fault?(e) && (tries -= 1) > 0

          reset_on_error(e)
          retry
        ensure
          run_statuses << cleanup_command(command_id, command_shell_id) if command_id && command_shell_id

          # Preserve the original execution error. Cleanup failures are
          # attached to it (and recorded in #cleanup_statuses) instead of
          # replacing it, so callers can still inspect the cause and the
          # output collected before the failure.
          if $!
            FailureDetails.attach($!, output: @last_output, cleanup_statuses: run_statuses)
          elsif (failed = run_statuses.find(&:failed?))
            raise_command_cleanup_error(failed, command_shell_id, command_id)
          end
        end
      end

      private

      # One-shot ownership token for a shell generation. Whichever of the
      # finalizer or an explicit close claims it first is the only one allowed
      # to send Delete for that id.
      class ShellHandle
        attr_reader :id

        def initialize(id)
          @id = id
          @mutex = Mutex.new
          @claimed = false
        end

        def claim
          @mutex.synchronize { claim_once }
        rescue ThreadError
          # Finalizers run in trap context, where Mutex#synchronize is not
          # allowed. The finalizer only runs once the shell is unreachable, so
          # no competing explicit close can be in flight on this instance; the
          # plain flag is sufficient there.
          claim_once
        end

        private

        def claim_once
          return false if @claimed

          @claimed = true
        end
      end

      # A fault may only be retried when it did not originate from the caller's
      # output callback. Retrying a callback failure would run the remote
      # command a second time.
      def retryable_command_fault?(error)
        return false if error.is_a?(WinRM::OutputCallbackError)

        FAULTS_FOR_RESET.include?(error.fault_code)
      end

      def reset_on_error(error)
        if error.fault_code == TOO_MANY_COMMANDS
          begin
            close
          rescue CleanupError => e
            logger.info("[WinRM] shell cleanup during reset failed: #{e.message}")
          end
        else
          # The server already reported the shell gone (closed or deleted
          # registry key); forget it without sending another destructive
          # request.
          retire_shell_handle
        end
        logger.debug('[WinRM] opening new shell since the current one was deleted')
      end

      def cleanup_command(command_id, command_shell_id = shell_id)
        return unless command_shell_id

        logger.debug("[WinRM] cleaning up command_id: #{command_id} on shell_id #{command_shell_id}")
        cleanup_msg = WinRM::WSMV::CleanupCommand.new(
          connection_opts,
          shell_uri: shell_uri,
          shell_id: command_shell_id,
          command_id: command_id
        )
        transport.send_request(cleanup_msg.build)
        record_cleanup_status(
          CleanupStatus.new(action: :signal, shell_id: command_shell_id, command_id: command_id)
        )
      rescue WinRMWSManFault => e
        outcome = [ERROR_OPERATION_ABORTED, SHELL_NOT_FOUND].include?(e.fault_code) ? :ignored : :failed
        record_cleanup_status(
          CleanupStatus.new(
            action: :signal, shell_id: command_shell_id, command_id: command_id,
            error: e, outcome: outcome
          )
        )
      rescue WinRMHTTPTransportError => t
        # Keep the original command error; record the cleanup failure instead
        # of dropping it entirely.
        logger.info("[WinRM] #{t.status_code} returned in cleanup with error: #{t.message}")
        record_cleanup_status(
          CleanupStatus.new(
            action: :signal, shell_id: command_shell_id, command_id: command_id,
            error: t, outcome: :failed
          )
        )
      rescue StandardError => e
        record_cleanup_status(
          CleanupStatus.new(
            action: :signal, shell_id: command_shell_id, command_id: command_id,
            error: e, outcome: :failed
          )
        )
      end

      def raise_command_cleanup_error(status, command_shell_id, command_id)
        error = CleanupError.new(
          "failed to terminate command #{command_id} on shell #{command_shell_id}: " \
          "#{status.error.class}: #{status.error.message}",
          action: :signal,
          shell_id: command_shell_id,
          command_id: command_id,
          original_error: status.error
        )
        raise FailureDetails.attach(error, output: @last_output, cleanup_statuses: [status])
      end

      def record_cleanup_status(status)
        @cleanup_statuses << status
        @cleanup_statuses.shift while @cleanup_statuses.length > CLEANUP_HISTORY_LIMIT
        status
      end

      def open
        close
        new_shell_id = nil
        retryable(connection_opts[:retry_limit], connection_opts[:retry_delay]) do
          logger.debug("[WinRM] opening remote shell on #{connection_opts[:endpoint]}")
          new_shell_id = open_shell
        end
        install_shell_handle(new_shell_id)
        @last_output = nil
        logger.debug("[WinRM] remote shell created with shell_id: #{new_shell_id}")
      end

      def install_shell_handle(new_shell_id)
        handle = ShellHandle.new(new_shell_id)
        @lifecycle_mutex.synchronize { @shell_handle = handle }
        add_finalizer(handle)
      end

      def add_finalizer(handle)
        ObjectSpace.define_finalizer(
          self,
          self.class.install_finalizer(connection_opts, transport, handle.id, handle)
        )
      end

      def remove_finalizer
        ObjectSpace.undefine_finalizer(self)
      end

      # Atomically take ownership of the current shell generation. Returns nil
      # when there is nothing to release or another path already claimed it.
      def take_shell_handle
        @lifecycle_mutex.synchronize do
          handle = @shell_handle
          return nil unless handle

          @shell_handle = nil
          remove_finalizer
          handle.claim ? handle : nil
        end
      end

      # Forget the shell without sending a destructive request (the server
      # already reported it gone). The skipped Delete is still recorded so the
      # cleanup state remains observable next to the primary error.
      def retire_shell_handle
        @lifecycle_mutex.synchronize do
          handle = @shell_handle
          @shell_handle = nil
          remove_finalizer
          return nil unless handle

          handle.claim
          record_cleanup_status(
            CleanupStatus.new(action: :delete, shell_id: handle.id, outcome: :skipped)
          )
          handle
        end
      end

      def release_shell_handle(handle)
        logger.debug("[WinRM] closing shell with shell_id: #{handle.id}")
        self.class.close_shell(connection_opts, transport, handle.id)
        record_cleanup_status(CleanupStatus.new(action: :delete, shell_id: handle.id))
      rescue WinRMWSManFault => e
        if [ERROR_OPERATION_ABORTED, SHELL_NOT_FOUND].include?(e.fault_code)
          record_cleanup_status(
            CleanupStatus.new(action: :delete, shell_id: handle.id, error: e, outcome: :ignored)
          )
        else
          record_cleanup_status(
            CleanupStatus.new(action: :delete, shell_id: handle.id, error: e, outcome: :failed)
          )
          raise_shell_cleanup_error(handle, e)
        end
      rescue StandardError => e
        record_cleanup_status(
          CleanupStatus.new(action: :delete, shell_id: handle.id, error: e, outcome: :failed)
        )
        raise_shell_cleanup_error(handle, e)
      end

      def raise_shell_cleanup_error(handle, original_error)
        raise CleanupError.new(
          "failed to close shell #{handle.id}: #{original_error.class}: #{original_error.message}",
          action: :delete,
          shell_id: handle.id,
          original_error: original_error
        )
      end
    end
  end
end
