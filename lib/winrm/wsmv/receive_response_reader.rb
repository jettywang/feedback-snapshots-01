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

require_relative 'soap'
require_relative 'header'
require_relative 'command_output_decoder'
require_relative '../exceptions'
require_relative '../output'

module WinRM
  module WSMV
    # Class for reading wsmv Receive_Response messages
    class ReceiveResponseReader
      include WinRM::WSMV::SOAP
      include WinRM::WSMV::Header

      COMMAND_STATE_DONE =
        'http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandState/Done'.freeze
      COMMAND_STATE_RUNNING =
        'http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandState/Running'.freeze
      OPERATION_TIMEOUT_FAULT = '2150858793'.freeze

      # Creates a new ReceiveResponseReader
      # @param transport [HttpTransport] The WinRM SOAP transport
      # @param logger [Logger] The logger to log diagnostic messages to
      def initialize(transport, logger)
        @transport = transport
        @logger = logger
        @output_decoder = CommandOutputDecoder.new
      end

      attr_reader :logger

      # Reads streams and returns decoded output
      # @param wsmv_message [WinRM::WSMV::Base] A wsmv message to send to endpoint
      # @yieldparam [string] standard out response text
      # @yieldparam [string] standard error response text
      # @yieldreturn [WinRM::Output] The command output
      def read_output(wsmv_message)
        with_output do |output|
          begin
            final_doc = read_response(wsmv_message, true) do |stream, doc|
              handled_out = handle_stream(stream, output)
              next unless handled_out && block_given?

              deliver_output(handled_out) { |handled| yield handled }
            end
            apply_exit_code(output, final_doc)
            if output.exitcode.nil?
              # A genuine Done state without an ExitCode is the historical OMI
              # behaviour; it is still a reported terminal state, not a guess.
              logger.debug('[WinRM] command reached Done without reporting an exit code')
              output.exitcode = 0
            end
            output
          rescue StandardError => e
            attach_output(e, output)
            raise
          end
        end
      end

      # Reads streams sent in one or more receive response messages
      # @param wsmv_message [WinRM::WSMV::Base] A wsmv message to send to endpoint
      # @param wait_for_done_state whether to poll for a CommandState of Done
      # @yieldparam [Hash] Hash representation of stream with type and text
      # @yieldparam [REXML::Document] Complete SOAP envelope returned to wsmv_message
      # @return [REXML::Document] The last response document received
      def read_response(wsmv_message, wait_for_done_state = false)
        loop do
          resp_doc = receive_document(wsmv_message)
          stream_count = read_streams(resp_doc) do |stream|
            yield stream, resp_doc
          end

          # Streams are delivered before the terminal state is interpreted so
          # the final batch of output is never lost.
          return resp_doc unless wait_for_done_state

          state = command_state(resp_doc)
          return resp_doc if state == :done
          next if state == :running
          next if state == :none && stream_count.positive?

          raise unknown_result(state)
        end
      end

      protected

      def with_output
        output = WinRM::Output.new
        yield output
        output
      end

      private

      def receive_document(wsmv_message)
        logger.debug('[WinRM] Waiting for output...')
        resp_doc = send_get_output_message(wsmv_message.build)
        raise unknown_result(:connection_lost) if resp_doc.nil?

        logger.debug('[WinRM] Processing output')
        resp_doc
      end

      def unknown_result(state, detail = nil)
        reason, message =
          case state
          when :connection_lost
            [:connection_lost,
             'The receive conversation ended before the command reported a terminal state']
          when :missing_command_state, :none
            [:missing_command_state,
             'The endpoint returned a response without a command state or output; ' \
             'the command result is unknown']
          else
            [:unknown_command_state,
             'The endpoint reported an unrecognised command state; the command result is unknown']
          end
        message = "#{message}: #{detail}" if detail
        WinRM::CommandResultUnknown.new(message, reason: reason)
      end

      # Errors that mean the receive conversation ended before a terminal
      # command state was reported. The command may or may not have run, so
      # they must never be reported as a successful (exit code 0) result.
      #
      # Computed at rescue time so it does not depend on HTTPClient having been
      # required before this file.
      def connection_interrupted_errors
        [
          EOFError,
          IOError,
          Errno::ECONNRESET,
          Errno::ECONNABORTED,
          Errno::EPIPE,
          Errno::ETIMEDOUT,
          (HTTPClient::KeepAliveDisconnected if defined?(HTTPClient::KeepAliveDisconnected)),
          (HTTPClient::ReceiveTimeoutError if defined?(HTTPClient::ReceiveTimeoutError)),
          (HTTPClient::ConnectTimeoutError if defined?(HTTPClient::ConnectTimeoutError))
        ].compact
      end

      def deliver_output(handled_out)
        yield handled_out
      rescue StandardError => e
        begin
          e.extend(WinRM::OutputCallbackError) unless e.is_a?(WinRM::OutputCallbackError)
        rescue StandardError
          # A frozen exception cannot be tagged; it is still re-raised below.
        end
        raise
      end

      def attach_output(error, output)
        error.extend(WinRM::PartialOutput) unless error.is_a?(WinRM::PartialOutput)
        error.output = output
      rescue StandardError
        # Some exception objects cannot be extended (for example frozen
        # ones); the original exception still propagates unchanged.
      end

      def handle_stream(stream, output, _resp_doc = nil)
        decoded_text = @output_decoder.decode(stream[:text])
        return unless decoded_text

        out = { stream[:type] => decoded_text }
        output << out
        [out[:stdout], out[:stderr]]
      end

      def apply_exit_code(output, resp_doc)
        done = command_states(resp_doc).find do |state|
          state.attributes['State'] == COMMAND_STATE_DONE
        end
        return unless done

        code = REXML::XPath.first(done, ".//*[local-name() = 'ExitCode']")
        return if code.nil? || code.text.nil? || code.text.strip.empty?
        raise WinRM::CommandResultUnknown.new(
          "The endpoint reported a non-numeric exit code #{code.text.inspect}",
          reason: :invalid_exit_code
        ) unless code.text.strip.match?(/\A-?\d+\z/)

        output.exitcode = code.text.to_i
      end

      def send_get_output_message(message)
        @transport.send_request(message)
      rescue WinRMWSManFault => e
        # If no output is available before the wsman:OperationTimeout expires,
        # the server MUST return a WSManFault with the Code attribute equal to
        # 2150858793. When the client receives this fault, it SHOULD issue
        # another Receive request.
        # http://msdn.microsoft.com/en-us/library/cc251676.aspx
        raise unless e.fault_code == OPERATION_TIMEOUT_FAULT

        logger.debug('[WinRM] retrying receive request after timeout')
        retry
      rescue *connection_interrupted_errors => e
        raise unknown_result(:connection_lost),
              "The receive conversation was interrupted before the command reported a terminal state: " \
              "#{e.class}: #{e.message}"
      end

      def command_states(resp_doc)
        return [] if resp_doc.nil?

        body = REXML::XPath.first(
          resp_doc,
          "/*[local-name() = 'Envelope']/*[local-name() = 'Body']"
        )
        scope = body || resp_doc
        REXML::XPath.match(scope, ".//*[local-name() = 'CommandState']")
      end

      def command_state(resp_doc)
        states = command_states(resp_doc)
        return :none if states.empty?
        return :done if states.any? { |state| state.attributes['State'] == COMMAND_STATE_DONE }
        return :running if states.any? { |state| state.attributes['State'] == COMMAND_STATE_RUNNING }

        :unknown
      end

      def read_streams(response_document)
        body_path = "/*[local-name() = 'Envelope']/*[local-name() = 'Body']"
        path = "#{body_path}/*[local-name() = 'ReceiveResponse']/*[local-name() = 'Stream']"
        count = 0
        REXML::XPath.match(response_document, path).each do |stream|
          next if stream.text.nil? || stream.text.empty?

          count += 1
          yield type: stream.attributes['Name'].to_sym, text: stream.text
        end
        count
      end
    end
  end
end
