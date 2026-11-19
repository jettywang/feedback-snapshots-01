# Copyright 2016 Matt Wrock <matt@mattwrock.com>
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

require 'nori'
require_relative 'clixml_parser'
require_relative 'powershell_output_decoder'
require_relative 'message_defragmenter'

module WinRM
  module PSRP
    # Class for reading powershell responses in Receive_Response messages
    class ReceiveResponseReader < WSMV::ReceiveResponseReader
      # Creates a new ReceiveResponseReader
      # @param transport [HttpTransport] The WinRM SOAP transport
      # @param logger [Logger] The logger to log diagnostic messages to
      def initialize(transport, logger)
        super
        @output_decoder = PowershellOutputDecoder.new
      end

      # Reads PSRP messages sent in one or more receive response messages
      # @param wsmv_message [WinRM::WSMV::Base] A wsmv message to send to endpoint
      # @param wait_for_done_state whether to poll for a CommandState of Done
      # @yield [Message] PSRP Message in response
      # @yieldreturn [Array<Message>] All messages in response
      def read_message(wsmv_message, wait_for_done_state = false)
        messages = []
        defragmenter = MessageDefragmenter.new
        read_response(wsmv_message, wait_for_done_state) do |stream|
          message = defragmenter.defragment(stream[:text])
          next unless message

          if block_given?
            yield message
          else
            messages.push(message)
          end
        end
        messages unless block_given?
      end

      # Reads streams and returns decoded output
      # @param wsmv_message [WinRM::WSMV::Base] A wsmv message to send to endpoint
      # @yieldparam [string] standard out response text
      # @yieldparam [string] standard error response text
      # @yieldreturn [WinRM::Output] The command output
      def read_output(wsmv_message)
        with_output do |output|
          read_message(wsmv_message, true) do |message|
            exit_code = find_exit_code(message)
            output.exitcode = exit_code if exit_code
            decoded_text = @output_decoder.decode(message)
            next unless decoded_text

            out = { stream_type(message) => decoded_text }
            output << out
            yield [out[:stdout], out[:stderr]] if block_given?
          end
        end
      end

      # Reads streams and returns structured CLIXML views alongside the decoded
      # text output. The text output is identical to #read_output; each PSRP
      # message that carries CLIXML additionally contributes a structured view
      # preserving object identity, type information and primitive values.
      #
      # @param wsmv_message [WinRM::WSMV::Base] A wsmv message to send to endpoint
      # @param max_depth [Integer] maximum CLIXML nesting depth before truncation
      # @param max_nodes [Integer] maximum CLIXML nodes before truncation
      # @yieldparam [String] standard out response text
      # @yieldparam [String] standard error response text
      # @return [Array<WinRM::Output, Array<Hash>>] text output and CLIXML views
      def read_structured_output(
        wsmv_message,
        max_depth: ClixmlParser::DEFAULT_MAX_DEPTH,
        max_nodes: ClixmlParser::DEFAULT_MAX_NODES
      )
        views = []
        output = with_output do |out|
          read_message(wsmv_message, true) do |message|
            exit_code = find_exit_code(message)
            out.exitcode = exit_code if exit_code

            decoded_text = @output_decoder.decode(message)
            if decoded_text
              stream = { stream_type(message) => decoded_text }
              out << stream
              yield [stream[:stdout], stream[:stderr]] if block_given?
            end

            views << structured_view(message, max_depth, max_nodes) if clixml_message?(message)
          end
        end
        [output, views]
      end

      private

      def clixml_message?(message)
        [
          WinRM::PSRP::Message::MESSAGE_TYPES[:pipeline_output],
          WinRM::PSRP::Message::MESSAGE_TYPES[:error_record],
          WinRM::PSRP::Message::MESSAGE_TYPES[:pipeline_host_call],
          WinRM::PSRP::Message::MESSAGE_TYPES[:runspacepool_host_call],
          WinRM::PSRP::Message::MESSAGE_TYPES[:pipeline_state]
        ].include?(message.type)
      end

      def structured_view(message, max_depth, max_nodes)
        {
          message_type: WinRM::PSRP::Message::MESSAGE_TYPES.key(message.type),
          stream: stream_type(message),
          clixml: @output_decoder.clixml_view(
            message,
            max_depth: max_depth,
            max_nodes: max_nodes
          )
        }
      end

      def stream_type(message)
        type = :stdout
        case message.type
        when WinRM::PSRP::Message::MESSAGE_TYPES[:error_record]
          type = :stderr
        when WinRM::PSRP::Message::MESSAGE_TYPES[:pipeline_host_call]
          type = :stderr if message.data.include?('WriteError')
        when WinRM::PSRP::Message::MESSAGE_TYPES[:pipeline_state]
          type = :stderr if message.parsed_data.pipeline_state == WinRM::PSRP::MessageData::PipelineState::FAILED
        end
        type
      end

      def find_exit_code(message)
        parsed = message.parsed_data
        return nil unless parsed.is_a?(MessageData::PipelineHostCall)

        parsed.method_parameters[:i32].to_i if parsed.method_identifier == 'SetShouldExit'
      end
    end
  end
end
