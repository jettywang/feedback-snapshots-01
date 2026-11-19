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

require 'securerandom' unless defined?(SecureRandom)
require_relative 'base'
require_relative '../psrp/fragment'
require_relative '../psrp/message_fragmenter'
require_relative '../psrp/receive_response_reader'
require_relative '../wsmv/configuration'
require_relative '../wsmv/create_pipeline'
require_relative '../wsmv/send_data'
require_relative '../wsmv/init_runspace_pool'
require_relative '../wsmv/keep_alive'

module WinRM
  module Shells
    # Proxy to a remote PowerShell instance
    class Powershell < Base
      include WinRM::WSMV::SOAP

      class << self
        def close_shell(connection_opts, transport, shell_id)
          msg = WinRM::WSMV::CloseShell.new(
            connection_opts,
            shell_id: shell_id,
            shell_uri: WinRM::WSMV::Header::RESOURCE_URI_POWERSHELL
          )
          transport.send_request(msg.build)
        end
      end

      # Create a new powershell shell
      # @param connection_opts [ConnectionOpts] The WinRM connection options
      # @param transport [HttpTransport] The WinRM SOAP transport
      # @param logger [Logger] The logger to log diagnostic messages to
      def initialize(connection_opts, transport, logger)
        super
        @shell_uri = WinRM::WSMV::Header::RESOURCE_URI_POWERSHELL
      end

      # Runs the specified command
      # @param command [String] The powershell script to run
      # @param block [&block] The optional callback for any realtime output
      # @yield [Message] PSRP Message in response
      # @yieldreturn [Array<Message>] All messages in response
      def send_pipeline_command(command, &block)
        with_command_shell(command) do |shell, cmd|
          response_reader.read_message(command_output_message(shell, cmd), true, &block)
        end
      end

      # Default endpoint MaxEnvelopeSizekb when the configuration query is not
      # available. PowerShell 2.0 speaks protocol 2.1 and defaults to 150 KB;
      # later protocol versions default to 500 KB.
      DEFAULT_MAX_ENVELOPE_SIZE_KB = 150
      LATER_PROTOCOL_MAX_ENVELOPE_SIZE_KB = 500

      # Placeholder ids used to measure envelope overhead. Real shell, command
      # and message ids are UUIDs of exactly this width.
      PLACEHOLDER_ID = '00000000-0000-0000-0000-000000000000'.freeze

      # Calculates the largest PSRP fragment blob whose SOAP envelope still
      # fits in the endpoint's MaxEnvelopeSize.
      #
      # The envelope contains the fragment encoded with strict Base64, so its
      # size grows in groups of four Base64 characters per three fragment
      # bytes. Both the PSRP fragment header and Base64 padding therefore have
      # to be part of the same calculation, rather than subtracted from a
      # plain byte count afterwards.
      def max_fragment_blob_size
        @max_fragment_blob_size ||= begin
          envelope_size = max_envelope_size_bytes
          fragment_blob_size_within(envelope_size)
        end
      end

      protected

      def response_reader
        @response_reader ||= WinRM::PSRP::ReceiveResponseReader.new(transport, logger)
      end

      def send_command(command, _arguments)
        command_id = SecureRandom.uuid.to_s.upcase
        command += "\r\nif (!$?) { if($LASTEXITCODE) { exit $LASTEXITCODE } else { exit 1 } }"
        message = PSRP::MessageFactory.create_pipeline_message(@runspace_id, command_id, command)
        fragmenter.fragment(message) do |fragment|
          envelope = fragment_envelope(fragment, command_id)
          ensure_envelope_fits!(envelope)
          if fragment.start_fragment
            resp_doc = transport.send_request(envelope)
            command_id = REXML::XPath.first(resp_doc, "//*[local-name() = 'CommandId']").text
          else
            transport.send_request(envelope)
          end
        end

        logger.debug("[WinRM] Command created for #{command} with id: #{command_id}")
        command_id
      end

      def open_shell
        @runspace_id = SecureRandom.uuid.to_s.upcase
        runspace_msg = WinRM::WSMV::InitRunspacePool.new(
          connection_opts,
          @runspace_id,
          open_shell_payload(@runspace_id)
        )
        envelope = runspace_msg.build
        ensure_envelope_fits!(envelope)
        resp_doc = transport.send_request(envelope)
        shell_id = REXML::XPath.first(resp_doc, "//*[@Name='ShellId']").text
        wait_for_running(shell_id)
        shell_id
      end

      def out_streams
        %w[stdout]
      end

      private

      def fragment_envelope(fragment, command_id)
        msg = if fragment.start_fragment
                WinRM::WSMV::CreatePipeline.new(connection_opts, shell_id, command_id, fragment)
              else
                WinRM::WSMV::SendData.new(connection_opts, shell_id, command_id, fragment)
              end
        msg.build
      end

      def ensure_envelope_fits!(envelope)
        envelope_size = max_envelope_size_bytes
        return if envelope.bytesize <= envelope_size

        raise WinRM::FragmentSizeError.new(
          "SOAP envelope is #{envelope.bytesize} bytes which exceeds the " \
          "negotiated MaxEnvelopeSize of #{envelope_size} bytes",
          envelope_size: envelope_size,
          actual_size: envelope.bytesize
        )
      end

      # Largest blob whose fragment, once Base64 encoded into a pipeline
      # envelope, still fits the given envelope size.
      #
      # A fragment occupies HEADER_SIZE + blob bytes, which strict Base64
      # expands to 4 characters per completed group of 3 bytes. The header and
      # padding are therefore part of the same group calculation instead of
      # being subtracted after the fact. <rsp:Arguments> and <rsp:Stream> only
      # ever contain Base64, so no XML escaping inflates this section.
      def fragment_blob_size_within(envelope_size)
        overhead = pipeline_envelope_overhead.bytesize
        budget = envelope_size - overhead
        if budget <= 0
          raise WinRM::FragmentSizeError.new(
            "A #{overhead}-byte SOAP envelope cannot fit in the " \
            "negotiated MaxEnvelopeSize of #{envelope_size} bytes",
            envelope_size: envelope_size
          )
        end

        blob_size = largest_blob_for(budget)
        if blob_size < 1
          raise WinRM::FragmentSizeError.new(
            "No fragment fits in the remaining #{budget} bytes of the " \
            "negotiated MaxEnvelopeSize of #{envelope_size} bytes",
            envelope_size: envelope_size
          )
        end

        blob_size
      end

      # Solves for the largest blob n where ceil((HEADER_SIZE + n) / 3) * 4
      # fits the budget, accounting for Base64 group padding.
      def largest_blob_for(budget)
        (budget / 4 * 3) - WinRM::PSRP::Fragment::HEADER_SIZE
      end

      def pipeline_envelope_overhead
        WinRM::WSMV::CreatePipeline.new(connection_opts, PLACEHOLDER_ID, PLACEHOLDER_ID).build
      end

      def max_envelope_size_bytes
        max_envelope_size_kb * 1024
      end

      def max_envelope_size_kb
        @max_envelope_size_kb ||= configured_max_envelope_size_kb || mark_fallback(default_max_envelope_size_kb)
      end

      def configured_max_envelope_size_kb
        config_msg = WinRM::WSMV::Configuration.new(connection_opts)
        resp_doc = transport.send_request(config_msg.build)
        size = REXML::XPath.first(resp_doc, "//*[local-name() = 'MaxEnvelopeSizekb']")
        kb = size && size.text.to_i
        kb if kb && kb > 0
      rescue WinRMWSManFault => e
        # A non administrator user will encounter an access denied error
        # attempting to query winrm configuration. Other faults are real.
        raise unless e.fault_code == '5'

        nil
      rescue WinRMSoapFault
        nil
      end

      def mark_fallback(kb)
        logger.debug('[WinRM] Endpoint did not report MaxEnvelopeSizekb; using the protocol default')
        @fallback_envelope_size = true
        kb
      end

      # Conservative default used until the endpoint tells us its protocol.
      def default_max_envelope_size_kb
        DEFAULT_MAX_ENVELOPE_SIZE_KB
      end

      def open_shell_payload(shell_id)
        [
          WinRM::PSRP::MessageFactory.session_capability_message(shell_id),
          WinRM::PSRP::MessageFactory.init_runspace_pool_message(shell_id)
        ].map do |message|
          fragmenter.fragment(message).bytes
        end.flatten
      end

      def wait_for_running(shell_id)
        state = WinRM::PSRP::MessageData::RunspacepoolState::OPENING
        keepalive_msg = WinRM::WSMV::KeepAlive.new(connection_opts, shell_id)

        # 2 is "openned". if we start issuing commands while in "openning" the runspace
        # seems to hang
        until state == WinRM::PSRP::MessageData::RunspacepoolState::OPENED
          response_reader.read_message(keepalive_msg) do |message|
            logger.debug("[WinRM] polling for pipeline state. message: #{message.inspect}")
            parsed = message.parsed_data
            case parsed
            when WinRM::PSRP::MessageData::RunspacepoolState
              state = parsed.runspace_state
            when WinRM::PSRP::MessageData::SessionCapability
              refresh_fallback_envelope_size(parsed.protocol_version)
            end
          end
        end
      end

      # When the configuration query was rejected, refine the conservative
      # default once the protocol version is known. Any cached budget depends
      # on the envelope size, so it must be discarded rather than reused.
      def refresh_fallback_envelope_size(protocol_version)
        return unless @fallback_envelope_size

        kb = default_protocol_envelope_size_kb(protocol_version)
        return if kb == @max_envelope_size_kb

        @max_envelope_size_kb = kb
        @max_fragment_blob_size = nil
        fragmenter.max_blob_length = max_fragment_blob_size
      end

      # Powershell v2.0 has a protocol version of 2.1
      # which defaults to a 150 MaxEnvelopeSizeKB
      # later versions default to 500
      def default_protocol_envelope_size_kb(protocol_version)
        if protocol_version.to_s > '2.1'
          LATER_PROTOCOL_MAX_ENVELOPE_SIZE_KB
        else
          DEFAULT_MAX_ENVELOPE_SIZE_KB
        end
      end

      def fragmenter
        @fragmenter ||= WinRM::PSRP::MessageFragmenter.new(max_fragment_blob_size)
      end
    end
  end
end
