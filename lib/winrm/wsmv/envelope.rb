# Copyright 2026 Shawn Neal <sneal@sneal.net>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

require 'rexml/document' unless defined?(REXML::Document)

module WinRM
  module WSMV
    # Namespace and Envelope/Header/Body position aware accessors for the
    # SOAP messages exchanged with a WinRM endpoint.
    #
    # Every accessor pins the nodes it returns to:
    #   * the namespace the WinRM/WS-Management protocol assigns to them, and
    #   * their structural position inside the SOAP Envelope.
    #
    # A node that merely reuses a local-name (ShellId, CommandId, ExitCode,
    # Fault, ...) but lives in another namespace or is buried inside an
    # unrelated/nested payload can therefore never override the real result.
    # Matching is prefix independent: a server may rename its namespace
    # prefixes freely without affecting parsing.
    module Envelope
      NS_SOAP_ENVELOPE = 'http://www.w3.org/2003/05/soap-envelope'.freeze
      NS_ADDRESSING = 'http://schemas.xmlsoap.org/ws/2004/08/addressing'.freeze
      NS_TRANSFER = 'http://schemas.xmlsoap.org/ws/2004/09/transfer'.freeze
      NS_WSMAN_DMTF = 'http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd'.freeze
      NS_WSMAN_MSFT = 'http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd'.freeze
      NS_WIN_SHELL = 'http://schemas.microsoft.com/wbem/wsman/1/windows/shell'.freeze
      NS_WSMAN_FAULT = 'http://schemas.microsoft.com/wbem/wsman/1/wsmanfault'.freeze
      NS_WSMAN_CONFIG = 'http://schemas.microsoft.com/wbem/wsman/1/config'.freeze
      NS_CIM_ERROR = 'http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/MSFT_WmiError'.freeze

      # WinRM/WS-Management namespaces a conforming endpoint may use for the
      # elements the client interprets. Elements outside these namespaces are
      # never treated as protocol results.
      KNOWN_NAMESPACES = [
        NS_SOAP_ENVELOPE,
        NS_ADDRESSING,
        NS_TRANSFER,
        NS_WSMAN_DMTF,
        NS_WSMAN_MSFT,
        NS_WIN_SHELL,
        NS_WSMAN_FAULT,
        NS_WSMAN_CONFIG,
        NS_CIM_ERROR
      ].freeze

      COMMAND_STATE_DONE =
        'http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandState/Done'.freeze

      class << self
        # The single SOAP Envelope element, regardless of its prefix.
        def envelope(doc)
          first(doc, envelope_path)
        end

        # WS-Addressing header value for the given local-name. Only a direct
        # child of Envelope/Header in the addressing namespace qualifies.
        def header_value(doc, local_name)
          node = first(doc, "#{header_path}/*[#{in_ns(local_name, NS_ADDRESSING)}]")
          text(node)
        end

        # RelatesTo value echoed by the server, if present.
        def relates_to(doc)
          header_value(doc, 'RelatesTo')
        end

        # MessageID of an outgoing request, from Envelope/Header in the
        # addressing namespace.
        def request_message_id(message)
          doc = message.is_a?(REXML::Document) ? message : REXML::Document.new(message)
          header_value(doc, 'MessageID')
        rescue REXML::ParseException
          nil
        end

        # Validate that a response belongs to the request that was sent by
        # comparing the response RelatesTo with the request MessageID.
        #
        # Returns the parsed response document unchanged.
        #
        # Boundary for legacy/non-conforming endpoints: when no expected
        # MessageID can be determined or the response carries no RelatesTo,
        # correlation is not enforced unless +strict+ is set. In strict mode a
        # missing or mismatched RelatesTo is always rejected.
        def correlate!(response_doc, expected_message_id, strict: false)
          received = relates_to(response_doc)
          return response_doc if !strict && (expected_message_id.nil? || received.nil?)
          return response_doc if expected_message_id == received

          raise WinRMResponseCorrelationError.new(expected_message_id, received)
        end

        # Direct children of Envelope/Body/Fault in the SOAP envelope
        # namespace. Returns an empty array for non-fault responses or for
        # shadow Fault elements nested inside payloads/other namespaces.
        def fault_children(doc)
          match(doc, "#{fault_path}/*[#{namespace_predicate([NS_SOAP_ENVELOPE])}]")
        end

        # WSManFault element carried by Envelope/Body/Fault/Detail in the
        # WSManFault namespace.
        def wsman_fault(doc)
          path = "#{fault_path}/*[#{local_ns('Detail')}]/" \
                 "*[#{in_ns('WSManFault', NS_WSMAN_FAULT)}]"
          first(doc, path)
        end

        # MSFT_WmiError element carried by Envelope/Body/Fault/Detail in the
        # CIM MSFT_WmiError schema namespace.
        def wmi_error(doc)
          path = "#{fault_path}/*[#{local_ns('Detail')}]/" \
                 "*[#{in_ns('MSFT_WmiError', NS_CIM_ERROR)}]"
          first(doc, path)
        end

        def wmi_error_code(wmi_error_node)
          node = first(wmi_error_node, "*[#{in_ns('error_Code', NS_CIM_ERROR)}]")
          text(node)
        end

        # Code/Subcode/Reason text nodes of the SOAP envelope Fault, scoped to
        # the SOAP envelope namespace and structural Fault position.
        def soap_fault_values(doc)
          {
            code: text(first(doc, fault_value_path('Code'))),
            subcode: text(first(doc, fault_subcode_path)),
            reason: text(first(doc, fault_reason_path))
          }
        end

        # ShellId Selector from the Create response ResourceCreated reference
        # parameters, in a WS-Management namespace.
        def shell_id(doc)
          text(selector(doc, 'ShellId'))
        end

        # CommandId from the Command/CreatePipeline response body, in the
        # Windows shell namespace.
        def command_id(doc)
          path = "#{body_path}/*[#{namespace_predicate([NS_WIN_SHELL])}]/" \
                 "*[#{in_ns('CommandId', NS_WIN_SHELL)}]"
          text(first(doc, path))
        end

        # MaxEnvelopeSizekb from the configuration Get response body, in the
        # WinRM configuration namespace.
        def max_envelope_size_kb(doc)
          path = "#{body_path}/*[#{namespace_predicate([NS_WSMAN_CONFIG])}]/" \
                 "*[#{in_ns('MaxEnvelopeSizekb', NS_WSMAN_CONFIG)}]"
          text(first(doc, path))
        end

        # Stream elements of the shell ReceiveResponse payload only.
        def streams(doc)
          path = "#{body_path}/*[#{in_ns('ReceiveResponse', NS_WIN_SHELL)}]/" \
                 "*[#{in_ns('Stream', NS_WIN_SHELL)}]"
          match(doc, path)
        end

        # ExitCode reported by a Done CommandState in the shell ReceiveResponse.
        def exit_code(doc)
          command_states(doc).map do |state|
            node = first(state, "*[#{in_ns('ExitCode', NS_WIN_SHELL)}]")
            return text(node) if node
          end
          nil
        end

        # Whether the ReceiveResponse reports a CommandState/Done. Only the
        # Done state attribute in the Windows shell namespace is honored.
        def command_done?(doc)
          command_states(doc).any? { |state| state.attributes['State'] == COMMAND_STATE_DONE }
        end

        private

        def command_states(doc)
          path = "#{body_path}/*[#{in_ns('ReceiveResponse', NS_WIN_SHELL)}]/" \
                 "*[#{in_ns('CommandState', NS_WIN_SHELL)}]"
          match(doc, path)
        end

        def selector(doc, name)
          path = "#{body_path}/*[#{in_ns('ResourceCreated', NS_TRANSFER)}]/" \
                 "*[#{in_ns('ReferenceParameters', NS_ADDRESSING)}]/" \
                 "*[#{in_ns('SelectorSet', NS_WSMAN_DMTF, NS_WSMAN_MSFT)}]/" \
                 "*[#{in_ns('Selector', NS_WSMAN_DMTF, NS_WSMAN_MSFT)} " \
                 "and @Name='#{name}']"
          first(doc, path)
        end

        def fault_value_path(local_name)
          "#{fault_path}/*[#{in_ns(local_name, NS_SOAP_ENVELOPE)}]/" \
            "*[#{in_ns('Value', NS_SOAP_ENVELOPE)}]/text()"
        end

        def fault_subcode_path
          "#{fault_path}/*[#{in_ns('Code', NS_SOAP_ENVELOPE)}]/" \
            "*[#{in_ns('Subcode', NS_SOAP_ENVELOPE)}]/" \
            "*[#{in_ns('Value', NS_SOAP_ENVELOPE)}]/text()"
        end

        def fault_reason_path
          "#{fault_path}/*[#{in_ns('Reason', NS_SOAP_ENVELOPE)}]/" \
            "*[#{in_ns('Text', NS_SOAP_ENVELOPE)}]/text()"
        end

        def envelope_path
          "/*[#{local_ns('Envelope')} and #{namespace_predicate([NS_SOAP_ENVELOPE])}]"
        end

        def header_path
          "#{envelope_path}/*[#{local_ns('Header')} and #{namespace_predicate([NS_SOAP_ENVELOPE])}]"
        end

        def body_path
          "#{envelope_path}/*[#{local_ns('Body')} and #{namespace_predicate([NS_SOAP_ENVELOPE])}]"
        end

        def fault_path
          "#{body_path}/*[#{local_ns('Fault')} and #{namespace_predicate([NS_SOAP_ENVELOPE])}]"
        end

        # local-name only predicate. Used together with an explicit namespace
        # predicate or a fully scoped parent path.
        def local_ns(local_name)
          "local-name()='#{local_name}'"
        end

        def in_ns(local_name, *namespaces)
          "#{local_ns(local_name)} and #{namespace_predicate(namespaces)}"
        end

        # Namespace-only predicate, for cases where any local-name in one of
        # the given namespaces is acceptable.
        def namespace_predicate(namespaces)
          "(#{namespaces.map { |ns| "namespace-uri()='#{ns}'" }.join(' or ')})"
        end

        def first(context, path)
          REXML::XPath.first(context, path)
        end

        def match(context, path)
          REXML::XPath.match(context, path)
        end

        def text(node)
          return nil if node.nil?

          value = node.respond_to?(:text) ? node.text : node.to_s
          value = value.to_s.strip
          value.empty? ? nil : value
        end
      end
    end
  end
end
