# Copyright 2016 Shawn Neal <sneal@sneal.net>
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

require 'rexml/document'
require 'rexml/parsers/baseparser'
require_relative 'exceptions'

module WinRM
  # Bounded parsing for XML that originates from an untrusted WinRM endpoint.
  #
  # Every XML entry point in this library (SOAP responses, CLIXML message
  # data, and diagnostic SOAP logging) funnels through here so one budget
  # governs both the outer message and any inner parse. The budget is
  # deliberately small: real WinRM/CLIXML payloads stay well under it while
  # the classic denial-of-service shapes (entity expansion, deep node
  # nesting, oversized text, malformed namespace declarations) are rejected
  # before they can drive unbounded CPU, memory, or parser stack.
  #
  # The work for one message stays linear in its bounded size. A streaming
  # pass rejects oversize, over-deep, or malformed input cheaply; callers that
  # need an {REXML::Document} then build one with matching per-document
  # entity limits. A message that fails validation is never parsed again while
  # the rejection is logged, and a rejected body is never returned as output.
  #
  # Limits are applied per parse and never mutate REXML's process-wide
  # {REXML::Security} globals, so one connection cannot loosen the bounds for
  # another.
  module SafeXML
    # Maximum byte size of a single XML document. Comfortably above the
    # library's 153,600 byte default MaxEnvelopeSize while still bounded.
    MAX_DOCUMENT_BYTES = 512 * 1024

    # Maximum element nesting depth. Kept far below the ~3,400 level where
    # REXML's recursive XPath traversal overflows the Ruby stack.
    MAX_DEPTH = 256

    # Maximum number of entity expansions allowed within one document.
    MAX_ENTITY_EXPANSIONS = 10_000

    # Maximum number of bytes produced by entity expansion within one
    # document. Bounds the "billion laughs" exponential/quadratic blowup.
    MAX_ENTITY_EXPANSION_BYTES = 64 * 1024

    module_function

    # Parses an untrusted XML string into a bounded {REXML::Document}.
    #
    # @param xml [String, nil] the raw XML bytes
    # @param source [String] short label of the parsing entry point, used in
    #   the error message so a rejection can be traced without re-parsing
    # @return [REXML::Document]
    # @raise [WinRMXMLParseError] if the input is missing, exceeds the size or
    #   nesting budget, expands entities beyond the budget, or is not
    #   well-formed (including malformed namespace declarations)
    def parse(xml, source = 'WinRM XML')
      return REXML::Document.new if xml.nil? || xml.empty?

      validate!(xml, source)
      build_document(xml, source)
    end

    # Validates an untrusted XML string against the budget without returning a
    # tree. Use this in front of a parser that drives REXML's pull parser
    # itself (the Nori-based CLIXML path). The depth and well-formedness
    # checks come from a single streaming pass, and a throwaway bounded
    # document is built to wire and cap custom entities, which the pull
    # parser would otherwise leave unexpanded and therefore uncounted. The
    # bytes are proven safe before the downstream parser touches them, so no
    # untrusted input bypasses the bounds.
    #
    # @param xml [String, nil] the raw XML bytes
    # @param source [String] short label of the parsing entry point
    # @return [String] the validated XML
    # @raise [WinRMXMLParseError] on any budget or well-formedness violation
    def validate!(xml, source = 'WinRM XML')
      bytes = xml.nil? ? 0 : xml.bytesize
      if bytes > MAX_DOCUMENT_BYTES
        raise parse_error(
          source,
          "document of #{bytes} bytes exceeds limit of #{MAX_DOCUMENT_BYTES}"
        )
      end
      return xml if bytes.zero?

      guard_depth(xml, source)
      build_document(xml, source)
      xml
    end

    # A single bounded streaming pass over element nesting. REXML's pull
    # parser surfaces malformed markup and namespace declarations as it goes,
    # so over-deep or malformed input is rejected before any tree build or
    # recursive XPath traversal.
    def guard_depth(xml, source)
      parser = REXML::Parsers::BaseParser.new(xml)
      depth = 0
      loop do
        event = parser.pull
        case event[0]
        when :start_element
          depth += 1
          if depth > MAX_DEPTH
            raise parse_error(source, "element depth exceeded #{MAX_DEPTH}")
          end
        when :end_element
          depth -= 1
        when :end_document
          break
        end
      end
    rescue REXML::ParseException => e
      # REXML::UndefinedNamespaceException is a REXML::ParseException subclass.
      raise parse_error(source, "malformed XML: #{e.message}")
    end

    # Builds a document whose per-instance entity budgets are locked to this
    # module's limits. REXML expands custom entities lazily (on text/attribute
    # access), so touching the document text forces every expansion through
    # the bounded path and turns an over-budget entity graph into a rejection.
    def build_document(xml, source)
      document = REXML::Document.new
      document.entity_expansion_limit = MAX_ENTITY_EXPANSIONS
      document.entity_expansion_text_limit = MAX_ENTITY_EXPANSION_BYTES
      document.send(:build, xml)
      force_entity_expansion(document)
      document
    rescue REXML::ParseException => e
      raise parse_error(source, "malformed XML: #{e.message}")
    rescue RuntimeError => e
      # REXML raises plain RuntimeErrors when an entity expansion budget is
      # hit ("number of entity expansions exceeded" / "entity expansion has
      # grown too large"). Re-raise anything unrelated unchanged.
      raise unless entity_budget_error?(e)

      raise parse_error(source, e.message)
    end

    # Walks every element, text/CDATA leaf, and attribute so lazily-expanded
    # custom entities are evaluated against the document's entity budgets up
    # front. Elements recurse (depth is already bounded); leaves expose their
    # content through +value+, which is the accessor that performs the bounded
    # REXML entity expansion rather than returning raw entity references.
    def force_entity_expansion(node)
      node.attributes.each_value(&:value) if node.is_a?(REXML::Element)
      node.children.each do |child|
        if child.is_a?(REXML::Element)
          force_entity_expansion(child)
        elsif child.respond_to?(:value)
          child.value
        end
      end
    end

    def entity_budget_error?(error)
      error.message.include?('entity expansion')
    end

    def parse_error(source, detail)
      WinRMXMLParseError.new("#{source} rejected by bounded parser: #{detail}")
    end

    private_class_method :guard_depth, :build_document, :force_entity_expansion,
                         :entity_budget_error?, :parse_error
  end
end
