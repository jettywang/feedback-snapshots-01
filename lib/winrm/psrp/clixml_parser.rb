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

require 'rexml/document' unless defined?(REXML::Document)

module WinRM
  module PSRP
    # Builds a structured, evidence-preserving view of a CLIXML payload.
    #
    # The view is plain Ruby data (Hash and Array, nil, and the leaf values that
    # are explicitly supported). It never instantiates classes named in the
    # remote payload: an unrecognized .NET type is recorded as type evidence
    # rather than mapped onto a Ruby class. Object identity (<Obj RefId>) and
    # type-name references (<TN RefId>) are resolved within a single message
    # only and are never carried across messages.
    #
    # rubocop:disable Metrics/ClassLength
    class ClixmlParser
      # Default bounds applied to a single parsed message.
      DEFAULT_MAX_DEPTH = 32
      DEFAULT_MAX_NODES = 5_000

      # Tags that carry a single, directly coercible primitive value.
      PRIMITIVE_TAGS = %w[
        S C B BYTE DATETIME D SINGLE DECIMAL GUID TIMESPAN URI
        I16 U16 I32 U32 I64 U64
      ].freeze
      private_constant :PRIMITIVE_TAGS

      # Tags whose text is interpreted as an integer.
      INTEGER_TAGS = %w[I16 U16 I32 U32 I64 U64 BYTE].freeze
      private_constant :INTEGER_TAGS

      # Tags whose text is interpreted as a floating point number.
      FLOAT_TAGS = %w[D SINGLE DECIMAL].freeze
      private_constant :FLOAT_TAGS

      # Collection element tags mapped onto an ordered Array.
      LIST_TAGS = %w[LST ARR].freeze
      private_constant :LIST_TAGS

      # Tags whose contents are named key/value members.
      MEMBER_TAGS = %w[MS PROPS].freeze
      private_constant :MEMBER_TAGS

      # Tags that represent dictionary containers.
      DICTIONARY_TAGS = %w[DCT].freeze
      private_constant :DICTIONARY_TAGS

      # Tags that only describe type names and never carry values.
      TYPE_TAGS = %w[TN T].freeze
      private_constant :TYPE_TAGS

      # @param max_depth [Integer] maximum nesting depth before truncation
      # @param max_nodes [Integer] maximum number of nodes before truncation
      def initialize(max_depth: DEFAULT_MAX_DEPTH, max_nodes: DEFAULT_MAX_NODES)
        @max_depth = max_depth
        @max_nodes = max_nodes
      end

      # Parse a CLIXML payload into a structured view.
      #
      # @param raw [String] the raw CLIXML document (a leading BOM is tolerated)
      # @return [Hash] a structured representation of the root element
      # @raise [WinRM::PSRP::ClixmlParseError] if the payload is not valid XML
      #   or has no root element
      def parse(raw)
        reset_scope
        doc =
          begin
            REXML::Document.new(strip_bom(raw.to_s))
          rescue REXML::ParseException => e
            raise WinRM::PSRP::ClixmlParseError, "invalid CLIXML payload: #{e.message}"
          end
        root = doc.root
        raise WinRM::PSRP::ClixmlParseError, 'CLIXML payload has no root element' unless root

        pre_scan(root)
        build_node(root, 0)
      end

      private

      def reset_scope
        # RefId -> built node. Scoped to this message only; never shared.
        @objects = {}
        # RefId -> Array of .NET type name strings, scoped to this message.
        @type_names = {}
        # RefIds currently being expanded, used to detect cycles.
        @active = {}
        @node_count = 0
      end

      def strip_bom(text)
        text.sub(/\A\xEF\xBB\xBF/, '')
      end

      # First pass: index every RefId-bearing object and type-name list so that
      # forward and backward references resolve regardless of document order.
      def pre_scan(element)
        register_element(element)
        child_elements(element).each { |child| pre_scan(child) }
      end

      def child_elements(element)
        element.elements.to_a
      end

      # CLIXML element names are case-insensitive; compare on the upper form.
      def tag(element)
        element.expanded_name.upcase
      end

      def register_element(element)
        ref_id = ref_id_of(element)
        return unless ref_id

        case tag(element)
        when 'TN'
          @type_names[ref_id] ||= type_names_from(element)
        when 'OBJ'
          # A childless <Obj RefId="n"/> is a reference, not a definition, so it
          # must not claim that RefId within this message's scope.
          @objects[ref_id] ||= nil if child_elements(element).any?
        end
      end

      def ref_id_of(element)
        value = element.attribute('RefId')
        return nil if value.nil? || value.value.empty?

        Integer(value.value)
      rescue ArgumentError
        nil
      end

      def type_names_from(element)
        child_elements(element).select { |node| tag(node) == 'T' }
                               .map { |node| node.text.to_s }
      end

      def build_node(element, depth)
        return truncation_node('depth_limit', depth: depth, max_depth: @max_depth) if depth >= @max_depth
        return truncation_node('node_limit', max_nodes: @max_nodes) unless consume_node_budget

        return build_object(element, depth) if tag(element) == 'OBJ'

        build_simple_node(element)
      end

      def build_object(element, depth)
        ref_id = ref_id_of(element)

        # A childless <Obj RefId="n"/> points at an object defined elsewhere.
        return resolve_reference(ref_id) if leaf_reference?(element, ref_id)

        node = new_object_node(element, ref_id)
        @objects[ref_id] = node if ref_id
        @active[ref_id] = true if ref_id
        populate_object(element, depth, node)
        @active.delete(ref_id) if ref_id
        node
      end

      def leaf_reference?(element, ref_id)
        ref_id && child_elements(element).none?
      end

      def new_object_node(element, ref_id)
        node = { kind: 'object', element: element.expanded_name }
        node[:ref_id] = ref_id if ref_id
        node[:type_names] = resolve_type_names(element)
        name = element.attribute('N')&.value
        node[:name] = name if name
        node
      end

      def populate_object(element, depth, node)
        children = value_children(element)
        if children.any? { |child| MEMBER_TAGS.include?(tag(child)) }
          node[:members] = build_members(children, depth + 1)
        elsif children.any? { |child| DICTIONARY_TAGS.include?(tag(child)) }
          node[:entries] = build_dictionary(children, depth + 1)
        elsif children.any? { |child| LIST_TAGS.include?(tag(child)) }
          node[:elements] = build_list(children, depth + 1)
        elsif children.empty?
          node[:value] = element.text.to_s.strip
        else
          node[:members] = build_anonymous_members(children, depth + 1)
        end
      end

      # Elements nested directly under MS/Props, or unwrapped for an Obj whose
      # only wrapper is an MS/Props container.
      def value_children(element)
        child_elements(element).reject { |child| tag(child) == 'TN' }
      end

      def build_members(children, depth)
        wrapper_members = children.select { |child| MEMBER_TAGS.include?(tag(child)) }
        member_elements = wrapper_members.flat_map { |wrapper| child_elements(wrapper) }
        member_elements += children.reject { |child| MEMBER_TAGS.include?(tag(child)) }
        member_elements.each_with_object({}) do |child, members|
          members[member_key(child)] = build_node(child, depth)
        end
      end

      def build_anonymous_members(children, depth)
        children.each_with_object({}) do |child, members|
          members[member_key(child)] = build_node(child, depth)
        end
      end

      def member_key(element)
        element.attribute('N')&.value || element.expanded_name
      end

      def build_list(children, depth)
        list_wrapper = children.find { |child| LIST_TAGS.include?(tag(child)) }
        items = list_wrapper ? child_elements(list_wrapper) : children
        items.reject { |child| tag(child) == 'TN' }
             .map { |child| build_node(child, depth) }
      end

      def build_dictionary(children, depth)
        dict_wrapper = children.find { |child| DICTIONARY_TAGS.include?(tag(child)) }
        entries = dict_wrapper ? child_elements(dict_wrapper) : children
        entries.reject { |child| tag(child) == 'TN' }
               .map { |child| build_entry(child, depth) }
      end

      def build_entry(element, depth)
        entry_children = child_elements(element)
        key_node = entry_children.find { |node| tag(node) == 'K' } ||
                   entry_children.find { |node| node.attribute('N')&.value == 'K' }
        value_node = entry_children.find { |node| tag(node) == 'V' } ||
                     entry_children.find { |node| node.attribute('N')&.value == 'V' }
        {
          key: key_node ? build_node(key_node, depth) : nil,
          value: value_node ? build_node(value_node, depth) : nil
        }
      end

      def build_simple_node(element)
        element_tag = tag(element)
        node = { kind: 'object', element: element.expanded_name }
        name = element.attribute('N')&.value
        node[:name] = name if name

        apply_simple_kind(node, element, element_tag, element.text.to_s)
        node
      end

      def apply_simple_kind(node, element, element_tag, raw_text)
        if element_tag == 'NIL'
          node.merge!(kind: 'null', value: nil)
        elsif TYPE_TAGS.include?(element_tag)
          node.merge!(kind: 'type_reference', type_names: type_names_from(element))
        elsif PRIMITIVE_TAGS.include?(element_tag)
          node.merge!(
            kind: 'primitive',
            value_type: element_tag,
            raw: raw_text,
            value: coerce_primitive(element_tag, raw_text)
          )
        else
          node.merge!(kind: 'unknown', value_type: element_tag, raw: raw_text)
        end
      end

      def coerce_primitive(element_tag, value)
        return value if %w[S C].include?(element_tag)
        return value == 'true' if element_tag == 'B'
        return Integer(value) if INTEGER_TAGS.include?(element_tag) && !value.empty?
        return Float(value) if FLOAT_TAGS.include?(element_tag) && !value.empty?

        value
      end

      def resolve_type_names(element)
        type_node = child_elements(element).find { |child| tag(child) == 'TN' }
        return [] unless type_node

        ref_id = ref_id_of(type_node)
        ref_id ? (@type_names[ref_id] || type_names_from(type_node)) : type_names_from(type_node)
      end

      def resolve_reference(ref_id)
        return { kind: 'unresolved_reference', ref_id: nil } unless ref_id

        if @active[ref_id]
          { kind: 'cycle', ref_id: ref_id }
        elsif @objects.key?(ref_id)
          # The target may be defined later in the document; the pre-scan
          # guarantees its RefId is known even if it has not been built yet.
          { kind: 'reference', ref_id: ref_id }
        else
          { kind: 'unresolved_reference', ref_id: ref_id }
        end
      end

      def truncation_node(reason, metadata)
        { kind: 'truncated', reason: reason }.merge(metadata)
      end

      def consume_node_budget
        return false if @node_count >= @max_nodes

        @node_count += 1
        true
      end
    end
    # rubocop:enable Metrics/ClassLength

    # Raised when a CLIXML payload cannot be parsed into a structured view.
    class ClixmlParseError < StandardError; end
  end
end
