# frozen_string_literal: true

module Grape
  # Builds the externally-facing view of the params a request declared,
  # together with where every value came from. It is read-only: the handler's
  # params are never mutated and a default's provider is never re-invoked.
  # Provenance is decided by comparing the params as the request sent them
  # against the params the validators handed the route, so a value the default
  # provider produced is recognised from that difference rather than recomputed.
  class DeclaredParamsAudit
    # One declared leaf's record in the provenance map.
    #
    # +source+ is one of:
    # - +:provided+ -- the request carried the key, an explicit nil included
    # - +:default+  -- the request omitted the key and a default supplied it
    # - +:missing+  -- the request omitted the key and no value was applied
    Entry = Struct.new(:source, :input_key, :output_key, :value, keyword_init: true) do
      def provided?
        source == :provided
      end

      def default?
        source == :default
      end

      def missing?
        source == :missing
      end
    end

    # The filtered declared view plus the provenance that explains each leaf.
    Audit = Struct.new(:view, :provenance, :as_sent, keyword_init: true)

    # @param as_sent [Hash] deep copy of the params taken before validation,
    #   keyed by the names the request used
    # @param as_effective [Hash] the params the route receives after
    #   validation, coercion and defaults, still keyed by the request names
    # @param declared_params [Array] the route's declared-param structure
    # @param renamed_params [Hash] input path => output name for +as:+ params
    # @param route_params [Hash] bracketed input path => details, for the empty
    #   container a declared Hash, Array or Set is answered with when omitted
    # @param evaluate_given [Boolean] drop params whose +given+ condition fails
    # @param stringify [Boolean] build String keys in the view
    def initialize(as_sent:, as_effective:, declared_params:, renamed_params:, route_params: {}, evaluate_given: false, stringify: false)
      @as_sent = as_sent
      @as_effective = as_effective
      @declared_params = declared_params
      @renamed_params = renamed_params
      @route_params = route_params
      @evaluate_given = evaluate_given
      @stringify = stringify
      @provenance = {}
    end

    # @return [Audit] the filtered view and its provenance
    def call
      view = build(
        @as_effective, @as_sent, @declared_params,
        input_path: [], output_path: [], decl_path: []
      )
      Audit.new(view: view || @as_effective.class.new, provenance: @provenance, as_sent: @as_sent)
    end

    private

    # +effective+ and +sent+ are kept in step: both are keyed by the request
    # names at every depth. Only the view and the provenance paths apply the
    # +as:+ renames, so a value is always read under the name it was sent as.
    def build(effective, sent, declared, input_path:, output_path:, decl_path:)
      if effective.is_a?(Array) || sent.is_a?(Array)
        build_array(effective, sent, declared, input_path:, output_path:, decl_path:)
      elsif effective.respond_to?(:key?) || sent.respond_to?(:key?)
        build_hash(effective, sent, declared, input_path:, output_path:, decl_path:)
      else
        effective
      end
    end

    def build_array(effective, sent, declared, input_path:, output_path:, decl_path:)
      elements = effective.is_a?(Array) ? effective : Array(sent)
      elements.each_with_index.map do |effective_element, index|
        sent_element = element_at(sent, index)
        build(
          effective_element,
          sent_element,
          declared,
          input_path: input_path + [index.to_s],
          output_path: output_path + [index.to_s],
          decl_path:
        )
      end
    end

    def build_hash(effective, sent, declared, input_path:, output_path:, decl_path:)
      memo = (effective || sent || {}).class.new
      declared.each do |declared_param_attr|
        next if @evaluate_given && !declared_param_attr.scope.attr_meets_dependency?(effective || sent || {})

        declared_key = declared_param_attr.key
        if declared_key.is_a?(Hash)
          declared_key.each_pair do |parent, children|
            build_nested(memo, effective, sent, parent, children, input_path:, output_path:, decl_path:)
          end
        else
          build_leaf(memo, effective, sent, declared_key, input_path:, output_path:, decl_path:)
        end
      end
      memo
    end

    def build_nested(memo, effective, sent, parent, children, input_path:, output_path:, decl_path:)
      child_input_path = input_path + [parent.to_s]
      child_decl_path = decl_path + [parent.to_s]
      output_name = renamed_name(child_decl_path) || parent
      child_output_path = output_path + [output_name.to_s]

      effective_children = child_of(effective, parent)
      sent_children = child_of(sent, parent)

      memo[key_for(output_name)] =
        if array_scope?(child_decl_path)
          build_array_scope(effective_children, sent_children, children,
                            input_path: child_input_path, output_path: child_output_path, decl_path: child_decl_path)
        else
          build_hash_scope(effective_children, sent_children, children,
                           input_path: child_input_path, output_path: child_output_path, decl_path: child_decl_path)
        end
    end

    # An omitted Array/Set scope has no elements to walk and answers the empty
    # container its type declares; a sent one is mapped element by element.
    def build_array_scope(effective_children, sent_children, children, input_path:, output_path:, decl_path:)
      sent_present = sent_children.is_a?(Array)
      return empty_value_for(route_type(decl_path), decl_path) unless sent_present || effective_children.is_a?(Array)

      build(effective_children, sent_children, children, input_path:, output_path:, decl_path:)
    end

    # An omitted Hash scope is walked as an empty hash so its declared leaves
    # still surface as missing, the way +declared()+ builds them.
    def build_hash_scope(effective_children, sent_children, children, input_path:, output_path:, decl_path:)
      sent_present = sent_children.respond_to?(:key?)
      effective_hash = effective_children.respond_to?(:key?) ? effective_children : @as_effective.class.new
      sent_hash = sent_present ? sent_children : @as_effective.class.new

      value = build(effective_hash, sent_hash, children, input_path:, output_path:, decl_path:)
      sent_present ? value : (empty_container(decl_path, value) || value)
    end

    def array_scope?(decl_path)
      type = route_type(decl_path)
      return false if type.nil?

      type == 'Array' || (type.start_with?('[') && !type.include?(',')) || type.start_with?('#<Set', 'Set')
    end

    def build_leaf(memo, effective, sent, declared_param, input_path:, output_path:, decl_path:)
      leaf_input_path = input_path + [declared_param.to_s]
      leaf_decl_path = decl_path + [declared_param.to_s]
      output_name = renamed_name(leaf_decl_path) || declared_param
      leaf_output_path = output_path + [output_name.to_s]

      provided = key?(sent, declared_param)
      original_value = read(effective, declared_param)
      source = leaf_source(provided, original_value)
      effective_value = provided ? original_value : leaf_empty_value(leaf_decl_path, original_value)

      memo[key_for(output_name)] = effective_value
      record(leaf_output_path, leaf_input_path, effective_value, source)
    end

    # Provenance is decided from the value the validators produced, before the
    # empty container #declared substitutes for an omitted Array or Set: that
    # container is a structural answer, not a default a provider supplied.
    def leaf_source(provided, original_value)
      return :provided if provided
      return :missing if original_value.nil?

      :default
    end

    # An omitted leaf whose type has an empty value (a bare Array or Set) is
    # answered with that empty container, mirroring #declared. A nil value the
    # request sent explicitly is left untouched.
    def leaf_empty_value(decl_path, value)
      return value unless value.nil?

      type = route_type(decl_path)
      return value if type.nil?

      empty_value_for(type, decl_path) || value
    end

    def record(output_path, input_path, value, source)
      @provenance[path_key(output_path)] = Entry.new(
        source:,
        input_key: path_key(input_path),
        output_key: path_key(output_path),
        value:
      )
    end

    def renamed_name(path)
      return if @renamed_params.empty?

      @renamed_params[path]
    end

    # The empty container +declared()+ answers for an omitted Hash scope, or nil
    # when the type has none (a bare Hash is represented by its built leaves).
    def empty_container(decl_path, built)
      type = route_type(decl_path)
      return built if type.nil?

      empty_value_for(type, decl_path) || built
    end

    def route_type(decl_path)
      key = decl_path.first
      key += "[#{decl_path[1..].join('][')}]" if decl_path.size > 1
      @route_params.dig(key, :type)
    end

    def empty_value_for(type, decl_path)
      prefix = "#{path_key(decl_path)}["
      return {} if type == 'Hash' && @route_params.keys.none? { |k| k.start_with?(prefix) }
      return [] if type == 'Array' || (type.start_with?('[') && !type.include?(','))

      Set.new if type.start_with?('#<Set', 'Set')
    end

    def key_for(name)
      @stringify ? name.to_s : name.to_sym
    end

    # A provenance key is the field's whole bracketed path, e.g. +items[0][name]+.
    def path_key(path)
      first = path.first
      return first.to_s if path.size == 1

      "#{first}[#{path[1..].join('][')}]"
    end

    def key?(hash, key)
      hash.respond_to?(:key?) && hash.key?(key)
    end

    def read(hash, key)
      return nil unless hash.respond_to?(:key?)

      hash[key]
    end

    def child_of(hash, key)
      value = read(hash, key)
      value.respond_to?(:key?) || value.is_a?(Array) ? value : nil
    end

    def element_at(array, index)
      return nil unless array.is_a?(Array)

      array[index]
    end
  end
end
