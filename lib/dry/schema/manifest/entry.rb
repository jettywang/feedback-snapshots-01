# frozen_string_literal: true

module Dry
  module Schema
    module Manifest
      # One predicate occurrence in a compiled schema
      #
      # An occurrence is matched across inventories by field path, logical
      # context, predicate name and encoded arguments. The binding is stored
      # separately: two inventories can agree on the occurrence and disagree on
      # what will execute, which is precisely a rebinding that name-only
      # comparisons miss.
      #
      # @api public
      class Entry
        # @return [Array<Symbol>] e.g. `[:account, :name]`
        attr_reader :schema_path

        # @return [String] structural path in the compiled rule tree
        attr_reader :rule_path

        # @return [Array<String>] canonical enclosing operators
        attr_reader :logical_path

        # @return [Symbol]
        attr_reader :predicate

        # @return [Array<Hash>] encoded arguments
        attr_reader :args

        # @return [Binding]
        attr_reader :binding

        # @return [Integer] zero-based position among identical occurrences
        attr_reader :occurrence

        # @api private
        def initialize(schema_path:, rule_path:, logical_path:, predicate:, args:, binding:, occurrence: 0)
          @schema_path = schema_path
          @rule_path = rule_path
          @logical_path = logical_path
          @predicate = predicate
          @args = args
          @binding = binding
          @occurrence = occurrence
        end

        # @return [String] dot-joined schema path
        # @api public
        def field
          field_path
        end

        # @return [String] e.g. `account.name`, `items[].sku`, `(root)`
        # @api public
        def field_path
          return "(root)" if schema_path.empty?

          schema_path.each_with_index.map { |segment, index|
            segment.to_s == "[]" ? "[]" : (index.zero? ? segment.to_s : ".#{segment}")
          }.join
        end

        # @return [String] logical context including the predicate itself
        # @api public
        def logical_rule_path
          (logical_path + [predicate.to_s]).join("/")
        end

        # @return [String]
        # @api public
        def kind
          binding.kind
        end

        # @return [String, nil] identity of the executable predicate binding
        # @api public
        def stable_id
          binding.stable_id(args: args)
        end

        # Identity of the approved rule occurrence
        #
        # A reviewer approves a field, a predicate usage and the code behind it,
        # not just a predicate name. This id changes when any of those change,
        # including a rebinding that keeps the predicate name.
        #
        # @return [String]
        # @api public
        def approval_id
          "dry-schema-rule/v1:#{Canonical.digest(
            "field" => field_path,
            "occurrence" => occurrence,
            "logical_path" => logical_path,
            "predicate" => predicate.to_s,
            "args" => args,
            "binding" => binding.signature(args: args)
          )}"
        end

        # The slot identifies an occurrence independently of its binding and
        # its position within an n-ary group
        #
        # @return [String]
        # @api public
        def fingerprint
          Canonical.digest(
            "field" => field_path,
            "logical_path" => logical_path,
            "predicate" => predicate.to_s,
            "args" => args
          )
        end

        # @return [Hash]
        # @api public
        def to_h
          {
            "field" => field_path,
            "occurrence" => occurrence,
            "logical_rule_path" => logical_rule_path,
            "rule_path" => rule_path,
            "predicate" => predicate.to_s,
            "args" => args,
            "approval_id" => approval_id,
            "binding" => binding.to_h(args: args)
          }
        end
      end
    end
  end
end
