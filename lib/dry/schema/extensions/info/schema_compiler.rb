# frozen_string_literal: true

require "dry/schema/constants"
require "dry/schema/extensions/info/visibility"

module Dry
  module Schema
    # @api private
    module Info
      # @api private
      class SchemaCompiler
        PREDICATE_TO_TYPE = {
          array?: "array",
          bool?: "bool",
          date?: "date",
          date_time?: "date_time",
          decimal?: "float",
          float?: "float",
          hash?: "hash",
          int?: "integer",
          nil?: "nil",
          str?: "string",
          time?: "time"
        }.freeze

        # @api private
        attr_reader :keys

        # @api private
        attr_reader :examples

        # @api private
        attr_reader :path

        # @api private
        attr_reader :undeclared

        # @api private
        def initialize(examples: EMPTY_HASH, path: EMPTY_ARRAY, undeclared: nil)
          @keys = EMPTY_HASH.dup
          @examples = examples.to_h { |key, list| [Visibility.path(key), list] }
          @path = path
          @undeclared = undeclared || @examples.keys.dup
        end

        # @api private
        def to_h
          {keys: keys}
        end

        # @api private
        def call(ast)
          visit(ast)

          return self if undeclared.empty?

          unknown = undeclared.map { _1.join(".") }.join(", ")

          raise ArgumentError, "info examples declared for unknown keys: #{unknown}"
        end

        # @api private
        def visit(node, opts = EMPTY_HASH)
          meth, rest = node
          public_send(:"visit_#{meth}", rest, opts)
        end

        # @api private
        def visit_set(node, opts = EMPTY_HASH)
          target = (key = opts[:key]) ? nested(key) : self

          node.each { |child| target.visit(child, opts) }

          return unless key

          target_info = opts[:member] ? {member: target.to_h} : target.to_h
          type = opts[:member] ? "array" : "hash"

          keys.update(key => {**keys[key], type: type, **target_info})
        end

        # @api private
        def visit_and(node, opts = EMPTY_HASH)
          left, right = node

          visit(left, opts)
          visit(right, opts)
        end

        # @api private
        def visit_implication(node, opts = EMPTY_HASH)
          case node
          in [:not, [:predicate, [:nil?, _]]], el
            visit(el, {**opts, nullable: true})
          else
            node.each do |el|
              visit(el, {**opts, required: false})
            end
          end
        end

        # @api private
        def visit_each(node, opts = EMPTY_HASH)
          visit(node, {**opts, member: true})
        end

        # @api private
        def visit_key(node, opts = EMPTY_HASH)
          name, rest = node
          visit(rest, {**opts, key: name, required: true})
          attach_examples(name)
        end

        # @api private
        def visit_predicate(node, opts = EMPTY_HASH)
          name, rest = node

          key = opts[:key]

          if name.equal?(:key?)
            keys[rest[0][1]] = {
              required: opts.fetch(:required, true)
            }
          else
            type = PREDICATE_TO_TYPE[name]
            nullable = opts.fetch(:nullable, false)
            assign_type(key, type, nullable) if type
            assign_values(key, rest) if name.equal?(:included_in?)
          end
        end

        # Only the built-in `included_in?` predicate exports its arguments as
        # documentation. Custom predicates never contribute values or examples,
        # so their arguments cannot leak into exported docs.
        #
        # @api private
        def assign_values(key, args)
          node = args[0]

          return unless node.is_a?(Array) && node[0].equal?(:list)

          values = node[1]
          keys[key][:values] = values.is_a?(::Range) ? values.to_a : values
        end

        # @api private
        def attach_examples(name)
          key_path = path + [name]
          declared = examples[key_path]

          return unless declared

          undeclared.delete(key_path)
          keys[name][:examples] = declared.map { |example| normalize_example(example) }
        end

        # @api private
        def normalize_example(example)
          if example.is_a?(::Hash)
            {value: example[:value], valid: example.fetch(:valid, true)}
          else
            {value: example, valid: true}
          end
        end

        # @api private
        def nested(key)
          self.class.new(examples: examples, path: path + [key], undeclared: undeclared)
        end

        # @api private
        def assign_type(key, type, nullable)
          if keys[key][:type]
            keys[key][:member] = type
          else
            keys[key][:type] = type
            keys[key][:nullable] = nullable
          end
        end
      end
    end
  end
end
