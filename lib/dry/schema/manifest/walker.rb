# frozen_string_literal: true

module Dry
  module Schema
    module Manifest
      # Walks a compiled rule tree and records every predicate occurrence
      #
      # The walker never calls a rule, a predicate, or a schema. It only reads
      # object structure and method reflection, which is what makes the result
      # safe to build in a release or approval pipeline.
      #
      # Each occurrence gets two paths:
      #
      # - `rule_path`: the exact structural path in the compiled tree, useful
      #   when matching entries against `rule.to_s`,
      # - `logical_path`: the enclosing operators with associative `and`/`or`
      #   groups collapsed, which is the approval identity. Reordering two
      #   predicates inside the same `and` group does not change it.
      #
      # @api private
      class Walker
        # @api private
        attr_reader :registry

        # @api private
        def initialize(registry)
          @registry = registry
        end

        # @param [Dry::Schema::Processor, Dry::Schema::RuleApplier] schema
        # @return [Array<Entry>]
        # @api private
        def call(schema)
          entries = []

          schema.rules.each do |name, rule|
            walk(rule, field: [], path: name.to_s, context: [], entries: entries)
          end

          entries
        end

        private

        # @api private
        def walk(rule, field:, path:, context:, entries:)
          case rule
          when ::Dry::Logic::Rule::Predicate
            entries << entry_for(rule, field: field, path: path, context: context)
          when ::Dry::Schema::NamespacedRule
            walk(
              rule.rule,
              field: field,
              path: "#{path}.namespace[#{rule.namespace}]",
              context: context,
              entries: entries
            )
          when ::Dry::Schema::RuleApplier
            walk_children(
              rule.rules.values,
              field: field,
              path: "#{path}.rules",
              context: context,
              entries: entries
            )
          else
            walk_node(rule, field: field, path: path, context: context, entries: entries)
          end
        end

        # @api private
        def walk_node(rule, field:, path:, context:, entries:)
          if (wrapper = key_wrapper(rule))
            walk_key_wrapper(wrapper, field: field, path: path, context: context, entries: entries)
          else
            walk_operation(rule, field: field, path: path, context: context, entries: entries)
          end
        end

        # @api private
        def walk_key_wrapper(wrapper, field:, path:, context:, entries:)
          name, kind, guard, body = wrapper

          nested_field = field + [name.to_s]
          nested_path = "#{path}.key[#{name}]"
          nested_context = push(context, "#{kind}(#{name})")

          walk(guard, field: nested_field, path: "#{nested_path}.guard", context: nested_context, entries: entries)
          walk(body, field: nested_field, path: "#{nested_path}.body", context: nested_context, entries: entries)
        end

        # @api private
        def walk_operation(rule, field:, path:, context:, entries:)
          case rule
          when ::Dry::Logic::Operations::Key, ::Dry::Logic::Operations::Attr
            name = rule.path

            walk(
              rule.rule,
              field: field + [name.to_s],
              path: "#{path}.key[#{name}]",
              context: push(context, "key(#{name})"),
              entries: entries
            )
          when ::Dry::Logic::Operations::Set
            walk_children(
              rule.rules,
              field: field,
              path: "#{path}.set",
              context: push(context, "set"),
              entries: entries
            )
          when ::Dry::Logic::Operations::Each
            walk(
              rule.rule,
              field: field + ["[]"],
              path: "#{path}.each",
              context: push(context, "each"),
              entries: entries
            )
          when ::Dry::Logic::Operations::Negation
            walk(rule.rule, field: field, path: "#{path}.not", context: push(context, "not"), entries: entries)
          when ::Dry::Logic::Operations::Check
            keys = rule.options[:keys]
            walk(
              rule.rule,
              field: field,
              path: "#{path}.check",
              context: push(context, "check(#{keys})"),
              entries: entries
            )
          when ::Dry::Logic::Operations::And
            walk_binary(rule, "and", field: field, path: path, context: context, entries: entries)
          when ::Dry::Logic::Operations::Or
            walk_binary(rule, "or", field: field, path: path, context: context, entries: entries)
          when ::Dry::Logic::Operations::Xor
            walk_children(
              rule.rules,
              field: field,
              path: "#{path}.xor",
              context: push(context, "xor"),
              entries: entries
            )
          when ::Dry::Logic::Operations::Implication
            walk(
              rule.left,
              field: field,
              path: "#{path}.then.left",
              context: push(context, "then.left"),
              entries: entries
            )
            walk(
              rule.right,
              field: field,
              path: "#{path}.then.right",
              context: push(context, "then.right"),
              entries: entries
            )
          else
            raise CollectionError.new(
              "Unsupported compiled rule node #{rule.class}; refusing to emit an incomplete manifest",
              schema_path: field.map(&:to_sym),
              rule_path: path
            )
          end
        end

        # @api private
        def walk_binary(rule, operator, field:, path:, context:, entries:)
          child_context = push(context, operator)

          walk(rule.left, field: field, path: "#{path}.left", context: child_context, entries: entries)
          walk(rule.right, field: field, path: "#{path}.right", context: child_context, entries: entries)
        end

        # @api private
        def walk_children(rules, field:, path:, context:, entries:)
          rules.each_with_index do |child, index|
            walk(child, field: field, path: "#{path}[#{index}]", context: context, entries: entries)
          end
        end

        # Collapse consecutive associative operators, so
        # `And(And(a, b), c)` and `And(And(a, c), b)` share a logical path.
        #
        # @api private
        def push(context, token)
          return context if %w[and or set].include?(token) && context.last == token

          context + [token]
        end

        # Detects `And(key?(:x), key[x](...))` and `Implication(key?(:x), key[x](...))`
        #
        # @api private
        def key_wrapper(rule)
          guard, key =
            case rule
            when ::Dry::Logic::Operations::And
              [rule.left, rule.right]
            when ::Dry::Logic::Operations::Implication
              [rule.left, rule.right]
            else
              return
            end

          kind = rule.is_a?(::Dry::Logic::Operations::Implication) ? "optional" : "required"

          return unless key.is_a?(::Dry::Logic::Operations::Key)
          return unless guard.is_a?(::Dry::Logic::Rule::Predicate)
          return unless guard.predicate.name == :key?

          name = key.path
          return unless guard.args.first == name

          [name, kind, guard, key.rule]
        end

        # @api private
        def entry_for(rule, field:, path:, context:)
          Entry.new(
            schema_path: field.map(&:to_sym),
            rule_path: path,
            logical_path: context,
            predicate: rule.predicate.name,
            args: Values.dump_all(rule.args),
            binding: Binding.new(name: rule.predicate.name, method: rule.predicate, registry: registry)
          )
        end
      end
    end
  end
end
