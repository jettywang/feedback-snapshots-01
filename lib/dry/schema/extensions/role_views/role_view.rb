# frozen_string_literal: true

module Dry
  module Schema
    module Extensions
      module RoleViews
        # Raised when a caller asks for a role that was never registered
        #
        # @api public
        class UnknownRoleError < ::ArgumentError
          # @api private
          def initialize(role, available)
            super(
              "unknown role #{role.inspect}. " \
              "Registered roles: #{available.map(&:inspect).join(", ")}"
            )
          end
        end

        # Raised when a role view permits a key the base schema does not define
        #
        # @api public
        class UnknownKeyError < ::ArgumentError
          # @api private
          def initialize(key, known)
            super(
              "cannot permit #{key.inspect}: it is not defined by the base schema. " \
              "Known keys: #{known.map(&:inspect).join(", ")}"
            )
          end
        end

        # Builds a stackable, role-specific view of a base processor
        #
        # A view keeps the base schema's public validation rules and types for the
        # permitted keys, drops every other key (so writing it fails key
        # validation) and relaxes `required` keys into `optional` ones, which lets
        # the same compiled rules back partial updates. An optional block may add
        # further, role-only rules on top of the inherited ones.
        #
        # @api private
        class RoleView
          # @return [Processor] the base schema the view is derived from
          attr_reader :base

          # @return [Array<Symbol>] writable keys exposed by this view
          attr_reader :permitted_keys

          # @api private
          def initialize(base, permitted_keys, &block)
            @base = base
            @permitted_keys = permitted_keys.map(&:to_sym)
            @block = block
            raise ::ArgumentError, "a role view must permit at least one key" if @permitted_keys.empty?
            assert_known_keys!
          end

          # Compile the view into a standalone processor
          #
          # The returned processor shares the base macro/type objects but never
          # mutates the base schema, so one compiled base can back many roles.
          #
          # @return [Processor]
          #
          # @api private
          def call
            dsl = base.schema_dsl

            child = DSL.new(
              processor_type: base.class,
              config: dsl.config,
              macros: permitted_macros(dsl),
              types: permitted_types(dsl),
              &@block
            )

            child.call
          end

          private

          # @api private
          def assert_known_keys!
            known = base.schema_dsl.macros.map(&:name)
            unknown = permitted_keys - known
            raise UnknownKeyError.new(unknown.first, known) unless unknown.empty?
          end

          # Reuse the base macro objects (and therefore their compiled rules) but
          # relax every required key so a partial payload does not have to carry it.
          #
          # @api private
          def permitted_macros(dsl)
            permitted_keys.map do |name|
              macro = dsl.macros.detect { |candidate| candidate.name.equal?(name) }
              relax(macro, dsl)
            end
          end

          # @api private
          def relax(macro, dsl)
            return macro unless macro.is_a?(Macros::Required)

            Macros::Optional.new(
              name: macro.name,
              compiler: macro.compiler,
              schema_dsl: dsl,
              filter_schema_dsl: dsl.filter_schema_dsl,
              trace: macro.trace
            )
          end

          # @api private
          def permitted_types(dsl)
            dsl.types.select { |name, _| permitted_keys.include?(name) }
          end
        end
      end
    end
  end
end
