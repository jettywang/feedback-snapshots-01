# frozen_string_literal: true

module Dry
  module Schema
    module Extensions
      module RoleViews
        # Processor-level API for defining and resolving role-specific views
        #
        # @see Dry::Schema::Processor
        #
        # @api public
        module ProcessorMethods
          # Register (and immediately compile) a role view over this schema
          #
          # The view inherits the base schema's rules for the `permitted_keys`,
          # drops every other writable key and relaxes required keys so partial
          # updates validate against the same rules. The base processor itself is
          # left untouched.
          #
          # @example
          #   schema = Dry::Schema.Params do
          #     configure { config.validate_keys = true }
          #     required(:name).filled(:string)
          #     required(:age).filled(:integer)
          #   end
          #
          #   schema.register_role(:member) { |s| s.view(:name, :age) }
          #   schema.for_role(:member)
          #
          # @param [Symbol] role
          # @yieldparam [Dry::Schema::Processor] base the schema being extended
          # @yieldreturn [Dry::Schema::Processor] the role-specific processor
          #
          # @return [Dry::Schema::Processor] the compiled role processor
          #
          # @api public
          def register_role(role, &block)
            role_views[role.to_sym] = block.call(self)
          end

          # Build a single role view without registering it
          #
          # @example
          #   member_schema = schema.view(:name, :age)
          #
          # @param [Array<Symbol>] permitted_keys keys this role is allowed to write
          #
          # @return [Dry::Schema::Processor]
          #
          # @api public
          def view(*permitted_keys, &block)
            RoleView.new(self, permitted_keys, &block).call
          end

          # Resolve a previously registered role view
          #
          # @param [Symbol] role
          #
          # @raise [UnknownRoleError] if the role was never registered
          #
          # @return [Dry::Schema::Processor]
          #
          # @api public
          def for_role(role)
            role_views.fetch(role.to_sym) do
              raise UnknownRoleError.new(role, role_views.keys)
            end
          end

          # Whether a role view has been registered
          #
          # @param [Symbol] role
          #
          # @return [Boolean]
          #
          # @api public
          def role?(role)
            role_views.key?(role.to_sym)
          end

          # The compiled role processors keyed by role name
          #
          # @return [Hash{Symbol => Dry::Schema::Processor}]
          #
          # @api public
          def roles
            role_views.dup
          end

          private

          # @api private
          def role_views
            @role_views ||= {}
          end
        end
      end
    end
  end
end
