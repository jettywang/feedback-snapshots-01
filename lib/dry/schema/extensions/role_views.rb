# frozen_string_literal: true

require "dry/schema/extensions/role_views/role_view"
require "dry/schema/extensions/role_views/processor_methods"

module Dry
  module Schema
    # Role views extension
    #
    # Lets a single, compiled base schema serve several caller roles. Each role
    # reuses the base schema's types and validation rules while restricting the
    # set of writable keys, and views relax required keys so partial updates can
    # be validated against the same rules.
    #
    # @see Dry::Schema::Processor#view
    #
    # @api public
    module Extensions
      # @api private
      module RoleViews
      end
    end

    Processor.prepend(Extensions::RoleViews::ProcessorMethods)
  end
end
