# frozen_string_literal: true

module Grape
  class Entity
    module Disclosure
      # Server supplied visibility rules for a single representation.
      #
      # The resolver receives the represented object, its occurrence and the
      # effective runtime options of the same representation. Returning +nil+
      # means "no rule for this occurrence", so it inherits the scope of its
      # parent at nested positions. +default:+ applies to the root occurrence
      # when no resolver grants a scope there, so nested abstentions cannot
      # upgrade a summarized group.
      #
      # +identifier+ is the only object attribute the receipt may expose. It is
      # never called for field values; it exists so an approved synthetic id can
      # be matched to an allowed identifier.
      class Policy
        attr_reader :default_scope, :levels

        def initialize(default: nil, identifier: nil, levels: nil, &resolver)
          @resolver = resolver
          @default_scope = default
          @identifier = identifier
          @levels = Array(levels).map(&:to_sym).freeze
          freeze
        end

        # Returns whatever the resolver granted for this occurrence, or +nil+
        # when there is no resolver or the resolver abstained. +nil+ means the
        # occurrence inherits its parent's scope; a Context may then fall back
        # to +default_scope+ only at the root.
        def resolve(object, occurrence, options)
          @resolver ? @resolver.call(object, occurrence, options) : nil
        end
        alias scope_for resolve

        def identifier_configured?
          !@identifier.nil?
        end

        def identifier_for(object)
          return unless identifier_configured?

          @identifier.call(object)
        end
      end
    end
  end
end
