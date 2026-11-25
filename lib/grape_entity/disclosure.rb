# frozen_string_literal: true

require 'grape_entity/disclosure/occurrence'
require 'grape_entity/disclosure/policy'
require 'grape_entity/disclosure/context'
require 'grape_entity/disclosure/receipt'
require 'grape_entity/disclosure/result'

module Grape
  class Entity
    # Optional per-object disclosure scopes and a controlled receipt.
    #
    # A representation only becomes scope-aware when the caller passes a
    # +:disclosure+ runtime option. Without it, every exposure renders exactly
    # as before, even when an exposure declares a +:scope+.
    #
    # Scopes are granted per occurrence, not per object identity. The same
    # object appearing in two groups can thus have different visibility in each
    # group, and the receipt records the effective scope at every output path.
    module Disclosure
      class << self
        # Expands a granted scope using the entity's declared levels.
        #
        # +levels+ is ordered from least to most privileged, e.g.
        # +%i[summary detail]+. Granting +:detail+ therefore also grants
        # +:summary+. Unknown scopes are kept as-is so callers are not forced to
        # declare every label up front.
        def expand_scope(scope, levels)
          granted = Array(scope).compact.map(&:to_sym).uniq
          return granted if granted.empty? || levels.nil? || levels.empty?

          granted.flat_map do |current|
            index = levels.index(current)
            index ? levels[0..index] : [current]
          end.uniq
        end

        # Keys actually present in a rendered value. The receipt later re-reads
        # them from the final payload, so this is only used while rendering.
        def rendered_fields(output)
          output = output.__getobj__ if output.respond_to?(:__getobj__)

          case output
          when Hash
            output.keys
          else
            []
          end
        end

        # Deep-copies the payload into plain Hash/Array structures. Nested
        # exposures normally return OutputBuilder delegators; a disclosure
        # payload is meant to be handed to partners, so a plain structure makes
        # the public output, receipt paths and later serialization agree.
        def normalize_output(output)
          output = output.__getobj__ if output.respond_to?(:__getobj__)

          case output
          when Hash
            output.each_with_object({}) { |(key, value), result| result[key] = normalize_output(value) }
          when Array
            output.map { |value| normalize_output(value) }
          else
            output
          end
        end

        def mode_for(effective_scope, levels)
          return :full if effective_scope.nil?
          return :full if levels.nil? || levels.empty?

          effective_scope.include?(levels.last) ? :full : :summary
        end

        # Builds the per-object options for one entity instance. The policy is
        # consulted once per occurrence; a nil answer inherits the enclosing
        # occurrence's effective scope instead of falling back to a sibling.
        # The configured default only applies to the root occurrence, so a
        # nested abstention cannot silently upgrade a summarized group.
        def options_for(object, options, occurrence, context)
          levels = context.levels
          parent_scope = options[:disclosure_scope]
          granted = context.resolve(object, occurrence, options)
          granted = context.default_scope if granted.nil? && options[:disclosure_root]

          if granted.nil?
            inherited = true
            effective = parent_scope
          else
            inherited = false
            effective = expand_scope(granted, levels)
          end

          options.merge(
            disclosure_context: context,
            disclosure_occurrence: occurrence,
            disclosure_scope: effective,
            disclosure_granted: granted,
            disclosure_inherited: inherited,
            disclosure_mode: mode_for(effective, levels),
            disclosure_rollup: []
          )
        end
      end
    end
  end
end
