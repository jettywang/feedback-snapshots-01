# frozen_string_literal: true

module Dry
  module Schema
    module Manifest
      # `#manifest` mixin for schema processors
      #
      # @api private
      module SchemaMethods
        # Build an inventory of the predicates compiled into this schema
        #
        # Nothing is validated or executed: only the compiled rule objects and
        # the bound methods are inspected.
        #
        # @param [String] name label stored in the document
        # @param [String, nil] generated_at timestamp stored in the document
        #
        # @return [Inventory]
        #
        # @api public
        def manifest(name: "schema", generated_at: nil)
          Manifest.build(self, name: name, generated_at: generated_at)
        end

        # Compare this schema's manifest with a previously approved document
        #
        # @param [Hash, String] previous a document produced by {#manifest}
        # @param [String] name label for the current document
        # @param [String, nil] generated_at timestamp stored in the new document
        #
        # @return [ChangeSet]
        #
        # @api public
        def manifest_changes(previous, name: "current", generated_at: nil)
          Manifest.compare(previous, manifest(name: name, generated_at: generated_at))
        end
      end
    end
  end
end

Dry::Schema::Processor.include(Dry::Schema::Manifest::SchemaMethods)
