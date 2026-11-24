# frozen_string_literal: true

require "digest"
require "json"

module Dry
  module Schema
    # Offline-verifiable inventory of the predicates compiled into a schema
    #
    # The DSL compiles rules eagerly, but a compiled rule keeps only the
    # predicate *name* and its arguments. The callable that will actually run is
    # resolved from the predicate registry while the rule is built, so two
    # schemas can expose the same field, predicate name, and arguments while
    # executing different code:
    #
    # - a child schema may replace `config.predicates`, binding the same names
    #   to a custom module,
    # - a gem upgrade may move a built-in predicate to a different
    #   implementation without renaming it,
    # - an application may monkey-patch a predicate module at runtime.
    #
    # This module walks the compiled rule objects (never input data) and records,
    # for each predicate occurrence:
    #
    # - the field path and the logical rule path,
    # - the predicate name and encoded arguments,
    # - a stable `stable_id` for built-in `Dry::Logic::Predicates` methods,
    # - an explicit evidence gap for any binding that can only be confirmed at
    #   runtime.
    #
    # Generating or comparing manifests never invokes a predicate or an
    # application callback. Only rule structure and method reflection are read.
    #
    # @example Build manifests for a parent/child pair
    #   Dry::Schema.load_extensions(:manifest)
    #
    #   parent = Dry::Schema.define { required(:age).value(:integer, gt: 18) }
    #   child = Dry::Schema.define(parent: parent) do
    #     required(:age).value(:integer, gt: 18)
    #   end
    #
    #   parent_manifest = parent.manifest(name: "parent")
    #   child_manifest = child.manifest(name: "child")
    #   changes = Dry::Schema::Manifest.compare(parent_manifest.to_h, child_manifest.to_h)
    #
    #   changes.approval_required # => [Change(field: "age", kind: "rebound")]
    #
    # @example Verify a committed document offline
    #   require "dry/schema/manifest"
    #
    #   Dry::Schema::Manifest.verify(File.read("parent.json")) # => true
    #
    # @api public
    module Manifest
      # Version of the manifest document format
      FORMAT = "dry-schema-manifest/v1"

      # The gem that owns the canonical built-in predicate implementation
      BUILTIN_PREDICATE_GEM = "dry-logic"

      # The module that defines the canonical built-in predicate implementation
      BUILTIN_PREDICATE_OWNER = "Dry::Logic::Predicates::Methods"

      # The registry the DSL uses when nothing is configured
      BUILTIN_REGISTRY = "Dry::Logic::Predicates"

      # A predicate occurrence that could not be collected
      #
      # Raised rather than emitting a manifest that silently omits unknown rule
      # nodes, because an incomplete approval list is worse than no list.
      #
      # @api public
      class CollectionError < ::StandardError
        # @return [Array<Symbol>, nil]
        attr_reader :schema_path

        # @return [String, nil]
        attr_reader :rule_path

        # @api private
        def initialize(message, schema_path: nil, rule_path: nil)
          super(message)
          @schema_path = schema_path
          @rule_path = rule_path
        end
      end

      # Build an inventory for a schema
      #
      # @param [Dry::Schema::Processor] schema
      # @param [String] name stable label stored in the document
      # @param [String, nil] generated_at timestamp stored in the document
      #
      # @return [Inventory]
      #
      # @api public
      def self.build(schema, name: "schema", generated_at: nil)
        Inventory.build(schema, name: name, generated_at: generated_at)
      end

      # Recompute a document's digests and report whether it was altered
      #
      # Accepts JSON text or a parsed document. Pure data check: nothing is
      # loaded or executed.
      #
      # @param [String, Hash] document
      #
      # @return [Boolean]
      #
      # @api public
      def self.verify(document)
        Inventory.verify(document)
      end

      # Compare two manifest documents
      #
      # Both sides may be `Inventory` objects or parsed documents, so committed
      # artifacts can be compared without rebuilding a schema.
      #
      # @param [Hash, Inventory] previous
      # @param [Hash, Inventory] current
      #
      # @return [ChangeSet]
      #
      # @api public
      def self.compare(previous, current)
        ChangeSet.build(previous: previous, current: current)
      end

      # A source anchor for a predicate implementation
      #
      # @api private
      module Source
        # @api private
        def self.gem_relative(path)
          return if path.nil?

          expanded = ::File.expand_path(path)

          Gem.loaded_specs.each_value do |spec|
            root = "#{::File.expand_path(spec.full_gem_path)}/"
            return ::File.join(spec.name, expanded.delete_prefix(root)) if expanded.start_with?(root)
          end

          nil
        end

        # Path relative to the working directory, or absolute when outside it
        #
        # @api private
        def self.app_relative(path)
          return if path.nil?

          expanded = ::File.expand_path(path)
          root = "#{::File.expand_path(::Dir.pwd)}/"

          expanded.start_with?(root) ? expanded.delete_prefix(root) : expanded
        end

        # @api private
        def self.gem_for(path)
          return if path.nil?

          expanded = ::File.expand_path(path)

          Gem.loaded_specs.each_value do |spec|
            root = "#{::File.expand_path(spec.full_gem_path)}/"
            return [spec.name, spec.version.to_s] if expanded.start_with?(root)
          end

          nil
        end

        # Extract the exact source text of a method body
        #
        # Uses the instruction sequence's code location, so aliases and single
        # line definitions resolve to the same body. Returns nil when the source
        # is not readable (eval'd code, stripped gems, unsupported Ruby).
        #
        # @api private
        def self.body(method)
          path, = method.source_location
          return if path.nil? || !::File.file?(path)

          location = iseq_location(method)
          return unless location

          lines = ::File.readlines(path, chomp: true)
          first_line, first_column, last_line, last_column = location

          if first_line == last_line
            lines.fetch(first_line - 1)[first_column...last_column]
          else
            text = lines[(first_line - 1)..(last_line - 1)].dup
            text[0] = text[0].byteslice(first_column..) || ""
            text[-1] = text[-1].byteslice(0, last_column) || text[-1]
            text.join("\n")
          end
        rescue ::IndexError, ::TypeError
          nil
        end

        # @api private
        def self.iseq_location(method)
          return unless defined?(::RubyVM::InstructionSequence)

          iseq = ::RubyVM::InstructionSequence.of(method)
          iseq&.to_a&.dig(4, :code_location)
        rescue ::StandardError
          nil
        end
      end
    end
  end
end

require "dry/schema/manifest/values"
require "dry/schema/manifest/binding"
require "dry/schema/manifest/entry"
require "dry/schema/manifest/walker"
require "dry/schema/manifest/inventory"
require "dry/schema/manifest/change"
require "dry/schema/manifest/report"
