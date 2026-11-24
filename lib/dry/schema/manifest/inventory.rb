# frozen_string_literal: true

module Dry
  module Schema
    module Manifest
      # A complete, offline-checkable inventory for one compiled schema
      #
      # @api public
      class Inventory
        # @return [String]
        attr_reader :name

        # @return [String, nil]
        attr_reader :generated_at

        # @return [Array<Entry>]
        attr_reader :entries

        # Build an inventory for a schema
        #
        # @param [Dry::Schema::Processor] schema
        # @param [String] name a stable label for the schema, e.g. "parent" or "child"
        # @param [String, nil] generated_at timestamp recorded in the document
        #
        # @return [Inventory]
        #
        # @api public
        def self.build(schema, name: "schema", generated_at: nil)
          registry = registry_for(schema)
          entries = Walker.new(registry).call(schema)
          new(name: name, generated_at: generated_at, entries: entries, registry: registry)
        end

        # Check a document's recorded digests
        #
        # Accepts JSON text or a parsed document. Pure: the document is replayed
        # as data, no schema or predicate is loaded.
        #
        # @param [String, Hash] document
        #
        # @return [Boolean]
        #
        # @api public
        def self.verify(document)
          data = document.is_a?(::String) ? ::JSON.parse(document) : document
          expected = data.fetch("digests")
          body = data.reject { |key, _| key == "digests" }

          expected.fetch("document") == Canonical.digest(body) &&
            expected.fetch("entries") == Canonical.digest(body.fetch("predicates"))
        rescue ::KeyError, ::JSON::ParserError, ::TypeError
          false
        end

        # @api private
        def self.registry_for(schema)
          dsl = schema.respond_to?(:schema_dsl) ? schema.schema_dsl : nil
          dsl ? dsl.predicates : Dry::Schema.config.predicates
        end

        # @api private
        def initialize(name:, entries:, registry:, generated_at: nil)
          @name = name
          @registry = registry
          @generated_at = generated_at
          @entries = number(sort(entries))
        end

        # @return [Array<Entry>]
        # @api public
        def builtins
          entries.select { |entry| entry.kind == "builtin" }
        end

        # @return [Array<Entry>] entries whose binding is only knowable at runtime
        # @api public
        def runtime_bindings
          entries.select { |entry| entry.kind == "runtime" }
        end

        # @return [Hash<String, String>] digests for replaying the document offline
        # @api public
        def digests
          {
            "entries" => Canonical.digest(entries.map(&:to_h)),
            "document" => Canonical.digest(document_without_digest)
          }
        end

        # Recheck this inventory against a previous manifest document
        #
        # @param [Hash, Inventory] previous a document produced by {#to_h}
        #
        # @return [ChangeSet]
        #
        # @api public
        def changes_from(previous)
          ChangeSet.build(previous: ChangeSet.document(previous), current: self)
        end

        # @param [ChangeSet, Array<Change>] changes
        # @return [String] Markdown suitable for an approval ticket
        # @api public
        def report(changes)
          ChangeSet.coerce(changes).report(current: self)
        end

        # @return [Hash]
        # @api public
        def to_h(include_digests: true)
          document = document_without_digest
          document["digests"] = digests if include_digests
          document
        end

        # @return [String]
        # @api public
        def to_json(...)
          ::JSON.pretty_generate(to_h, ...)
        end

        # @return [String]
        # @api public
        def inspect
          "#<#{self.class} name=#{name.inspect} entries=#{entries.size} " \
            "builtin=#{builtins.size} runtime=#{runtime_bindings.size}>"
        end

        # @return [Dry::Schema::PredicateRegistry]
        # @api private
        attr_reader :registry

        # @api private
        def document_without_digest
          {
            "format" => FORMAT,
            "name" => name,
            "generated_at" => generated_at,
            "predicate_registry" => registry_name,
            "summary" => {
              "predicates" => entries.size,
              "builtin" => builtins.size,
              "runtime" => runtime_bindings.size,
              "evidence_gaps" => runtime_bindings.size
            },
            "evidence_gaps" => evidence_gaps,
            "predicates" => entries.map(&:to_h)
          }
        end

        # @return [Array<Hash>] runtime-bound occurrences and why they cannot be
        #   verified offline
        # @api public
        def evidence_gaps
          runtime_bindings.map do |entry|
            {
              "field" => entry.field_path,
              "logical_rule_path" => entry.logical_rule_path,
              "predicate" => entry.predicate.to_s,
              "args" => entry.args,
              "owner" => entry.binding.owner,
              "registry" => entry.binding.registry_name,
              "source" => entry.binding.source_path && {
                "path" => entry.binding.source_path,
                "line" => entry.binding.source_line
              },
              "evidence_gap" => entry.binding.evidence_gap
            }
          end
        end

        # @api private
        def registry_name
          predicates = registry.predicates
          custom = predicates.respond_to?(:name) && predicates.name
          custom || registry.class.name || registry.class.inspect
        end

        # @api private
        def sort(entries)
          entries.sort_by do |entry|
            [
              entry.field_path,
              entry.logical_rule_path,
              Canonical.dump(entry.args),
              entry.rule_path
            ]
          end
        end

        # Number identical occurrences so a reviewer can name one
        #
        # @api private
        def number(entries)
          counters = ::Hash.new(0)

          entries.map do |entry|
            occurrence = counters[entry.fingerprint]
            counters[entry.fingerprint] += 1

            if occurrence.zero?
              entry
            else
              Entry.new(
                schema_path: entry.schema_path,
                rule_path: entry.rule_path,
                logical_path: entry.logical_path,
                predicate: entry.predicate,
                args: entry.args,
                binding: entry.binding,
                occurrence: occurrence
              )
            end
          end
        end
      end
    end
  end
end
