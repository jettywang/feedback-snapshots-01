# frozen_string_literal: true

module Dry
  module Schema
    module Manifest
      # One approval-relevant difference between two inventories
      #
      # The change records why a reviewer should or should not
      # re-approve a field. `kind` is the machine-readable verdict, `reasons`
      # names the observable facts behind it, and `basis` points at the exact
      # manifest fields a reviewer can recheck offline.
      #
      # Kinds:
      #
      # - `unchanged`: same occurrence, same binding identity.
      # - `proof_order`: same logical group, same binding, only the declaration
      #   order changed. Equivalent order is not a semantic change.
      # - `rebound`: same field, predicate name and arguments, different
      #   binding. Always requires re-approval.
      # - `added` / `removed`: the occurrence did not exist before / no longer
      #   exists. Requires re-approval.
      #
      # @api public
      class Change
        # @return [String]
        attr_reader :kind

        # @return [String]
        attr_reader :field

        # @return [Integer]
        attr_reader :occurrence

        # @return [String]
        attr_reader :predicate

        # @return [String, nil]
        attr_reader :logical_rule_path

        # @return [String, nil]
        attr_reader :previous_rule_path

        # @return [String, nil]
        attr_reader :current_rule_path

        # @return [String, nil]
        attr_reader :previous_stable_id

        # @return [String, nil]
        attr_reader :current_stable_id

        # @return [Hash, nil]
        attr_reader :previous_binding

        # @return [Hash, nil]
        attr_reader :current_binding

        # @return [Array<String>]
        attr_reader :reasons

        # @return [Hash]
        attr_reader :basis

        # @api private
        def initialize(kind:, field:, predicate:, logical_rule_path: nil, occurrence: 0,
          previous_rule_path: nil, current_rule_path: nil,
          previous_stable_id: nil, current_stable_id: nil,
          previous_binding: nil, current_binding: nil, reasons: [], basis: {})
          @kind = kind
          @field = field
          @occurrence = occurrence
          @predicate = predicate
          @logical_rule_path = logical_rule_path
          @previous_rule_path = previous_rule_path
          @current_rule_path = current_rule_path
          @previous_stable_id = previous_stable_id
          @current_stable_id = current_stable_id
          @previous_binding = previous_binding
          @current_binding = current_binding
          @reasons = reasons
          @basis = basis
        end

        # @return [Boolean] whether a security reviewer must re-approve the field
        # @api public
        def approval_required?
          case kind
          when "unchanged", "proof_order"
            current_stable_id.nil?
          else
            true
          end
        end

        # @return [Boolean] True when the compiled code behind the field changed
        # @api public
        def implementation_changed?
          kind == "rebound"
        end

        # @return [Hash]
        # @api public
        def to_h
          {
            "kind" => kind,
            "field" => field,
            "occurrence" => occurrence,
            "predicate" => predicate,
            "logical_rule_path" => logical_rule_path,
            "approval_required" => approval_required?,
            "implementation_changed" => implementation_changed?,
            "previous_stable_id" => previous_stable_id,
            "current_stable_id" => current_stable_id,
            "previous_rule_path" => previous_rule_path,
            "current_rule_path" => current_rule_path,
            "previous_binding" => previous_binding,
            "current_binding" => current_binding,
            "reasons" => reasons,
            "basis" => basis
          }
        end

        # @api public
        def to_json(...)
          ::JSON.generate(to_h, ...)
        end
      end

      # The ordered set of differences between two manifest documents
      #
      # Comparison is pure data: no schema is rebuilt and no predicate runs.
      #
      # @api public
      class ChangeSet
        KINDS = %w[unchanged proof_order rebound added removed].freeze

        # @return [Array<Change>]
        attr_reader :changes

        # @return [String, nil]
        attr_reader :previous_name

        # @return [String, nil]
        attr_reader :current_name

        # Compare two manifest documents
        #
        # @param [Hash, Inventory] previous
        # @param [Hash, Inventory] current
        #
        # @return [ChangeSet]
        #
        # @api public
        def self.build(previous:, current:)
          before = document(previous)
          after = document(current)

          new(
            changes: diff(before, after),
            previous_name: before["name"],
            current_name: after["name"],
            previous_format: before["format"],
            current_format: after["format"],
            current_document: after
          )
        end

        # @api private
        def self.document(value)
          value = ::JSON.parse(value) if value.is_a?(::String)
          value.is_a?(Inventory) ? value.to_h : value
        end

        # @api private
        def self.coerce(value)
          value.is_a?(ChangeSet) ? value : new(changes: value)
        end

        # @api private
        def self.diff(previous, current)
          remaining = previous.fetch("predicates").group_by { |entry| slot(entry) }
          changes = []

          current.fetch("predicates").group_by { |entry| slot(entry) }.each do |key, entries|
            changes.concat(match_slot(entries, remaining.delete(key) || []))
          end

          remaining.each_value do |entries|
            entries.each { |entry| changes << removed_change(entry) }
          end

          changes.sort_by do |change|
            [change.field, change.logical_rule_path.to_s, change.occurrence, change.predicate, change.kind]
          end
        end

        # Match occurrences sharing one slot: the same field, logical path and
        # predicate name.
        #
        # Pairing order matters for a useful report:
        #
        # 1. identical arguments -> unchanged, proof_order, or rebound when the
        #    binding differs,
        # 2. different arguments -> rebound (the rule now validates different
        #    values),
        # 3. anything left -> added or removed.
        #
        # Pairing identical occurrences first means declaring the same predicate
        # twice does not make every occurrence look rebound.
        #
        # @api private
        def self.match_slot(entries, before_entries)
          by_exact = before_entries.group_by { |entry| exact_key(entry) }
          changes = []
          pending = []

          entries.each do |entry|
            before = by_exact[exact_key(entry)]&.shift

            if before
              changes << order_change(entry, before)
            else
              pending << entry
            end
          end

          unmatched = by_exact.values.flatten

          pending.zip(unmatched).each do |entry, before|
            changes << (before ? argument_change(entry, before) : added_change(entry))
          end

          changes.concat(unmatched.drop(pending.size).map { |entry| removed_change(entry) })
          changes
        end

        # @api private
        def self.slot(entry)
          Canonical.digest(
            "field" => entry.fetch("field"),
            "logical_path" => entry.fetch("logical_rule_path").split("/")[0...-1],
            "predicate" => entry.fetch("predicate")
          )
        end

        # @api private
        def self.exact_key(entry)
          Canonical.digest("slot" => slot(entry), "args" => entry.fetch("args"))
        end

        # @api private
        def self.order_change(entry, before)
          return rebound_change(entry, before) unless same_binding?(entry, before)

          if before.fetch("rule_path") == entry.fetch("rule_path")
            unchanged_change(entry, before)
          else
            proof_order_change(entry, before)
          end
        end

        # @api private
        def self.same_binding?(entry, before)
          entry.dig("binding", "signature") == before.dig("binding", "signature")
        end

        # @api private
        def self.added_change(entry)
          Change.new(
            kind: "added",
            field: entry.fetch("field"),
            occurrence: entry.fetch("occurrence", 0),
            predicate: entry.fetch("predicate"),
            logical_rule_path: entry.fetch("logical_rule_path"),
            current_rule_path: entry.fetch("rule_path"),
            current_stable_id: entry.dig("binding", "stable_id"),
            current_binding: entry.fetch("binding"),
            reasons: [
              "No occurrence with this field, logical path, predicate and arguments existed before"
            ],
            basis: {
              "previous" => {"present" => false},
              "current" => binding_basis(entry.fetch("binding"))
            }
          )
        end

        # @api private
        def self.removed_change(entry)
          Change.new(
            kind: "removed",
            field: entry.fetch("field"),
            occurrence: entry.fetch("occurrence", 0),
            predicate: entry.fetch("predicate"),
            logical_rule_path: entry.fetch("logical_rule_path"),
            previous_rule_path: entry.fetch("rule_path"),
            previous_stable_id: entry.dig("binding", "stable_id"),
            previous_binding: entry.fetch("binding"),
            reasons: ["Occurrence is no longer compiled into the current schema"],
            basis: {
              "previous" => binding_basis(entry.fetch("binding")),
              "current" => {"present" => false}
            }
          )
        end

        # @api private
        def self.unchanged_change(entry, before)
          Change.new(
            kind: "unchanged",
            field: entry.fetch("field"),
            occurrence: entry.fetch("occurrence", 0),
            predicate: entry.fetch("predicate"),
            logical_rule_path: entry.fetch("logical_rule_path"),
            previous_rule_path: before.fetch("rule_path"),
            current_rule_path: entry.fetch("rule_path"),
            previous_stable_id: before.dig("binding", "stable_id"),
            current_stable_id: entry.dig("binding", "stable_id"),
            previous_binding: before.fetch("binding"),
            current_binding: entry.fetch("binding"),
            reasons: unchanged_reasons(entry),
            basis: {
              "previous" => binding_basis(before.fetch("binding")),
              "current" => binding_basis(entry.fetch("binding"))
            }
          )
        end

        # @api private
        def self.argument_change(entry, before)
          Change.new(
            kind: "rebound",
            field: entry.fetch("field"),
            occurrence: entry.fetch("occurrence", 0),
            predicate: entry.fetch("predicate"),
            logical_rule_path: entry.fetch("logical_rule_path"),
            previous_rule_path: before.fetch("rule_path"),
            current_rule_path: entry.fetch("rule_path"),
            previous_stable_id: before.dig("binding", "stable_id"),
            current_stable_id: entry.dig("binding", "stable_id"),
            previous_binding: before.fetch("binding"),
            current_binding: entry.fetch("binding"),
            reasons: [
              "Field, logical path and predicate name match",
              "Predicate arguments changed: #{before.fetch("args").inspect} -> #{entry.fetch("args").inspect}",
              "The rule now validates different values"
            ],
            basis: {
              "previous" => binding_basis(before.fetch("binding")).merge("args" => before.fetch("args")),
              "current" => binding_basis(entry.fetch("binding")).merge("args" => entry.fetch("args"))
            }
          )
        end

        # @api private
        def self.proof_order_change(entry, before)
          Change.new(
            kind: "proof_order",
            field: entry.fetch("field"),
            occurrence: entry.fetch("occurrence", 0),
            predicate: entry.fetch("predicate"),
            logical_rule_path: entry.fetch("logical_rule_path"),
            previous_rule_path: before.fetch("rule_path"),
            current_rule_path: entry.fetch("rule_path"),
            previous_stable_id: before.dig("binding", "stable_id"),
            current_stable_id: entry.dig("binding", "stable_id"),
            previous_binding: before.fetch("binding"),
            current_binding: entry.fetch("binding"),
            reasons: [
              "Only the declaration order inside the same logical and/or group changed",
              *unchanged_reasons(entry)
            ],
            basis: {
              "previous" => binding_basis(before.fetch("binding")),
              "current" => binding_basis(entry.fetch("binding"))
            }
          )
        end

        # @api private
        def self.rebound_change(entry, before)
          previous_binding = before.fetch("binding")
          current_binding = entry.fetch("binding")

          Change.new(
            kind: "rebound",
            field: entry.fetch("field"),
            occurrence: entry.fetch("occurrence", 0),
            predicate: entry.fetch("predicate"),
            logical_rule_path: entry.fetch("logical_rule_path"),
            previous_rule_path: before.fetch("rule_path"),
            current_rule_path: entry.fetch("rule_path"),
            previous_stable_id: previous_binding["stable_id"],
            current_stable_id: current_binding["stable_id"],
            previous_binding: previous_binding,
            current_binding: current_binding,
            reasons: rebound_reasons(previous_binding, current_binding),
            basis: {
              "previous" => binding_basis(previous_binding),
              "current" => binding_basis(current_binding)
            }
          )
        end

        # @api private
        def self.unchanged_reasons(entry)
          binding = entry.fetch("binding")

          reasons = ["Field, logical path, predicate name and arguments match"]

          if binding["kind"] == "builtin"
            reasons << "Binding has the same stable id, so the built-in implementation is identical"
          else
            reasons << "Both sides are runtime bindings with the same owner, source and registry, " \
              "but that does not prove behavioural equality offline"
          end

          reasons
        end

        # @api private
        def self.rebound_reasons(previous, current)
          reasons = [
            "Field, logical path, predicate name and arguments are unchanged",
            "The compiled predicate is bound to a different implementation or configuration"
          ]

          if previous["kind"] != current["kind"]
            reasons << "Binding kind changed from #{previous["kind"].inspect} to #{current["kind"].inspect}"
          elsif current["kind"] == "runtime"
            reasons << "At least one side is a runtime-only binding, so behavioural equality " \
              "cannot be established offline"
          end

          reasons.concat(identity_differences(previous, current))

          reasons
        end

        # @api private
        def self.identity_differences(previous, current)
          labels = {
            "owner" => "owning module",
            "source" => "source location",
            "body_sha256" => "implementation digest",
            "signature" => "binding signature"
          }

          labels.filter_map do |field, label|
            next if previous[field] == current[field]

            "#{label} changed: #{previous[field].inspect} -> #{current[field].inspect}"
          end
        end

        # @api private
        def self.binding_basis(binding)
          {
            "kind" => binding["kind"],
            "predicate" => binding["predicate"],
            "args" => binding["args"],
            "owner" => binding["owner"],
            "source" => binding["source"],
            "gem" => binding["gem"],
            "gem_version" => binding["gem_version"],
            "body_sha256" => binding["body_sha256"],
            "registry" => binding["registry"],
            "stable_id" => binding["stable_id"],
            "signature" => binding["signature"]
          }
        end

        # @api private
        def initialize(changes:, previous_name: nil, current_name: nil,
          previous_format: nil, current_format: nil, current_document: nil)
          @changes = changes
          @current_document = current_document
          @previous_name = previous_name
          @current_name = current_name
          @previous_format = previous_format
          @current_format = current_format
        end

        # @return [Array<Change>]
        # @api public
        def approval_required
          changes.select(&:approval_required?)
        end

        # @return [Boolean]
        # @api public
        def approval_required?
          approval_required.any?
        end

        # @return [Boolean]
        # @api public
        def changed?
          changes.any? { |change| change.kind != "unchanged" }
        end

        # @return [Hash]
        # @api public
        def to_h
          {
            "format" => FORMAT,
            "previous" => previous_name,
            "current" => current_name,
            "previous_format" => @previous_format,
            "current_format" => @current_format,
            "approval_required" => approval_required?,
            "approval_required_count" => approval_required.size,
            "summary" => summary,
            "changes" => changes.map(&:to_h)
          }
        end

        # @api public
        def to_json(...)
          ::JSON.pretty_generate(to_h, ...)
        end

        # @return [String]
        # @api public
        def report(current: nil)
          Report.new(self, current: current, current_document: @current_document).to_s
        end

        private

        # @api private
        def summary
          counts = KINDS.to_h { |kind| [kind, changes.count { |change| change.kind == kind }] }
          counts.merge("approval_required" => approval_required.size)
        end
      end
    end
  end
end
