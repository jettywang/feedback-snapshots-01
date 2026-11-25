# frozen_string_literal: true

module Grape
  class Entity
    module Disclosure
      # Controlled, read-only record of what one representation disclosed.
      #
      # Entries are appended during the same rendering pass that produces the
      # public payload, so the receipt never re-runs an exposure condition or a
      # formatter. At the end of the representation each entry is matched to the
      # actual payload node at its path; entries whose enclosing exposure was
      # filtered out disappear, and the field list is taken from the payload.
      class Receipt
        Entry = Struct.new(
          :position,
          :path,
          :group,
          :group_path,
          :index,
          :field,
          :entity_class,
          :mode,
          :granted_scope,
          :effective_scope,
          :inherited,
          :policy_applied,
          :identifier,
          :fields,
          :scope_withheld_fields,
          keyword_init: true
        ) do
          def visible?
            mode == :full
          end

          def summary?
            mode == :summary
          end

          def entity_name
            entity_class.respond_to?(:name) && entity_class.name ? entity_class.name : entity_class.to_s
          end

          def to_h
            {
              position: position,
              path: path,
              group: group,
              group_path: group_path,
              index: index,
              field: field,
              entity: entity_name,
              mode: mode,
              granted_scope: granted_scope,
              effective_scope: effective_scope,
              inherited: inherited,
              policy_applied: policy_applied,
              identifier: identifier,
              fields: fields,
              scope_withheld_fields: scope_withheld_fields
            }
          end
        end

        attr_reader :payload

        def initialize
          @entries = []
          @entries_by_path = {}
          @ordered = nil
          @closed = false
          @payload = nil
        end

        # Called once by the outermost representation. Walks the payload in its
        # real insertion/index order and keeps only occurrences that are present
        # there, so positions and field lists match the public output exactly.
        def finalize!(payload)
          @payload = payload
          ordered = []
          walk(payload, []) do |path, value|
            entry = @entries_by_path[path]
            next unless entry

            entry.fields = value.keys.map(&:to_sym).freeze if value.is_a?(Hash)
            ordered << entry
          end

          ordered.each_with_index { |entry, index| entry.position = index + 1 }
          @ordered = ordered.freeze
          @closed = true
          self
        end

        # Appends one occurrence. Called from the rendering pass, never from
        # callers.
        def record(occurrence:, field:, entity_class:, mode:, granted_scope:, effective_scope:,
                   inherited:, policy_applied:, identifier:, fields:, scope_withheld_fields: [])
          raise FrozenError, 'receipt is closed' if @closed

          entry = Entry.new(
            position: nil,
            path: occurrence.path.dup.freeze,
            group: occurrence.group,
            group_path: occurrence.group_path,
            index: occurrence.index,
            field: field,
            entity_class: entity_class,
            mode: mode,
            granted_scope: Array(granted_scope).map(&:to_sym).freeze,
            effective_scope: Array(effective_scope).map(&:to_sym).freeze,
            inherited: inherited,
            policy_applied: policy_applied,
            identifier: identifier,
            fields: Array(fields).map(&:to_sym).freeze,
            scope_withheld_fields: Array(scope_withheld_fields).map(&:to_sym).freeze
          )
          @entries << entry
          @entries_by_path[occurrence.path] ||= entry
          entry
        end

        # Stops accepting writes. Reading a closed receipt is always safe.
        def close!
          @closed = true
          self
        end

        def closed?
          @closed
        end

        # One entry per rendered object occurrence, in the output order of the
        # payload. Falls back to path order for an unfinalized receipt.
        def entries
          @ordered || sorted_by_path
        end

        # Declared fields hidden only because their +:scope+ was not granted at
        # this occurrence. This is a superset of what the payload is missing:
        # fields also blocked by an +:if+/+:unless+ condition are not included.
        def withheld_fields_at(path)
          entry = entry_at(path)
          entry ? entry.scope_withheld_fields : []
        end
        alias occurrences entries

        def entry_at(path)
          entries.find { |entry| entry.path == Array(path) }
        end

        def entries_for_group(group)
          group = group.to_sym
          entries.select { |entry| entry.group == group || entry.group_path.last == group }
        end

        def entries_for_object(identifier)
          return [] if identifier.nil?

          entries.select { |entry| entry.identifier == identifier }
        end

        def identifiers
          entries.map(&:identifier).compact.uniq
        end

        def to_a
          entries.map(&:to_h)
        end

        def count
          entries.length
        end

        def empty?
          entries.empty?
        end

        def to_h
          entries_list = entries
          {
            entries: entries_list.map(&:to_h),
            object_count: entries_list.length,
            visible_count: entries_list.count(&:visible?),
            summarized_count: entries_list.count(&:summary?)
          }
        end

        private

        def walk(value, path, &block)
          value = value.__getobj__ if value.respond_to?(:__getobj__)
          yield(path, value)

          case value
          when Hash
            value.each { |key, child| walk(child, path + [key], &block) }
          when Array
            value.each_with_index { |child, index| walk(child, path + [index], &block) }
          end
        end

        def sorted_by_path
          @entries.sort { |left, right| compare_paths(left.path, right.path) }
                  .each_with_index { |entry, index| entry.position = index + 1 }
        end

        # Output order puts a parent before its children and keeps sibling
        # indexes numeric. Comparing part by part avoids Symbol <=> Integer.
        def compare_paths(left, right)
          left.zip(right).each do |left_part, right_part|
            next if left_part == right_part

            return compare_parts(left_part, right_part)
          end
          left.length <=> right.length
        end

        def compare_parts(left, right)
          if left.is_a?(Integer) && right.is_a?(Integer)
            left <=> right
          else
            left.to_s <=> right.to_s
          end
        end
      end
    end
  end
end
