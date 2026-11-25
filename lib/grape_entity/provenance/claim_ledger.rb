# frozen_string_literal: true

module Grape
  class Entity
    module Provenance
      # Ledger of every declared exposure ("claim") that an entity class has
      # registered. It is the archival index an investigator consults: each
      # exposure produced by `expose_claim` is tagged with a stable claim id
      # and the relationship it has to any claim it supersedes.
      class ClaimLedger
        def initialize
          @claims = []
          @by_id = {}
          @auto = 0
        end

        def dup
          copy = ClaimLedger.new
          copied = @claims.each_with_object({}) do |record, memo|
            memo[record[:id]] = deep_dup_record(record)
          end
          copy.instance_variable_set(:@claims, copied.values)
          copy.instance_variable_set(:@by_id, copied)
          copy.instance_variable_set(:@auto, @auto)
          copy
        end

        def register(entity_class:, attribute:, key:, nesting:, override:, kind:,
                     overridden_ids: [], explicit_id: nil)
          id = explicit_id || next_auto_id(entity_class)
          raise ArgumentError, "duplicate claim id #{id.inspect}" if @by_id.key?(id)

          record = {
            id: id,
            entity: entity_class,
            attribute: attribute,
            key: key,
            nesting: nesting,
            override: override,
            kind: kind,
            overridden_ids: overridden_ids.dup
          }
          @claims << record
          @by_id[id] = record
          id
        end

        def [](id)
          @by_id[id]
        end

        def ids
          @by_id.keys
        end

        def records
          @claims.dup
        end

        # Claims that were removed at definition time by a later `override: true`
        # declaration. They never reach the runtime, so they cannot be the source
        # of any field that actually appears.
        def superseded_ids
          @claims.select { |record| record[:superseded] }.map { |record| record[:id] }
        end

        def mark_superseded!(ids)
          ids.each do |id|
            @by_id[id][:superseded] = true if @by_id.key?(id)
          end
        end

        private

        def deep_dup_record(record)
          record.each_with_object({}) do |(key, value), memo|
            memo[key] = value.is_a?(Array) ? value.dup : value
          end
        end

        def next_auto_id(entity_class)
          @auto += 1
          base = entity_class.name || 'AnonymousEntity'
          :"claim-#{base.gsub(/[^a-zA-Z0-9_]+/, '-')}-#{@auto}"
        end
      end
    end
  end
end
