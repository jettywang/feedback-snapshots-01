# frozen_string_literal: true

require 'digest'

module Grape
  class Entity
    module Provenance
      # An immutable, already-materialized source receipt. It is assembled once
      # from a Trace and thereafter only read: viewing it never re-enters the
      # entity or executes a formatter again.
      #
      # Two views exist:
      #   * #to_h            - the full internal receipt (real claim ids)
      #   * #public_receipt  - every claim id is routed through the approval
      #                        registry, so only approved identifiers appear
      class Receipt
        def initialize(trace:, ledger:, output:, approval_registry:)
          @data = build(trace, ledger, output)
          @approval_registry = approval_registry
          deep_freeze(@data)
          @public_receipt = deep_freeze(redact(@data))
        end

        # Full receipt with the original claim identifiers (internal use).
        def to_h
          @data
        end

        # Publication-safe projection: the only place claim identifiers are
        # rendered for an external audience. Unapproved ids become the fixed
        # redaction token, so an unapproved identifier is never emitted. It is
        # memoized and frozen, so repeated reads never rebuild or run anything.
        def public_receipt
          @public_receipt
        end

        # Convenience accessor for the set of formatters that actually ran,
        # expressed through the approval registry. Re-reading this never runs
        # anything; it only filters the frozen record.
        def formatter_runs
          @data[:formatter_runs]
        end

        private

        def build(trace, ledger, output)
          adopted = trace.adoptions
          condition_only = trace.condition_checks.reject { |entry| entry[:met] }.map do |entry|
            ledger_record(ledger, entry[:claim_id], entry[:path])
          end

          {
            output: output,
            fields: build_fields(adopted, ledger),
            segment_merges: build_segment_merges(ledger),
            equal_value_groups: build_equal_value_groups(adopted),
            condition_only_candidates: condition_only,
            superseded_claims: ledger.superseded_ids.map do |id|
              record = ledger[id]
              {
                claim_id: id,
                key: record[:key],
                reason: :superseded_by_override,
                superseded_by: superseder_for(ledger, id)
              }
            end,
            formatter_runs: trace.formatter_runs.dup
          }
        end

        # Same-name nested segments that coexist (neither used override) are
        # merged by Grape::Entity into one object. This is a structural fact
        # read from the declaration ledger, so it is documented even though the
        # merged wrapper itself produces no leaf value.
        def build_segment_merges(ledger)
          nesting = ledger.records.select { |record| record[:nesting] && !record[:superseded] }
          nesting.group_by { |record| record[:key] }.each_with_object([]) do |(key, records), memo|
            next unless records.size > 1

            memo << {
              key: key,
              relationship: :nested_segment_merge,
              claim_ids: records.map { |record| record[:id] }
            }
          end
        end

        def build_fields(adoptions, ledger)
          adoptions.map do |adoption|
            {
              path: adoption[:path].dup,
              path_key: path_join(adoption[:path]),
              claim_id: adoption[:claim_id],
              relationship: relationship_for(adoption, ledger),
              kind: adoption[:kind],
              value_fingerprint: fingerprint(adoption[:value]),
              value: adoption[:value]
            }
          end
        end

        # Two declarations in different positions that yield an identical value
        # are surfaced together under one fingerprint. They remain separate,
        # adopted claims (distinct ids) - this grouping never collapses them,
        # it only points out the equality, unlike condition-only candidates.
        def build_equal_value_groups(adoptions)
          scalar = adoptions.reject { |adoption| adoption[:nesting] }
          grouped = scalar.group_by { |adoption| fingerprint(adoption[:value]) }
          grouped.each_with_object([]) do |(digest, entries), memo|
            next unless entries.map { |entry| entry[:claim_id] }.uniq.size > 1

            memo << {
              value_fingerprint: digest,
              value: entries.first[:value],
              claim_ids: entries.map { |entry| entry[:claim_id] }.uniq,
              paths: entries.map { |entry| path_join(entry[:path]) }
            }
          end
        end

        def relationship_for(adoption, ledger)
          record = ledger[adoption[:claim_id]]
          if record && record[:override]
            :override_replacement
          elsif adoption[:nesting]
            :nested_merge
          else
            case adoption[:kind]
            when :formatter then :formatted_transcription
            when :block then :computed_transcription
            else :direct_delegation
            end
          end
        end

        def ledger_record(ledger, claim_id, path)
          record = ledger[claim_id] || {}
          {
            claim_id: claim_id,
            key: record[:key],
            path: path.dup,
            reason: :condition_not_met
          }
        end

        def superseder_for(ledger, superseded_id)
          ledger.records.find do |record|
            record[:overridden_ids].include?(superseded_id)
          end&.dig(:id)
        end

        def fingerprint(value)
          Digest::SHA256.hexdigest(Marshal.dump(value))
        rescue TypeError
          Digest::SHA256.hexdigest(value.object_id.to_s)
        end

        def path_join(path)
          path.map(&:to_s).join('.').to_sym
        end

        def redact(node)
          case node
          when Hash
            node.each_with_object({}) do |(key, value), memo|
              memo[key] = key == :claim_id || key == :claim_ids || key == :superseded_by ?
                redact_identifier(value) : redact(value)
            end
          when Array
            node.map { |element| redact(element) }
          else
            node
          end
        end

        def redact_identifier(value)
          if value.is_a?(Array)
            value.map { |id| @approval_registry.public_reference(id) }
          elsif value.nil?
            nil
          else
            @approval_registry.public_reference(value)
          end
        end

        def deep_freeze(value)
          case value
          when Hash
            value.each { |key, item| deep_freeze(key); deep_freeze(item) }
          when Array
            value.each { |item| deep_freeze(item) }
          end
          value.freeze
        end
      end
    end
  end
end
