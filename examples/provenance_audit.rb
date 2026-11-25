# frozen_string_literal: true

# Runnable archival-investigation demo.
#
#   .feedback/bundle-env exec ruby -Ilib examples/provenance_audit.rb
#
# It renders the three minimal provenance entities, prints the final readable
# object, the formatters that actually executed, the per-field source receipt,
# and the publication-safe receipt that references approved claim ids only.
# Re-reading a receipt is shown to execute no formatter a second time.

require 'pp'
require 'grape_entity/provenance/demo_entities'

module Grape
  class Entity
    module Provenance
      module Demo
        ENTITIES = Grape::Entity::Provenance::DemoEntities
        REGISTRY = ENTITIES.approval_registry

        def self.run
          scenarios.each do |title, entity_class, object, options|
            entity = entity_class.new(object, options)
            receipt = entity.provenance_receipt(REGISTRY)
            after_render = ENTITIES::FORMATTER_CALLS.dup
            receipt.public_receipt # an investigator opens the receipt...
            receipt.public_receipt # ...and opens it again
            after_views = ENTITIES::FORMATTER_CALLS.dup

            puts "=" * 72
            puts title
            puts "-" * 72
            pp readable_object: receipt.to_h[:output]
            pp formatters_that_ran: receipt.formatter_runs
            pp field_sources: receipt.to_h[:fields].map { |f|
                 [f[:path_key], f[:claim_id], f[:relationship]]
               }
            pp segment_merges: receipt.to_h[:segment_merges]
            pp equal_value_groups: receipt.to_h[:equal_value_groups]
            pp condition_only: receipt.to_h[:condition_only_candidates]
            pp superseded: receipt.to_h[:superseded_claims]
            puts "formatter calls  render=#{after_render}  after_reviews=#{after_views} " \
                 "(reviews_reran_formatters=#{after_render != after_views})"
            puts
          end

          puts "=" * 72
          puts "Public receipt (approved claim ids only; unapproved -> :unapproved_claim)"
          puts "-" * 72
          receipt = ENTITIES::MergeEntity.new(
            { name: 'ada', kind: 'admin', internal_note: 'secret' }, {}
          ).provenance_receipt(REGISTRY)
          pp receipt.public_receipt
        end

        def self.scenarios
          [
            ['1. same-name nested segments merged',
             ENTITIES::MergeEntity,
             { name: 'ada', kind: 'admin', internal_note: 'secret' }, {}],
            ['2. later plain value overrides whole segment',
             ENTITIES::OverrideEntity,
             { profile: 'p', name: 'n' }, {}],
            ['3a. conditional override disabled (condition fails)',
             ENTITIES::ConditionalOverrideEntity,
             { profile: 'p', name: 'n' }, {}],
            ['3b. conditional override enabled (condition passes)',
             ENTITIES::ConditionalOverrideEntity,
             { profile: 'p', name: 'n' }, { use_override: true }],
            ['4. two declarations, identical value',
             ENTITIES::EqualValueEntity, {}, {}]
          ]
        end
      end
    end
  end
end

Grape::Entity::Provenance::Demo.run
