# frozen_string_literal: true

require 'grape_entity/provenance'

module Grape
  class Entity
    module Provenance
      # Minimal entities that exercise every provenance scenario required for
      # an archival investigation. All claim ids used here are the identifiers
      # an approval registry is expected to know about.
      module DemoEntities
        # A call counter shared across the demo so a test can prove that merely
        # re-reading a receipt never executes a formatter again.
        FORMATTER_CALLS = Hash.new(0)

        # Entity A: two same-name nested segments are merged into one object.
        class MergeEntity < Provenance::Entity
          format_with(:upcase) { |value| FORMATTER_CALLS[:upcase] += 1; value.to_s.upcase }

          expose_claim :merge_profile_first, :profile do
            expose_claim :merge_name, :name, format_with: :upcase
          end
          expose_claim :merge_profile_second, :profile do
            expose_claim :merge_kind, :kind
          end

          # An exposure whose claim is deliberately left out of the approval
          # registry, to demonstrate redaction in the public receipt.
          expose_claim :merge_internal_note, :internal_note
        end

        # Entity B: a later plain-value declaration with override: true replaces
        # the whole same-name nested segment.
        class OverrideEntity < Provenance::Entity
          format_with(:bracket) { |value| FORMATTER_CALLS[:bracket] += 1; "[#{value}]" }

          expose_claim :override_profile_nested, :profile do
            expose_claim :override_profile_name, :name
          end
          expose_claim :override_profile_replacement, :profile,
                       override: true, format_with: :bracket
        end

        # Entity C: the replacing declaration from B is made conditional. When
        # the condition fails the replacement never runs; because override
        # removed the nested segment at definition time, the key is absent.
        class ConditionalOverrideEntity < Provenance::Entity
          format_with(:bracket) { |value| FORMATTER_CALLS[:bracket] += 1; "[#{value}]" }

          expose_claim :conditional_profile_nested, :profile do
            expose_claim :conditional_profile_name, :name
          end
          expose_claim :conditional_profile_replacement, :profile,
                       override: true, if: { use_override: true }, format_with: :bracket
        end

        # Entity D: two declarations at different positions produce an exactly
        # equal value. Both are adopted; the receipt groups them rather than
        # hiding one, which is distinct from a condition-only candidate.
        class EqualValueEntity < Provenance::Entity
          expose_claim :equal_primary, :label, proc: ->(_object, _options) { 'same' }
          expose_claim :equal_secondary, :alias_label, as: :label,
                                                 proc: ->(_object, _options) { 'same' }
        end

        def self.approval_registry
          ApprovalRegistry.new(
            %i[
              merge_profile_first
              merge_name
              merge_profile_second
              merge_kind
              override_profile_nested
              override_profile_name
              override_profile_replacement
              conditional_profile_nested
              conditional_profile_name
              conditional_profile_replacement
              equal_primary
              equal_secondary
            ]
          )
        end
      end
    end
  end
end
