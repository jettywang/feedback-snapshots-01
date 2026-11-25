# frozen_string_literal: true

module Grape
  class Entity
    module Provenance
      # The set of claim identifiers that have been approved for publication.
      # A public receipt may only ever reference these ids verbatim; any other
      # reference is replaced by a fixed redaction token so an unapproved
      # identifier can never leak through the public surface.
      class ApprovalRegistry
        REDACTION_TOKEN = :unapproved_claim

        def initialize(approved_ids = [])
          @approved = approved_ids.map(&:to_sym).to_set
        end

        def approve!(id)
          @approved.add(id.to_sym)
          self
        end

        def approved?(id)
          @approved.include?(id.to_sym)
        end

        # Returns the claim id when it is approved, otherwise the redaction
        # token. This is the single chokepoint through which every id rendered
        # into a public receipt must pass.
        def public_reference(id)
          return id if id.is_a?(Symbol) && approved?(id)

          REDACTION_TOKEN
        end

        def approved_ids
          @approved.to_a
        end
      end
    end
  end
end
