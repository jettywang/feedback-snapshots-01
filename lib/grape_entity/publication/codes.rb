# frozen_string_literal: true

module Grape
  class Entity
    module Publication
      # Stable public identifiers for publication outcomes. Internal exception
      # messages are never part of these codes.
      module Codes
        PUBLISHED = :published
        FIELD_EXCLUDED = :field_excluded
        OPTIONAL_FIELD_DEGRADED = :optional_field_degraded
        OPTIONAL_FIELD_ABORTED = :optional_field_aborted
        MANDATORY_FIELD_MISSING = :mandatory_field_missing
        OBJECT_MISSING = :object_missing
        RETAINED_REPRESENTATION_USED = :retained_representation_used
        NO_RETAINED_REPRESENTATION = :no_retained_representation

        FORMATTER_FAILURE = :formatter_failure
        EXPOSURE_FAILURE = :exposure_failure

        BATCH_COMPLETE = :batch_complete
        BATCH_DEGRADED = :batch_degraded
        BATCH_PARTIAL = :batch_partial
        BATCH_ABORTED = :batch_aborted
      end
    end
  end
end
