# frozen_string_literal: true

module Grape
  class Entity
    module Publication
      # Outcome of publishing several objects. Distinguishes a batch-wide
      # termination from a deliberate per-object degradation of optional
      # fields.
      class BatchResult
        attr_reader :members, :events, :policy

        def initialize(members:, events:, policy:, aborted: false)
          @members = members.freeze
          @events = events.freeze
          @policy = policy
          @aborted = aborted
        end

        # True when a mandatory failure terminated the whole batch.
        def aborted?
          @aborted
        end

        # True when members were rejected but the batch continued.
        def partial?
          !aborted? && members.any?(&:rejected?)
        end

        # True when at least one member degraded optional fields but still
        # delivered a result.
        def degraded?
          members.any? { |member| member.deliverable? && member.event_codes.include?(Codes::OPTIONAL_FIELD_DEGRADED) }
        end

        def complete?
          !aborted? && !partial?
        end

        def deliverable?
          !aborted?
        end

        # When the batch aborted, no member content is delivered. Only a member
        # whose own key previously had a stable representation may surface that
        # retained view.
        def representations
          return members.map { |member| member.retained } if aborted?

          members.map(&:review_representation)
        end

        def delivered
          return [] if aborted?

          members.select(&:deliverable?)
        end

        def rejected
          members.reject(&:deliverable?)
        end

        def error_code
          if aborted?
            Codes::BATCH_ABORTED
          elsif partial?
            Codes::BATCH_PARTIAL
          elsif degraded?
            Codes::BATCH_DEGRADED
          else
            Codes::BATCH_COMPLETE
          end
        end

        def event_codes
          events.map(&:code)
        end

        def to_h
          {
            aborted: aborted?,
            partial: partial?,
            degraded: degraded?,
            deliverable: deliverable?,
            members: members.map(&:to_h)
          }
        end

        def inspect
          "#<#{self.class.name} aborted=#{aborted?} partial=#{partial?} members=#{members.size}>"
        end
      end
    end
  end
end
