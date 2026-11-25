# frozen_string_literal: true

module Grape
  class Entity
    module Publication
      # Outcome of publishing a single object.
      #
      # A rejected result never exposes the candidate hash built during the
      # failed attempt. If a previous stable representation was retained, it is
      # available through #retained and #review_representation.
      class Result
        attr_reader :representation, :events, :errors, :retained, :key

        def initialize(representation: nil, events: [], errors: [], retained: nil, key: nil,
                       deliverable: false, reason: nil)
          @representation = representation
          @events = events.freeze
          @errors = errors.freeze
          @retained = retained
          @key = key
          @deliverable = deliverable
          @reason = reason
        end

        def deliverable?
          @deliverable
        end

        def rejected?
          !deliverable?
        end

        def retained?
          !@retained.nil?
        end

        # The approved representation a reviewer should use. A rejected result
        # falls back to the retained representation, never to a partial hash.
        def review_representation
          deliverable? ? representation : retained
        end

        # Public identifier for the submission decision. When a mandatory gate
        # failed this is :mandatory_field_missing even though the underlying
        # error records the formatter/exposure cause.
        def error_code
          return nil if deliverable?

          @reason || errors.first&.code
        end

        # Publication outcome for this object, including a successful delivery
        # that degraded optional fields.
        def outcome
          return error_code unless deliverable?

          @reason || Codes::PUBLISHED
        end

        # Codes of the underlying field failures, useful for diagnostics while
        # the public decision remains Error#code / #error_code.
        def failure_codes
          errors.map(&:code)
        end

        def error_fields
          errors.map(&:field)
        end

        def mandatory_errors
          errors.select(&:mandatory?)
        end

        def optional_errors
          errors.reject(&:mandatory?)
        end

        # Internal exception objects for operators. Never surfaced in the
        # public representation or in Error#message.
        def internal_reasons
          errors.map(&:internal_reason).compact
        end

        def event_codes
          events.map(&:code)
        end

        def to_h
          {
            deliverable: deliverable?,
            representation: review_representation,
            event_codes: event_codes,
            error_code: error_code,
            failure_codes: failure_codes,
            error_fields: error_fields,
            retained: retained?
          }
        end

        def inspect
          "#<#{self.class.name} deliverable=#{deliverable?} " \
            "error_code=#{error_code.inspect} events=#{event_codes.inspect}>"
        end
      end
    end
  end
end
