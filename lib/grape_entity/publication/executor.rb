# frozen_string_literal: true

module Grape
  class Entity
    module Publication
      # Runs formatting and commit as separate phases for one entity.
      #
      # Formatting builds a candidate hash and records field-level failures in a
      # Session. Commit then decides whether the candidate satisfies the
      # publication contract; only an accepted candidate is returned as a
      # representation.
      class Executor
        def initialize(entity)
          @entity = entity
        end

        def publish
          session = Session.new(declaration)
          candidate = format(session)
          commit(session, candidate)
        end

        private

        attr_reader :entity

        def declaration
          entity.class.publication_declaration
        end

        def format(session)
          Publication.with_session(session) do
            value = entity.root_exposure.serializable_value(entity, entity.options)
            value.is_a?(Hash) ? deep_dup(value) : {}
          end
        end

        def deep_dup(value)
          case value
          when Hash
            value.each_with_object({}) { |(k, v), out| out[k] = deep_dup(v) }
          when Array
            value.map { |v| deep_dup(v) }
          else
            value
          end
        end

        def commit(session, candidate)
          mandatory_failures, optional_failures = session.failures.partition(&:mandatory?)
          excluded_mandatory, = session.excluded.partition(&:mandatory?)
          missing_failures = missing_mandatory(mandatory_failures, excluded_mandatory, candidate)

          mandatory_errors = mandatory_failures + excluded_mandatory + missing_failures
          optional_errors = optional_failures

          unless mandatory_errors.empty?
            return reject(mandatory_errors, optional_errors, Codes::MANDATORY_FIELD_MISSING)
          end

          if declaration.optional_policy == :abort && optional_failures.any?
            return reject(optional_errors, [], Codes::OPTIONAL_FIELD_ABORTED)
          end

          accept(candidate, optional_errors)
        end

        def missing_mandatory(mandatory_failures, excluded_mandatory, candidate)
          already_failed = (mandatory_failures + excluded_mandatory).map(&:field)
          declaration.mandatory_fields.reject do |path|
            already_failed.include?(path) || value_present?(candidate, path)
          end.map { |path| FieldFailure.new(path, Codes::MANDATORY_FIELD_MISSING, nil, true) }
        end

        def value_present?(candidate, path)
          cursor = candidate
          path.each do |part|
            return false unless cursor.is_a?(Hash)

            key = cursor.key?(part) ? part : part.to_s
            return false unless cursor.key?(key)

            cursor = cursor[key]
          end
          true
        end

        def accept(candidate, optional_errors)
          events = [Event.new(Codes::PUBLISHED)]
          optional_errors.each do |failure|
            events << Event.new(Codes::OPTIONAL_FIELD_DEGRADED, field: failure.field, mandatory: false)
          end
          retain(candidate)

          Result.new(
            representation: candidate,
            events: events,
            errors: optional_errors.map(&:to_error),
            key: entity.publication_key,
            deliverable: true,
            reason: optional_errors.empty? ? nil : Codes::OPTIONAL_FIELD_DEGRADED
          )
        end

        def reject(errors, optional_errors, reason)
          retained = retained_representation
          reported = errors.map { |failure| [declared_mandatory_path(failure), failure] }
          events = reported.map { |field, failure| Event.new(reason, field: field, mandatory: failure.mandatory?) }
          optional_errors.each do |failure|
            events << Event.new(Codes::OPTIONAL_FIELD_ABORTED, field: failure.field, mandatory: false)
          end
          events << Event.new(Codes::RETAINED_REPRESENTATION_USED) if retained

          public_errors = reported.map do |field, failure|
            Error.new(failure.code, field: field, mandatory: failure.mandatory?, original: failure.original)
          end
          public_errors += optional_errors.map(&:to_error)
          public_errors << Error.new(Codes::NO_RETAINED_REPRESENTATION) unless retained

          Result.new(
            representation: nil,
            events: events,
            errors: public_errors,
            retained: retained,
            key: entity.publication_key,
            deliverable: false,
            reason: reason
          )
        end

        # When a nested child fails inside a mandatory parent, the review
        # event points at the declared mandatory path (the protected entry).
        def declared_mandatory_path(failure)
          name = declaration.mandatory_fields.find do |path|
            path == failure.field || prefix?(path, failure.field) || prefix?(failure.field, path)
          end
          name || failure.field
        end

        def prefix?(prefix, path)
          path[0, prefix.length] == prefix
        end

        def retain(candidate)
          return unless declaration.retain?

          entity.retain_representation(candidate)
        end

        def retained_representation
          return nil unless declaration.retain?

          entity.retained_representation
        end
      end
    end
  end
end
