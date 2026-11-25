# frozen_string_literal: true

module Grape
  class Entity
    module Publication
      # Collects field-level observations while a candidate representation is
      # being formatted. Observations are per publication attempt; nothing
      # recorded here is delivered until the executor commits.
      class Session
        attr_reader :declaration, :failures, :excluded, :present

        def initialize(declaration)
          @declaration = declaration
          @failures = []
          @excluded = []
          @present = []
        end

        def allowed?(path)
          declaration.allowed?(path)
        end

        def record_failure(path, exposure, exception)
          failure = FieldFailure.new(
            path.map(&:to_sym),
            failure_code(exposure),
            exception,
            covered_by_mandatory?(path)
          )
          @failures << failure
          nil
        end

        def record_excluded(path, exposure)
          @excluded << FieldFailure.new(path.map(&:to_sym), Codes::FIELD_EXCLUDED, nil, covered_by_mandatory?(path))
        end

        def record_present(path)
          @present << path.map(&:to_sym).freeze
        end

        def present?(path)
          @present.any? { |candidate| path_equals?(candidate, path) }
        end

        def failures_for(path)
          (@failures + @excluded).select { |failure| path_equals?(failure.field, path) }
        end

        def excluded_for?(path)
          @excluded.any? { |failure| path_equals?(failure.field, path) }
        end

        # A failed field is removed from the candidate unless the contract
        # explicitly asks for a null placeholder. Mandatory failures are
        # removed as well; the object is rejected at commit.
        def suppress?(path)
          failure = failures_for(path).first
          return false unless failure
          return true if failure.mandatory?

          declaration.optional_policy != :null
        end

        # While formatting, a failed field leaves no value in the candidate.
        # The commit phase decides whether the omission is an acceptable
        # optional degradation or a mandatory rejection.
        def replacement_for(_path)
          nil
        end

        def covered_by_mandatory?(path)
          declaration.mandatory_fields.any? { |mandatory_path| covers?(mandatory_path, path) }
        end

        def failure_code(exposure)
          if exposure.respond_to?(:formatter?) && exposure.formatter?
            Codes::FORMATTER_FAILURE
          else
            Codes::EXPOSURE_FAILURE
          end
        end

        def path_equals?(left, right)
          left.map(&:to_sym) == right.map(&:to_sym)
        end

        def covers?(declared_path, actual_path)
          declared_path == actual_path[0, declared_path.length] ||
            actual_path == declared_path[0, actual_path.length]
        end
      end
    end
  end
end
