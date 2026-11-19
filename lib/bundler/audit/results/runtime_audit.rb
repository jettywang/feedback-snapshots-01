require 'bundler/audit/results/result'

module Bundler
  module Audit
    module Results
      #
      # Represents the result of the optional Ruby runtime audit.
      #
      # The runtime result is intentionally separate from {UnpatchedGem} and
      # {InsecureSource} results. It records the deployment target which was
      # explicitly supplied by the caller and the local runtime advisories
      # which were used.
      #
      # @since 0.10.0
      #
      class RuntimeAudit < Result

        # The underlying runtime assessment.
        #
        # @return [Runtime::Assessment]
        attr_reader :assessment

        #
        # Initializes the runtime audit result.
        #
        # @param [Runtime::Assessment] assessment
        #
        def initialize(assessment)
          @assessment = assessment
        end

        #
        # The deployment target.
        #
        # @return [Runtime::Target]
        #
        def target
          @assessment.target
        end

        #
        # @return [:affected, :clean, :unknown]
        #
        def status
          @assessment.status
        end

        #
        # @return [Boolean]
        #
        def affected?
          @assessment.affected?
        end

        #
        # @return [Boolean]
        #
        def clean?
          @assessment.clean?
        end

        #
        # @return [Boolean]
        #
        def unknown?
          @assessment.unknown?
        end

        #
        # @return [Array<Runtime::Assessment::Finding>]
        #
        def findings
          @assessment.findings
        end

        #
        # The affected findings.
        #
        # @return [Array<Runtime::Assessment::Finding>]
        #
        def affected_findings
          @assessment.affected_findings
        end

        #
        # The unknown findings.
        #
        # @return [Array<Runtime::Assessment::Finding>]
        #
        def unknown_findings
          @assessment.unknown_findings
        end

        #
        # Explanations about the inputs and their conflicts.
        #
        # @return [Array<Hash>]
        #
        def notes
          @assessment.notes
        end

        #
        # The inputs which were actually used.
        #
        # @return [Hash]
        #
        def inputs
          @assessment.inputs
        end

        #
        # @return [String]
        #
        def to_s
          "Ruby runtime #{@assessment.target}"
        end

        #
        # @return [Hash{Symbol => Object}]
        #
        def to_h
          @assessment.to_h
        end

      end
    end
  end
end
