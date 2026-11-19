require 'set'
require 'bundler/audit/runtime/target'
require 'bundler/audit/runtime/declaration'
require 'bundler/audit/runtime/advisory_set'

module Bundler
  module Audit
    module Runtime
      #
      # The result of evaluating an explicit deployment target against the
      # runtime advisories.
      #
      # The assessment records exactly which inputs were used. It never
      # consults the Ruby which runs `bundler-audit`.
      #
      class Assessment

        #
        # A single runtime advisory finding.
        #
        class Finding

          # The runtime advisory (or advisories, when conflicting duplicates
          # exist).
          #
          # @return [Array<Advisory>]
          attr_reader :advisories

          # The finding status: `:affected`, `:patched` or `:unknown`.
          #
          # @return [Symbol]
          attr_reader :status

          # A short machine readable reason.
          #
          # @return [Symbol]
          attr_reader :reason

          # A human readable explanation.
          #
          # @return [String]
          attr_reader :message

          # The version used for the evaluation.
          #
          # @return [Gem::Version, nil]
          attr_reader :evaluated_version

          def initialize(advisories, status:, reason:, message:, evaluated_version: nil)
            @advisories        = Array(advisories)
            @status            = status
            @reason            = reason
            @message           = message
            @evaluated_version = evaluated_version
          end

          #
          # The primary advisory.
          #
          # @return [Advisory]
          #
          def advisory
            @advisories.first
          end

          #
          # All identifiers for the finding.
          #
          # @return [Array<String>]
          #
          def identifiers
            @advisories.flat_map(&:identifiers).uniq
          end

          #
          # @return [Boolean]
          #
          def affected?
            status == :affected
          end

          #
          # @return [Boolean]
          #
          def unknown?
            status == :unknown
          end

          #
          # @return [Hash{Symbol => Object}]
          #
          def to_h
            {
              status:            status,
              reason:            reason,
              message:           message,
              evaluated_version: evaluated_version && evaluated_version.to_s,
              advisories:        @advisories.map(&:to_h)
            }
          end

        end

        # The explicit deployment target.
        #
        # @return [Target]
        attr_reader :target

        # The lock file Ruby declaration, when present.
        #
        # @return [Declaration, nil]
        attr_reader :declaration

        # The runtime advisories considered.
        #
        # @return [Array<Advisory>]
        attr_reader :advisories

        # The findings.
        #
        # @return [Array<Finding>]
        attr_reader :findings

        # Explanations about the inputs and their conflicts.
        #
        # @return [Array<Hash>]
        attr_reader :notes

        # The inputs which were actually used.
        #
        # @return [Hash]
        attr_reader :inputs

        #
        # Initializes an assessment.
        #
        # @param [Target] target
        #
        # @param [AdvisorySet, nil] advisory_set
        #
        # @param [Declaration, nil] declaration
        #
        # @param [Hash] inputs
        #
        # @param [Array<Hash>] notes
        #   Additional notes from the deployment manifest.
        #
        def initialize(target:, advisory_set: nil, declaration: nil, inputs: {},
                       notes: [])
          @target        = target
          @declaration   = declaration
          @advisory_set  = advisory_set
          @inputs        = inputs.dup
          @notes         = notes.dup
          @advisories    = []
          @findings      = []
          @status        = nil

          evaluate
        end

        #
        # The overall status.
        #
        # @return [:affected, :clean, :unknown]
        #
        def status
          @status
        end

        #
        # @return [Boolean]
        #
        def affected?
          @status == :affected
        end

        #
        # @return [Boolean]
        #
        def vulnerable?
          affected?
        end

        #
        # @return [Boolean]
        #
        def clean?
          @status == :clean
        end

        #
        # @return [Boolean]
        #
        def unknown?
          @status == :unknown
        end

        #
        # The affected findings.
        #
        # @return [Array<Finding>]
        #
        def affected_findings
          @findings.select(&:affected?)
        end

        #
        # The unknown findings.
        #
        # @return [Array<Finding>]
        #
        def unknown_findings
          @findings.select(&:unknown?)
        end

        #
        # Converts the assessment to a Hash.
        #
        # @return [Hash{Symbol => Object}]
        #
        def to_h
          {
            type:        :runtime,
            status:      @status,
            target:      @target.to_h,
            declaration: @declaration && @declaration.to_h,
            inputs:      @inputs,
            notes:       @notes,
            findings:    @findings.map(&:to_h)
          }
        end

        #
        # @return [String]
        #
        def to_s
          "runtime #{@target}"
        end

        private

        def evaluate
          target_notes = @target.notes

          target_notes.each do |note|
            @notes << note unless @notes.any? { |existing| existing[:code] == note[:code] }
          end

          if @declaration
            @notes.concat(@declaration.notes)
            @notes.concat(@declaration.differences(@target))
          end

          unless target.known_engine?
            note(:runtime_unknown,
                 "the deployment runtime engine is missing or unsupported; runtime advisories cannot be selected")
            return finish(:unknown)
          end

          version = target.evaluation_version

          if version.nil?
            if target.mri?
              message = "the deployment runtime version is missing"
            else
              message = "the deployment #{target.engine} engine version is missing"
            end

            note(:runtime_unknown,message)
            return finish(:unknown)
          end

          @inputs = @inputs.merge(
            'evaluated_version' => version.to_s,
            'engine'            => target.engine
          )

          unless @advisory_set
            note(:runtime_advisories_missing,
                 "no local runtime advisory source was supplied")
            return finish(:unknown)
          end

          @inputs['runtime_advisories'] = @advisory_set.to_s

          unless @advisory_set.exist?
            note(:runtime_advisories_unavailable,
                 "no `rubies/` runtime advisory directory exists in #{@advisory_set.to_s.inspect}")
            return finish(:unknown)
          end

          misplaced = @advisory_set.misplaced_advisories(target.engine)

          unless misplaced.empty?
            misplaced.each do |entry|
              note(:runtime_advisory_engine_mismatch,
                   "runtime advisory #{entry[:id]} is stored under `#{entry[:declared]}` but declares engine `#{target.engine}`")

              @findings << Finding.new(
                entry[:advisory],
                status: :unknown,
                reason: :misplaced_advisory,
                message: "runtime advisory #{entry[:id]} is stored under `#{entry[:declared]}` but declares engine `#{target.engine}`; no directory or body was preferred",
                evaluated_version: version
              )
            end
          end

          @advisories = @advisory_set.advisories_for(target.engine)

          unless @advisory_set.load_errors.empty?
            @advisory_set.load_errors.each do |entry|
              note(:runtime_advisory_load_error,
                   "runtime advisory #{entry[:path].inspect} could not be loaded: #{entry[:error]}")
            end
          end

          @inputs['runtime_advisory_count'] = @advisories.length

          if @advisories.empty?
            note(:no_runtime_advisories,
                 "no runtime advisories exist for engine `#{target.engine}`; the runtime result is unknown")
            return finish(:unknown)
          end

          evaluate_advisories(version)

          return finish(overall_status)
        end

        def evaluate_advisories(version)
          conflict_ids = Set.new
          visited_ids  = Set.new

          @advisories.group_by { |advisory| advisory_key(advisory) }.each do |key,same_key|
            signatures = same_key.map { |advisory| advisory_signature(advisory) }.uniq

            next if signatures.length <= 1

            conflict_ids << key
            next if visited_ids.include?(key)

            visited_ids << key

            note(:conflicting_runtime_advisories,
                 "runtime advisory #{key} has conflicting version data; the result is unknown")

            @findings << Finding.new(
              same_key,
              status: :unknown,
              reason: :conflicting_advisories,
              message: "conflicting runtime advisory records share the identifier #{key}; no version range was chosen",
              evaluated_version: version
            )
          end

          @advisories.each do |advisory|
            next unless advisory.engine == target.engine
            next if conflict_ids.include?(advisory_key(advisory))

            evaluate_advisory(advisory,version)
          end
        end

        def advisory_key(advisory)
          advisory.cve_id || advisory.osvdb_id || advisory.id
        end

        def evaluate_advisory(advisory,base_version)
          if !advisory.invalid_requirements.empty?
            @findings << Finding.new(
              advisory,
              status: :unknown,
              reason: :invalid_version_requirements,
              message: "runtime advisory #{advisory.id} contains version requirements which could not be parsed: #{advisory.invalid_requirements.join(', ')}",
              evaluated_version: base_version
            )
            return
          end

          unless advisory.evaluable?
            @findings << Finding.new(
              advisory,
              status: :unknown,
              reason: :missing_patched_versions,
              message: "runtime advisory #{advisory.id} does not declare patched versions; no vulnerability conclusion is possible",
              evaluated_version: base_version
            )
            return
          end

          if requires_patchlevel?(advisory) && !target_patchlevel_known?
            note(:missing_target_patchlevel,
                 "runtime advisory #{advisory.id} uses patchlevel specific versions, but the deployment target has no patchlevel")

            @findings << Finding.new(
              advisory,
              status: :unknown,
              reason: :missing_patchlevel,
              message: "runtime advisory #{advisory.id} uses patchlevel specific versions, but the deployment target has no patchlevel",
              evaluated_version: nil
            )
            return
          end

          version = version_for(advisory,base_version)

          case advisory.affected?(version)
          when true
            @findings << Finding.new(
              advisory,
              status: :affected,
              reason: :unpatched_version,
              message: "#{version} is not covered by the patched versions of #{advisory.id}",
              evaluated_version: version
            )
          when false
            if advisory.unaffected?(version)
              @findings << Finding.new(
                advisory,
                status: :patched,
                reason: :unaffected_version,
                message: "#{version} is explicitly unaffected by #{advisory.id}",
                evaluated_version: version
              )
            else
              @findings << Finding.new(
                advisory,
                status: :patched,
                reason: :patched_version,
                message: "#{version} matches a patched version of #{advisory.id}",
                evaluated_version: version
              )
            end
          else
            @findings << Finding.new(
              advisory,
              status: :unknown,
              reason: :insufficient_advisory_data,
              message: "runtime advisory #{advisory.id} does not provide enough version data for #{version}",
              evaluated_version: version
            )
          end
        end

        def overall_status
          return :affected if @findings.any?(&:affected?)
          return :unknown  if @findings.any?(&:unknown?)

          :clean
        end

        def finish(status)
          @status = status
          return self
        end

        def note(code,message)
          @notes << {code: code, message: message}
        end

        def advisory_signature(advisory)
          [
            advisory.engine,
            advisory.cve,
            advisory.osvdb,
            advisory.unaffected_versions.map(&:to_s).sort,
            advisory.patched_versions.map(&:to_s).sort
          ]
        end

        def requires_patchlevel?(advisory)
          return false unless target.mri?
          return false unless target.version

          target_segments = target.version.segments.first(3)

          (advisory.patched_versions + advisory.unaffected_versions).any? do |requirement|
            requirement.requirements.any? do |(_,requirement_version)|
              segments = requirement_version.segments

              segments.length >= 4 && segments.first(3) == target_segments
            end
          end
        end

        def target_patchlevel_known?
          target.patchlevel? || (target.version && target.version.segments.length >= 4)
        end

        #
        # Selects the version to compare against a specific advisory.
        #
        # MRI patchlevels are folded into the version only for advisories
        # which use four component versions for the same release series.
        # Other advisories are compared against the plain version so that an
        # unrelated range comparison is not changed by the patchlevel.
        #
        def version_for(advisory,base_version)
          if requires_patchlevel?(advisory)
            target.effective_mri_version
          else
            base_version
          end
        end

      end
    end
  end
end
