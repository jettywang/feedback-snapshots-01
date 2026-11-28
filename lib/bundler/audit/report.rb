require 'bundler/audit/results'
require 'bundler/audit/version'

require 'time'

module Bundler
  module Audit
    #
    # Represents the result of a scan.
    #
    class Report

      include Enumerable

      # The version of `bundler-audit` which created the report object.
      #
      # @return [String]
      attr_reader :version

      # The time when the report was generated.
      #
      # @return [Time]
      attr_reader :created_at

      # The list of all results.
      #
      # @return [Array<Results::Result>]
      attr_reader :results

      # The insecure sources results.
      #
      # @return [Array<Results::InsecureSources>]
      attr_reader :insecure_sources

      # The source assessment results.
      #
      # @return [Array<Results::SourceAssessment>]
      attr_reader :source_assessments

      # The unpatched gems results.
      #
      # @return [Array<Results::UnpatchedGems>]
      attr_reader :unpatched_gems

      # The version advisories approved through an exemption.
      #
      # @return [Array<Results::ExemptedGem>]
      attr_reader :exemptions

      alias exempted_gems exemptions

      #
      # Initializes the report.
      #
      # @param [#each] results
      #
      def initialize(results=[])
        @version    = VERSION
        @created_at = Time.now

        @results = []
        @insecure_sources = []
        @source_assessments = []
        @unpatched_gems = []
        @exemptions = []

        results.each { |result| self << result }
      end

      #
      # Enumerates over the results.
      #
      # @yield [result]
      #
      # @yieldparam [Results::InsecureSource, Results::UnpatchedGem] result
      #
      # @return [Enumerator]
      #
      def each(&block)
        @results.each(&block)
      end

      #
      # Appends a result to the report.
      #
      # @param [Result] result
      #
      # @return [Report]
      #
      def <<(result)
        @results << result

        case result
        when Results::InsecureSource
          @insecure_sources << result
        when Results::SourceAssessment
          @source_assessments << result
        when Results::ExemptedGem
          @exemptions << result
        when Results::UnpatchedGem
          @unpatched_gems << result
        end

        return self
      end

      #
      # Determines if there are findings that were not approved for release.
      #
      # @return [Boolean]
      #
      def vulnerable?
        !passes?
      end

      #
      # The sources that explicitly block the release.
      #
      # @return [Array<Results::InsecureSource>]
      #
      def blocked_sources
        @insecure_sources.select(&:blocked?)
      end

      #
      # The sources whose identity could not be established.
      #
      # @return [Array<Results::SourceAssessment>]
      #
      def undetermined_sources
        @source_assessments.select(&:undetermined?)
      end

      #
      # The sources that matched the source policy.
      #
      # @return [Array<Results::SourceAssessment>]
      #
      def allowed_sources
        @source_assessments.select(&:allowed?)
      end

      #
      # Determines whether the release is permitted.
      #
      # Sources are evaluated independently of version results. An explicit
      # version exemption cannot clear a blocked or undetermined source.
      #
      # @return [Boolean]
      #
      def passes?
        @results.none?(&:blocks_release?)
      end

      #
      # The results that block the release.
      #
      # @return [Array<Result>]
      #
      def blocking_results
        @results.select(&:blocks_release?)
      end

      #
      # The approved results.
      #
      # @return [Array<Result>]
      #
      def approved_results
        @results.select(&:approved?)
      end

      #
      # @yield [advisory]
      #
      # @yieldparam [Advisory] advisory
      #
      # @return [Enumerator]
      #
      def each_advisory
        return enum_for(__method__) unless block_given?

        @unpatched_gems.each { |result| yield result.advisory }
      end

      #
      # @return [Array<Advisory>]
      #
      def advisories
        @unpatched_gems.map(&:advisory)
      end

      #
      # @yield [gem]
      #
      # @yieldparam [Gem::Specification]
      #
      # @return [Enumerator]
      #
      def each_vulnerable_gem
        return enum_for(__method__) unless block_given?

        @unpatched_gems.each { |result| yield result.gem }
      end

      #
      # @return [Array<Gem::Specification>]
      #
      def vulnerable_gems
        @unpatched_gems.map(&:gem)
      end

      #
      # @return [Hash{Symbol => Object}]
      #
      def to_h
        {
          version:    @version,
          created_at: @created_at,
          passed:     passes?,
          results:    @results.map(&:to_h)
        }
      end

    end
  end
end
