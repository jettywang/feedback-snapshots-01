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
      # @return [Array<Results::InsecureSource>]
      attr_reader :insecure_sources

      # The unpatched gems results.
      #
      # @return [Array<Results::UnpatchedGem>]
      attr_reader :unpatched_gems

      # The optional Ruby runtime audit result.
      #
      # @return [Results::RuntimeAudit, nil]
      #
      # @since 0.10.0
      attr_reader :runtime_audit

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
        @unpatched_gems = []
        @runtime_audit = nil

        results.each { |result| self << result }
      end

      #
      # Enumerates over the results.
      #
      # @yield [result]
      #
      # @yieldparam [Results::InsecureSource, Results::UnpatchedGem, Results::RuntimeAudit] result
      #
      # @return [Enumerator]
      #
      def each(&block)
        @results.each(&block)
      end

      #
      # Appends a result to the report.
      #
      # @param [InsecureSource, UnpatchedGem, RuntimeAudit] result
      #
      def <<(result)
        @results << result

        case result
        when Results::InsecureSource
          @insecure_sources << result
        when Results::UnpatchedGem
          @unpatched_gems << result
        when Results::RuntimeAudit
          @runtime_audit = result
        end

        return self
      end

      #
      # Determines if there were vulnerabilities found.
      #
      # @return [Boolean]
      #
      def vulnerable?
        @results.any? do |result|
          case result
          when Results::RuntimeAudit
            result.affected?
          else
            true
          end
        end
      end

      #
      # Determines if the optional runtime audit was inconclusive.
      #
      # @return [Boolean]
      #
      # @since 0.10.0
      #
      def runtime_unknown?
        !@runtime_audit.nil? && @runtime_audit.unknown?
      end

      #
      # Determines whether the report only contains the runtime audit.
      #
      # @return [Boolean]
      #
      # @since 0.10.0
      #
      def runtime_only?
        !@runtime_audit.nil? && @results.all? { |result| result.equal?(@runtime_audit) }
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
        hash = {
          version:    @version,
          created_at: @created_at,
          results:    @results.reject { |result| result.kind_of?(Results::RuntimeAudit) }.map(&:to_h)
        }

        if @runtime_audit
          hash[:runtime] = @runtime_audit.to_h
        end

        return hash
      end

    end
  end
end
