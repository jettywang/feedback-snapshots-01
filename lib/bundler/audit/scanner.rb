#
# Copyright (c) 2013-2026 Hal Brodigan (postmodern.mod3 at gmail.com)
#
# bundler-audit is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# bundler-audit is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with bundler-audit.  If not, see <https://www.gnu.org/licenses/>.
#

require 'bundler'
require 'bundler/audit/configuration'
require 'bundler/audit/exemption'
require 'bundler/audit/database'
require 'bundler/audit/report'
require 'bundler/audit/results/exempted_gem'
require 'bundler/audit/results/insecure_source'
require 'bundler/audit/results/source_assessment'
require 'bundler/audit/results/unpatched_gem'
require 'bundler/lockfile_parser'

require 'ipaddr'
require 'resolv'
require 'set'
require 'uri'
require 'yaml'

module Bundler
  module Audit
    #
    # Scans a `Gemfile.lock` for security issues.
    #
    class Scanner

      # The advisory database.
      #
      # @return [Database]
      attr_reader :database

      # Project root directory
      attr_reader :root

      # The parsed `Gemfile.lock` from the project.
      #
      # @return [Bundler::LockfileParser]
      attr_reader :lockfile

      # The configuration loaded from the `.bundler-audit.yml` file from the
      # project.
      #
      # @return [Hash]
      attr_reader :config

      #
      # Initializes a scanner.
      #
      # @param [String] root
      #   The path to the project root.
      #
      # @param [String] gemfile_lock
      #   Alternative name for the `Gemfile.lock` file.
      #
      # @param [Database] database
      #   The database to scan against.
      #
      # @param [String] config_dot_file
      #   The file name of the bundler-audit config file.
      #
      # @param [#getaddresses] resolver
      #   The resolver used to look up gem source hosts. Defaults to
      #   `Resolv`. A custom resolver can be supplied for offline or
      #   deterministic scans.
      #
      # @raise [Bundler::GemfileLockNotFound]
      #   The `gemfile_lock` file could not be found within the `root`
      #   directory.
      #
      def initialize(root=Dir.pwd,gemfile_lock='Gemfile.lock',database=Database.new,config_dot_file='.bundler-audit.yml',resolver: Resolv)
        @root     = File.expand_path(root)
        @database = database
        @resolver = resolver

        gemfile_lock_path = File.join(@root,gemfile_lock)

        unless File.file?(gemfile_lock_path)
          raise(Bundler::GemfileLockNotFound,"Could not find #{gemfile_lock.inspect} in #{@root.inspect}")
        end

        @lockfile = LockfileParser.new(File.read(gemfile_lock_path))

        config_dot_file_full_path = File.absolute_path(config_dot_file, @root)

        @config = if File.exist?(config_dot_file_full_path)
                    Configuration.load(config_dot_file_full_path)
                  else
                    Configuration.new
                  end
      end

      #
      # Preforms a {#scan} and collects the results into a {Report report}.
      #
      # @param [Hash] options
      #   Additional options.
      #
      # @option options [Array<String>] :ignore
      #   The advisories to ignore.
      #
      # @option options [Array<Exemption>] :exemptions
      #   Time-limited version advisory exemptions. These only apply to
      #   version results; source results are always assessed independently.
      #
      # @yield [result]
      #   The given block will be passed the results of the scan.
      #
      # @yieldparam [Results::InsecureSource, Results::SourceAssessment, Results::ExemptedGem, Results::UnpatchedGem] result
      #   A result from the scan.
      #
      # @return [Report]
      #
      # @since 0.8.0
      #
      def report(options={})
        report = Report.new()

        each_source_assessment do |assessment|
          result = source_result(assessment)

          report << result
          yield result if block_given?
        end

        scan_specs(options) do |result|
          report << result
          yield result if block_given?
        end

        return report
      end

      #
      # Scans the project for issues.
      #
      # @param [Hash] options
      #   Additional options.
      #
      # @option options [Array<String>] :ignore
      #   The advisories to ignore.
      #
      # @option options [Array<Exemption>] :exemptions
      #   Time-limited version advisory exemptions. These only apply to
      #   version results; source results are always assessed independently.
      #
      # @yield [result]
      #   The given block will be passed the results of the scan.
      #
      # @yieldparam [Results::InsecureSource, Results::SourceAssessment, Results::ExemptedGem, Results::UnpatchedGem] result
      #   A result from the scan.
      #
      # @return [Enumerator]
      #   If no block is given, an Enumerator will be returned.
      #
      def scan(options={},&block)
        return enum_for(__method__,options) unless block

        scan_sources(options,&block)
        scan_specs(options,&block)

        return self
      end

      #
      # Scans the gem sources in the lockfile.
      #
      # @param [Hash] options
      #   Additional options.
      #
      # @yield [result]
      #   The given block will be passed the results of the source scan.
      #
      # @yieldparam [Results::InsecureSource, Results::SourceAssessment] result
      #   A result from the source scan.
      #
      # @return [Enumerator]
      #   If no block is given, an Enumerator will be returned.
      #
      # @note
      #   Source results are independent of version results. Passing
      #   `:ignore` or `:exemptions` does not affect this method.
      #
      # @api semipublic
      #
      # @since 0.4.0
      #
      def scan_sources(options={})
        return enum_for(__method__,options) unless block_given?

        each_source_assessment do |assessment|
          unless assessment.allowed?
            yield source_result(assessment)
          end
        end
      end

      #
      # Assesses every gem source, including sources that were allowed.
      #
      # This is the complete source-side view. {#scan_sources} only yields the
      # sources that need attention (blocked or undetermined), so that an
      # allowed source does not turn into a finding.
      #
      # @param [Hash] options
      #   Additional options. These are accepted for API consistency but do
      #   not affect the source policy.
      #
      # @yield [assessment]
      #
      # @yieldparam [Results::SourceAssessment] assessment
      #
      # @return [Enumerator]
      #   If no block is given, an Enumerator will be returned.
      #
      # @api semipublic
      #
      def assess_sources(options={})
        return enum_for(__method__,options) unless block_given?

        each_source_assessment do |assessment|
          yield assessment
        end
      end

      #
      # Scans the gem sources in the lockfile.
      #
      # @param [Hash] options
      #   Additional options.
      #
      # @option options [Array<String>] :ignore
      #   The advisories to ignore.
      #
      # @option options [Array<Exemption>] :exemptions
      #   Time-limited version advisory exemptions.
      #
      # @yield [result]
      #   The given block will be passed the results of the scan.
      #
      # @yieldparam [Results::ExemptedGem, Results::UnpatchedGem] result
      #   A result from the scan.
      #
      # @return [Enumerator]
      #   If no block is given, an Enumerator will be returned.
      #
      # @note
      #   Exemptions only affect version results. They never suppress
      #   {#scan_sources} results.
      #
      # @api semipublic
      #
      # @since 0.4.0
      #
      def scan_specs(options={})
        return enum_for(__method__,options) unless block_given?

        ignore = if options[:ignore]
                   Set.new(options[:ignore])
                 else
                   config.ignore
                 end

        exemptions = if options[:exemptions]
                       Array(options[:exemptions]).map { |exemption|
                         exemption.kind_of?(Exemption) ? exemption : Exemption.from_h(exemption)
                       }
                     else
                       config.exemptions
                     end

        @lockfile.specs.each do |gem|
          @database.check_gem(gem) do |advisory|
            is_ignored = ignore.intersect?(advisory.identifiers.to_set)
            next if is_ignored

            applicable = exemptions.select do |candidate|
              candidate.applies_to?(advisory,gem)
            end

            if (exemption = applicable.find(&:active?))
              yield Results::ExemptedGem.new(gem,advisory,exemption)
            elsif (expired = applicable.first)
              yield Results::UnpatchedGem.new(gem,advisory,
                evidence: {
                  reason:            'exemption expired',
                  expired_exemption: expired.to_h
                })
            else
              yield Results::UnpatchedGem.new(gem,advisory)
            end
          end
        end
      end

      private

      #
      # Enumerates over the assessment of every source in the lockfile.
      #
      # @yield [assessment]
      #
      # @yieldparam [Results::SourceAssessment] assessment
      #
      def each_source_assessment
        each_source_uri do |source|
          uri = parse_source_uri(source)
          disposition, reason, evidence = assess_source(uri)

          yield Results::SourceAssessment.new(source,disposition,
            reason: reason,evidence: evidence)
        end
      end

      #
      # Converts an assessment into the result used by reports.
      #
      # Blocked sources are represented as {Results::InsecureSource} for
      # backwards compatibility, while every other assessment is retained
      # as-is.
      #
      # @param [Results::SourceAssessment] assessment
      #
      # @return [Results::InsecureSource, Results::SourceAssessment]
      #
      def source_result(assessment)
        if assessment.blocked?
          Results::InsecureSource.new(assessment.source,
            reason: assessment.reason,
            evidence: assessment.evidence)
        else
          assessment
        end
      end

      #
      # Enumerates over the URIs of every source in the lockfile.
      #
      # @yield [source]
      #
      # @yieldparam [String] source
      #
      def each_source_uri
        @lockfile.sources.each do |source|
          case source
          when Source::Git
            yield source.uri.to_s
          when Source::Rubygems
            source.remotes.each do |uri|
              yield uri.to_s
            end
          end
        end
      end

      #
      # Parses a source string into a URI.
      #
      # @param [String] source
      #
      # @return [URI::Generic]
      #
      def parse_source_uri(source)
        URI.parse(source.to_s)
      rescue URI::Error
        URI.parse('')
      end

      #
      # Determines whether a source URI may be resolved and trusted.
      #
      # A source with no scheme or host cannot be classified, so it is
      # reported as undetermined rather than silently allowed.
      #
      # @param [URI::Generic] uri
      #
      # @return [Boolean]
      #
      def identifiable_source?(uri)
        uri.scheme && uri.host && !uri.host.empty?
      end

      #
      # Assesses a source against the source policy.
      #
      # @param [URI::Generic] uri
      #
      # @return [Array<(Symbol, String, Hash)>]
      #   The disposition, reason, and evidence.
      #
      def assess_source(uri)
        scheme = uri.scheme
        host   = uri.host

        unless identifiable_source?(uri)
          return [:undetermined, 'source has no identifiable host',
                  {scheme: scheme, host: host}]
        end

        unless insecure_scheme?(scheme)
          return [:allowed, "secure #{scheme || 'unknown'} scheme", {scheme: scheme, host: host}]
        end

        addresses, resolution = resolve_host(host)
        evidence = {scheme: scheme, host: host, addresses: addresses}
        evidence[:resolution] = resolution if resolution

        if resolution == :unresolved || addresses.empty?
          return [:undetermined, 'source host could not be resolved', evidence]
        end

        parsed = addresses.map { |address| parse_address(address) }

        if parsed.any?(&:nil?)
          return [:undetermined, 'source host returned an unparseable address', evidence]
        end

        internal = parsed.all? { |address| internal_ip?(address) }
        evidence[:internal] = internal

        if internal
          [:allowed, 'internal source', evidence]
        else
          [:blocked, "insecure #{scheme} source", evidence]
        end
      end

      #
      # Determines whether a URI scheme is explicitly prohibited.
      #
      # @param [String, nil] scheme
      #
      # @return [Boolean]
      #
      def insecure_scheme?(scheme)
        scheme == 'http' || scheme == 'git'
      end

      #
      # Resolves a host using the configured resolver.
      #
      # @param [String] host
      #
      # @return [Array<(Array<String>, Symbol)>]
      #   The addresses and the resolution status. The status is `nil` when
      #   the resolver answered, or `:unresolved` when it could not.
      #
      def resolve_host(host)
        addresses = @resolver.getaddresses(host)

        if addresses.nil? || addresses.empty?
          [[], :unresolved]
        else
          [addresses, nil]
        end
      rescue StandardError
        [[], :unresolved]
      end

      # List of internal IP address ranges.
      #
      # @see https://tools.ietf.org/html/rfc1918#section-3
      # @see https://tools.ietf.org/html/rfc4193#section-8
      # @see https://tools.ietf.org/html/rfc6890#section-2.2.2
      # @see https://tools.ietf.org/html/rfc6890#section-2.2.3
      INTERNAL_SUBNETS = %w[
        10.0.0.0/8
        172.16.0.0/12
        192.168.0.0/16
        fc00::/7
        127.0.0.0/8
        ::1/128
      ].map(&IPAddr.method(:new))

      #
      # Determines whether an IP is internal.
      #
      # @param [String] ip
      #   The IPv4/IPv6 address.
      #
      # @return [Boolean]
      #
      def parse_address(address)
        IPAddr.new(address.to_s)
      rescue IPAddr::Error
        nil
      end

      #
      # Determines whether an IP is internal.
      #
      # @param [IPAddr] address
      #
      # @return [Boolean]
      #
      def internal_ip?(address)
        INTERNAL_SUBNETS.any? { |subnet| subnet.include?(address) }
      end
    end
  end
end
