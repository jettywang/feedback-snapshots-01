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

module Bundler
  module Audit
    #
    # A single, reproducible explanation of why a locked gem version is or is
    # not affected by one {Advisory}.
    #
    # This class is the *only* place where the advisory's version ranges are
    # evaluated. Both the boolean predicates ({#vulnerable?},
    # {Advisory#vulnerable?}) and the machine/human explanations are derived
    # from the same {#range_checks}, so they can never quietly drift into two
    # divergent algorithms.
    #
    # ## Verdict semantics
    #
    # The advisory ranges are evaluated independently and then combined with
    # an explicit, documented precedence:
    #
    # 1. any matching `unaffected_versions` range wins first;
    # 2. otherwise any matching `patched_versions` range means patched;
    # 3. otherwise the version is treated as vulnerable.
    #
    # A locked prerelease that no published range covers cannot be classified
    # from the advisory alone and is reported as {#undetermined?} while still
    # being treated as vulnerable by the boolean interface for backwards
    # compatibility.
    #
    class VersionDecision

      # The possible combined verdicts.
      #
      # @return [Array<Symbol>]
      VERDICTS = [:unaffected, :patched, :vulnerable, :undetermined].freeze

      # The advisory the decision was computed against.
      #
      # @return [Advisory]
      attr_reader :advisory

      # The name of the dependency the locked version belongs to.
      #
      # @return [String]
      attr_reader :gem_name

      # The locked version, exactly as supplied before normalization.
      #
      # @return [String]
      attr_reader :raw_version

      # The normalized version used for every comparison.
      #
      # @return [Gem::Version]
      attr_reader :version

      # Every individual range evaluated against {#version}.
      #
      # @return [Array<Hash{Symbol => Object}>]
      attr_reader :range_checks

      #
      # Evaluates an advisory against a locked version.
      #
      # @param [Advisory] advisory
      #   The advisory documenting the vulnerability.
      #
      # @param [Gem::Version, String] version
      #   The locked dependency version.
      #
      # @param [String] gem_name
      #   The name of the dependency the locked version belongs to.
      #
      def initialize(advisory,version,gem_name=nil)
        @advisory    = advisory
        @gem_name    = gem_name
        @raw_version = version.to_s
        @version     = normalize(version)

        @range_checks = []
        evaluate_ranges(:unaffected, advisory.unaffected_versions)
        evaluate_ranges(:patched,    advisory.patched_versions)

        @verdict = decide
      end

      #
      # Normalizes an externally supplied version into the canonical
      # RubyGems representation used by every comparison.
      #
      # @param [Gem::Version, String] version
      #
      # @return [Gem::Version]
      #
      def self.normalize(version)
        return version if version.kind_of?(Gem::Version)

        Gem::Version.new(version.to_s)
      end

      #
      # The path of the advisory source file the decision is bound to.
      #
      # @return [String]
      def advisory_path
        @advisory.path
      end

      #
      # The advisory identifier.
      #
      # @return [String]
      def advisory_id
        @advisory.id
      end

      #
      # Whether the locked version is a prerelease.
      #
      # @return [Boolean]
      def prerelease?
        @version.prerelease?
      end

      #
      # The ranges declared as not affected.
      #
      # @return [Array<Hash>]
      def unaffected_checks
        @range_checks.select { |check| check[:kind] == :unaffected }
      end

      #
      # The ranges declared as patched.
      #
      # @return [Array<Hash>]
      def patched_checks
        @range_checks.select { |check| check[:kind] == :patched }
      end

      #
      # @return [Boolean]
      #   True when an `unaffected_versions` range matches.
      #
      def unaffected?
        unaffected_checks.any? { |check| check[:matched] }
      end

      #
      # @return [Boolean]
      #   True when a `patched_versions` range matches.
      #
      def patched?
        patched_checks.any? { |check| check[:matched] }
      end

      #
      # The combined verdict.
      #
      # @return [Symbol]
      #   One of {VERDICTS}.
      #
      attr_reader :verdict

      #
      # A positive match for an unaffected or patched range could not be made.
      #
      # @return [Boolean]
      #
      def undetermined?
        @verdict == :undetermined
      end

      #
      # Whether the advisory positively establishes the version as affected.
      #
      # @return [Boolean]
      #
      def affected?
        @verdict == :vulnerable
      end

      #
      # The single boolean used by the scanner and every boolean caller.
      #
      # An {#undetermined?} prerelease is still surfaced (returns `true`) so
      # that a lockfile pinning an unreviewed prerelease is never silently
      # treated as safe; the explanation distinguishes the two cases.
      #
      # @return [Boolean]
      #
      def vulnerable?
        affected? || undetermined?
      end

      #
      # A human-readable, reviewer-facing explanation that can be recomputed
      # from {#range_checks}.
      #
      # @return [String]
      #
      def explain
        lines = []
        lines << "#{@gem_name} #{@raw_version} against #{advisory_id} " \
                 "(#{advisory_path})"
        lines << "normalized version: #{@version} (prerelease: #{prerelease?})"

        if @range_checks.empty?
          lines << "advisory declares no unaffected_versions or " \
                   "patched_versions ranges"
        else
          @range_checks.each do |check|
            lines << "#{check[:kind]} range #{check[:requirement].inspect} " \
                     "matched=#{check[:matched]} - #{check[:reason]}"
          end
        end

        lines << "verdict: #{@verdict} - #{verdict_reason}"
        return lines.join($/)
      end

      alias to_s explain

      #
      # A machine-readable representation suitable for JSON reports.
      #
      # @return [Hash{Symbol => Object}]
      #
      def to_h
        {
          gem: {
            name: @gem_name,
            raw_version: @raw_version,
            version: @version.to_s,
            prerelease: prerelease?
          },
          advisory: {
            id: advisory_id,
            path: advisory_path
          },
          range_checks: @range_checks.map { |check|
            {
              kind: check[:kind].to_s,
              requirement: check[:requirement],
              matched: check[:matched],
              reason: check[:reason]
            }
          },
          verdict: @verdict.to_s,
          vulnerable: vulnerable?,
          undetermined: undetermined?,
          reason: verdict_reason
        }
      end

      private

      def normalize(version)
        self.class.normalize(version)
      end

      def evaluate_ranges(kind,requirements)
        requirements.each do |requirement|
          matched = requirement.satisfied_by?(@version)

          @range_checks << {
            kind: kind,
            requirement: requirement.to_s,
            requirement_object: requirement,
            matched: matched,
            reason: range_reason(kind,requirement,matched)
          }
        end
      end

      def range_reason(kind,requirement,matched)
        relation = kind == :unaffected ? 'unaffected' : 'patched'

        if matched
          return "version #{@version} satisfies the #{relation} requirement " \
                 "#{requirement.to_s.inspect}"
        end

        if prerelease? && !requirement.prerelease?
          return "prerelease #{@version} is excluded by non-prerelease " \
                 "#{relation} requirement #{requirement.to_s.inspect}; " \
                 "RubyGems only matches a prerelease against a requirement " \
                 "that itself names a prerelease"
        end

        "version #{@version} does not satisfy #{relation} requirement " \
        "#{requirement.to_s.inspect}"
      end

      def decide
        return :unaffected if unaffected?
        return :patched    if patched?

        if prerelease? && !coverable_by_prerelease_range?
          return :undetermined
        end

        :vulnerable
      end

      #
      # A prerelease version can only be positively classified by a range
      # whose requirement itself names a prerelease (RubyGems ignores
      # non-prerelease requirements for prerelease versions).
      #
      def coverable_by_prerelease_range?
        @range_checks.any? { |check| check[:requirement_object].prerelease? }
      end

      def verdict_reason
        case @verdict
        when :unaffected
          matched = unaffected_checks.find { |check| check[:matched] }
          "matched unaffected_versions #{matched[:requirement].inspect}; " \
          "unaffected takes precedence and the version is not affected"
        when :patched
          matched = patched_checks.find { |check| check[:matched] }
          "no unaffected range matched; matched patched_versions " \
          "#{matched[:requirement].inspect}, so the version is patched"
        when :undetermined
          "no unaffected or patched range covers prerelease #{@version}; " \
          "the advisory cannot determine whether it is affected, reported " \
          "as undetermined while still surfaced for review"
        else
          if @range_checks.empty?
            "the advisory publishes no patched or unaffected versions; " \
            "the version is treated as affected with no patch available"
          else
            "no unaffected_versions and no patched_versions range matched; " \
            "the version falls inside the affected set"
          end
        end
      end

    end
  end
end
