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
    # Selects, for a single gem, the minimal version from a caller-provided
    # list of candidate versions that avoids every given advisory while
    # satisfying the project's explicit constraints.
    #
    # This is intentionally *not* a general dependency solver: it never
    # consults a remote gem index and only considers the finite version
    # list supplied by the caller. Versions are tested individually against
    # every advisory (honoring multiple patched branches and unaffected
    # ranges) and every project constraint, instead of collapsing the
    # advisories into a single "maximum lower bound".
    #
    # Candidates originating from sources or platforms that the caller has
    # not declared as covered by the explicit constraints cannot yield a
    # definite suggestion; they are reported as caveats instead.
    #
    class Remediation

      #
      # A single candidate version, optionally tagged with the source and
      # platform it would be resolved from.
      #
      class Candidate

        # The candidate version.
        #
        # @return [Gem::Version]
        attr_reader :version

        # The source the version would be resolved from (ie: `:rubygems`,
        # `:git`), if known.
        #
        # @return [Symbol, nil]
        attr_reader :source

        # The platform the version would be resolved for (ie: `:ruby`,
        # `:java`), if known.
        #
        # @return [Symbol, nil]
        attr_reader :platform

        #
        # Initializes the candidate.
        #
        # @param [Gem::Version, String] version
        #   The candidate version.
        #
        # @param [Symbol, String, nil] source
        #   Optional source the version would be resolved from.
        #
        # @param [Symbol, String, nil] platform
        #   Optional platform the version would be resolved for.
        #
        def initialize(version, source: nil, platform: nil)
          @version  = version.kind_of?(Gem::Version) ? version
                                                     : Gem::Version.new(version.to_s)
          @source   = source&.to_sym
          @platform = platform&.to_sym
        end

        #
        # Compares candidates by version.
        #
        # @param [Candidate] other
        #
        # @return [-1, 0, 1, nil]
        #
        def <=>(other)
          @version <=> other.version
        end

        include Comparable

        #
        # Converts the candidate to a String.
        #
        # @return [String]
        #
        def to_s
          @version.to_s
        end

      end

      #
      # The recorded outcome of testing one candidate against the
      # constraints and advisories.
      #
      class Evaluation

        # The evaluated candidate.
        #
        # @return [Candidate]
        attr_reader :candidate

        # The exclusion reasons, if any. Each reason is a Hash with a
        # `:type` of `:prerelease`, `:constraint`, or `:advisory`, plus the
        # offending `:requirement` or `:advisory` when applicable.
        #
        # @return [Array<Hash>]
        attr_reader :reasons

        # Evidence of how the candidate relates to each advisory it avoids.
        # Each entry is a Hash with the `:advisory`, the `:status`
        # (`:patched` or `:unaffected`), and the matching `:requirement`.
        #
        # @return [Array<Hash>]
        attr_reader :advisory_matches

        #
        # Initializes the evaluation.
        #
        # @param [Candidate] candidate
        #
        def initialize(candidate)
          @candidate        = candidate
          @reasons          = []
          @advisory_matches = []
        end

        #
        # The candidate version.
        #
        # @return [Gem::Version]
        #
        def version
          @candidate.version
        end

        #
        # Records an exclusion reason.
        #
        # @param [Hash] reason
        #
        def exclude!(reason)
          @reasons << reason
        end

        #
        # Records advisory evidence for a non-vulnerable candidate.
        #
        # @param [Hash] match
        #
        def match!(match)
          @advisory_matches << match
        end

        #
        # Determines whether the candidate was excluded.
        #
        # @return [Boolean]
        #
        def excluded?
          !@reasons.empty?
        end

      end

      #
      # A successful remediation suggestion.
      #
      class Suggestion

        # The gem name.
        #
        # @return [String]
        attr_reader :gem

        # The chosen candidate.
        #
        # @return [Candidate]
        attr_reader :candidate

        # The project constraints the chosen version satisfies.
        #
        # @return [Array<Gem::Requirement>]
        attr_reader :constraints

        # Per-advisory evidence for the chosen version. Each entry is a
        # Hash with the `:advisory`, the `:status` (`:patched` or
        # `:unaffected`), and the exact `:requirement` that matched.
        #
        # @return [Array<Hash>]
        attr_reader :advisory_evidence

        # Evaluations of every excluded candidate, preserving the actual
        # exclusion reasons.
        #
        # @return [Array<Evaluation>]
        attr_reader :exclusions

        # Caveats about the suggestion (ie: uncovered sources or
        # platforms).
        #
        # @return [Array<String>]
        attr_reader :caveats

        #
        # Initializes the suggestion.
        #
        def initialize(gem:,candidate:,constraints:,advisory_evidence:,exclusions:,definite:,caveats:)
          @gem               = gem
          @candidate         = candidate
          @constraints       = constraints
          @advisory_evidence = advisory_evidence
          @exclusions        = exclusions
          @definite          = definite
          @caveats           = caveats
        end

        #
        # The suggested version.
        #
        # @return [Gem::Version]
        #
        def version
          @candidate.version
        end

        #
        # Determines whether the suggestion is definite. A suggestion is
        # not definite when the chosen candidate comes from a source or
        # platform not covered by the explicit project constraints.
        #
        # @return [Boolean]
        #
        def definite?
          @definite
        end

        #
        # Evidence that the chosen version is minimal: every smaller
        # candidate together with the reasons it was excluded.
        #
        # @return [Array<Evaluation>]
        #
        def minimality_evidence
          @exclusions.select { |evaluation| evaluation.version < version }
        end

        #
        # Converts the suggestion to a Hash.
        #
        # @return [Hash{Symbol => Object}]
        #
        def to_h
          {
            type: :remediation_suggestion,
            gem:  @gem,
            version: version,
            definite: definite?,
            constraints: @constraints.map(&:to_s),
            advisory_evidence: @advisory_evidence.map { |match|
              {
                advisory:    match[:advisory].id,
                status:      match[:status],
                requirement: match[:requirement].to_s
              }
            },
            exclusions: @exclusions.map { |evaluation|
              {
                version: evaluation.version,
                reasons: evaluation.reasons.map { |reason|
                  reason.merge(
                    requirement: reason[:requirement]&.to_s,
                    advisory:    reason[:advisory]&.id
                  ).compact
                }
              }
            },
            caveats: @caveats
          }
        end

      end

      #
      # The result when no candidate can avoid all advisories while
      # satisfying the project constraints.
      #
      class Unsatisfiable

        # The gem name.
        #
        # @return [String]
        attr_reader :gem

        # Evaluations of every candidate, preserving the actual exclusion
        # reasons.
        #
        # @return [Array<Evaluation>]
        attr_reader :exclusions

        # The candidate versions that passed the prerelease and project
        # constraint filters, before advisory checks.
        #
        # @return [Array<Gem::Version>]
        attr_reader :constraint_survivors

        # Maps each advisory id to the candidate versions (out of
        # {#constraint_survivors}) that avoid that specific advisory.
        # Demonstrates that each advisory may be individually avoidable
        # even when no common candidate exists.
        #
        # @return [Hash{String => Array<Gem::Version>}]
        attr_reader :advisory_survivors

        #
        # Initializes the unsatisfiable result.
        #
        def initialize(gem:,exclusions:,constraint_survivors:,advisory_survivors:)
          @gem                  = gem
          @exclusions           = exclusions
          @constraint_survivors = constraint_survivors
          @advisory_survivors   = advisory_survivors
        end

        #
        # Determines whether the result is definite (it never is a
        # suggestion).
        #
        # @return [false]
        #
        def definite?
          false
        end

        #
        # Converts the result to a Hash.
        #
        # @return [Hash{Symbol => Object}]
        #
        def to_h
          {
            type: :remediation_unsatisfiable,
            gem:  @gem,
            constraint_survivors: @constraint_survivors,
            advisory_survivors: @advisory_survivors,
            exclusions: @exclusions.map { |evaluation|
              {
                version: evaluation.version,
                reasons: evaluation.reasons.map { |reason|
                  reason.merge(
                    requirement: reason[:requirement]&.to_s,
                    advisory:    reason[:advisory]&.id
                  ).compact
                }
              }
            }
          }
        end

      end

      # The gem name.
      #
      # @return [String]
      attr_reader :gem

      # The candidate versions to consider.
      #
      # @return [Array<Candidate>]
      attr_reader :candidates

      # The explicit project constraints.
      #
      # @return [Array<Gem::Requirement>]
      attr_reader :constraints

      # The advisories the selected version must avoid.
      #
      # @return [Array<Advisory>]
      attr_reader :advisories

      #
      # Initializes the remediation.
      #
      # @param [String] gem
      #   The gem name.
      #
      # @param [Array<String, Gem::Version, Hash, Candidate>] versions
      #   The finite, caller-provided list of candidate versions. Entries
      #   may be version strings, or Hashes of the form
      #   `{version:, source:, platform:}`.
      #
      # @param [Array<Gem::Requirement, String>] constraints
      #   The explicit project constraints (ie: from the `Gemfile`).
      #
      # @param [Array<Advisory>] advisories
      #   The advisories the selected version must avoid.
      #
      # @param [Boolean] allow_prerelease
      #   Whether prerelease versions are permitted.
      #
      # @param [Array<Symbol, String>, nil] covered_sources
      #   The sources the explicit constraints are known to cover.
      #   Candidates from any other source cannot yield a definite
      #   suggestion.
      #
      # @param [Array<Symbol, String>, nil] covered_platforms
      #   The platforms the explicit constraints are known to cover.
      #   Candidates for any other platform cannot yield a definite
      #   suggestion.
      #
      def initialize(gem:,versions:,constraints: [],advisories: [],allow_prerelease: false,covered_sources: nil,covered_platforms: nil)
        @gem              = gem
        @candidates       = versions.map { |entry| coerce_candidate(entry) }
                                    .uniq { |candidate| [candidate.version, candidate.source, candidate.platform] }
                                    .sort
        @constraints      = constraints.map { |requirement| coerce_requirement(requirement) }
        @advisories       = advisories
        @allow_prerelease = allow_prerelease
        @covered_sources   = Array(covered_sources).map(&:to_sym)
        @covered_platforms = Array(covered_platforms).map(&:to_sym)
      end

      #
      # Selects the minimal candidate version that avoids every advisory
      # and satisfies every project constraint.
      #
      # @return [Suggestion, Unsatisfiable]
      #   A {Suggestion} when a common candidate exists, otherwise an
      #   {Unsatisfiable} result explaining why no intersection exists.
      #
      def suggest
        evaluations = @candidates.map { |candidate| evaluate(candidate) }
        excluded    = evaluations.select(&:excluded?)
        survivors   = evaluations.reject(&:excluded?)

        if survivors.empty?
          return Unsatisfiable.new(
            gem:                  @gem,
            exclusions:           excluded,
            constraint_survivors: constraint_survivors(evaluations),
            advisory_survivors:   advisory_survivors(evaluations)
          )
        end

        covered, uncovered = survivors.partition { |evaluation| covered?(evaluation.candidate) }

        if covered.empty?
          chosen   = uncovered.first
          definite = false
          caveats  = uncovered_caveats(chosen.candidate)
        else
          chosen   = covered.first
          definite = true
          caveats  = []

          smaller_uncovered = uncovered.select { |evaluation| evaluation.version < chosen.version }

          smaller_uncovered.each do |evaluation|
            caveats.concat(uncovered_caveats(evaluation.candidate,prefix: "smaller candidate #{evaluation.version} was not selected:"))
          end
        end

        Suggestion.new(
          gem:               @gem,
          candidate:         chosen.candidate,
          constraints:       @constraints,
          advisory_evidence: chosen.advisory_matches,
          exclusions:        excluded,
          definite:          definite,
          caveats:           caveats
        )
      end

      #
      # Selects the minimal safe version for the gem.
      #
      # @param [Hash] options
      #   Additional options (see {#initialize}).
      #
      # @return [Suggestion, Unsatisfiable]
      #
      def self.suggest(**options)
        new(**options).suggest
      end

      private

      #
      # Coerces a version list entry into a {Candidate}.
      #
      # @param [String, Gem::Version, Hash, Candidate] entry
      #
      # @return [Candidate]
      #
      def coerce_candidate(entry)
        case entry
        when Candidate then entry
        when Hash
          entry     = entry.transform_keys(&:to_sym)
          Candidate.new(entry.fetch(:version),source: entry[:source],platform: entry[:platform])
        else
          Candidate.new(entry)
        end
      end

      #
      # Coerces a constraint into a {Gem::Requirement}.
      #
      # @param [Gem::Requirement, String, Array] requirement
      #
      # @return [Gem::Requirement]
      #
      def coerce_requirement(requirement)
        case requirement
        when Gem::Requirement then requirement
        else Gem::Requirement.new(*Array(requirement))
        end
      end

      #
      # Determines whether the candidate's source and platform are covered
      # by the explicit project constraints.
      #
      # @param [Candidate] candidate
      #
      # @return [Boolean]
      #
      def covered?(candidate)
        (candidate.source.nil?   || @covered_sources.include?(candidate.source)) &&
        (candidate.platform.nil? || @covered_platforms.include?(candidate.platform))
      end

      #
      # Evaluates a candidate against the prerelease policy, the project
      # constraints, and every advisory.
      #
      # @param [Candidate] candidate
      #
      # @return [Evaluation]
      #
      def evaluate(candidate)
        evaluation = Evaluation.new(candidate)
        version    = candidate.version

        if version.prerelease? && !@allow_prerelease
          evaluation.exclude!(type: :prerelease)
        end

        @constraints.each do |requirement|
          unless requirement.satisfied_by?(version)
            evaluation.exclude!(type: :constraint, requirement: requirement)
          end
        end

        @advisories.each do |advisory|
          if (requirement = advisory.patched_versions.find { |patched| patched === version })
            evaluation.match!(advisory: advisory, status: :patched, requirement: requirement)
          elsif (requirement = advisory.unaffected_versions.find { |unaffected| unaffected === version })
            evaluation.match!(advisory: advisory, status: :unaffected, requirement: requirement)
          else
            evaluation.exclude!(type: :advisory, advisory: advisory)
          end
        end

        evaluation
      end

      #
      # The versions that passed the prerelease and project constraint
      # filters, before advisory checks.
      #
      # @param [Array<Evaluation>] evaluations
      #
      # @return [Array<Gem::Version>]
      #
      def constraint_survivors(evaluations)
        evaluations.reject { |evaluation|
          evaluation.reasons.any? { |reason| reason[:type] != :advisory }
        }.map(&:version)
      end

      #
      # Maps each advisory to the constraint-satisfying versions that avoid
      # it, to show whether each advisory is individually avoidable.
      #
      # @param [Array<Evaluation>] evaluations
      #
      # @return [Hash{String => Array<Gem::Version>}]
      #
      def advisory_survivors(evaluations)
        survivors = constraint_survivors(evaluations)

        @advisories.each_with_object({}) do |advisory,hash|
          hash[advisory.id] = survivors.reject { |version| advisory.vulnerable?(version) }
        end
      end

      #
      # Builds caveat messages for an uncovered candidate.
      #
      # @param [Candidate] candidate
      #
      # @param [String, nil] prefix
      #
      # @return [Array<String>]
      #
      def uncovered_caveats(candidate,prefix: nil)
        caveats = []

        if candidate.source && !@covered_sources.include?(candidate.source)
          caveats << "source #{candidate.source.inspect} is not covered by the project constraints"
        end

        if candidate.platform && !@covered_platforms.include?(candidate.platform)
          caveats << "platform #{candidate.platform.inspect} is not covered by the project constraints"
        end

        caveats.map { |caveat| [prefix,caveat].compact.join(' ') }
      end

    end
  end
end
