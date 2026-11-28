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

require 'bundler/audit/results/result'

module Bundler
  module Audit
    module Results
      #
      # Describes the policy decision for a single gem source.
      #
      # Unlike {InsecureSource}, which is only emitted when a source was
      # explicitly rejected, a source assessment is produced for every source
      # that was inspected. This keeps a "blocked" decision distinct from an
      # "undetermined" one where the identity of the source could not be
      # resolved.
      #
      class SourceAssessment < Result

        # The disposition values.
        #
        # * `:allowed` - the source matched the project policy.
        # * `:blocked` - the source was explicitly rejected.
        # * `:undetermined` - the source could not be classified because its
        #   identity could not be established.
        DISPOSITIONS = [:allowed, :blocked, :undetermined]

        # The source URI.
        #
        # @return [String]
        attr_reader :source

        # The disposition of the source.
        #
        # @return [:allowed, :blocked, :undetermined]
        attr_reader :disposition

        # The reason for the disposition.
        #
        # @return [String]
        attr_reader :reason

        # The evidence collected while classifying the source.
        #
        # @return [Hash{Symbol => Object}]
        attr_reader :evidence

        #
        # Initializes the source assessment.
        #
        # @param [String] source
        #
        # @param [:allowed, :blocked, :undetermined] disposition
        #
        # @param [String] reason
        #
        # @param [Hash{Symbol => Object}] evidence
        #
        def initialize(source,disposition,reason:,evidence: {})
          unless DISPOSITIONS.include?(disposition)
            raise(ArgumentError,"unknown source disposition: #{disposition.inspect}")
          end

          @source      = source.to_s
          @disposition = disposition
          @reason      = reason.to_s
          @evidence    = evidence
        end

        #
        # Determines whether the source was explicitly rejected.
        #
        # @return [Boolean]
        #
        def blocked?
          @disposition == :blocked
        end

        #
        # Determines whether the source identity could not be established.
        #
        # @return [Boolean]
        #
        def undetermined?
          @disposition == :undetermined
        end

        #
        # Determines whether the source was allowed.
        #
        # @return [Boolean]
        #
        def allowed?
          @disposition == :allowed
        end

        #
        # Determines whether the assessment still permits the release.
        #
        # Undetermined sources are not evidence of an explicit policy
        # violation, but they also are not an approval. Only an explicit
        # `:allowed` disposition clears the source.
        #
        # @return [Boolean]
        #
        def permits_release?
          allowed?
        end

        #
        # Compares the assessment with another result.
        #
        # @param [Result] other
        #
        # @return [Boolean]
        #
        def ==(other)
          self.class == other.class &&
            @source == other.source &&
            @disposition == other.disposition
        end

        #
        # Converts the assessment to a String.
        #
        # @return [String]
        #
        def to_s
          "#{@source}: #{@disposition}"
        end

        #
        # Converts the assessment to a Hash.
        #
        # @return [Hash{Symbol => Object}]
        #
        def to_h
          {
            type:        :source_assessment,
            source:      @source,
            disposition: @disposition,
            reason:      @reason,
            evidence:    @evidence
          }
        end

      end
    end
  end
end
