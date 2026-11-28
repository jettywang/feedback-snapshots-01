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
      # Represents an insecure gem source (ex: `git://...` or `http://...`).
      #
      class InsecureSource < Result

        # The insecure `git://` or `http://` URI.
        #
        # @return [URI::Generic, URI::HTTP]
        attr_reader :source

        # The reason the source was rejected.
        #
        # @return [String]
        attr_reader :reason

        # The evidence collected while classifying the source.
        #
        # @return [Hash{Symbol => Object}]
        attr_reader :evidence

        #
        # Initializes the insecure source result.
        #
        # @param [URI::Generic, URI::HTTP] source
        #   The insecure `git://` or `http://` URI.
        #
        # @param [String] reason
        #   The reason the source was rejected.
        #
        # @param [Hash{Symbol => Object}] evidence
        #   The evidence collected while classifying the source.
        #
        def initialize(source,reason: 'insecure source',evidence: {})
          @source   = source
          @reason   = reason.to_s
          @evidence = evidence
        end

        #
        # The source result always blocks the release.
        #
        # @return [:blocked]
        #
        def disposition
          :blocked
        end

        #
        # Insecure sources always block the release.
        #
        # @return [Boolean]
        #
        def blocked?
          true
        end

        #
        # Insecure sources were identified, so they are not undetermined.
        #
        # @return [Boolean]
        #
        def undetermined?
          false
        end

        #
        # Insecure sources are not an approval.
        #
        # @return [Boolean]
        #
        def allowed?
          false
        end

        #
        # Insecure sources do not permit the release.
        #
        # @return [Boolean]
        #
        def permits_release?
          false
        end

        #
        # Compares the insecure source with another result.
        #
        # @param [Result] other
        #
        # @return [Boolean]
        #
        def ==(other)
          self.class == other.class && @source == other.source
        end

        #
        # Converts the insecure source result to a String.
        #
        # @return [String]
        #
        def to_s
          @source.to_s
        end

        #
        # Converts the insecure source into a Hash.
        #
        # @return [Hash{Symbol => Object}]
        #
        def to_h
          {
            type:        :insecure_source,
            source:      @source,
            disposition: disposition,
            reason:      @reason,
            evidence:    @evidence
          }
        end

      end
    end
  end
end
