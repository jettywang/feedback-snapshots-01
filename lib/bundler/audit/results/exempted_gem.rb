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

require 'bundler/audit/exemption'
require 'bundler/audit/results/result'

module Bundler
  module Audit
    module Results
      #
      # Represents a version advisory that was approved through a time-limited
      # exemption.
      #
      # This result is retained in the report so that approved items and the
      # reason for their approval remain auditable.
      #
      class ExemptedGem < Result

        # The specification of the exempted gem.
        #
        # @return [Gem::Specification]
        attr_reader :gem

        # The advisory that was exempted.
        #
        # @return [Advisory]
        attr_reader :advisory

        # The exemption that approved the advisory.
        #
        # @return [Exemption]
        attr_reader :exemption

        #
        # Initializes the exempted gem result.
        #
        # @param [Gem::Specification] gem
        #
        # @param [Advisory] advisory
        #
        # @param [Exemption] exemption
        #
        def initialize(gem,advisory,exemption)
          @gem       = gem
          @advisory  = advisory
          @exemption = exemption
        end

        #
        # The result was approved for release.
        #
        # @return [:approved]
        #
        def disposition
          :approved
        end

        #
        # The reason the result was approved.
        #
        # @return [String]
        #
        def reason
          @exemption.reason
        end

        #
        # The date the exemption expires.
        #
        # @return [Date, nil]
        #
        def expires_on
          @exemption.expires_on
        end

        #
        # Compares the exempted gem with another result.
        #
        # @param [Result] other
        #
        # @return [Boolean]
        #
        def ==(other)
          self.class == other.class &&
            @gem.name == other.gem.name &&
            @gem.version == other.gem.version &&
            @advisory == other.advisory &&
            @exemption.to_h == other.exemption.to_h
        end

        #
        # Converts the exempted gem result into a String.
        #
        # @return [String]
        #
        def to_s
          @advisory.id
        end

        #
        # Converts the exempted gem to a Hash.
        #
        # @return [Hash{Symbol => Object}]
        #
        def to_h
          {
            type:        :exempted_gem,
            gem:         {
              name:    @gem.name,
              version: @gem.version
            },
            advisory:    @advisory.to_h,
            disposition: disposition,
            reason:      reason,
            exemption:   @exemption.to_h
          }
        end

      end
    end
  end
end
