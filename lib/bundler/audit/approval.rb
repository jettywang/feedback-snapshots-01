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

require 'date'

module Bundler
  module Audit
    #
    # Represents a single approval to ignore an advisory. An approval always
    # references an advisory by one of its identifiers and may optionally
    # bind the gem the approval was granted for and an expiration date.
    #
    class Approval

      # The advisory identifier the approval references.
      #
      # @return [String]
      attr_reader :advisory

      # The gem name the approval was granted for, if bound.
      #
      # @return [String, nil]
      attr_reader :gem

      # The date the approval expires on, if any.
      #
      # @return [Date, nil]
      attr_reader :expires

      #
      # Initializes the approval.
      #
      # @param [String] advisory
      #   The advisory identifier the approval references.
      #
      # @param [String, nil] gem
      #   The gem name the approval was granted for.
      #
      # @param [Date, String, nil] expires
      #   The date the approval expires on.
      #
      # @raise [ArgumentError]
      #   The advisory identifier was missing.
      #
      def initialize(advisory, gem: nil, expires: nil)
        unless advisory
          raise(ArgumentError,"approval is missing the advisory identifier")
        end

        @advisory = advisory
        @gem      = gem
        @expires  = case expires
                    when Date   then expires
                    when String then Date.parse(expires)
                    end
      end

      #
      # Loads an approval from a plain advisory identifier or a Hash.
      #
      # @param [String, Hash] object
      #   The advisory identifier or a Hash with `'advisory'`/`:advisory`,
      #   optional `'gem'`/`:gem` and optional `'expires'`/`:expires` keys.
      #
      # @return [Approval]
      #
      # @raise [ArgumentError]
      #   The object could not be converted into an approval.
      #
      def self.load(object)
        case object
        when String
          new(object)
        when Hash
          new(
            object['advisory'] || object[:advisory],
            gem:     object['gem']     || object[:gem],
            expires: object['expires'] || object[:expires]
          )
        else
          raise(ArgumentError,"cannot load an approval from #{object.inspect}")
        end
      end

      #
      # Determines whether the approval explicitly binds both the gem and the
      # advisory it was granted for.
      #
      # @return [Boolean]
      #
      def bound?
        !@gem.nil?
      end

      #
      # Determines whether the approval has expired.
      #
      # @param [Date] today
      #   The date to compare against {#expires}.
      #
      # @return [Boolean]
      #
      def expired?(today=Date.today)
        !@expires.nil? && today > @expires
      end

      #
      # Converts the approval to a Hash.
      #
      # @return [Hash{Symbol => Object}]
      #
      def to_h
        {
          advisory: @advisory,
          gem:      @gem,
          expires:  @expires
        }
      end

      alias to_s advisory

    end
  end
end
