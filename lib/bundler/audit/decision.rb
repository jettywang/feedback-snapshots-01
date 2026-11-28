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
    # Represents the outcome of checking an {Approval} against the advisory
    # database, along with the basis for the decision.
    #
    class Decision

      # All possible decision statuses.
      STATUSES = [:applied, :expired, :review]

      # The approval that was checked.
      #
      # @return [Approval]
      attr_reader :approval

      # The gem the decision applies to, if any.
      #
      # @return [Gem::Specification, nil]
      attr_reader :gem

      # The advisory the decision applies to, if any.
      #
      # @return [Advisory, nil]
      attr_reader :advisory

      # The status of the decision (`:applied`, `:expired` or `:review`).
      #
      # @return [Symbol]
      attr_reader :status

      # The human readable basis for the decision.
      #
      # @return [String]
      attr_reader :reason

      #
      # Initializes the decision.
      #
      # @param [Approval] approval
      #   The approval that was checked.
      #
      # @param [Symbol] status
      #   The status of the decision (`:applied`, `:expired` or `:review`).
      #
      # @param [String] reason
      #   The human readable basis for the decision.
      #
      # @param [Gem::Specification, nil] gem
      #   The gem the decision applies to.
      #
      # @param [Advisory, nil] advisory
      #   The advisory the decision applies to.
      #
      # @raise [ArgumentError]
      #   The status was not one of {STATUSES}.
      #
      def initialize(approval:, status:, reason:, gem: nil, advisory: nil)
        unless STATUSES.include?(status)
          raise(ArgumentError,"unknown decision status #{status.inspect}")
        end

        @approval = approval
        @gem      = gem
        @advisory = advisory
        @status   = status
        @reason   = reason
      end

      #
      # Determines whether the approval was applied.
      #
      # @return [Boolean]
      #
      def applied?
        @status == :applied
      end

      #
      # Converts the decision to a String.
      #
      # @return [String]
      #
      def to_s
        target = if @gem && @advisory
                   "#{@gem.name} (#{@gem.version}) / #{@advisory.id}"
                 else
                   @approval.advisory
                 end

        "[#{@status}] #{target}: #{@reason}"
      end

      #
      # Converts the decision to a Hash.
      #
      # @return [Hash{Symbol => Object}]
      #
      def to_h
        {
          approval: @approval.to_h,
          gem:      @gem && {name: @gem.name, version: @gem.version},
          advisory: @advisory && @advisory.id,
          status:   @status,
          reason:   @reason
        }
      end

    end
  end
end
