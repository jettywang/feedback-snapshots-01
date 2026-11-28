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
    # A time-limited exemption for a version advisory.
    #
    # Exemptions only apply to results produced by {Scanner#scan_specs}.
    # They never suppress results produced by {Scanner#scan_sources}; source
    # policy decisions have their own evidence and disposition.
    #
    # @since 0.10.0
    #
    class Exemption

      # The advisory identifier covered by the exemption.
      #
      # @return [String]
      attr_reader :advisory

      # The gem the exemption is bound to, if any.
      #
      # @return [String, nil]
      attr_reader :gem

      # The reason the exemption was approved.
      #
      # @return [String]
      attr_reader :reason

      # The last date on which the exemption is effective.
      #
      # @return [Date, nil]
      attr_reader :expires_on

      # Who approved the exemption.
      #
      # @return [String, nil]
      attr_reader :approved_by

      #
      # Initializes the exemption.
      #
      # @param [String] advisory
      #   The advisory identifier covered by the exemption.
      #
      # @param [String] reason
      #   The reason the exemption was approved.
      #
      # @param [String, nil] gem
      #   The gem the exemption is bound to.
      #
      # @param [Date, String, nil] expires_on
      #   The last date on which the exemption is effective.
      #
      # @param [String, nil] approved_by
      #   Who approved the exemption.
      #
      # @raise [ArgumentError]
      #   The advisory or reason was missing.
      #
      def initialize(advisory:,reason:,gem: nil,expires_on: nil,approved_by: nil)
        if advisory.nil? || advisory.to_s.empty?
          raise(ArgumentError,"exemption advisory must be a non-empty String")
        end

        if reason.nil? || reason.to_s.empty?
          raise(ArgumentError,"exemption reason must be a non-empty String")
        end

        @advisory    = advisory.to_s
        @gem         = gem && gem.to_s
        @reason      = reason.to_s
        @expires_on  = case expires_on
                       when nil  then nil
                       when Date then expires_on
                       else
                         begin
                           Date.parse(expires_on.to_s)
                         rescue ArgumentError
                           raise(ArgumentError,"invalid exemption expires_on: #{expires_on.inspect}")
                         end
                       end
        @approved_by = approved_by && approved_by.to_s
      end

      #
      # Builds an exemption from a configuration Hash.
      #
      # @param [Hash] hash
      #
      # @return [Exemption]
      #
      def self.from_h(hash)
        value = lambda { |key| hash[key] || hash[key.to_s] }

        new(
          advisory:    value[:advisory],
          gem:         value[:gem],
          reason:      value[:reason],
          expires_on:  value[:expires_on],
          approved_by: value[:approved_by]
        )
      end

      #
      # Determines whether the exemption is still effective.
      #
      # @param [Date] on
      #
      # @return [Boolean]
      #
      def active?(on: Date.today)
        @expires_on.nil? || on <= @expires_on
      end

      #
      # Determines whether the exemption has expired.
      #
      # @param [Date] on
      #
      # @return [Boolean]
      #
      def expired?(on: Date.today)
        !active?(on: on)
      end

      #
      # Determines whether the exemption covers an advisory and gem.
      #
      # @param [Advisory] advisory
      #
      # @param [Gem::Specification, nil] gem
      #
      # @return [Boolean]
      #
      def applies_to?(advisory,gem=nil)
        identifiers = [advisory.id, *advisory.identifiers]

        return false unless identifiers.include?(@advisory)
        return false if @gem && gem && @gem != gem.name

        true
      end

      #
      # Converts the exemption to a Hash.
      #
      # @return [Hash{Symbol => Object}]
      #
      def to_h
        {
          advisory:    @advisory,
          gem:         @gem,
          reason:      @reason,
          expires_on:  @expires_on && @expires_on.to_s,
          approved_by: @approved_by
        }
      end

    end
  end
end
