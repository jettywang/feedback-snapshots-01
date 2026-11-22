# encoding: utf-8
# frozen_string_literal: true
require 'forwardable'

require 'warden/mixins/common'
require 'warden/proxy'
require 'warden/manager'
require 'warden/errors'
require 'warden/session_serializer'
require 'warden/strategies'
require 'warden/strategies/base'

module Warden
  class NotAuthenticated < StandardError; end

  # Sessions written before authentication levels existed carry no level.
  # They are treated as unknown: ordinary (level-less) authentication keeps
  # working, but they can never satisfy a positive level requirement.
  UNKNOWN_AUTHENTICATION_LEVEL = 0

  # A strategy that succeeds without declaring a level performed an ordinary
  # login. This is also the level used by #set_user when none is given.
  DEFAULT_AUTHENTICATION_LEVEL = 1

  # Coerces a declared authentication level into a non-negative Integer.
  # Raises ArgumentError with an actionable message for invalid values.
  def self.coerce_authentication_level(value)
    if value.nil?
      nil
    else
      level = begin
        Integer(value)
      rescue ArgumentError, TypeError
        nil
      end

      if level.nil? || level < 0
        raise ArgumentError, "authentication level must be a non-negative integer, got #{value.inspect}"
      end
      level
    end
  end

  module Test
    autoload :WardenHelpers,  'warden/test/warden_helpers'
    autoload :Helpers,        'warden/test/helpers'
    autoload :Mock,        'warden/test/mock'
  end

  # Provides helper methods to warden for testing.
  #
  # To setup warden in test mode call the +test_mode!+ method on warden
  #
  # @example
  #   Warden.test_mode!
  #
  # This will provide a number of methods.
  # Warden.on_next_request(&blk) - captures a block which is yielded the warden proxy on the next request
  # Warden.test_reset! - removes any captured blocks that would have been executed on the next request
  #
  # Warden.test_reset! should be called in after blocks for rspec, or teardown methods for Test::Unit
  def self.test_mode!
    unless Warden::Test::WardenHelpers === Warden
      Warden.extend Warden::Test::WardenHelpers
      Warden::Manager.on_request do |proxy|
        unless proxy.asset_request?
          while blk = Warden._on_next_request.shift
            blk.call(proxy)
          end
        end
      end
    end
    true
  end
end
