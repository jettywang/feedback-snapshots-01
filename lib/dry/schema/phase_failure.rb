# frozen_string_literal: true

module Dry
  module Schema
    # Error raised by a step callback to fail its phase explicitly
    #
    # Raising this error stops processing, records the failure in
    # {Result#diagnostics}, and makes the result non-deliverable. Other errors
    # raised by callbacks are not rescued.
    #
    # @example
    #   after(:rule_applier, permit: :validation) do |result|
    #     raise Dry::Schema::PhaseFailure, "security check failed"
    #   end
    #
    # @api public
    class PhaseFailure < ::StandardError
    end
  end
end
