# encoding: utf-8
# frozen_string_literal: true
module Warden
  # Holds the authentication callbacks that belong to a single mounted
  # application (one Warden::Manager instance).
  #
  # Callbacks registered through Warden::Manager itself remain global and are,
  # by definition, the only callbacks shared across applications. A registry
  # keeps the callbacks of an individual application separate from those
  # global ones.
  #
  # It reuses Warden::Hooks so the registration API, the supported conditions
  # (scope/event) and the prepend_ variants match the global registration.
  class CallbackRegistry
    include Warden::Hooks

    def initialize
      @_after_set_user    = []
      @_before_failure    = []
      @_after_failed_fetch = []
      @_before_logout     = []
      @_on_request        = []
    end

    # Returns the callbacks registered for +kind+ as a frozen array.
    # The frozen copy is captured once per request so that a callback removed
    # or added while a request is already in flight never changes the flow the
    # request started with.
    def snapshot(kind)
      public_send("_#{kind}").dup.freeze
    end
  end
end
