# encoding: utf-8
# frozen_string_literal: true
module Warden
  # A reconcilable description of a single login-related event that happened
  # during a request. Login events let an application answer "when did the
  # user actually present fresh credentials" by distinguishing a strategy
  # that just succeeded (:authentication) from a user restored from the
  # session (:fetch), a user set manually by the application (:set_user)
  # and a rejected credential attempt (:failure).
  #
  # Events are recorded on the proxy and can be inspected per request:
  #
  #   env['warden'].login_events.each do |event|
  #     logger.info(event.to_h)
  #   end
  #
  # :api: public
  class LoginEvent
    # All events a login event can describe.
    EVENTS = [:authentication, :fetch, :set_user, :failure].freeze

    # The kind of event (one of EVENTS), the scope the identity is
    # restricted to, the user object (nil for failures) and the label of
    # the strategy that produced the event (nil unless a strategy ran).
    # :api: public
    attr_reader :event, :scope, :user, :strategy, :at

    # The error raised by an after_set_user hook, if any. The error is
    # still re-raised after being recorded here.
    # :api: public
    attr_accessor :hook_error

    def initialize(event, scope, user, opts = {}) #:nodoc:
      @event, @scope, @user = event, scope, user
      @strategy   = opts[:strategy]
      @stored     = opts.fetch(:stored, false)
      @at         = opts[:at] || Time.now
      @hook_error = nil
    end

    # True only when a strategy just verified fresh credentials during
    # this request. This is the event to count when reconciling "the user
    # actually typed credentials" as opposed to session restores.
    # :api: public
    def fresh_credentials?
      event == :authentication
    end

    # True when the identity was restored from the session.
    # :api: public
    def fetched?
      event == :fetch
    end

    # True when a strategy ran and rejected the presented credentials.
    # :api: public
    def failure?
      event == :failure
    end

    # True when the identity was serialized into the session.
    # :api: public
    def stored?
      !!@stored
    end

    # True when an after_set_user hook raised while handling this event.
    # :api: public
    def hook_failed?
      !hook_error.nil?
    end

    # A plain hash of the recorded evidence, suitable for logging and
    # reconciliation.
    # :api: public
    def to_h
      {
        :event      => event,
        :scope      => scope,
        :user       => user,
        :strategy   => strategy,
        :stored     => stored?,
        :at         => at,
        :hook_error => hook_error
      }
    end
  end # LoginEvent
end # Warden
