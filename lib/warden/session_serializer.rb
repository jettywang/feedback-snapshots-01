# encoding: utf-8
# frozen_string_literal: true
module Warden
  class SessionSerializer
    # Return contract for the block registered through
    # Warden::Manager.serialize_from_session.
    #
    # A deserialization block can return one of these objects instead of a bare
    # user (or nil) to tell Warden why the stored session key could not be turned
    # back into a user. This matters when, for example, an account was disabled
    # after the session was issued: the cookie may still be valid even though the
    # site must no longer trust the principal it represents.
    #
    # Statuses:
    #   :ok            - the user was reconstituted and remains usable
    #   :denied        - the principal is permanently rejected (e.g. a disabled
    #                    account). The stored session is always removed.
    #   :unconfirmed   - the user could not be confirmed temporarily (e.g. a
    #                    storage outage). Whether the stored session survives is
    #                    decided by configuration, see
    #                    Warden::Config#clear_stored_session_on_unconfirmed?
    class SessionResult
      STATUSES = [:ok, :denied, :unconfirmed].freeze

      attr_reader :status, :user, :reason

      def initialize(status, user = nil, reason = nil)
        unless STATUSES.include?(status)
          raise ArgumentError, "unknown session result status #{status.inspect}"
        end
        @status, @user, @reason = status, user, reason
      end

      # Builds a result for a user that was reconstituted successfully.
      def self.ok(user, reason = nil)
        new(:ok, user, reason)
      end

      # Builds a result for a principal that must never be accepted again.
      def self.denied(reason = nil)
        new(:denied, nil, reason)
      end

      # Builds a result for a principal that could not be confirmed because of a
      # temporary condition.
      def self.unconfirmed(reason = nil)
        new(:unconfirmed, nil, reason)
      end

      def ok?
        status == :ok
      end

      def denied?
        status == :denied
      end

      def unconfirmed?
        status == :unconfirmed
      end
    end

    attr_reader :env, :config

    def initialize(env, config = nil)
      @env = env
      @config = config
    end

    def key_for(scope)
      "warden.user.#{scope}.key"
    end

    def serialize(user)
      user
    end

    def deserialize(key)
      key
    end

    def store(user, scope)
      return unless user
      method_name = "#{scope}_serialize"
      specialized = respond_to?(method_name)
      session[key_for(scope)] = specialized ? send(method_name, user) : serialize(user)
    end

    def fetch(scope)
      key = session[key_for(scope)]
      return nil unless key

      method_name = "#{scope}_deserialize"
      result = respond_to?(method_name) ? send(method_name, key) : deserialize(key)

      resolve_result(scope, result)
    end

    # Removes the stored session key for a scope. A denied principal can never
    # recover its previous session, while an unconfirmed one is only removed when
    # the configured security policy demands it.
    def resolve_result(scope, result)
      if result.is_a?(SessionResult)
        case result.status
        when :ok
          result.user
        when :denied
          delete(scope)
          nil
        when :unconfirmed
          delete(scope) if clear_stored_session_on_unconfirmed?
          nil
        end
      else
        delete(scope) unless result
        result
      end
    end

    def clear_stored_session_on_unconfirmed?
      config ? !!config[:clear_stored_session_on_unconfirmed] : false
    end

    def stored?(scope)
      !!session[key_for(scope)]
    end

    def delete(scope, user=nil)
      session.delete(key_for(scope))
    end

    # We can't cache this result because the session can be lazy loaded
    def session
      env["rack.session"] || {}
    end
  end # SessionSerializer
end # Warden
