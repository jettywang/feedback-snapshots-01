# encoding: utf-8
# frozen_string_literal: true
module Warden
  class SessionSerializer
    attr_reader :env

    def initialize(env)
      @env = env
    end

    def key_for(scope)
      "warden.user.#{scope}.key"
    end

    # Key used to persist the authentication level of a scope's session.
    def level_key_for(scope)
      "warden.user.#{scope}.level"
    end

    def serialize(user)
      user
    end

    def deserialize(key)
      key
    end

    # Persists the user key for the scope.
    def store(user, scope)
      return unless user
      method_name = "#{scope}_serialize"
      specialized = respond_to?(method_name)
      session[key_for(scope)] = specialized ? send(method_name, user) : serialize(user)
    end

    # Persists the authentication level that produced the scope's session.
    def store_level(scope, level)
      session[level_key_for(scope)] = Warden.coerce_authentication_level(level)
    end

    def fetch(scope)
      key = session[key_for(scope)]
      return nil unless key

      method_name = "#{scope}_deserialize"
      user = respond_to?(method_name) ? send(method_name, key) : deserialize(key)
      delete(scope) unless user
      user
    end

    # Returns the authentication level recorded for the scope, treating
    # sessions written before levels existed (or carrying an unreadable value)
    # as UNKNOWN_AUTHENTICATION_LEVEL.
    def fetch_level(scope)
      return nil unless stored?(scope)

      raw = session[level_key_for(scope)]
      Warden.coerce_authentication_level(raw) || Warden::UNKNOWN_AUTHENTICATION_LEVEL
    rescue ArgumentError
      Warden::UNKNOWN_AUTHENTICATION_LEVEL
    end

    def stored?(scope)
      !!session[key_for(scope)]
    end

    def delete(scope, user=nil)
      session.delete(key_for(scope))
      session.delete(level_key_for(scope))
    end

    # We can't cache this result because the session can be lazy loaded
    def session
      env["rack.session"] || {}
    end
  end # SessionSerializer
end # Warden
