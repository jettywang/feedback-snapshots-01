# frozen_string_literal: true

module Sorcery
  module Controller
    module Submodules
      # Controller-side half of the reset_password submodule.
      #
      # When `reset_password_invalidate_active_sessions_enabled` is on, a password
      # change that actually commits rotates the user's persistent login token and
      # records a session cutoff (see the model submodule). This module makes that
      # transition usable from a controller:
      #
      # * `change_password` / `change_password!` delegate to the user and re-stamp
      #   only the session that performed the committed change, so the user can
      #   finish the flow without logging in again.
      # * A prepended before_action rejects sessions whose login_time predates the
      #   persisted cutoff. Those requests are treated exactly like a normal
      #   logout: the session is reset and the stale remember-me cookie is dropped.
      #
      # Nothing happens when the option is off, so existing reset and logout
      # behavior is unchanged.
      module ResetPassword
        def self.included(base)
          base.send(:include, InstanceMethods)

          Config.after_login << :register_password_change_login_time
          Config.after_remember_me << :register_password_change_login_time

          base.prepend_before_action :validate_password_change_session
        end

        module InstanceMethods
          # Changes the password of the current user (or the given user) and, only
          # when the change committed, keeps this session usable. A failed or
          # rolled-back change returns its falsy result and preserves nothing.
          def change_password(new_password, user: nil, **options)
            user ||= current_user
            return false unless user

            result = user.change_password(new_password, **options)
            preserve_session_after_password_change!(user) if result && password_change_committed?(user)
            result
          end

          def change_password!(new_password, user: nil)
            user ||= current_user
            return false unless user

            result = user.change_password!(new_password)
            preserve_session_after_password_change!(user) if password_change_committed?(user)
            result
          end

          # Re-stamps the session so it survives the cutoff written by the change.
          # Call this only after the change has been persisted; a change that was
          # not committed must not extend the current session.
          def preserve_session_after_password_change!(user = nil)
            user ||= current_user
            return false unless user

            config = password_reset_config(user)
            return false unless password_change_invalidation_enabled?(config)
            return false unless config.reset_password_preserve_current_session
            return false if session[:user_id].blank? || session[:user_id].to_s != user.id.to_s

            now = Time.now.in_time_zone
            session[:login_time] = now
            session[:last_action_time] = now
            # The generation marker is the exact cutoff this change wrote. If
            # the surrounding transaction rolls back, the database keeps the
            # previous cutoff (or none at all), so the marker no longer matches
            # and cannot exempt the session from a generation it never persisted.
            session[:password_change_cutoff] = password_change_cutoff_generation(user.password_change_invalidated_at)
            refresh_remember_me_cookie_after_password_change(user)
            true
          end

          protected

          # Runs before every action. Only sessions that predate the persisted
          # cutoff are dropped; the transition is opt-in and inert when the model
          # has no cutoff attribute. The session that announced the persisted
          # cutoff is the one that performed the change and is left alone.
          def validate_password_change_session
            config = password_reset_config
            return unless password_change_invalidation_enabled?(config)

            user = current_user
            if user.nil?
              discard_stale_remember_me_cookie if stale_remember_me_cookie?
              return
            end

            cutoff = password_change_cutoff(user, config)
            return if cutoff.blank?
            return if session_password_change_generation?(cutoff)

            time = session[:login_time] || session[:last_action_time]
            # Without a stamped login time we cannot attribute the session to the
            # old credentials, so leave it alone (same as session_timeout).
            return if time.blank?
            return unless time.to_time < cutoff

            reset_sorcery_session
            remove_instance_variable :@current_user if defined? @current_user
            discard_stale_remember_me_cookie
          end

          # Stamps the login time for every session, so the cutoff check works
          # even when the session_timeout submodule is not enabled.
          def register_password_change_login_time(user, _credentials = nil)
            config = password_reset_config(user)
            return unless password_change_invalidation_enabled?(config)

            now = Time.now.in_time_zone
            session[:login_time] = now
            session[:last_action_time] = now
          end

          # Lets the controller submodule coexist with a model that does not load
          # the reset_password model submodule; it then simply stays inert.
          def password_change_invalidation_enabled?(config)
            config.respond_to?(:reset_password_invalidate_active_sessions_enabled) &&
              config.reset_password_invalidate_active_sessions_enabled
          end

          def password_change_committed?(user)
            user.respond_to?(:password_change_invalidated_at) && user.password_change_invalidated_at.present?
          end

          # True when this session announced the generation of the persisted
          # cutoff, i.e. it is the session that performed the committed change.
          # The comparison is exact, so a rolled-back change whose cutoff never
          # persisted does not match the cutoff still in the database.
          def session_password_change_generation?(cutoff)
            stamp = session[:password_change_cutoff]
            return false if stamp.blank?

            password_change_cutoff_generation(stamp) == password_change_cutoff_generation(cutoff)
          rescue StandardError
            false
          end

          def password_change_cutoff_generation(time)
            return if time.nil?

            Time.zone ? time.in_time_zone.to_f : time.to_time.to_f
          end

          def password_change_cutoff(user, config)
            attribute = config.reset_password_invalidate_sessions_before_attribute_name
            return unless user.respond_to?(attribute)

            user.public_send(attribute)
          end

          def password_reset_config(user = nil)
            return user.sorcery_config if user.respond_to?(:sorcery_config)

            user_class.sorcery_config
          end

          def cookies_available?
            instance_variable_defined?(:@_request) && !request.nil?
          rescue StandardError
            false
          end

          # A remember-me cookie whose token no longer resolves was issued before
          # a reset; the persistent login is gone, so drop the cookie instead of
          # sending the browser back with it.
          def stale_remember_me_cookie?
            return false unless cookies_available?
            return false if cookies.signed[:remember_me_token].blank?

            user_class.sorcery_adapter.find_by_remember_me_token(cookies.signed[:remember_me_token]).nil?
          rescue StandardError
            false
          end

          def discard_stale_remember_me_cookie
            return unless cookies_available?

            cookies.delete(:remember_me_token, domain: Config.cookie_domain)
          end

          # The rotation invalidated every old remember-me cookie, including the
          # one this browser may hold. Only a browser that already had a remember-me
          # cookie gets the freshly minted token back, so the reset does not grant
          # a persistent login the user never asked for. Other browsers keep the
          # old token, which no longer resolves.
          def refresh_remember_me_cookie_after_password_change(user)
            return unless cookies_available?
            return unless Config.respond_to?(:remember_me_httponly)
            return if cookies.signed[:remember_me_token].blank?

            config = user.sorcery_config
            token_attribute = config.remember_me_token_attribute_name
            return unless user.respond_to?(token_attribute)
            return if user.public_send(token_attribute).blank?

            cookies.signed[:remember_me_token] = {
              value: user.public_send(token_attribute),
              expires: user.public_send(config.remember_me_token_expires_at_attribute_name),
              httponly: Config.remember_me_httponly,
              domain: Config.cookie_domain
            }
          end
        end
      end
    end
  end
end
