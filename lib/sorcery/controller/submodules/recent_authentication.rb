# frozen_string_literal: true

require 'securerandom'

module Sorcery
  module Controller
    module Submodules
      # Adds a server-side recent (step-up) authentication proof.
      #
      # The proof is deliberately kept apart from the ordinary login state:
      # restoring a session from a remember-me cookie only re-establishes the
      # ordinary identity. A sensitive action has to be explicitly confirmed
      # through `confirm_recent_authentication!`, which records the confirmation
      # time, the operation it was granted for and the session it happened in.
      #
      # Confirmation lifetime is independent from the session timeout, so a
      # long-lived ordinary session never silently satisfies a higher
      # authentication requirement.
      module RecentAuthentication
        SESSION_KEY = :recent_authentication_session_id

        def self.included(base)
          base.send(:include, InstanceMethods)
          Config.module_eval do
            class << self
              # how long in seconds a confirmation remains usable.
              attr_accessor :recent_authentication_timeout
              # persistence boundary for confirmation records. Any object that
              # implements the methods documented on
              # Sorcery::RecentAuthenticationStore::ActiveRecordStore can be used.
              attr_accessor :recent_authentication_store
              # what to invalidate on logout: :session (default), :user, or nil.
              attr_accessor :recent_authentication_revocation_on_logout
              # what to invalidate when the ordinary session times out:
              # :session (default), :user, or nil.
              attr_accessor :recent_authentication_revocation_on_timeout

              def merge_recent_authentication_defaults!
                @defaults.merge!(:@recent_authentication_timeout => 15 * 60,
                                 :@recent_authentication_store => Sorcery::RecentAuthenticationStore::ActiveRecordStore.new,
                                 :@recent_authentication_revocation_on_logout => :session,
                                 :@recent_authentication_revocation_on_timeout => :session)
              end
            end
            merge_recent_authentication_defaults!
          end

          Config.after_login << :rotate_recent_authentication_session
          Config.after_remember_me << :rotate_recent_authentication_session
          Config.before_logout << :revoke_recent_authentication_on_logout
        end

        module InstanceMethods
          # Records a fresh confirmation for the supplied operation types.
          # Only this explicit call grants a recent-authentication proof;
          # ordinary login and remember-me restoration never do.
          def confirm_recent_authentication!(*operations)
            operations = normalize_recent_authentication_operations(operations)
            raise ArgumentError, 'at least one operation is required' if operations.empty?
            return false unless logged_in?

            now = Time.now.in_time_zone
            expires_at = now + Config.recent_authentication_timeout
            token = recent_authentication_session_id
            user = current_user

            operations.map do |operation|
              recent_authentication_store.revoke_session(
                user_id: user.id,
                session_id: token,
                operations: [operation],
                at: now
              )
              recent_authentication_store.create(
                user_id: user.id,
                session_id: token,
                operation: operation,
                authenticated_at: now,
                expires_at: expires_at
              )
            end
          end

          # True when the current user confirmed one of the supplied operations
          # in this session and that confirmation has not expired or been revoked.
          # With no operations, any active confirmation in this session counts.
          def recent_authentication_valid_for?(*operations)
            return false unless logged_in?

            token = session[SESSION_KEY]
            return false unless token

            !recent_authentication_store.active(
              user_id: current_user.id,
              session_id: token,
              operations: normalize_recent_authentication_operations(operations),
              at: Time.now.in_time_zone
            ).nil?
          end
          alias recently_authenticated? recent_authentication_valid_for?

          # Expiry of the active confirmation for the supplied operations,
          # or nil when there is none.
          def recent_authentication_expires_at(*operations)
            return nil unless logged_in?

            token = session[SESSION_KEY]
            return nil unless token

            store = recent_authentication_store
            if store.respond_to?(:expires_at)
              store.expires_at(
                user_id: current_user.id,
                session_id: token,
                operations: normalize_recent_authentication_operations(operations),
                at: Time.now.in_time_zone
              )
            else
              record = store.active(
                user_id: current_user.id,
                session_id: token,
                operations: normalize_recent_authentication_operations(operations),
                at: Time.now.in_time_zone
              )
              record&.expires_at
            end
          end

          # Opaque token binding a confirmation to this session. It is rotated
          # on every login/remember-me restore and disappears with the session,
          # so another terminal can never reuse this terminal's confirmation.
          def recent_authentication_session_id
            session[SESSION_KEY] ||= SecureRandom.hex(16)
          end

          # Clears confirmations for the current session or for the user.
          # Exposed so applications can react to password changes and similar
          # events on their own schedule.
          def revoke_recent_authentication!(scope = :session, operations: nil, at: Time.now.in_time_zone)
            scope = normalize_recent_authentication_revocation(scope)
            return false unless scope

            if scope == :user
              user_id = recent_authentication_user_id
              return false unless user_id

              recent_authentication_store.revoke_user(user_id: user_id, at: at)
            else
              token = session[SESSION_KEY]
              return false unless token

              recent_authentication_store.revoke_session(
                user_id: recent_authentication_user_id,
                session_id: token,
                operations: normalize_recent_authentication_operations(operations),
                at: at
              )
            end
          end

          # To be used as a before_action on sensitive endpoints.
          # It does not treat an ordinary (or remember-me restored) session as
          # a recent confirmation.
          def require_recent_authentication(*operations)
            return true if recent_authentication_valid_for?(*operations)

            recent_authentication_failed
            false
          end

          # Override to render a custom response for an unmet requirement.
          # Signed-out visitors are sent through the configured
          # not_authenticated_action; signed-in visitors get a plain 403.
          def recent_authentication_failed
            return send(Config.not_authenticated_action) unless logged_in?

            head :forbidden
          end

          protected

          # Runs after a successful login or remember-me restoration. Any
          # confirmation bound to the previous session token must not survive
          # an identity change, whichever user it belonged to.
          def rotate_recent_authentication_session(_user = nil, _credentials = nil)
            previous = session[SESSION_KEY]
            if previous
              recent_authentication_store.revoke_session(
                session_id: previous,
                at: Time.now.in_time_zone
              )
            end

            session[SESSION_KEY] = SecureRandom.hex(16)
          end

          # Runs as a before-logout hook, while current_user is still available.
          def revoke_recent_authentication_on_logout
            revoke_recent_authentication!(Config.recent_authentication_revocation_on_logout, at: Time.now.in_time_zone)
          end

          # Called by the session timeout submodule before it resets the session.
          def revoke_recent_authentication_on_session_timeout
            revoke_recent_authentication!(Config.recent_authentication_revocation_on_timeout, at: Time.now.in_time_zone)
          end

          private

          def normalize_recent_authentication_operations(operations)
            Array(operations).flatten.compact.map(&:to_s).reject(&:empty?)
          end

          def normalize_recent_authentication_revocation(scope)
            case scope.to_s
            when 'session' then :session
            when 'user' then :user
            end
          end

          def recent_authentication_store
            Config.recent_authentication_store
          end

          # Reads the identity already established in this session. Unlike
          # `current_user`, it never triggers a remember-me restore, so logout
          # and timeout revocation cannot accidentally sign the user back in.
          def recent_authentication_user_id
            return @current_user.id if defined?(@current_user) && @current_user

            session[:user_id]
          end
        end
      end
    end
  end
end
