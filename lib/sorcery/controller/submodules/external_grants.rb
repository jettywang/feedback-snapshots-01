# frozen_string_literal: true

module Sorcery
  module Controller
    module Submodules
      # This submodule is the limited-authorization entry point from the external
      # provider callback to business actions.
      #
      # After an external login, the scopes the provider actually granted are
      # synced into per-purpose grant records - but only for purposes listed in
      # Config.external_grant_purposes. Business (e.g. admin) actions then guard
      # themselves with require_external_grant(purpose), which derives access
      # from the approved purpose, the provider of the current session and the
      # current scope, and can tell unconfirmed, granted and stopped grants apart.
      #
      # Requires the :external submodule to be listed before :external_grants.
      module ExternalGrants
        SESSION_KEY = :external_grants

        def self.included(base)
          base.send(:include, InstanceMethods)

          Config.module_eval do
            class << self
              attr_accessor :external_grant_purposes

              def merge_external_grants_defaults!
                @defaults.merge!(:@external_grant_purposes => {})
              end
            end
            merge_external_grants_defaults!
          end
        end

        module InstanceMethods
          protected

          # Logs the user in from the provider callback, then syncs the approved
          # grant purposes from the scopes the provider actually granted.
          # A failing grant sync never breaks the login itself.
          def login_from(provider_name, should_remember = false)
            user = super
            sorcery_sync_external_grants(provider_name, user) if user
            user
          end

          # Records the current provider/scope in the session and registers a
          # grant for every approved purpose the current scope covers.
          # Returns false when the sync fails; the login stays usable and the
          # previously persisted grants remain the source of truth.
          def sorcery_sync_external_grants(provider_name, user)
            scope = sorcery_current_external_scope
            session[ExternalGrants::SESSION_KEY] = { 'provider' => provider_name.to_s, 'scope' => scope }

            sorcery_approved_grant_purposes.each do |purpose, required_scope|
              next unless Model::Submodules::ExternalGrants.scope_covers?(scope, required_scope)

              user.register_external_grant(provider_name, purpose, scope)
            end
            true
          rescue StandardError
            false
          end

          # before_action guard for actions that need an approved external grant,
          # e.g. before_action -> { require_external_grant(:admin_console) }.
          def require_external_grant(purpose)
            reason = sorcery_external_grant_failure(purpose)
            return true if reason.nil?

            external_grant_access_denied(purpose, reason)
            false
          end

          # nil when access is granted, otherwise the distinguishable reason:
          # :purpose_not_approved, :not_logged_in, :no_provider, :no_grant,
          # :unconfirmed, :stopped or :scope_insufficient.
          def sorcery_external_grant_failure(purpose)
            purposes = sorcery_approved_grant_purposes
            return :purpose_not_approved unless purposes.key?(purpose.to_sym)
            return :not_logged_in unless current_user

            grant_session = session[ExternalGrants::SESSION_KEY] || {}
            provider = grant_session['provider']
            return :no_provider if provider.blank?

            status = current_user.external_grant_status(provider, purpose)
            return :no_grant if status.nil?
            return status.to_sym if status != Model::Submodules::ExternalGrants::STATUS_GRANTED

            unless Model::Submodules::ExternalGrants.scope_covers?(grant_session['scope'], purposes[purpose.to_sym])
              return :scope_insufficient
            end

            nil
          end

          # Overridable hook called when require_external_grant denies access.
          def external_grant_access_denied(_purpose, _reason)
            head :forbidden
          end

          def sorcery_approved_grant_purposes
            Config.external_grant_purposes.each_with_object({}) do |(purpose, scope), purposes|
              purposes[purpose.to_sym] = scope
            end
          end

          def sorcery_current_external_scope
            params = @access_token.respond_to?(:params) ? @access_token.params : {}
            raw_scope = params['scope'] || params[:scope]
            Model::Submodules::ExternalGrants.normalize_scope(raw_scope).join(' ')
          end
        end
      end
    end
  end
end
