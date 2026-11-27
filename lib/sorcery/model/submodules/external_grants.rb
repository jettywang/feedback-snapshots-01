# frozen_string_literal: true

module Sorcery
  module Model
    module Submodules
      # This submodule records the scoped grants a user authorized at an external
      # provider and exposes their lifecycle, so the application can hand only
      # approved purposes to downstream (e.g. admin) actions.
      #
      # A grant moves through three distinguishable states:
      #
      # * unconfirmed - recorded from the provider callback, not yet approved.
      # * granted     - approved for the purpose/provider/scope it was recorded with.
      # * stopped     - revoked; no longer usable even though it is still present.
      #
      # For the controller side see Sorcery::Controller::Submodules::ExternalGrants.
      module ExternalGrants
        STATUS_UNCONFIRMED = 'unconfirmed'
        STATUS_GRANTED = 'granted'
        STATUS_STOPPED = 'stopped'

        # Checks whether a granted scope covers the required one.
        # A blank required scope is always covered.
        def self.scope_covers?(granted_scope, required_scope)
          required = normalize_scope(required_scope)
          return true if required.empty?

          (required - normalize_scope(granted_scope)).empty?
        end

        # Normalizes a scope given as a string or an array into a list of entries.
        def self.normalize_scope(scope)
          entries = scope.is_a?(Array) ? scope : scope.to_s.split(/[\s,]+/)
          entries.flat_map { |entry| entry.to_s.split(/[\s,]+/) }.reject(&:empty?)
        end

        def self.included(base)
          base.sorcery_config.class_eval do
            attr_accessor :grants_class,
                          :grants_user_id_attribute_name,
                          :grant_provider_attribute_name,
                          :grant_purpose_attribute_name,
                          :grant_scope_attribute_name,
                          :grant_status_attribute_name
          end

          base.sorcery_config.instance_eval do
            @defaults.merge!(:@grants_class => nil,
                             :@grants_user_id_attribute_name => :user_id,
                             :@grant_provider_attribute_name => :provider,
                             :@grant_purpose_attribute_name => :purpose,
                             :@grant_scope_attribute_name => :scope,
                             :@grant_status_attribute_name => :status)

            reset!
          end

          base.send(:include, InstanceMethods)
        end

        module InstanceMethods
          # Returns the persisted grant for the provider/purpose pair, if any.
          def external_grant(provider, purpose)
            config = sorcery_config

            send(external_grants_association).where(
              config.grant_provider_attribute_name => provider.to_s,
              config.grant_purpose_attribute_name => purpose.to_s
            ).first
          end

          # Registers a grant for the provider/purpose pair, or refreshes the
          # scope of an existing one. New grants, and grants whose scope changed,
          # go back to unconfirmed so widened access must be approved again.
          # Returns false when the update fails, leaving the persisted state
          # untouched, so callers keep the previously approved source of truth.
          def register_external_grant(provider, purpose, scope)
            config = sorcery_config
            grant = external_grant(provider, purpose)

            if grant.nil?
              grant = send(external_grants_association).build(
                config.grant_provider_attribute_name => provider.to_s,
                config.grant_purpose_attribute_name => purpose.to_s
              )
            end

            scope = scope.to_s
            scope_changed = grant.send(config.grant_scope_attribute_name).to_s != scope

            grant.send(:"#{config.grant_scope_attribute_name}=", scope)
            if grant.send(config.grant_status_attribute_name).blank? || scope_changed
              grant.send(:"#{config.grant_status_attribute_name}=", STATUS_UNCONFIRMED)
            end

            grant.sorcery_adapter.save ? grant : false
          rescue StandardError
            false
          end

          # Approves the grant for the provider/purpose pair.
          # Returns false when no such grant exists or the update fails.
          def confirm_external_grant(provider, purpose)
            transition_external_grant(provider, purpose, STATUS_GRANTED)
          end

          # Stops the grant for the provider/purpose pair.
          # Returns false when no such grant exists or the update fails.
          def stop_external_grant(provider, purpose)
            transition_external_grant(provider, purpose, STATUS_STOPPED)
          end

          # The current status ('unconfirmed', 'granted' or 'stopped'),
          # or nil when no grant exists for the provider/purpose pair.
          def external_grant_status(provider, purpose)
            external_grant(provider, purpose)&.send(sorcery_config.grant_status_attribute_name)
          end

          # True only when the grant is granted and its persisted scope covers
          # the required one.
          def external_grant_allows?(provider, purpose, required_scope = nil)
            grant = external_grant(provider, purpose)
            return false if grant.nil?

            config = sorcery_config
            return false unless grant.send(config.grant_status_attribute_name) == STATUS_GRANTED

            ExternalGrants.scope_covers?(grant.send(config.grant_scope_attribute_name), required_scope)
          end

          private

          def transition_external_grant(provider, purpose, status)
            grant = external_grant(provider, purpose)
            return false if grant.nil?

            grant.send(:"#{sorcery_config.grant_status_attribute_name}=", status)
            grant.sorcery_adapter.save ? grant : false
          rescue StandardError
            false
          end

          def external_grants_association
            sorcery_config.grants_class.name.demodulize.underscore.pluralize
          end
        end
      end
    end
  end
end
