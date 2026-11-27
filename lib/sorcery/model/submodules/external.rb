# frozen_string_literal: true

module Sorcery
  module Model
    module Submodules
      # This submodule helps you login users from external providers such as Twitter.
      # This is the model part which handles finding the user using access tokens.
      # For the controller options see Sorcery::Controller::External.
      #
      # Sorcery assumes (read: requires) you will create external users in the same table where
      # you keep your regular users,
      # but that you will have a separate table for keeping their external authentication data,
      # and that that separate table has a few rows for each user, facebook and twitter
      # for example (a one-to-many relationship).
      #
      # External users will have a null crypted_password field, since we do not hold their password.
      # They will not be sent activation emails on creation.
      module External
        def self.included(base)
          base.sorcery_config.class_eval do
            attr_accessor :authentications_class,
                          :authentications_user_id_attribute_name,
                          :provider_attribute_name,
                          :provider_uid_attribute_name,
                          :authentication_disabled_at_attribute_name
          end

          base.sorcery_config.instance_eval do
            @defaults.merge!(:@authentications_class => nil,
                             :@authentications_user_id_attribute_name => :user_id,
                             :@provider_attribute_name => :provider,
                             :@provider_uid_attribute_name => :uid,
                             :@authentication_disabled_at_attribute_name => :disabled_at)

            reset!
          end

          base.send(:include, InstanceMethods)
          base.extend(ClassMethods)
        end

        module ClassMethods
          # takes a provider and uid and finds a user by them.
          # Associations that were marked unavailable (disabled) are ignored,
          # so a suspended external login can no longer sign the user in.
          def load_from_provider(provider, uid)
            config = sorcery_config
            authentication = config.authentications_class.sorcery_adapter.find_by_oauth_credentials(provider, uid)
            # Return user if a matching, enabled authentication found
            return unless authentication
            return if authentication.send(config.authentication_disabled_at_attribute_name).present?

            sorcery_adapter.find_by_id(authentication.send(config.authentications_user_id_attribute_name))
          end

          # Marks the matching external association (provider + uid) as unavailable in response
          # to an application-confirmed suspension notification from a provider.
          #
          # The record itself is kept for auditing; only its disabled-at timestamp is set.
          # The operation is idempotent: duplicate notifications leave an already disabled
          # association untouched and never re-enable it. Re-enabling must go through the
          # approved application flow via +reactivate_provider+.
          #
          # Returns the disabled authentication record, or nil when no association matches.
          def disable_provider(provider, uid)
            config = sorcery_config
            disabled_at = config.authentication_disabled_at_attribute_name
            authentication = find_provider_authentication(provider, uid)
            return unless authentication

            authentication.sorcery_adapter.update_attribute(disabled_at, Time.current) unless authentication.send(disabled_at).present?
            authentication
          end

          # Clears the disabled-at timestamp on the matching external association.
          # This is the only supported way to restore a suspended login and is meant to be
          # called from an explicitly approved application flow; ordinary logins never call it.
          #
          # Returns the reactivated authentication record, or nil when no association matches.
          def reactivate_provider(provider, uid)
            disabled_at = sorcery_config.authentication_disabled_at_attribute_name
            authentication = find_provider_authentication(provider, uid)
            return unless authentication

            authentication.sorcery_adapter.update_attribute(disabled_at, nil) if authentication.send(disabled_at).present?
            authentication
          end

          # Locates the association regardless of its disabled state so that suspension
          # notifications can target records that are already unavailable.
          def find_provider_authentication(provider, uid)
            config = sorcery_config
            conditions = {
              config.provider_uid_attribute_name => uid,
              config.provider_attribute_name => provider
            }
            config.authentications_class.where(conditions).first
          end

          def create_and_validate_from_provider(provider, uid, attrs)
            user = new(attrs)
            user.send(sorcery_config.authentications_class.name.demodulize.underscore.pluralize).build(
              sorcery_config.provider_uid_attribute_name => uid,
              sorcery_config.provider_attribute_name => provider
            )
            saved = user.sorcery_adapter.save
            [user, saved]
          end

          def create_from_provider(provider, uid, attrs)
            user = new
            attrs.each do |k, v|
              user.send(:"#{k}=", v)
            end

            return false if block_given? && !yield(user)

            sorcery_adapter.transaction do
              user.sorcery_adapter.save(validate: false)
              sorcery_config.authentications_class.create!(
                sorcery_config.authentications_user_id_attribute_name => user.id,
                sorcery_config.provider_attribute_name => provider,
                sorcery_config.provider_uid_attribute_name => uid
              )
            end
            user
          end

          # NOTE: Should this build the authentication as well and return [user, auth]?
          # Currently, users call this function for the user and call add_provider_to_user after saving
          def build_from_provider(attrs)
            user = new
            attrs.each do |k, v|
              user.send(:"#{k}=", v)
            end

            return false if block_given? && !yield(user)

            user
          end
        end

        module InstanceMethods
          def add_provider_to_user(provider, uid)
            authentications = sorcery_config.authentications_class.name.demodulize.underscore.pluralize
            config = sorcery_config
            conditions = {
              config.provider_attribute_name => provider,
              config.provider_uid_attribute_name => uid
            }
            # Look at every association, including disabled ones. A suspended login must not
            # be resurrected by an ordinary login/link flow; only an approved reactivation
            # (see #reactivate_external_authentication) may clear the disabled-at timestamp.
            existing = send(authentications).where(conditions).first
            # first check to see if user has a particular authentication already
            if existing.nil?
              user = send(authentications).build(sorcery_config.provider_uid_attribute_name => uid,
                                                 sorcery_config.provider_attribute_name => provider)
              user.sorcery_adapter.save(validate: false)
            else
              user = false
            end

            user
          end

          # Disables one of this user's external logins (provider + uid) while leaving the
          # user's other providers and regular password login untouched. The association is
          # retained for auditing and only its disabled-at timestamp is set.
          #
          # Idempotent: a repeated suspension notification does not change an already disabled
          # record. Returns the record, or nil when this user has no such association.
          def disable_external_authentication(provider, uid)
            authentication = find_own_provider_authentication(provider, uid)
            return unless authentication

            disabled_at = sorcery_config.authentication_disabled_at_attribute_name
            authentication.sorcery_adapter.update_attribute(disabled_at, Time.current) unless authentication.send(disabled_at).present?
            authentication
          end

          # Restores one of this user's external logins by clearing the disabled-at timestamp.
          # Intended to be invoked only from an approved application flow.
          # Returns the record, or nil when this user has no such association.
          def reactivate_external_authentication(provider, uid)
            authentication = find_own_provider_authentication(provider, uid)
            return unless authentication

            disabled_at = sorcery_config.authentication_disabled_at_attribute_name
            authentication.sorcery_adapter.update_attribute(disabled_at, nil) if authentication.send(disabled_at).present?
            authentication
          end

          private

          # Looks up the association only among this user's own authentications, including
          # disabled ones, so suspension and recovery never touch another account's records.
          def find_own_provider_authentication(provider, uid)
            config = sorcery_config
            relation_name = config.authentications_class.name.demodulize.underscore.pluralize
            conditions = {
              config.provider_attribute_name => provider,
              config.provider_uid_attribute_name => uid
            }
            send(relation_name).where(conditions).first
          end
        end
      end
    end
  end
end
