# frozen_string_literal: true

module Sorcery
  module Model
    module Submodules
      # This submodule adds the ability to reset password via email confirmation.
      # When the user requests an email is sent to him with a url.
      # The url includes a token, which is also saved with the user's record in the db.
      # The token has configurable expiration.
      # When the user clicks the url in the email, providing the token has not yet expired,
      # he will be able to reset his password via a form.
      #
      # When using this submodule, supplying a mailer is mandatory.
      module ResetPassword
        def self.included(base)
          base.sorcery_config.class_eval do
            # Reset password code attribute name.
            attr_accessor :reset_password_token_attribute_name
            # Expires at attribute name.
            attr_accessor :reset_password_token_expires_at_attribute_name
            # Counter access to reset password page
            attr_accessor :reset_password_page_access_count_attribute_name
            # When was email sent, used for hammering protection.
            attr_accessor :reset_password_email_sent_at_attribute_name
            # Mailer class (needed)
            attr_accessor :reset_password_mailer
            # When true sorcery will not automatically email password reset details and allow you to
            # manually handle how and when email is sent
            attr_accessor :reset_password_mailer_disabled
            # Reset password email method on your mailer class.
            attr_accessor :reset_password_email_method_name
            # How many seconds before the reset request expires. nil for never expires.
            attr_accessor :reset_password_expiration_period
            # Hammering protection, how long to wait before allowing another email to be sent.
            attr_accessor :reset_password_time_between_emails
            # Optional generation-scoped credential policy. When set, reset tokens
            # are signed and verified against the generation that issued them.
            # Defaults to nil (legacy plain-token behaviour).
            attr_accessor :reset_password_token_policy
          end

          base.sorcery_config.instance_eval do
            @defaults.merge!(:@reset_password_token_attribute_name => :reset_password_token,
                             :@reset_password_token_policy => nil,
                             :@reset_password_token_expires_at_attribute_name => :reset_password_token_expires_at,
                             :@reset_password_page_access_count_attribute_name =>
                                 :access_count_to_reset_password_page,
                             :@reset_password_email_sent_at_attribute_name => :reset_password_email_sent_at,
                             :@reset_password_mailer => nil,
                             :@reset_password_mailer_disabled => false,
                             :@reset_password_email_method_name => :reset_password_email,
                             :@reset_password_expiration_period => nil,
                             :@reset_password_time_between_emails => 5 * 60)

            reset!
          end

          base.extend(ClassMethods)

          base.sorcery_config.after_config << :validate_mailer_defined
          base.sorcery_config.after_config << :define_reset_password_fields

          base.send(:include, InstanceMethods)
        end

        module ClassMethods
          # Assigns the credential lifecycle policy. Pass nil to return to the
          # legacy plain-token behaviour.
          def reset_password_token_policy=(policy)
            unless policy.nil? || policy.is_a?(ResetPasswordTokenPolicy)
              raise ArgumentError, 'reset_password_token_policy must be a Sorcery::Model::ResetPasswordTokenPolicy'
            end

            @sorcery_config.reset_password_token_policy = policy
          end

          # Returns the configured credential lifecycle policy, if any.
          def reset_password_token_policy
            @sorcery_config.reset_password_token_policy
          end

          # Token-free lifecycle registration and diagnostics for the configured
          # policy. Returns empty collections when no policy is configured.
          def reset_password_token_registry
            reset_password_token_policy&.registry || []
          end

          def reset_password_token_diagnostics
            reset_password_token_policy&.diagnostics || []
          end

          # Find user by token, also checks for expiration.
          # Returns the user if token found and is valid.
          def load_from_reset_password_token(token, &)
            policy = @sorcery_config.reset_password_token_policy
            return load_from_legacy_reset_password_token(token, &) unless policy

            resolution = policy.resolve(token)
            policy.record_lookup(resolution)
            user = if resolution.ok?
                     sorcery_adapter.find_by_token(@sorcery_config.reset_password_token_attribute_name, token)
                   end

            unless user
              failure = resolution.ok? ? :user_not_found : resolution.status
              return token_response(failure: failure, &)
            end

            if resolution.legacy? && policy.admit_legacy? && !policy.redeem_legacy!(token)
              return token_response(failure: :legacy_already_used, &)
            end

            unless check_expiration_date(user, @sorcery_config.reset_password_token_expires_at_attribute_name)
              return token_response(user: user, failure: :token_expired, &)
            end

            token_response(user: user, return_value: user, &)
          end

          protected

          def load_from_legacy_reset_password_token(token, &)
            load_from_token(
              token,
              @sorcery_config.reset_password_token_attribute_name,
              @sorcery_config.reset_password_token_expires_at_attribute_name,
              &
            )
          end

          # This submodule requires the developer to define his own mailer class to be used by it
          # when reset_password_mailer_disabled is false
          def validate_mailer_defined
            message = 'To use reset_password submodule, you must define a mailer (config.reset_password_mailer = YourMailerClass).'
            if @sorcery_config.reset_password_mailer.nil? && @sorcery_config.reset_password_mailer_disabled == false
              raise ArgumentError, message
            end
          end

          def define_reset_password_fields
            sorcery_adapter.define_field sorcery_config.reset_password_token_attribute_name, String
            sorcery_adapter.define_field sorcery_config.reset_password_token_expires_at_attribute_name, Time
            sorcery_adapter.define_field sorcery_config.reset_password_email_sent_at_attribute_name, Time
          end
        end

        module InstanceMethods
          # Generates a reset code with expiration
          def generate_reset_password_token!
            config = sorcery_config
            policy = config.reset_password_token_policy
            return generate_legacy_reset_password_token! unless policy

            issuance = policy.build_issuance
            unless issuance
              policy.record_issue_failure(nil, reason: :no_issuing_generation)
              return false
            end

            attributes = {
              config.reset_password_token_attribute_name => issuance.credential,
              config.reset_password_email_sent_at_attribute_name => Time.now.in_time_zone
            }
            if config.reset_password_expiration_period
              attributes[config.reset_password_token_expires_at_attribute_name] = Time.now.in_time_zone + config.reset_password_expiration_period
            end

            previous = attributes.keys.to_h { |name| [name, send(name)] }
            stored = begin
              sorcery_adapter.update_attributes(attributes)
            rescue *storage_error_classes
              false
            end
            unless stored
              previous.each { |name, value| send(:"#{name}=", value) }
              policy.record_issue_failure(issuance, reason: :storage_failed)
              return false
            end

            policy.record_issued(issuance)
            true
          end

          # Returns the generation identifier adopted by the reset token
          # currently held by this record. Nil when no policy is configured or
          # the token cannot be classified.
          def reset_password_token_generation
            policy = sorcery_config.reset_password_token_policy
            return unless policy

            token = send(sorcery_config.reset_password_token_attribute_name)
            resolution = policy.resolve(token)
            resolution.generation_id if resolution.ok?
          end

          # Generates a reset code with expiration and sends an email to the user.
          def deliver_reset_password_instructions!
            mail = false
            config = sorcery_config
            # hammering protection
            if config.reset_password_time_between_emails.present? && send(config.reset_password_email_sent_at_attribute_name) && send(config.reset_password_email_sent_at_attribute_name) > config.reset_password_time_between_emails.seconds.ago.utc
              return false
            end

            self.class.sorcery_adapter.transaction do
              if config.reset_password_token_policy
                return false unless generate_reset_password_token!
              else
                generate_reset_password_token!
              end

              mail = send_reset_password_email! unless config.reset_password_mailer_disabled
            end
            mail
          end

          # Increment access_count_to_reset_password_page attribute.
          # For example, access_count_to_reset_password_page attribute is over 1, which
          # means the user doesn't have a right to access.
          def increment_password_reset_page_access_counter
            sorcery_adapter.increment(sorcery_config.reset_password_page_access_count_attribute_name)
          end

          # Reset access_count_to_reset_password_page attribute into 0.
          # This is expected to be used after sending an instruction email.
          def reset_password_reset_page_access_counter
            send(:"#{sorcery_config.reset_password_page_access_count_attribute_name}=", 0)
            sorcery_adapter.save
          end

          # Clears token and tries to update the new password for the user.
          def change_password(new_password, raise_on_failure: false)
            clear_reset_password_token
            send(:"#{sorcery_config.password_attribute_name}=", new_password)
            sorcery_adapter.save raise_on_failure: raise_on_failure
          end

          def change_password!(new_password)
            raise ArgumentError, 'Blank password passed to change_password!' if new_password.blank?

            change_password(new_password, raise_on_failure: true)
          end

          protected

          def storage_error_classes
            classes = []
            classes << ActiveRecord::ActiveRecordError if defined?(ActiveRecord::ActiveRecordError)
            classes << Mongo::Error if defined?(Mongo::Error)
            classes.empty? ? [StandardError] : classes
          end

          def generate_legacy_reset_password_token!
            config = sorcery_config
            attributes = { config.reset_password_token_attribute_name => TemporaryToken.generate_random_token,
                           config.reset_password_email_sent_at_attribute_name => Time.now.in_time_zone }
            if config.reset_password_expiration_period
              attributes[config.reset_password_token_expires_at_attribute_name] = Time.now.in_time_zone + config.reset_password_expiration_period
            end

            sorcery_adapter.update_attributes(attributes)
          end

          def send_reset_password_email!
            generic_send_email(:reset_password_email_method_name, :reset_password_mailer)
          end

          # Clears the token.
          def clear_reset_password_token
            config = sorcery_config
            send(:"#{config.reset_password_token_attribute_name}=", nil)
            return unless config.reset_password_expiration_period

            send(:"#{config.reset_password_token_expires_at_attribute_name}=", nil)
          end
        end
      end
    end
  end
end
