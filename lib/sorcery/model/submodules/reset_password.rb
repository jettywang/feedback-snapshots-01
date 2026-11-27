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
            # Invalidate other sessions and persistent logins after a committed password change.
            attr_accessor :reset_password_invalidate_active_sessions_enabled
            # Attribute holding the cutoff used to invalidate sessions.
            attr_accessor :reset_password_invalidate_sessions_before_attribute_name
            # Keep the session that performed the committed change usable.
            attr_accessor :reset_password_preserve_current_session
          end

          base.sorcery_config.instance_eval do
            @defaults.merge!(:@reset_password_token_attribute_name => :reset_password_token,
                             :@reset_password_token_expires_at_attribute_name => :reset_password_token_expires_at,
                             :@reset_password_page_access_count_attribute_name =>
                                 :access_count_to_reset_password_page,
                             :@reset_password_email_sent_at_attribute_name => :reset_password_email_sent_at,
                             :@reset_password_mailer => nil,
                             :@reset_password_mailer_disabled => false,
                             :@reset_password_email_method_name => :reset_password_email,
                             :@reset_password_expiration_period => nil,
                             :@reset_password_time_between_emails => 5 * 60,
                             :@reset_password_invalidate_active_sessions_enabled => false,
                             :@reset_password_invalidate_sessions_before_attribute_name => :invalidate_sessions_before,
                             :@reset_password_preserve_current_session => true)

            reset!
          end

          base.extend(ClassMethods)

          base.sorcery_config.after_config << :validate_mailer_defined
          base.sorcery_config.after_config << :define_reset_password_fields

          base.send(:include, InstanceMethods)
        end

        module ClassMethods
          # Find user by token, also checks for expiration.
          # Returns the user if token found and is valid.
          def load_from_reset_password_token(token, &)
            load_from_token(
              token,
              @sorcery_config.reset_password_token_attribute_name,
              @sorcery_config.reset_password_token_expires_at_attribute_name,
              &
            )
          end

          protected

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
          # The cutoff that was persisted by the last successful #change_password
          # when session invalidation is enabled. nil when invalidation is off or
          # the change did not commit.
          attr_reader :password_change_invalidated_at

          # Generates a reset code with expiration
          def generate_reset_password_token!
            config = sorcery_config
            attributes = { config.reset_password_token_attribute_name => TemporaryToken.generate_random_token,
                           config.reset_password_email_sent_at_attribute_name => Time.now.in_time_zone }
            if config.reset_password_expiration_period
              attributes[config.reset_password_token_expires_at_attribute_name] = Time.now.in_time_zone + config.reset_password_expiration_period
            end

            sorcery_adapter.update_attributes(attributes)
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
              generate_reset_password_token!
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
          #
          # When reset_password_invalidate_active_sessions_enabled is on, a
          # committed password change also rotates the persistent login token and
          # records a session cutoff, so sessions and remember-me cookies created
          # with the old credentials stop being usable. Both are written through
          # the same model save as the password, so the database never holds a
          # rotated token without the matching new password. A failed save leaves
          # the persisted password, token and cutoff untouched; the in-memory
          # record is put back to its pre-change invalidation state as well.
          def change_password(new_password, raise_on_failure: false)
            config = sorcery_config
            invalidated_at = nil
            previous_invalidation = nil
            if password_change_invalidation_requested?(new_password)
              validate_password_change_cutoff_attribute!
              previous_invalidation = capture_password_change_invalidation_state
              invalidated_at = prepare_password_change_invalidation
            end

            clear_reset_password_token
            send(:"#{config.password_attribute_name}=", new_password)

            result = begin
              sorcery_adapter.save raise_on_failure: raise_on_failure
            rescue StandardError
              # Nothing was committed, so the invalidation attributes must not
              # survive in memory where a later save could persist them.
              restore_password_change_invalidation_state(previous_invalidation) if previous_invalidation
              clear_password_change_commit_state
              raise
            end

            unless result
              # Same guard for a silent failed save: keep the loaded record
              # consistent with the database.
              restore_password_change_invalidation_state(previous_invalidation) if previous_invalidation
              clear_password_change_commit_state
              return result
            end

            @password_change_invalidated_at = invalidated_at ? (persisted_password_change_cutoff || invalidated_at) : nil
            register_password_change_rollback(previous_invalidation) if invalidated_at
            result
          end

          def change_password!(new_password)
            raise ArgumentError, 'Blank password passed to change_password!' if new_password.blank?

            change_password(new_password, raise_on_failure: true)
          end

          protected

          # Invalidation only applies to a real password submission while the
          # option is on.
          def password_change_invalidation_requested?(new_password)
            new_password.present? && sorcery_config.reset_password_invalidate_active_sessions_enabled
          end

          def validate_password_change_cutoff_attribute!
            cutoff_attribute = sorcery_config.reset_password_invalidate_sessions_before_attribute_name
            return if respond_to?(cutoff_attribute)

            raise ArgumentError,
                  "To invalidate sessions on password reset, the model needs an `#{cutoff_attribute}` attribute " \
                  '(for example an `invalidate_sessions_before` datetime column).'
          end

          # Applies the invalidation attributes and returns the cutoff that must be
          # persisted.
          def prepare_password_change_invalidation
            cutoff = Time.now.in_time_zone
            password_change_invalidation_attributes(cutoff).each do |name, value|
              send(:"#{name}=", value)
            end
            cutoff
          end

          # The attributes changed in the same save as the password.
          # The persistent login token is rotated, so every cookie that still
          # holds the old token stops resolving. The controller can hand the
          # freshly minted token back to the session that performed the change.
          # The fields are only included when that submodule is active.
          def password_change_invalidation_attributes(cutoff)
            config = sorcery_config
            attributes = { config.reset_password_invalidate_sessions_before_attribute_name => cutoff }

            if remember_me_fields_defined?
              attributes[config.remember_me_token_attribute_name] = TemporaryToken.generate_random_token
              attributes[config.remember_me_token_expires_at_attribute_name] = cutoff + config.remember_me_for
            end

            attributes
          end

          def remember_me_fields_defined?
            config = sorcery_config
            config.respond_to?(:remember_me_token_attribute_name) &&
              config.respond_to?(:remember_me_token_expires_at_attribute_name) &&
              config.respond_to?(:remember_me_for) &&
              respond_to?(config.remember_me_token_attribute_name) &&
              respond_to?(config.remember_me_token_expires_at_attribute_name)
          end

          # Reads the cutoff back with the precision the adapter actually stored,
          # so callers comparing against the database use the same value.
          def persisted_password_change_cutoff
            cutoff_attribute = sorcery_config.reset_password_invalidate_sessions_before_attribute_name
            return unless respond_to?(:id) && id

            reloaded = self.class.sorcery_adapter.find(id)
            reloaded&.public_send(cutoff_attribute)
          rescue StandardError
            nil
          end

          # A password change is reported as committed only once the surrounding
          # transaction ends without a rollback. A rollback puts the loaded record
          # back to its pre-change invalidation state and clears the marker, so
          # callers that preserve the current session do not act on a change the
          # database never accepted.
          def register_password_change_rollback(previous_invalidation)
            transaction = model_current_transaction
            return unless transaction.respond_to?(:after_rollback) && !transaction.closed?

            transaction.after_rollback do
              restore_password_change_invalidation_state(previous_invalidation)
              clear_password_change_commit_state
            end
          end

          def model_current_transaction
            return unless self.class.respond_to?(:connection)
            return unless defined?(ActiveRecord::Base) && self.class.connection.respond_to?(:current_transaction)

            self.class.connection.current_transaction
          end

          def clear_password_change_commit_state
            @password_change_invalidated_at = nil
          end

          def capture_password_change_invalidation_state
            password_change_invalidation_attribute_names.to_h { |name| [name, send(name)] }
          end

          def restore_password_change_invalidation_state(state)
            state.each do |name, value|
              send(:"#{name}=", value)
            end
          end

          def password_change_invalidation_attribute_names
            config = sorcery_config
            names = []
            names << config.reset_password_invalidate_sessions_before_attribute_name if
              config.reset_password_invalidate_active_sessions_enabled
            if remember_me_fields_defined?
              names << config.remember_me_token_attribute_name
              names << config.remember_me_token_expires_at_attribute_name
            end
            names
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
