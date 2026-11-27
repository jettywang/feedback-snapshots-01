# frozen_string_literal: true

module Sorcery
  # Persistence boundary for recent (step-up) authentication proofs.
  #
  # A proof is a server-side record that binds a user, the session it was
  # confirmed in, the operation it was confirmed for and the time it was
  # confirmed. Keeping it separate from the ordinary session means that
  # restoring a remembered login never implies that a higher authentication
  # requirement has been satisfied.
  module RecentAuthenticationStore
    # Default Active Record backed store. Applications can replace it with
    # an object exposing the same methods through
    # `config.recent_authentication_store`.
    class ActiveRecordStore
      def create(user_id:, session_id:, operation:, authenticated_at:, expires_at:)
        record_class.create!(
          user_id: user_id,
          session_id: session_id,
          operation: operation.to_s,
          authenticated_at: authenticated_at,
          expires_at: expires_at
        )
      end

      def active(user_id:, session_id:, operations: nil, at: Time.now.in_time_zone)
        scope = active_scope(user_id, session_id, at)

        operations = normalize_operations(operations)
        scope = scope.where(operation: operations) if operations.any?

        scope.order(authenticated_at: :desc).first
      end

      def expires_at(user_id:, session_id:, operations: nil, at: Time.now.in_time_zone)
        scope = active_scope(user_id, session_id, at)

        operations = normalize_operations(operations)
        scope = scope.where(operation: operations) if operations.any?

        scope.maximum(:expires_at)
      end

      def revoke_session(session_id:, user_id: nil, operations: nil, at: Time.now.in_time_zone)
        scope = record_class.where(session_id: session_id, revoked_at: nil)
        scope = scope.where(user_id: user_id) if user_id

        operations = normalize_operations(operations)
        scope = scope.where(operation: operations) if operations.any?

        scope.update_all(revoked_at: at, updated_at: at)
      end

      def revoke_user(user_id:, at: Time.now.in_time_zone)
        record_class.where(user_id: user_id, revoked_at: nil)
                    .update_all(revoked_at: at, updated_at: at)
      end

      private

      def active_scope(user_id, session_id, at)
        record_class
          .where(user_id: user_id, session_id: session_id, revoked_at: nil)
          .where('expires_at > ?', at)
      end

      def normalize_operations(operations)
        Array(operations).compact.map(&:to_s).reject(&:empty?)
      end

      def record_class
        unless defined?(Sorcery::RecentAuthenticationRecord)
          require 'sorcery/recent_authentication' if defined?(ActiveRecord::Base)
        end

        unless defined?(Sorcery::RecentAuthenticationRecord)
          raise Sorcery::Error,
                'Recent authentication requires an Active Record record class. ' \
                'Configure config.recent_authentication_store with an application store, ' \
                'or install the recent_authentication migration.'
        end

        Sorcery::RecentAuthenticationRecord
      end
    end
  end
end
