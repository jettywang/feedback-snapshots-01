# frozen_string_literal: true

require "thread"
require "webauthn/backup_attributes"
require "webauthn/error"

module WebAuthn
  class CredentialAlreadyExistsError < Error; end
  class CredentialNotFoundError < Error; end
  class CredentialVersionConflictError < Error; end

  class InMemoryCredentialStore
    Snapshot = Struct.new(
      :id,
      :public_key,
      :sign_count,
      :backup_attributes,
      :version,
      keyword_init: true
    ) do
      def initialize(**keyword_arguments)
        super
        self.version ||= 1
      end

      def with(**changes)
        self.class.new(**to_h.merge(changes))
      end
    end

    def initialize
      @records = {}
      @mutex = Mutex.new
    end

    def register(id:, public_key:, sign_count:, backup_attributes:)
      @mutex.synchronize do
        if @records.key?(id)
          raise CredentialAlreadyExistsError, "Credential #{id} is already registered"
        end

        @records[id] = Snapshot.new(
          id: id,
          public_key: public_key,
          sign_count: sign_count,
          backup_attributes: backup_attributes,
          version: 1
        ).freeze
      end
    end

    def migrate(id:, public_key:, sign_count:, backup_attributes:, expected_version: nil)
      @mutex.synchronize do
        current = @records[id]

        if current
          if expected_version && current.version != expected_version
            raise CredentialVersionConflictError,
                  "Expected version #{expected_version}, found #{current.version}"
          end

          version = current.version + 1
        else
          unless expected_version.nil?
            raise CredentialVersionConflictError,
                  "Expected version #{expected_version}, but no credential is stored"
          end

          version = 1
        end

        @records[id] = Snapshot.new(
          id: id,
          public_key: public_key,
          sign_count: sign_count,
          backup_attributes: backup_attributes,
          version: version
        ).freeze
      end
    end

    def snapshot(id)
      @mutex.synchronize { @records[id] }
    end
    alias_method :fetch, :snapshot

    def commit_authentication(snapshot:, backup_attributes:, sign_count:)
      @mutex.synchronize do
        current = @records[snapshot.id]

        return nil unless current
        return nil unless current.version == snapshot.version

        if sign_count && current.sign_count && sign_count < current.sign_count
          return nil
        end

        next_sign_count = [current.sign_count || 0, sign_count || 0].max
        unchanged =
          current.backup_attributes == backup_attributes &&
          current.sign_count == next_sign_count

        return current if unchanged

        @records[snapshot.id] = current.with(
          sign_count: next_sign_count,
          backup_attributes: backup_attributes,
          version: current.version + 1
        ).freeze
      end
    end

    def delete(id)
      @mutex.synchronize { @records.delete(id) }
    end

    def clear
      @mutex.synchronize { @records.clear }
    end
  end
end
