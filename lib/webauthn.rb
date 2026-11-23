# frozen_string_literal: true

require "webauthn/json_serializer"
require "webauthn/configuration"
require "webauthn/credential"
require "webauthn/backup_attributes"
require "webauthn/backup_policy"
require "webauthn/backup_receipt"
require "webauthn/in_memory_credential_store"
require "webauthn/backup_credential_manager"
require "webauthn/credential_creation_options"
require "webauthn/credential_request_options"
require "webauthn/version"

module WebAuthn
  TYPE_PUBLIC_KEY = "public-key"

  class << self
    def generate_user_id
      configuration.encoder.encode(SecureRandom.random_bytes(64))
    end
    alias_method :generate_user_handle, :generate_user_id
  end
end
