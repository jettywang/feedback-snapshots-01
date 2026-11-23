# frozen_string_literal: true

require "webauthn/error"
require "webauthn/encoders"

module WebAuthn
  # Opt-in registration flow that keeps exclusion lists scoped to one account and
  # only reports success after the store confirms the credential is still active.
  #
  # The store is a duck-typed application object. It must implement
  #
  #   active_credentials(account_id:) #=> iterable of credential records
  #   register(account_id:, credential:) #=> Result-like value
  #
  # and may implement
  #
  #   find_credential(account_id:, raw_id:) #=> record or nil
  #
  # Records may be hashes or objects. Credential identifiers may be stored as
  # raw bytes (:raw_id) or as base64/base64url text (:webauthn_id,
  # :credential_id, :credential_identifier, :external_id). Both encodings are
  # normalized to the same raw identifier before the browser sees them.
  class AccountRegistration
    class ContractError < Error; end
    class ConflictError < Error; end
    class InvalidCredentialIdError < Error; end
    class ApprovalMismatchError < Error; end

    RAW_IDENTIFIER_KEYS = [:raw_id].freeze
    ENCODED_IDENTIFIER_KEYS = [
      :webauthn_id,
      :credential_id,
      :credential_identifier,
      :external_id
    ].freeze
    ACCOUNT_KEYS = [:account_id, :user_id, :owner_id].freeze
    ACCOUNT_ASSOCIATION_KEYS = [:account, :user, :owner].freeze
    ARCHIVED_STATUSES = [:archived, :revoked, :deleted, :inactive].freeze

    Credential = Struct.new(
      :account_id,
      :webauthn_id,
      :raw_id,
      :public_key,
      :sign_count,
      :transports,
      keyword_init: true
    ) do
      alias_method :id, :webauthn_id

      def to_h
        {
          account_id: account_id,
          webauthn_id: webauthn_id,
          raw_id: raw_id,
          public_key: public_key,
          sign_count: sign_count,
          transports: transports
        }
      end
    end

    # Return value used by stores to describe an atomic register attempt.
    # Stores may also return :created / :conflict, true / false, or a persisted
    # credential record.
    class Result
      attr_reader :status, :credential, :reason

      def initialize(status:, credential: nil, reason: nil)
        @status = status
        @credential = credential
        @reason = reason
      end

      def self.created(credential: nil)
        new(status: :created, credential: credential)
      end

      def self.conflict(credential: nil)
        new(status: :conflict, credential: credential)
      end

      def self.unconfirmed(reason: nil)
        new(status: :unconfirmed, reason: reason)
      end

      def created?
        status == :created
      end

      def conflict?
        status == :conflict
      end

      def unconfirmed?
        status == :unconfirmed
      end
    end

    # Server-side proof of the registration ceremony that produced the options.
    # It binds the challenge to the account and to that relying party.
    class Approval
      attr_reader :account_id, :challenge, :relying_party_fingerprint, :issued_at

      def initialize(account_id:, challenge:, relying_party:)
        @account_id = account_id
        @challenge = challenge
        @relying_party_fingerprint = relying_party_fingerprint_for(relying_party)
        @issued_at = Time.now
        freeze
      end

      def matches?(relying_party:, account_id: nil)
        return false if account_id && self.account_id.to_s != account_id.to_s

        relying_party_fingerprint == relying_party_fingerprint_for(relying_party)
      end

      private

      def relying_party_fingerprint_for(relying_party)
        [
          relying_party.id,
          Array(relying_party.allowed_origins),
          relying_party.encoding
        ].freeze
      end
    end

    class RegistrationAttempt
      attr_reader :account_id, :options, :approval, :excluded_credential_ids

      def initialize(account_id:, options:, approval:, excluded_credential_ids:)
        @account_id = account_id
        @options = options
        @approval = approval
        @excluded_credential_ids = excluded_credential_ids.freeze
      end

      def challenge
        options.challenge
      end

      def exclude_credentials
        Array(options.exclude_credentials)
      end

      def as_json(*args)
        options.as_json(*args)
      end

      def to_h
        as_json
      end
    end

    class RegistrationReceipt
      attr_reader :status, :account_id, :credential, :stored_credential, :reason, :error

      def initialize(status:, account_id:, credential: nil, stored_credential: nil, reason: nil, error: nil)
        @status = status
        @account_id = account_id
        @credential = credential
        @stored_credential = stored_credential
        @reason = reason
        @error = error
      end

      def registered?
        status == :registered
      end
      alias_method :success?, :registered?

      def conflict?
        status == :conflict
      end

      def unconfirmed?
        status == :unconfirmed
      end

      def last_write_verified?
        registered?
      end
    end

    attr_reader :relying_party, :store

    def initialize(relying_party:, store:)
      @relying_party = relying_party
      @store = store

      validate_store!
    end

    # Builds creation options whose `excludeCredentials` contains only active
    # credentials belonging to `account_id`. Identifier text in either base64
    # spelling is normalized to one descriptor per raw credential.
    def options_for_create(account_id:, user:, **keyword_arguments)
      reject_manual_exclusions!(keyword_arguments)

      descriptors, excluded_ids = exclusion_data(account_id)

      options = relying_party.options_for_registration(
        user: user,
        exclude_credentials: descriptors.empty? ? nil : descriptors,
        **keyword_arguments
      )

      approval = Approval.new(
        account_id: account_id,
        challenge: options.challenge,
        relying_party: relying_party
      )

      RegistrationAttempt.new(
        account_id: account_id,
        options: options,
        approval: approval,
        excluded_credential_ids: excluded_ids
      )
    end

    # Checks the account's currently active credentials for the raw credential
    # identifier. This is the same evidence used to confirm a registration.
    def credential_active?(account_id:, raw_id:)
      raw_id = raw_id.to_s.b
      active_credential_records(account_id).any? do |record|
        identifier_pairs(record).any? { |candidate, _| candidate == raw_id }
      end
    end

    # Verifies the browser response, performs exactly one store write, and then
    # re-reads the account's active credentials to confirm the write. A store
    # conflict or an unconfirmed write never returns a successful receipt.
    def complete_registration(
      raw_credential,
      approval: nil,
      attempt: nil,
      account_id: nil,
      user_presence: nil,
      user_verification: nil
    )
      approval ||= attempt.approval if attempt
      raise ContractError, "a registration approval is required" unless approval

      unless approval.matches?(relying_party: relying_party, account_id: account_id)
        raise ApprovalMismatchError, "approval does not belong to this account and relying party"
      end

      webauthn_credential = relying_party.verify_registration(
        raw_credential,
        approval.challenge,
        user_presence: user_presence,
        user_verification: user_verification
      )

      credential = build_credential(
        account_id: approval.account_id,
        webauthn_credential: webauthn_credential,
        raw_credential: raw_credential
      )

      if credential_active?(account_id: approval.account_id, raw_id: credential.raw_id)
        return RegistrationReceipt.new(
          status: :conflict,
          account_id: approval.account_id,
          credential: credential,
          reason: :already_active
        )
      end

      result = normalize_result(
        store.register(account_id: approval.account_id, credential: credential)
      )

      receipt_for(approval.account_id, credential, result)
    rescue ConflictError => e
      RegistrationReceipt.new(
        status: :conflict,
        account_id: approval&.account_id || account_id,
        credential: credential,
        reason: :store_conflict,
        error: e
      )
    end

    private

    def validate_store!
      missing_methods = [:active_credentials, :register].reject { |method| store.respond_to?(method) }

      return if missing_methods.empty?

      raise ContractError, "store must implement #{missing_methods.join(' and ')}"
    end

    def reject_manual_exclusions!(keyword_arguments)
      if keyword_arguments.key?(:exclude) || keyword_arguments.key?(:exclude_credentials)
        raise ContractError, "exclude lists are generated from the account and cannot be overridden"
      end
    end

    def exclusion_data(account_id)
      records_by_raw_id = {}

      active_credentials(account_id).each do |record|
        next unless active_record?(record)
        next unless record_belongs_to_account?(record, account_id)

        identifier_pairs(record).each do |raw_id, _|
          records_by_raw_id[raw_id] ||= record
        end
      end

      descriptors = records_by_raw_id.map do |raw_id, record|
        descriptor = { type: TYPE_PUBLIC_KEY, id: encoder.encode(raw_id) }
        transports = transports_for(record)
        descriptor[:transports] = transports unless transports.empty?
        descriptor
      end

      [descriptors, records_by_raw_id.keys.map { |raw_id| encoder.encode(raw_id) }]
    end

    def active_credentials(account_id)
      Array(store.active_credentials(account_id: account_id))
    end

    def active_credential_records(account_id)
      active_credentials(account_id).select do |record|
        active_record?(record) && record_belongs_to_account?(record, account_id)
      end
    end

    def active_record?(record)
      return false if archived?(record)
      return false if record.respond_to?(:active?) && !record.active?
      return false if explicit_active_flag(record) == false

      !ARCHIVED_STATUSES.include?(status_for(record))
    end

    def explicit_active_flag(record)
      value = record_value(record, :active)
      value if value == true || value == false
    end

    def archived?(record)
      if record.is_a?(Hash)
        return true if fetch(record, :archived) == true
        return true if fetch(record, :archived_at)

        false
      else
        return true if record.respond_to?(:archived?) && record.archived?
        return true if record.respond_to?(:archived_at) && record.archived_at

        false
      end
    end

    def status_for(record)
      value = record_value(record, :status)
      value&.to_s&.downcase&.to_sym
    end

    def record_belongs_to_account?(record, account_id)
      record_account_id = ACCOUNT_KEYS.lazy.map { |key| record_value(record, key) }.find { |value| !value.nil? }
      record_account_id ||= ACCOUNT_ASSOCIATION_KEYS.lazy
        .map { |key| record_value(record, key) }
        .select { |value| value.respond_to?(:id) }
        .map(&:id)
        .find { |value| !value.nil? }

      record_account_id.nil? || record_account_id.to_s == account_id.to_s
    end

    def identifier_pairs(record)
      pairs = []

      RAW_IDENTIFIER_KEYS.each do |key|
        value = record_value(record, key)
        pairs << [binary_bytes(value), value] unless value.nil?
      end

      ENCODED_IDENTIFIER_KEYS.each do |key|
        value = record_value(record, key)
        next if value.nil?

        pairs << [text_or_binary_identifier(value), value]
      end

      pairs
    end

    def binary_bytes(value)
      value.to_s.b
    end

    def text_or_binary_identifier(value)
      string = value.to_s
      return string.b unless string.valid_encoding?
      return string.b if string.b.each_byte.any? { |byte| byte < 0x20 || byte > 0x7e }

      decode_identifier(string)
    end

    def decode_identifier(value)
      string = value.to_s
      raise InvalidCredentialIdError, "credential identifier cannot be empty" if string.empty?

      base64_decoders.each do |decoder|
        decoded = try_decode(decoder, string)
        return decoded if decoded
      end

      raise InvalidCredentialIdError, "credential identifier is not valid base64 or base64url"
    end

    def base64_decoders
      [Encoders::Base64UrlEncoder, Encoders::Base64Encoder]
    end

    def try_decode(decoder, string)
      decoded = decoder.decode(string.dup)
      return decoded unless decoded.empty?

      nil
    rescue ArgumentError, TypeError
      nil
    end

    def transports_for(record)
      value = record_value(record, :transports)
      return [] if value.nil?

      Array(value).map(&:to_s).reject(&:empty?)
    end

    def record_value(record, key)
      if record.is_a?(Hash)
        fetch(record, key)
      elsif record.respond_to?(key)
        record.public_send(key)
      end
    end

    def fetch(hash, key)
      return hash[key] if hash.key?(key)
      return hash[key.to_s] if hash.key?(key.to_s)

      nil
    end

    def build_credential(account_id:, webauthn_credential:, raw_credential:)
      Credential.new(
        account_id: account_id,
        webauthn_id: webauthn_credential.id,
        raw_id: webauthn_credential.raw_id,
        public_key: webauthn_credential.public_key,
        sign_count: webauthn_credential.sign_count,
        transports: transports_from_credential(raw_credential)
      )
    end

    def transports_from_credential(raw_credential)
      return [] unless raw_credential.respond_to?(:[])

      response = raw_credential["response"] || raw_credential[:response]
      return [] unless response.respond_to?(:[])

      Array(response["transports"] || response[:transports]).map(&:to_s).reject(&:empty?)
    end

    def normalize_result(result)
      case result
      when Result
        result
      when nil
        Result.unconfirmed(reason: :empty_store_result)
      when true
        Result.created
      when false
        Result.conflict
      when Symbol
        normalize_symbol_result(result)
      when Hash
        normalize_hash_result(result)
      else
        normalize_object_result(result)
      end
    end

    def normalize_symbol_result(result)
      case result
      when :created, :registered, :ok
        Result.created
      when :conflict, :already_registered, :duplicate
        Result.conflict
      else
        Result.unconfirmed(reason: result)
      end
    end

    def normalize_hash_result(result)
      status = fetch(result, :status)

      case status&.to_s
      when "created", "registered", "ok"
        Result.created(credential: fetch(result, :credential))
      when "conflict", "already_registered", "duplicate"
        Result.conflict(credential: fetch(result, :credential) || fetch(result, :existing_credential))
      when "unconfirmed", "failed", "error"
        Result.unconfirmed(reason: status)
      else
        return Result.conflict(credential: result) if fetch(result, :conflict) == true
        return Result.created(credential: fetch(result, :credential)) if fetch(result, :created) == true
        return Result.created(credential: result) if persisted_credential_hash?(result)

        Result.unconfirmed(reason: :unrecognized_store_result)
      end
    end

    def normalize_object_result(result)
      if result.respond_to?(:conflict?) && result.conflict?
        return Result.conflict(credential: safe_reader(result, :credential))
      end

      if result.respond_to?(:created?) && result.created?
        return Result.created(credential: safe_reader(result, :credential))
      end

      if result.respond_to?(:unconfirmed?) && result.unconfirmed?
        return Result.unconfirmed(reason: safe_reader(result, :reason))
      end

      if result.respond_to?(:status)
        normalized = normalize_symbol_result(result.status.to_s.downcase.to_sym)
        return normalized unless normalized.unconfirmed?
      end

      return Result.created(credential: result) if persisted_credential_object?(result)

      Result.unconfirmed(reason: :unrecognized_store_result)
    end

    def persisted_credential_hash?(result)
      has_identifier = (RAW_IDENTIFIER_KEYS + ENCODED_IDENTIFIER_KEYS).any? do |key|
        !fetch(result, key).nil?
      end

      has_identifier && !fetch(result, :public_key).nil?
    end

    def persisted_credential_object?(result)
      has_identifier = (RAW_IDENTIFIER_KEYS + ENCODED_IDENTIFIER_KEYS).any? do |key|
        result.respond_to?(key) && !result.public_send(key).nil?
      end

      has_identifier && result.respond_to?(:public_key) && !result.public_key.nil?
    end

    def safe_reader(object, method)
      object.public_send(method) if object.respond_to?(method)
    end

    def receipt_for(account_id, credential, result)
      if result.conflict?
        return RegistrationReceipt.new(
          status: :conflict,
          account_id: account_id,
          credential: credential,
          stored_credential: result.credential,
          reason: :store_conflict
        )
      end

      if result.unconfirmed?
        return RegistrationReceipt.new(
          status: :unconfirmed,
          account_id: account_id,
          credential: credential,
          stored_credential: result.credential,
          reason: result.reason || :unconfirmed_store_result
        )
      end

      confirm_last_write(account_id, credential, result)
    end

    def confirm_last_write(account_id, credential, result)
      if store.respond_to?(:find_credential)
        stored = store.find_credential(account_id: account_id, raw_id: credential.raw_id)

        if stored && active_record?(stored) && record_belongs_to_account?(stored, account_id)
          return registered_receipt(account_id, credential, stored)
        end

        return unconfirmed_receipt(account_id, credential, result, :not_active_after_write)
      end

      matches = active_credential_records(account_id).select do |record|
        identifier_pairs(record).any? { |raw_id, _| raw_id == credential.raw_id }
      end

      if matches.size == 1
        registered_receipt(account_id, credential, matches.first)
      else
        unconfirmed_receipt(
          account_id,
          credential,
          result,
          matches.empty? ? :not_found_in_active_credentials : :ambiguous_active_credentials
        )
      end
    end

    def registered_receipt(account_id, credential, stored)
      RegistrationReceipt.new(
        status: :registered,
        account_id: account_id,
        credential: credential,
        stored_credential: stored
      )
    end

    def unconfirmed_receipt(account_id, credential, result, reason)
      RegistrationReceipt.new(
        status: :unconfirmed,
        account_id: account_id,
        credential: credential,
        stored_credential: result.credential,
        reason: reason
      )
    end

    def encoder
      relying_party.encoder
    end
  end
end
