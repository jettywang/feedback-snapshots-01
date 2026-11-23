# frozen_string_literal: true

require "openssl"
require "webauthn/account_binding/attempt"
require "webauthn/account_binding/errors"
require "webauthn/account_binding/principal"
require "webauthn/account_binding/result"
require "webauthn/account_binding/stored_credential"
require "webauthn/credential"

module WebAuthn
  module AccountBinding
    # Turns a verified WebAuthn assertion into a usable principal without ever
    # treating verification material read during lookup as authoritative for
    # account state. The phases are deliberately separate:
    #
    #   1. #verify reads the credential and account, applies the handle policy
    #      for the chosen entry and asks the relying party to verify the
    #      assertion against that snapshot. It returns an Attempt, never a
    #      session.
    #   2. #commit re-reads the credential and account, checks that the
    #      credential is still bound to the same active, unmerged account and
    #      that the handle policy still holds with the current handle. Only
    #      then does it produce a Principal.
    #
    # A merge, unbind or disable that happens between #verify and #commit
    # therefore rejects the attempt instead of letting the older read decide
    # the new account state.
    class Contract
      ENTRIES = [:usernameless, :known_account].freeze
      HANDLE_POLICIES = [:modern_only, :legacy_fallback].freeze
      DEFAULT_HANDLE_POLICIES = { usernameless: :modern_only, known_account: :modern_only }.freeze

      Lookup = Struct.new(:account, :credential, :user_handle, keyword_init: true)

      attr_reader :store, :relying_party, :handle_policies

      def initialize(store:, relying_party: WebAuthn.configuration.relying_party, handle_policies: {})
        @store = store
        @relying_party = relying_party
        @handle_policies = DEFAULT_HANDLE_POLICIES.merge(handle_policies)

        validate_handle_policies!
      end

      # Performs lookup, entry-specific handle-policy checks and signature
      # verification. The returned Attempt is not a session and must not be
      # used to sign a user in before #commit succeeds.
      def verify(
        entry:,
        raw_credential:,
        challenge:,
        account_id: nil,
        user_presence: nil,
        user_verification: nil
      )
        validate_entry!(entry)
        validate_account_id!(entry, account_id)

        policy = handle_policies.fetch(entry)
        reads = { account: 0, credential: 0 }
        lookup = nil

        begin
          verified_credential, _snapshot = relying_party.verify_authentication(
            raw_credential,
            challenge,
            user_presence: user_presence,
            user_verification: user_verification
          ) do |webauthn_credential|
            lookup = lookup!(entry, policy, webauthn_credential, account_id, reads)

            StoredCredentialSnapshot.new(
              public_key: lookup.credential.public_key,
              sign_count: lookup.credential.sign_count
            )
          end
        rescue LookupError => error
          return Attempt.new(
            entry: entry,
            handle_policy: policy,
            account_id: lookup&.account&.id,
            credential_id: lookup&.credential&.id,
            user_handle: lookup&.user_handle,
            rejection: error.reason,
            account_reads: reads[:account],
            credential_reads: reads[:credential]
          )
        rescue WebAuthn::Error => error
          return Attempt.new(
            entry: entry,
            handle_policy: policy,
            account_id: lookup&.account&.id,
            credential_id: lookup&.credential&.id,
            user_handle: lookup&.user_handle,
            rejection: :assertion_invalid,
            error: error,
            account_reads: reads[:account],
            credential_reads: reads[:credential]
          )
        end

        Attempt.new(
          entry: entry,
          handle_policy: policy,
          account_id: lookup.account.id,
          credential_id: lookup.credential.id,
          user_handle: lookup.user_handle,
          assertion_verified: true,
          verified_credential: verified_credential,
          stored_credential: StoredCredentialSnapshot.new(
            public_key: lookup.credential.public_key,
            sign_count: lookup.credential.sign_count
          ),
          account_reads: reads[:account],
          credential_reads: reads[:credential]
        )
      end

      # Re-reads the account binding and only then creates a Principal. A
      # given Attempt can be committed at most once, so one assertion cannot
      # mint two sessions.
      def commit(attempt)
        unless attempt.verified?
          return Result.new(
            entry: attempt.entry,
            handle_policy: attempt.handle_policy,
            status: :rejected,
            reason: attempt.rejection || :not_verified,
            account_reads: attempt.account_reads,
            credential_reads: attempt.credential_reads,
            credential_id: attempt.credential_id,
            error: attempt.error
          )
        end

        if attempt.consumed?
          return Result.new(
            entry: attempt.entry,
            handle_policy: attempt.handle_policy,
            status: :rejected,
            reason: :attempt_consumed,
            account_reads: attempt.account_reads,
            credential_reads: attempt.credential_reads,
            credential_id: attempt.credential_id
          )
        end

        attempt.consume!

        account_reads = attempt.account_reads
        credential_reads = attempt.credential_reads

        credential_reads += 1
        fresh_credential = store.find_credential(attempt.credential_id)

        unless fresh_credential
          return rejected_result(attempt, :unknown_credential, account_reads, credential_reads)
        end

        account_reads += 1
        fresh_account = store.find_account(attempt.account_id)

        unless fresh_account
          return rejected_result(attempt, :unknown_account, account_reads, credential_reads)
        end

        account_rejection = account_rejection(fresh_account)

        if account_rejection
          return rejected_result(attempt, account_rejection, account_reads, credential_reads)
        end

        if !fresh_credential.active?
          return rejected_result(attempt, :credential_disabled, account_reads, credential_reads)
        end

        unless fresh_credential.account_id == attempt.account_id
          reason = fresh_credential.account_id.nil? ? :credential_unbound : :credential_rebound

          return rejected_result(attempt, reason, account_reads, credential_reads)
        end

        unless fresh_credential.public_key == attempt.stored_credential.public_key
          return rejected_result(attempt, :credential_changed, account_reads, credential_reads)
        end

        handle_rejection = handle_rejection(
          attempt.entry,
          attempt.handle_policy,
          fresh_account,
          fresh_credential,
          attempt.verified_credential
        )

        if handle_rejection
          return rejected_result(attempt, handle_rejection, account_reads, credential_reads)
        end

        if sign_count_replayed?(fresh_credential.sign_count, attempt.verified_credential.sign_count)
          return rejected_result(attempt, :sign_count_replayed, account_reads, credential_reads)
        end

        store.record_sign_count!(fresh_credential.id, attempt.verified_credential.sign_count)

        Result.new(
          entry: attempt.entry,
          handle_policy: attempt.handle_policy,
          status: :authenticated,
          principal: Principal.new(account_id: fresh_account.id, user_handle: fresh_account.user_handle),
          account_reads: account_reads,
          credential_reads: credential_reads,
          credential_id: fresh_credential.id
        )
      end

      def authenticate(
        entry:,
        raw_credential:,
        challenge:,
        account_id: nil,
        user_presence: nil,
        user_verification: nil
      )
        commit(
          verify(
            entry: entry,
            raw_credential: raw_credential,
            challenge: challenge,
            account_id: account_id,
            user_presence: user_presence,
            user_verification: user_verification
          )
        )
      end

      private

      def lookup!(entry, policy, webauthn_credential, account_id, reads)
        reads[:credential] += 1
        credential = store.find_credential(webauthn_credential.id)

        raise LookupError, :unknown_credential unless credential

        if entry == :usernameless
          raise LookupError, :credential_not_discoverable unless credential.discoverable?
        end

        raise LookupError, :credential_disabled unless credential.active?

        if credential.account_id.nil?
          raise LookupError, :credential_unbound
        end

        if entry == :known_account && credential.account_id != account_id
          raise LookupError, :credential_rebound
        end

        resolved_account_id = entry == :known_account ? account_id : credential.account_id

        reads[:account] += 1
        account = store.find_account(resolved_account_id)

        raise LookupError, :unknown_account unless account

        lookup = Lookup.new(account: account, credential: credential, user_handle: webauthn_credential.user_handle)

        rejection = account_rejection(account)

        raise LookupError, rejection if rejection

        rejection = handle_rejection(entry, policy, account, credential, webauthn_credential)

        raise LookupError, rejection if rejection

        lookup
      end

      def validate_entry!(entry)
        return if ENTRIES.include?(entry)

        raise ArgumentError, "Unknown account binding entry: #{entry.inspect}"
      end

      def validate_account_id!(entry, account_id)
        return unless entry == :known_account

        raise ArgumentError, "known_account entry requires an account_id" if account_id.nil?
      end

      def validate_handle_policies!
        handle_policies.each do |entry, policy|
          validate_entry!(entry)

          unless HANDLE_POLICIES.include?(policy)
            raise ArgumentError, "Unknown handle policy for #{entry.inspect}: #{policy.inspect}"
          end

          if entry == :usernameless && policy == :legacy_fallback
            raise ArgumentError, "legacy_fallback is only available for the known_account entry"
          end
        end
      end

      def account_rejection(account)
        return :account_merged if account.merged_into
        return :account_disabled unless account.active?

        nil
      end

      def handle_rejection(entry, policy, account, credential, webauthn_credential)
        presented = webauthn_credential.raw_user_handle

        if policy == :modern_only
          return :legacy_handle_not_allowed if credential.legacy_handle?
          return :handle_missing if account.user_handle.nil?

          if entry == :usernameless
            return :handle_missing if presented.nil?
          end

          return :handle_mismatch if presented && !same_handle?(presented, modern_handle(account.user_handle))

          return nil
        end

        # legacy_fallback is restricted to the known_account entry by
        # #validate_handle_policies!. The account was already established
        # before verification, and the credential must still be bound to it.
        # For an account and credential that are already in the new format the
        # modern handle remains authoritative; legacy material is only
        # accepted while either of them is still in the legacy format.
        return nil if presented.nil?

        if account.user_handle && same_handle?(presented, modern_handle(account.user_handle))
          return nil
        end

        legacy_material = account.user_handle.nil? || credential.legacy_handle?

        if legacy_material
          legacy_handles = [account.legacy_user_handle, credential.user_handle]

          return nil if legacy_handles.compact.any? { |handle| same_handle?(presented, handle) }
        end

        :handle_mismatch
      end

      def modern_handle(handle)
        relying_party.encoder.decode(handle)
      end

      def same_handle?(left, right)
        return false if left.nil? || right.nil?
        return false unless left.bytesize == right.bytesize

        OpenSSL.secure_compare(left, right)
      end

      def sign_count_replayed?(fresh_sign_count, assertion_sign_count)
        if fresh_sign_count.nonzero? || assertion_sign_count.nonzero?
          assertion_sign_count <= fresh_sign_count
        else
          false
        end
      end

      def rejected_result(attempt, reason, account_reads, credential_reads)
        Result.new(
          entry: attempt.entry,
          handle_policy: attempt.handle_policy,
          status: :rejected,
          reason: reason,
          account_reads: account_reads,
          credential_reads: credential_reads,
          credential_id: attempt.credential_id
        )
      end
    end
  end
end
