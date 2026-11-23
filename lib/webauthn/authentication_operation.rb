# frozen_string_literal: true

require "webauthn/error"

module WebAuthn
  class OperationError < Error; end
  class OperationConsumedError < OperationError; end
  class OperationRevokedError < OperationError; end

  # Records the terms approved when authentication options were issued,
  # so the ceremony is later verified against those exact terms even if
  # the caller's policy changes while the operation is still pending.
  class AuthenticationOperation
    STATE_PENDING = :pending
    STATE_CONSUMED = :consumed
    STATE_REVOKED = :revoked

    attr_reader :options, :context, :state

    def initialize(options, context: nil)
      @options = options
      @context = context
      @state = STATE_PENDING
    end

    def challenge
      options.challenge
    end

    # The user verification requirement approved at issuance time.
    def user_verification
      options.user_verification
    end

    def user_verification_required?
      user_verification == "required" || user_verification == true
    end

    def pending?
      state == STATE_PENDING
    end

    def consumed?
      state == STATE_CONSUMED
    end

    def revoked?
      state == STATE_REVOKED
    end

    def ensure_pending!
      raise OperationConsumedError, "Authentication operation was already consumed" if consumed?
      raise OperationRevokedError, "Authentication operation was revoked" if revoked?

      true
    end

    def consume!
      ensure_pending!

      @state = STATE_CONSUMED
    end

    def revoke!
      raise OperationConsumedError, "Authentication operation was already consumed" if consumed?

      @state = STATE_REVOKED
    end
  end
end
