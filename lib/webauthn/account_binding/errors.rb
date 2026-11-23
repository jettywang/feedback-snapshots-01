# frozen_string_literal: true

require "webauthn/error"

module WebAuthn
  module AccountBinding
    # Raised inside the relying-party lookup callback when the material read
    # for verification cannot satisfy the entry's handle policy. It is
    # converted into a rejected Attempt and never escapes #verify.
    class LookupError < WebAuthn::Error
      attr_reader :reason

      def initialize(reason)
        @reason = reason

        super(reason.to_s)
      end
    end
  end
end
