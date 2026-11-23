# frozen_string_literal: true

module WebAuthn
  module AccountBinding
    # Immutable view of the verification material read before the assertion is
    # checked. It is deliberately not linked to the mutable store record.
    class StoredCredentialSnapshot
      attr_reader :public_key, :sign_count

      def initialize(public_key:, sign_count:)
        @public_key = public_key
        @sign_count = sign_count
      end
    end
  end
end
