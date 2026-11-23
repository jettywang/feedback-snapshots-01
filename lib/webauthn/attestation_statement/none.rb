# frozen_string_literal: true

require "webauthn/attestation_statement/base"

module WebAuthn
  module AttestationStatement
    class None < Base
      def valid?(*_args)
        if valid_format? && trustworthy?
          [WebAuthn::AttestationStatement::ATTESTATION_TYPE_NONE, nil]
        else
          false
        end
      end

      def valid_format?
        statement == {}
      end

      private

      def attestation_type
        WebAuthn::AttestationStatement::ATTESTATION_TYPE_NONE
      end
    end
  end
end
