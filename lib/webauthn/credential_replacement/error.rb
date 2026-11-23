# frozen_string_literal: true

require "webauthn/error"

module WebAuthn
  module CredentialReplacement
    class InvalidApprovalError < Error; end
    class OperatorNotAuthorizedError < Error; end
    class ApprovalMismatchError < Error; end
  end
end
