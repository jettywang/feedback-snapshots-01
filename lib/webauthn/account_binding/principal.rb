# frozen_string_literal: true

module WebAuthn
  module AccountBinding
    class Principal
      attr_reader :account_id, :user_handle

      def initialize(account_id:, user_handle: nil)
        @account_id = account_id
        @user_handle = user_handle
      end

      def to_h
        {
          account_id: account_id,
          user_handle: user_handle
        }
      end
    end
  end
end
