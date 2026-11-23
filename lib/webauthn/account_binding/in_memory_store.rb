# frozen_string_literal: true

module WebAuthn
  module AccountBinding
    class Account
      attr_accessor :id, :user_handle, :legacy_user_handle, :status, :merged_into

      def initialize(id:, user_handle: nil, legacy_user_handle: nil, status: :active, merged_into: nil)
        @id = id
        @user_handle = user_handle
        @legacy_user_handle = legacy_user_handle
        @status = status
        @merged_into = merged_into
      end

      def active?
        status == :active
      end
    end

    class StoredCredential
      attr_accessor :id,
                    :account_id,
                    :public_key,
                    :sign_count,
                    :user_handle,
                    :handle_format,
                    :discoverable,
                    :active

      def initialize(
        id:,
        account_id:,
        public_key:,
        sign_count: 0,
        user_handle: nil,
        handle_format: :modern,
        discoverable: false,
        active: true
      )
        @id = id
        @account_id = account_id
        @public_key = public_key
        @sign_count = sign_count
        @user_handle = user_handle
        @handle_format = handle_format
        @discoverable = discoverable
        @active = active
      end

      def active?
        !!active
      end

      def discoverable?
        !!discoverable
      end

      def legacy_handle?
        handle_format == :legacy
      end
    end

    # A deliberately small account store for the contract examples and specs.
    # Reads are counted so callers can assert how many times a decision was
    # based on freshly-read account state.
    class InMemoryStore
      attr_reader :account_reads, :credential_reads

      def initialize
        @accounts = {}
        @credentials = {}
        @account_reads = 0
        @credential_reads = 0
      end

      def add_account(id:, user_handle: nil, legacy_user_handle: nil, status: :active, merged_into: nil)
        accounts[id] = Account.new(
          id: id,
          user_handle: user_handle,
          legacy_user_handle: legacy_user_handle,
          status: status,
          merged_into: merged_into
        )
      end

      def add_credential(**keyword_arguments)
        credential = StoredCredential.new(**keyword_arguments)
        credentials[credential.id] = credential
      end

      def find_account(id)
        @account_reads += 1
        accounts[id]
      end

      def find_credential(id)
        @credential_reads += 1
        credentials[id]
      end

      def credentials_for(account_id)
        credentials.each_value.select { |credential| credential.account_id == account_id }
      end

      def merge_accounts!(from:, into:)
        source = accounts.fetch(from)
        target = accounts.fetch(into)

        credentials.each_value do |credential|
          credential.account_id = target.id if credential.account_id == source.id
        end

        source.status = :merged
        source.merged_into = target.id
      end

      def unbind_credential!(id)
        credentials.fetch(id).account_id = nil
      end

      def disable_account!(id)
        accounts.fetch(id).status = :disabled
      end

      def disable_credential!(id)
        credentials.fetch(id).active = false
      end

      def record_sign_count!(id, sign_count)
        credential = credentials.fetch(id)
        credential.sign_count = sign_count
      end

      def reset_reads!
        @account_reads = 0
        @credential_reads = 0
      end

      private

      attr_reader :accounts, :credentials
    end
  end
end
