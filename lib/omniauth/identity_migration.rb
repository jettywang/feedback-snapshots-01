module OmniAuth
  module IdentityMigration
    class Error < StandardError; end
    class UnknownRegistration < Error; end
    class UnapprovedMapping < Error; end
    class InvalidMapping < Error; end
  end
end

require_relative 'identity_migration/principal'
require_relative 'identity_migration/registration'
require_relative 'identity_migration/mapping'
require_relative 'identity_migration/receipt'
require_relative 'identity_migration/ledger'
require_relative 'identity_migration/contract'

module OmniAuth
  module IdentityMigration
    Registry = Contract
    Directory = Registration
    Identity = Principal
    Conversion = Receipt
    MigrationResult = Receipt
  end
end

module OmniAuth
  ProviderMigration = IdentityMigration
  Migration = IdentityMigration
  IdentityPinning = IdentityMigration
  IdentityContract = IdentityMigration::Contract
  CallbackContract = IdentityMigration::Contract
end
