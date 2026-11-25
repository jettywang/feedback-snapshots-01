# frozen_string_literal: true

module Grape
  module Authorization
    # The role policy an API attaches to one approved identity source.
    #
    # +management: true+ marks the single source allowed to attest management
    # duties. Roles that count as management roles (by default +:admin+) are
    # removed from an identity authenticated by any other source while the
    # effective roles are composed, even if that source -- or a mount
    # declaration -- asserts the very same role name.
    SourcePolicy = Data.define(:name, :management) do
      def initialize(name:, management: false)
        super(name: name.to_s.to_sym, management: management == true)
      end

      alias management? management
    end
  end
end
