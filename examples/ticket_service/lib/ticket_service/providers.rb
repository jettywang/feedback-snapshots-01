# frozen_string_literal: true

require 'omniauth'

module TicketService
  # Two fictional enterprise-directory providers. Both vouch for the same
  # person ("Casey Jordan") and both place the same role placeholder value
  # in BOTH the user profile (info) and the extra claims. The two auth
  # hashes are indistinguishable once merged — only the provider (and thus
  # the tenant, and thus the policy registry) can tell them apart.
  module Providers
    class FictionalDirectory
      include OmniAuth::Strategy

      # A real strategy would redirect to the IdP here. These fictional
      # directories confirm the identity immediately.
      def request_phase
        callback_call
      end

      uid { 'casey-001' }

      info do
        {
          name: 'Casey Jordan',
          email: 'casey@example.test',
          role: 'ticket_exporter' # placeholder, also present in extra
        }
      end

      extra do
        {
          role: 'ticket_exporter', # same placeholder as in info
          department: 'support'
        }
      end
    end

    class AlphaDirectory < FictionalDirectory
      option :name, 'alpha_directory'
    end

    class BetaDirectory < FictionalDirectory
      option :name, 'beta_directory'
    end
  end
end
