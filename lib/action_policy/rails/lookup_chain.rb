# frozen_string_literal: true

module ActionPolicy # :nodoc:
  module Rails
    # Add ActiveSupport::Notifications support for policy lookup.
    #
    # Fires `action_policy.lookup` event on every `ActionPolicy.lookup` call
    # and records the policy class that has been finally adopted (or nil when
    # no policy was found).
    module LookupChain
      EVENT_NAME = "action_policy.lookup"

      def lookup(target, **options)
        event = {
          target: target,
          namespace: options[:namespace],
          strict_namespace: options[:strict_namespace] == true
        }

        ActiveSupport::Notifications.instrument(EVENT_NAME, event) do
          policy_class = super
          event[:policy] = policy_class
          policy_class
        end
      end
    end
  end
end
