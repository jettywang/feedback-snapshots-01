# frozen_string_literal: true

require "action_policy/trusted_context"

module ActionPolicy
  class AuthorizationContextMissing < Error # :nodoc:
    MESSAGE_TEMPLATE = "Missing policy authorization context: %s"

    attr_reader :message

    def initialize(id)
      @message = MESSAGE_TEMPLATE % id
    end
  end

  # Raised when a trusted authorization context key is provided or replaced
  # outside of the trusted ingress (i.e., by a derived policy call).
  class UntrustedAuthorizationContext < Error # :nodoc:
    MESSAGE_TEMPLATE = "Authorization context %s must be provided by the trusted ingress, " \
      "but was provided by %s"

    attr_reader :message

    def initialize(id, source: "a derived policy call")
      @message = MESSAGE_TEMPLATE % [id, source]
    end
  end

  module Policy
    # Authorization context could include multiple parameters.
    #
    # It is possible to provide more verificatio contexts, by specifying them in the policy and
    # providing them at the authorization step.
    #
    # For example:
    #
    #   class ApplicationPolicy < ActionPolicy::Base
    #     # Add user and account to the context; it's required to be passed
    #     # to a policy constructor and be not nil
    #     authorize :user, :account
    #
    #     # you can skip non-nil check if you want
    #     # authorize :account, allow_nil: true
    #
    #     # you can also mark a context key as trusted: its value must be
    #     # provided by the trusted ingress (a controller, channel, job, etc.)
    #     # and cannot be introduced or replaced by a derived policy call
    #     authorize :approver, trusted: true
    #
    #     def manage?
    #       # available as a simple accessor
    #       account.enabled?
    #     end
    #   end
    #
    #   ApplicantPolicy.new(user: user, account: account)
    module Authorization
      class << self
        def included(base)
          base.extend ClassMethods
        end
      end

      attr_reader :authorization_context
      alias_method :build_authorization_context, :authorization_context

      def initialize(record = nil, **params)
        super(record)

        ActionPolicy::TrustedContext.validate!(self.class.authorization_targets, params)

        # Keep only the values that are trusted at this point (including keys
        # this policy doesn't declare), so nested policies sharing a subset of
        # the context can still verify the identity's provenance.
        @action_policy_trusted_context =
          ActionPolicy::TrustedContext.trusted_values(params)

        @authorization_context = {}

        self.class.authorization_targets.each do |id, opts|
          raise AuthorizationContextMissing, id unless params.key?(id) || opts[:optional]

          val = params.fetch(id, nil)

          raise AuthorizationContextMissing, id if val.nil? && opts[:allow_nil] != true

          authorization_context[id] = instance_variable_set("@#{id}", val)
        end

        authorization_context.freeze
      end

      # The context provided when this policy was resolved. Used as the trusted
      # provenance for derived policy lookups during the rule application.
      def action_policy_trusted_context # :nodoc:
        @action_policy_trusted_context
      end

      module ClassMethods # :nodoc:
        def authorize(*ids, allow_nil: false, optional: false, trusted: false)
          allow_nil ||= optional

          ids.each do |id|
            authorization_targets[id] = {allow_nil:, optional:, trusted:}
          end

          attr_reader(*ids)
        end

        # A map of the declared authorization context keys to their options.
        def authorization_targets
          return @authorization_targets if instance_variable_defined?(:@authorization_targets)

          @authorization_targets = if superclass.respond_to?(:authorization_targets)
            superclass.authorization_targets.dup
          else
            {}
          end
        end

        # The list of keys that must be provided by the trusted ingress.
        def trusted_authorization_targets
          authorization_targets.select { |_id, opts| opts[:trusted] }.keys
        end
      end
    end
  end
end
