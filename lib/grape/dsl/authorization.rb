# frozen_string_literal: true

module Grape
  module DSL
    # Fine-grained, per-handler authorization. Where +http_basic+ / +auth+
    # answer "who is the caller", +authorize+ answers "may this caller run
    # this handler":
    #
    #   class AccountAPI < Grape::API
    #     authorize do
    #       error!('Forbidden', 403) unless current_user.can?(:read_accounts)
    #     end
    #
    #     get '/accounts' do
    #       accounts
    #     end
    #   end
    #
    # An authorizer is an inheritable, stackable setting like the callbacks:
    # declared at the API level it wraps every route, inside a namespace it
    # wraps that namespace, and on a route just that route, with every
    # enclosing authorizer still running, outermost first.
    #
    # The block is stored on the endpoint that owns the route and evaluated by
    # that endpoint when it actually serves a request, after the router has
    # settled which handler answers. Two Grape APIs mounted on the same visible
    # path -- different versions, or one declining with X-Cascade so a sibling
    # candidate takes over -- therefore each run their own authorizers, and an
    # authorization granted on one never carries over to the other.
    module Authorization
      # Register an authorization block for the current scope. Repeated calls
      # stack, and every enclosing scope's blocks still runs, outermost first.
      #
      # @param name [Symbol, String, nil] optional label identifying the
      #   permission this check guards, available inside the block as
      #   +authorization_name+ and on the endpoint as
      #   {Grape::Endpoint#authorization_names}. Pass it when several handlers
      #   share a path so logs and tests can tell which permission set ran.
      # @yield block evaluated in the serving endpoint's context; call
      #   +error!+ (or raise) to deny the request, return normally to allow it.
      def authorize(name = nil, &block)
        raise ArgumentError, 'authorize requires a block' unless block

        inheritable_setting.add_authorizer(name, block)
      end
    end
  end
end
