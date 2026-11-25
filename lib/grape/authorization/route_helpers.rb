# frozen_string_literal: true

module Grape
  module Authorization
    # Endpoint-context helpers mixed into Grape::DSL::InsideRoute, so the same
    # methods are reachable from authentication blocks, role predicates and
    # route business blocks.
    module RouteHelpers
      # Publish the source-attested identity produced by an authenticator into
      # the request env. Called from the +auth+ block; returns the identity so
      # the auth strategy sees a truthy result.
      def authenticate_identity(identity)
        env[Grape::Env::AUTHORIZATION_IDENTITY] = identity
      end

      def authorization_identity
        env[Grape::Env::AUTHORIZATION_IDENTITY]
      end
      alias current_identity authorization_identity

      # The per-request role context (source + version + mount declaration).
      def authorization_context
        @authorization_context ||= Grape::Authorization::Context.new(endpoint: self, env:)
      end

      def effective_roles
        authorization_context.effective_roles
      end

      def role?(*roles)
        authorization_context.role?(*roles)
      end
      alias has_role? role?
    end
  end
end
