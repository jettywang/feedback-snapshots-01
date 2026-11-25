# frozen_string_literal: true

module Grape
  module DSL
    # Endpoint role checking enriched with the context the authentication
    # phase produced.
    #
    # A role condition stays usable on its own: with no source / version /
    # mount policies declared, +require_role+ simply checks the roles carried
    # by the request's Identity (or a zero-argument predicate, evaluated in
    # the endpoint like any route block).
    #
    #   require_role :admin
    #   require_role { |context| context.name == 'root' }
    #
    # When an API declares sources, a version role map and mount grants or
    # ceilings, Authorization::Context composes all of them into the effective
    # roles for the serving endpoint. Every declaration is an inheritable,
    # scope-local setting, so a mount / namespace override never reaches a
    # sibling mount.
    module Roles
      # Register a role condition for the current scope. Symbol/String roles
      # are accepted when the context has at least one of them; several roles
      # in one call are an ANY match. Repeated calls stack and every condition
      # must pass. An optional block receives the Authorization::Context;
      # return false (or call +error!+) to deny.
      def require_role(*roles, &block)
        condition = { roles: roles.flatten.map(&:to_sym), block: }
        inheritable_setting.add_role_condition(condition)
      end
      alias role require_role

      # Register one approved identity source. +management: true+ marks the
      # only source whose identities may keep management roles such as
      # +:admin+ after composition.
      def identity_source(name, management: false)
        policy = Grape::Authorization::SourcePolicy.new(name:, management:)
        inheritable_setting.add_authorization_policy(sources: { name.to_sym => policy })
      end
      alias authorization_source identity_source

      # Declare how source roles translate for each negotiated API version:
      #
      #   version_role_map 'v1' => { steward: :admin },
      #                    'v2' => { steward: :auditor }
      def version_role_map(map)
        normalized = map.each_with_object({}) do |(version, translations), memo|
          memo[version.to_s] = translations.transform_keys(&:to_sym).transform_values(&:to_sym)
        end
        inheritable_setting.add_authorization_policy(version_roles: normalized)
      end
      alias authorization_version_roles version_role_map

      # Roles this scope (or mount declaration) adds to every identity.
      def grant_roles(*roles)
        inheritable_setting.add_authorization_policy(grants: roles.flatten.map(&:to_sym))
      end

      # Upper bound this scope (or mount declaration) imposes: effective roles
      # are intersected with the ceiling. Several ceilings intersect.
      def role_ceiling(*roles)
        inheritable_setting.add_authorization_policy(ceiling: roles.flatten.map(&:to_sym))
      end

      # Roles treated as management duties, stripped for non-management
      # sources. Defaults to +[:admin]+.
      def management_roles(*roles)
        inheritable_setting.add_authorization_policy(management_roles: roles.flatten.map(&:to_sym))
      end
    end
  end
end
