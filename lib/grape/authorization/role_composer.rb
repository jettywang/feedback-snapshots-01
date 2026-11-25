# frozen_string_literal: true

module Grape
  module Authorization
    # Computes the effective roles of one request from the four inputs the
    # task separates:
    #
    # * the source-attested {Identity} produced by the authentication phase,
    # * the source policies registered for this endpoint scope,
    # * the role map declared for the negotiated API version,
    # * the grants and ceilings declared by the mount / namespace.
    #
    # The result is per-request and scope-local. It is never looked up by user
    # name in a global table, so two "ada" principals authenticated by
    # different sources never share a result and a grant declared on one mount
    # never reaches a sibling mount.
    class RoleComposer
      DEFAULT_MANAGEMENT_ROLES = %i[admin].freeze

      def initialize(identity:, sources: {}, version: nil, version_roles: {}, grants: [], ceilings: [],
                     management_roles: DEFAULT_MANAGEMENT_ROLES)
        @identity = identity
        @sources = sources
        @version = version&.to_s
        @version_roles = version_roles
        @grants = Array(grants).flatten
        @ceilings = Array(ceilings).reject { |ceiling| Array(ceiling).empty? }
        @management_roles = Array(management_roles).flatten
      end

      def call
        return [] unless identity

        # No source policies declared in this scope: classic standalone role
        # checking, where the identity's own roles are authoritative. Once at
        # least one source is registered, an identity from any other source
        # attests no roles here.
        return [] if sources.any? && !sources.key?(identity.source)

        roles = identity.roles.dup
        apply_version_map(roles)
        roles.concat(grants.map(&:to_sym))
        roles.reject! { |role| management_roles.include?(role.to_sym) } if sources.any? && !sources[identity.source]&.management?
        apply_ceilings(roles)
        roles.map(&:to_sym).uniq.sort
      end

      private

      attr_reader :identity, :sources, :version, :version_roles, :grants, :ceilings, :management_roles

      def apply_version_map(roles)
        map = version_roles[version] || version_roles[version&.to_sym]
        return unless map

        map.each do |from, to|
          roles << to.to_sym if roles.include?(from.to_sym)
        end
      end

      def apply_ceilings(roles)
        return if ceilings.empty?

        allowed = ceilings.map { |ceiling| Array(ceiling).map(&:to_sym) }.reduce(:&)
        roles.select! { |role| allowed.include?(role.to_sym) }
      end
    end
  end
end
