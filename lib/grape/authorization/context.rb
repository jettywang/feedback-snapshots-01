# frozen_string_literal: true

module Grape
  module Authorization
    # The context handed to endpoint role checks. It gathers, for the serving
    # endpoint and this request only:
    #
    # * the source-attested {Identity} from the authentication phase,
    # * the negotiated API version (+env['api.version']+),
    # * the mount declaration (mount path stack, label, grants and ceiling),
    # * the source / version policies in force on this endpoint scope.
    #
    # Build one through {Grape::Authorization::RouteHelpers#authorization_context};
    # do not retain it across requests.
    class Context
      attr_reader :identity, :version, :mount_paths

      def initialize(endpoint:, env: endpoint.env, identity: nil)
        @endpoint = endpoint
        @env = env
        @identity = identity || env[Grape::Env::AUTHORIZATION_IDENTITY]
        @version = env[Grape::Env::API_VERSION]
        @mount_paths = Array(setting.mount_paths).compact.reject { |path| path == '/' }
      end

      def authenticated?
        !identity.nil?
      end

      def name
        identity&.name
      end

      def source
        identity&.source
      end

      # The full mount declaration path, outermost mount first.
      def mount_path
        return '/' if mount_paths.empty?

        joined = mount_paths.join
        joined.start_with?('/') ? joined : "/#{joined}"
      end

      def mount_label
        policies.filter_map { |entry| entry[:mount_label] }.last
      end

      def source_policy
        source_policies[source]
      end

      def effective_roles
        @effective_roles ||= RoleComposer.new(
          identity:,
          sources: source_policies,
          version:,
          version_roles: version_role_map,
          grants: effective_grants,
          ceilings: policy_ceilings,
          management_roles:
        ).call
      end

      def role?(*wanted)
        wanted.flatten.any? { |role| effective_roles.include?(role.to_sym) }
      end
      alias has_role? role?

      def to_h
        {
          name:,
          source:,
          version:,
          mount_path:,
          mount_label:,
          effective_roles:
        }
      end

      private

      attr_reader :endpoint, :env

      def setting
        endpoint.inheritable_setting
      end

      def policies
        @policies ||= setting.authorization_policies
      end

      def source_policies
        @source_policies ||= policies.each_with_object({}) do |entry, memo|
          entry[:sources]&.each { |name, policy| memo[name.to_sym] = policy }
        end
      end

      def version_role_map
        @version_role_map ||= policies.each_with_object({}) do |entry, memo|
          next unless entry[:version_roles]

          entry[:version_roles].each do |version, map|
            key = version.to_s
            memo[key] = (memo[key] || {}).merge(map)
          end
        end
      end

      def effective_grants
        policies.flat_map { |entry| Array(entry[:grants]) }
      end

      def policy_ceilings
        policies.filter_map { |entry| entry[:ceiling] }
      end

      def management_roles
        declared = policies.flat_map { |entry| Array(entry[:management_roles]) }
        declared.empty? ? RoleComposer::DEFAULT_MANAGEMENT_ROLES : declared
      end
    end
  end
end
