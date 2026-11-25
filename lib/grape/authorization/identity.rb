# frozen_string_literal: true

module Grape
  module Authorization
    # The source-attested principal the authentication phase puts in the
    # request env (see {Grape::DSL::InsideRoute#authenticate_identity}).
    #
    # An Identity is a per-request value object, never a global record keyed by
    # user name. Two requests for the same name authenticated by different
    # sources produce different instances with different #source and may hold
    # different roles; nothing here is shared between them, so a role granted to
    # "ada" by one source can never leak to an "ada" approved by another.
    Identity = Data.define(:name, :source, :roles, :attributes) do
      def initialize(name:, source:, roles: [], attributes: {})
        normalized_roles = Array(roles).map { |role| role.to_s.to_sym }.uniq
        super(
          name: name.to_s,
          source: source.to_s.to_sym,
          roles: normalized_roles.freeze,
          attributes: attributes.transform_keys(&:to_sym).freeze
        )
      end

      def role?(*wanted)
        wanted.any? { |role| roles.include?(role.to_s.to_sym) }
      end
      alias has_role? role?

      def to_s
        "#{name}@#{source}"
      end
    end
  end
end
