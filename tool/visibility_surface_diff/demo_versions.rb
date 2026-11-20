# frozen_string_literal: true
# In-memory simulation of two schema versions for visibility-surface review.
# V2 contains exactly three kinds of changes compared to V1:
#
#   1. New role-visible definitions: `Employee.salaryBand` and
#      `Query.search(includeArchived:)` appear for the `admin` profile only.
#   2. A type hidden on an interface: `InternalBot` leaves
#      `NamedEntity.possibleTypes` for the `public` profile.
#   3. Internal-only changes with no visible impact: a resolver rewrite and
#      a new field that is hidden from every profile.
#
# Run from the repo root:
#
#   ruby tool/visibility_surface_diff.rb tool/visibility_surface_diff/demo_versions.rb

module VisibilitySurfaceDiffDemo
  class BaseArgument < GraphQL::Schema::Argument
    def initialize(*args, roles: nil, **kwargs, &block)
      @roles = roles
      super(*args, **kwargs, &block)
    end

    def visible?(context)
      super && (@roles.nil? || @roles.include?(context[:role]))
    end
  end

  class BaseField < GraphQL::Schema::Field
    argument_class(BaseArgument)

    def initialize(*args, roles: nil, **kwargs, &block)
      @roles = roles
      super(*args, **kwargs, &block)
    end

    def visible?(context)
      super && (@roles.nil? || @roles.include?(context[:role]))
    end
  end

  class BaseObject < GraphQL::Schema::Object
    field_class(BaseField)

    class << self
      attr_writer :visible_to_roles

      def visible?(context)
        (!defined?(@visible_to_roles) || @visible_to_roles.nil? || @visible_to_roles.include?(context[:role])) && super
      end
    end
  end

  module NamedEntity
    include GraphQL::Schema::Interface
    field_class(BaseField)

    field :name, String
  end

  class Store < BaseObject
    implements NamedEntity
  end

  PROFILES = {
    public: { role: :public },
    admin: { role: :admin },
  }

  def self.build_schema(version:)
    # Change 2: in V2, InternalBot is hidden from the public profile.
    internal_bot = Class.new(BaseObject) do
      graphql_name("InternalBot")
      self.visible_to_roles = (version == 2 ? [:admin] : nil)
      implements(NamedEntity)
      field :name, String
    end

    employee = Class.new(BaseObject) do
      graphql_name("Employee")
      field :name, String
      if version == 2
        # Change 1a: new field, visible to the admin profile only.
        field :salary_band, Integer, roles: [:admin]
        # Change 3a: new field, hidden from every profile -- internal only.
        field :internal_metrics, String, roles: []
      end
    end

    query_type = Class.new(BaseObject) do
      graphql_name("Query")
      field :employee, employee
      field :search, [NamedEntity] do
        argument :query, String
        if version == 2
          # Change 1b: new argument, visible to the admin profile only.
          argument :include_archived, GraphQL::Schema::Member::GraphQLTypeNames::Boolean, required: false, roles: [:admin]
        end
      end

      # Change 3b: resolver rewrite between versions, same response shape.
      if version == 1
        def employee
          { name: "Ada" }
        end
      else
        def employee
          { "name" => "Ada" }
        end
      end
    end

    Class.new(GraphQL::Schema) do
      query(query_type)
      orphan_types(Store, internal_bot)
      use GraphQL::Schema::Visibility, profiles: PROFILES.transform_values(&:dup), preload: true
    end
  end
end

SCHEMA_V1 = VisibilitySurfaceDiffDemo.build_schema(version: 1)
SCHEMA_V2 = VisibilitySurfaceDiffDemo.build_schema(version: 2)
VISIBILITY_PROFILES = [:public, :admin]
