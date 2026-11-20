# frozen_string_literal: true
require "spec_helper"

describe GraphQL::Schema::Visibility do
  class VisSchema < GraphQL::Schema
    class BaseField < GraphQL::Schema::Field
      def initialize(*args, admin_only: false, **kwargs, &block)
        super(*args, **kwargs, &block)
        @admin_only = admin_only
      end

      def visible?(ctx)
        super && (@admin_only ? !!ctx[:is_admin] : true)
      end
    end

    class BaseObject < GraphQL::Schema::Object
      field_class(BaseField)

      def self.visible?(ctx)
        (@admin_only ? !!ctx[:is_admin] : true) && super
      end

      def self.admin_only(new_value = nil)
        if new_value.nil?
          @admin_only
        else
          @admin_only = new_value
        end
      end
    end

    class Product < BaseObject
      field :name, String, hash_key: :name
      field :price, Integer, hash_key: :price
      field :cost_of_goods_sold, Integer, admin_only: true, hash_key: :cost_of_goods_sold
    end

    class Widget < BaseObject
      admin_only(true)
      field :name, String
    end

    class WidgetKind < GraphQL::Schema::Enum
      value :FOO
      value :BAR
    end

    class Query < BaseObject
      field :products, [Product], resolve_legacy_instance_method: true
      field :widget, Widget do
        argument :type, WidgetKind
      end

      def products
        [{ name: "Pool Noodle", price: 100, cost_of_goods_sold: 5 }]
      end
    end

    query(Query)
    use GraphQL::Schema::Visibility, profiles: { public: {}, admin: { is_admin: true } }, preload: true
  end

  class DynVisSchema < VisSchema
    use GraphQL::Schema::Visibility, profiles: { public: {}, admin: {} }, dynamic: true, preload: false
  end

  class PreloadDynVisSchema < VisSchema
    use GraphQL::Schema::Visibility, profiles: { public: {}, admin: {} }, dynamic: true, preload: true
  end

  def exec_query(...)
    VisSchema.execute(...)
  end

  describe "top-level schema caches" do
    it "re-uses results" do
      assert_equal DynVisSchema.types.object_id, DynVisSchema.types.object_id
      assert_equal PreloadDynVisSchema.types.object_id, PreloadDynVisSchema.types.object_id
    end
  end

  it "hides unused arguments" do
    schema_sdl = VisSchema.to_definition(context: { visibility_profile: :public })
    refute_includes schema_sdl, "WidgetKind"
  end

  it "raises errors when configuration comes after preload: true" do
    assert_raises GraphQL::Schema::Visibility::TypeConfigurationError do
      Class.new(GraphQL::Schema) do
        use GraphQL::Schema::Visibility, profiles: { public: {}, admin: { is_admin: true } }, preload: true
        query(VisSchema::Query)
      end
    end

    assert_raises GraphQL::Schema::Visibility::TypeConfigurationError do
      Class.new(GraphQL::Schema) do
        use GraphQL::Schema::Visibility, profiles: { public: {}, admin: { is_admin: true } }, preload: true
        mutation(VisSchema::Mutation)
      end
    end

    assert_raises GraphQL::Schema::Visibility::TypeConfigurationError do
      Class.new(GraphQL::Schema) do
        use GraphQL::Schema::Visibility, profiles: { public: {}, admin: { is_admin: true } }, preload: true
        subscription(VisSchema::Subscription)
      end
    end

    assert_raises GraphQL::Schema::Visibility::TypeConfigurationError do
      Class.new(GraphQL::Schema) do
        use GraphQL::Schema::Visibility, profiles: { public: {}, admin: { is_admin: true } }, preload: true
        orphan_types([VisSchema::Query])
      end
    end

    assert_raises GraphQL::Schema::Visibility::TypeConfigurationError do
      Class.new(GraphQL::Schema) do
        use GraphQL::Schema::Visibility, profiles: { public: {}, admin: { is_admin: true } }, preload: true
        introspection(VisSchema::IntrospectionSystem)
      end
    end
  end

  it "doesn't raise when preload: false" do
    assert(Class.new(GraphQL::Schema) do
      use GraphQL::Schema::Visibility, profiles: { public: {}, admin: { is_admin: true } }, preload: false
      query(VisSchema::Query)
    end)
  end

  it "doesn't raise on subclasses and preloads" do
    base_schema = Class.new(GraphQL::Schema) do
      query(VisSchema::Query)
      use GraphQL::Schema::Visibility, profiles: { public: {}, admin: { is_admin: true } }, preload: true
    end

    child_schema = Class.new(base_schema) do
      query(VisSchema::Query)
    end

    assert_equal [:public, :admin], base_schema.visibility.cached_profiles.keys
    assert_equal [:public, :admin], child_schema.visibility.cached_profiles.keys
    assert_equal [:public, :admin], Class.new(child_schema).visibility.cached_profiles.keys
  end

  it "raises when preload: nil" do
    assert_raises GraphQL::Schema::Visibility::TypeConfigurationError do
      Class.new(GraphQL::Schema) do
        use GraphQL::Schema::Visibility, profiles: { public: {}, admin: { is_admin: true } }, preload: nil
        query(VisSchema::Query)
      end
    end
  end

  describe "running queries" do
    it "requires context[:visibility]" do
      err = assert_raises ArgumentError do
        exec_query("{ products { name } }")
      end
      expected_msg = "VisSchema expects a visibility profile, but `visibility_profile:` wasn't passed. Provide a `visibility_profile:` value or add `dynamic: true` to your visibility configuration."
      assert_equal expected_msg, err.message
    end

    it "requires a context[:visibility] which is on the list" do
      err = assert_raises ArgumentError do
        exec_query("{ products { name } }", visibility_profile: :nonsense )
      end
      expected_msg = "`:nonsense` isn't allowed for `visibility_profile:` (must be one of :public, :admin). Or, add `:nonsense` to the list of profiles in the schema definition."
      assert_equal expected_msg, err.message
    end

    it "permits `nil` when nil is on the list" do
      res = DynVisSchema.execute("{ products { name } }")
      assert_equal 1, res["data"]["products"].size
      assert_nil res.context.types.name
      assert_equal [], DynVisSchema.visibility.cached_profiles.keys
    end

    it "uses the named visibility" do
      res = exec_query("{ products { name } }", visibility_profile: :public)
      assert_equal ["Pool Noodle"], res["data"]["products"].map { |p| p["name"] }
      assert_equal :public, res.context.types.name
      assert res.context.types.equal?(VisSchema.visibility.cached_profiles[:public]), "It uses the cached instance"

      res = exec_query("{ products { costOfGoodsSold } }", visibility_profile: :public)
      assert_equal ["Field 'costOfGoodsSold' doesn't exist on type 'Product'"], res["errors"].map { |e| e["message"] }

      res = exec_query("{ products { name costOfGoodsSold } }", visibility_profile: :admin)
      assert_equal [{ "name" => "Pool Noodle", "costOfGoodsSold" => 5}], res["data"]["products"]
    end

    it "works with subclasses" do
      child_schema = Class.new(VisSchema) do
        query(VisSchema::Query)
      end
      res = child_schema.execute("{ products { name } }", visibility_profile: :public)
      assert_equal ["Pool Noodle"], res["data"]["products"].map { |p| p["name"] }
      assert_equal :public, res.context.types.name
    end
  end

  describe "preloading profiles" do
    it "preloads when true" do
      assert_equal [:public, :admin], VisSchema.visibility.cached_profiles.keys, "preload: true"
      assert_equal 0, DynVisSchema.visibility.cached_profiles.size, "preload: false"
    end

    describe "when no profile is defined" do
      class NoProfileSchema < GraphQL::Schema
        class ExampleExtension < GraphQL::Schema::FieldExtension; end
        class OtherExampleExtension < GraphQL::Schema::FieldExtension; end

        class Query < GraphQL::Schema::Object
          field :str do
            type(String)
            extension(ExampleExtension)
          end
        end

        class Mutation < GraphQL::Schema::Object
          field :str do
            type(String)
            extension(ExampleExtension)
          end
        end

        class Subscription < GraphQL::Schema::Object
          field :str do
            type(String)
            extension(ExampleExtension)
          end
        end

        class OrphanType < GraphQL::Schema::Object
          field :str do
            type(String)
            extension(ExampleExtension)
            extension(OtherExampleExtension)
          end
        end
        # This one is added before `Visibility`
        subscription(Subscription)
        query { Query }
        mutation { Mutation }
        orphan_types(OrphanType)
        use GraphQL::Schema::Visibility, preload: true

        module CustomIntrospection
          class DynamicFields < GraphQL::Introspection::DynamicFields
            field :__hello do
              type(String)
              extension(OtherExampleExtension)
            end
          end
        end
      end

      it "still preloads" do
        assert_equal [NoProfileSchema::ExampleExtension], NoProfileSchema::Query.all_field_definitions.first.extensions.map(&:class)
        assert_equal [NoProfileSchema::ExampleExtension], NoProfileSchema::Mutation.all_field_definitions.first.extensions.map(&:class)
        assert_equal [NoProfileSchema::ExampleExtension], NoProfileSchema::Subscription.all_field_definitions.first.extensions.map(&:class)
        assert_equal [NoProfileSchema::ExampleExtension, NoProfileSchema::OtherExampleExtension], NoProfileSchema::OrphanType.all_field_definitions.first.extensions.map(&:class)
        custom_int_field = NoProfileSchema::CustomIntrospection::DynamicFields.all_field_definitions.find { |f| f.original_name == :__hello }
        assert_equal [], custom_int_field.extensions
        assert_raises GraphQL::Schema::Visibility::TypeConfigurationError do
          NoProfileSchema.introspection(NoProfileSchema::CustomIntrospection)
        end
        assert_equal [NoProfileSchema::OtherExampleExtension], custom_int_field.extensions.map(&:class)
      end
    end
  end

  describe "lazy-loading root types" do
    class NoVisSchema < GraphQL::Schema
      self.visibility = nil
      @use_visibility_profile = false
    end
    class LazyLoadingSchema < NoVisSchema
      class ExampleExtension < GraphQL::Schema::FieldExtension; end
      class OtherExampleExtension < GraphQL::Schema::FieldExtension; end

      class Query < GraphQL::Schema::Object
        field :str, fallback_value: "Query field", resolve_static: true do
          type(String)
          extension(ExampleExtension)
        end

        def self.str(_context)
          "Query field"
        end
      end

      class Mutation < GraphQL::Schema::Object
        field :str, fallback_value: "Mutation field", resolve_static: true do
          type(String)
          extension(ExampleExtension)
        end

        def self.str(_context)
          "Mutation field"
        end
      end

      class Subscription < GraphQL::Schema::Object
        field :str do
          type(String)
          extension(ExampleExtension)
        end
      end

      class OrphanType < GraphQL::Schema::Object
        field :str do
          type(String)
          extension(ExampleExtension)
          extension(OtherExampleExtension)
        end
      end
      # This one is added before `Visibility`
      subscription(Subscription)
      use GraphQL::Schema::Visibility, preload: false
      query { Query }
      mutation { Mutation }
      orphan_types(OrphanType)
    end

    it "loads types as-needed" do
      assert_equal [LazyLoadingSchema::ExampleExtension], LazyLoadingSchema::Subscription.all_field_definitions.first.extensions.map(&:class)
      assert_equal [], LazyLoadingSchema::Query.all_field_definitions.first.extensions.map(&:class)
      assert_equal [], LazyLoadingSchema::Mutation.all_field_definitions.first.extensions.map(&:class)
      assert_equal [], LazyLoadingSchema::OrphanType.all_field_definitions.first.extensions.map(&:class)

      res = LazyLoadingSchema.execute("{ __typename }")
      assert_equal "Query", res["data"]["__typename"]
      assert_equal [], LazyLoadingSchema::Query.all_field_definitions.first.extensions.map(&:class)
      assert_equal [LazyLoadingSchema::ExampleExtension], LazyLoadingSchema::Subscription.all_field_definitions.first.extensions.map(&:class)
      assert_equal [], LazyLoadingSchema::Mutation.all_field_definitions.first.extensions.map(&:class)
      assert_equal [], LazyLoadingSchema::OrphanType.all_field_definitions.first.extensions.map(&:class)

      res = LazyLoadingSchema.execute("{ str }")
      assert_equal "Query field", res["data"]["str"]
      assert_equal [LazyLoadingSchema::ExampleExtension], LazyLoadingSchema::Query.all_field_definitions.first.extensions.map(&:class)
      assert_equal [LazyLoadingSchema::ExampleExtension], LazyLoadingSchema::Subscription.all_field_definitions.first.extensions.map(&:class)
      assert_equal [], LazyLoadingSchema::Mutation.all_field_definitions.first.extensions.map(&:class)
      assert_equal [], LazyLoadingSchema::OrphanType.all_field_definitions.first.extensions.map(&:class)

      res = LazyLoadingSchema.execute("mutation { str }")
      assert_equal "Mutation field", res["data"]["str"]
      assert_equal [LazyLoadingSchema::ExampleExtension], LazyLoadingSchema::Query.all_field_definitions.first.extensions.map(&:class)
      assert_equal [LazyLoadingSchema::ExampleExtension], LazyLoadingSchema::Subscription.all_field_definitions.first.extensions.map(&:class)
      assert_equal [LazyLoadingSchema::ExampleExtension], LazyLoadingSchema::Mutation.all_field_definitions.first.extensions.map(&:class)
      assert_equal [], LazyLoadingSchema::OrphanType.all_field_definitions.first.extensions.map(&:class)
    end
  end

  describe "interfaces thru superclass" do
    class InterfaceSuperclassSchema < GraphQL::Schema
      module Node
        include GraphQL::Schema::Interface
        field :id, ID, hash_key: :id
      end

      class NodeObject < GraphQL::Schema::Object
        implements Node
      end

      class Thing < NodeObject
        field :name, String, hash_key: :name
      end

      class Query < GraphQL::Schema::Object
        field :node, Node, resolve_static: true

        def self.node(context)
          { id: "101", name: "Hat" }
        end

        def node
          self.class.node(context)
        end

        field :thing, Thing
      end

      query(Query)
      use GraphQL::Schema::Visibility
      def self.resolve_type(...); Thing; end
    end
  end

  it "Can use interface relationship properly" do
    res = InterfaceSuperclassSchema.execute("{ node { id ... on Thing { name } } }")
    assert_equal "Hat", res["data"]["node"]["name"]
  end

  describe "profile admission rules across two internal schemas" do
    class SiteAlphaSchema < GraphQL::Schema
      class BaseField < GraphQL::Schema::Field
        def initialize(*args, internal_only: false, **kwargs, &block)
          super(*args, **kwargs, &block)
          @internal_only = internal_only
        end

        def visible?(ctx)
          super && (@internal_only ? !!ctx[:internal] : true)
        end
      end

      class BaseObject < GraphQL::Schema::Object
        field_class(BaseField)
      end

      class Product < BaseObject
        field :name, String, hash_key: :name
        field :internal_notes, String, internal_only: true, hash_key: :internal_notes
      end

      class Query < BaseObject
        field :product, Product

        def product
          { name: "Alpha Gadget", internal_notes: "alpha-secret" }
        end
      end

      query(Query)
      use GraphQL::Schema::Visibility, profiles: { guest: {}, staff: { internal: true } }
    end

    class SiteBetaSchema < GraphQL::Schema
      class BaseField < GraphQL::Schema::Field
        def initialize(*args, internal_only: false, **kwargs, &block)
          super(*args, **kwargs, &block)
          @internal_only = internal_only
        end

        def visible?(ctx)
          super && (@internal_only ? !!ctx[:internal] : true)
        end
      end

      class BaseObject < GraphQL::Schema::Object
        field_class(BaseField)

        def self.visible?(ctx)
          (@internal_only ? !!ctx[:internal] : true) && super
        end

        def self.internal_only(new_value = nil)
          if new_value.nil?
            @internal_only
          else
            @internal_only = new_value
          end
        end
      end

      class AuditLog < BaseObject
        internal_only(true)
        field :message, String, hash_key: :message
      end

      class Order < BaseObject
        field :total, Integer, hash_key: :total
        field :cost_breakdown, [Integer], internal_only: true, hash_key: :cost_breakdown
      end

      class Query < BaseObject
        field :order, Order
        field :audit_log, AuditLog, internal_only: true

        def order
          { total: 42, cost_breakdown: [40, 2] }
        end

        def audit_log
          { message: "beta-secret" }
        end
      end

      query(Query)
      use GraphQL::Schema::Visibility, profiles: { viewer: {}, operator: { internal: true } }
    end

    ALPHA_QUERY = "{ product { name internalNotes } }"
    BETA_QUERY = "{ order { total costBreakdown } auditLog { message } }"
    ALPHA_INTROSPECTION = "{ __type(name: \"Product\") { fields { name } } }"
    BETA_INTROSPECTION = "{ __schema { types { name } } __type(name: \"Order\") { fields { name } } }"

    it "exposes explicit, checkable admission rules" do
      assert_equal [:guest, :staff], SiteAlphaSchema.visibility.profile_names
      assert_equal [:viewer, :operator], SiteBetaSchema.visibility.profile_names

      assert SiteAlphaSchema.visibility.registered_profile?(:guest)
      assert SiteAlphaSchema.visibility.registered_profile?(:staff)
      refute SiteAlphaSchema.visibility.registered_profile?(:operator), "SiteBetaSchema's profile isn't registered on SiteAlphaSchema"
      refute SiteAlphaSchema.visibility.registered_profile?(:intruder)
      assert SiteBetaSchema.visibility.registered_profile?(:viewer)
      refute SiteBetaSchema.visibility.registered_profile?(:guest)

      assert SiteAlphaSchema.visibility.allowed_profile?(:staff)
      refute SiteAlphaSchema.visibility.allowed_profile?(:intruder)
      assert DynVisSchema.visibility.allowed_profile?(:anything), "`dynamic: true` admits unregistered profiles"
    end

    it "rejects unregistered profiles before validation or execution" do
      assert_raises(ArgumentError) { SiteAlphaSchema.execute("{ product { name } }", visibility_profile: :intruder) }
      assert_raises(ArgumentError) { SiteAlphaSchema.validate("{ product { name } }", context: { visibility_profile: :intruder }) }
      assert_raises(ArgumentError) { GraphQL::Query.new(SiteAlphaSchema, "{ __typename }", visibility_profile: :intruder) }
      # A profile registered on another schema is still unregistered here:
      assert_raises(ArgumentError) { SiteAlphaSchema.execute("{ product { name } }", visibility_profile: :operator) }
      assert_raises(ArgumentError) { SiteBetaSchema.execute("{ order { total } }", visibility_profile: :guest) }
      # A missing profile is rejected, too:
      assert_raises(ArgumentError) { SiteBetaSchema.execute("{ order { total } }") }
    end

    it "gives introspection, static validation, and execution consistent views per profile" do
      # Introspection only shows internal fields to the authorized profile:
      guest_fields = SiteAlphaSchema.execute(ALPHA_INTROSPECTION, visibility_profile: :guest)["data"]["__type"]["fields"].map { |f| f["name"] }
      staff_fields = SiteAlphaSchema.execute(ALPHA_INTROSPECTION, visibility_profile: :staff)["data"]["__type"]["fields"].map { |f| f["name"] }
      assert_equal ["name"], guest_fields
      assert_equal ["internalNotes", "name"], staff_fields.sort

      # Static validation agrees:
      guest_validation = SiteAlphaSchema.validate(ALPHA_QUERY, context: { visibility_profile: :guest })
      assert_equal ["Field 'internalNotes' doesn't exist on type 'Product'"], guest_validation.map(&:message)
      assert_equal [], SiteAlphaSchema.validate(ALPHA_QUERY, context: { visibility_profile: :staff })

      # Real field access agrees — the same query shape, decided by the profile:
      guest_res = SiteAlphaSchema.execute(ALPHA_QUERY, visibility_profile: :guest)
      assert_equal ["Field 'internalNotes' doesn't exist on type 'Product'"], guest_res["errors"].map { |e| e["message"] }
      staff_res = SiteAlphaSchema.execute(ALPHA_QUERY, visibility_profile: :staff)
      assert_equal({ "name" => "Alpha Gadget", "internalNotes" => "alpha-secret" }, staff_res["data"]["product"])
    end

    it "keeps profiles isolated when two schemas run sequentially and interleaved in one process" do
      # Sequential runs, one schema at a time:
      assert_equal({ "name" => "Alpha Gadget", "internalNotes" => "alpha-secret" }, SiteAlphaSchema.execute(ALPHA_QUERY, visibility_profile: :staff)["data"]["product"])
      assert_equal({ "total" => 42, "costBreakdown" => [40, 2] }, SiteBetaSchema.execute(BETA_QUERY, visibility_profile: :operator)["data"]["order"])

      # Interleaved runs of both schemas and both profiles, twice to catch cache pollution:
      results = {}
      2.times do
        results[:alpha_guest] = SiteAlphaSchema.execute(ALPHA_QUERY, visibility_profile: :guest)
        results[:beta_operator] = SiteBetaSchema.execute(BETA_QUERY, visibility_profile: :operator)
        results[:alpha_staff] = SiteAlphaSchema.execute(ALPHA_QUERY, visibility_profile: :staff)
        results[:beta_viewer] = SiteBetaSchema.execute(BETA_QUERY, visibility_profile: :viewer)
      end

      assert_equal ["Field 'internalNotes' doesn't exist on type 'Product'"], results[:alpha_guest]["errors"].map { |e| e["message"] }
      assert_equal({ "name" => "Alpha Gadget", "internalNotes" => "alpha-secret" }, results[:alpha_staff]["data"]["product"])
      assert_equal({ "total" => 42, "costBreakdown" => [40, 2] }, results[:beta_operator]["data"]["order"])
      assert_equal "beta-secret", results[:beta_operator]["data"]["auditLog"]["message"]
      beta_viewer_errors = results[:beta_viewer]["errors"].map { |e| e["message"] }
      assert_includes beta_viewer_errors, "Field 'costBreakdown' doesn't exist on type 'Order'"
      assert_includes beta_viewer_errors, "Field 'auditLog' doesn't exist on type 'Query'"

      # A multiplex mixes both profiles in a single same-process run:
      mixed_guest, mixed_staff = SiteAlphaSchema.multiplex([
        { query: ALPHA_QUERY, context: { visibility_profile: :guest } },
        { query: ALPHA_QUERY, context: { visibility_profile: :staff } },
      ])
      assert_equal ["Field 'internalNotes' doesn't exist on type 'Product'"], mixed_guest["errors"].map { |e| e["message"] }
      assert_equal({ "name" => "Alpha Gadget", "internalNotes" => "alpha-secret" }, mixed_staff["data"]["product"])

      # Introspection stays isolated per schema and per profile:
      viewer_intro = SiteBetaSchema.execute(BETA_INTROSPECTION, visibility_profile: :viewer)["data"]
      operator_intro = SiteBetaSchema.execute(BETA_INTROSPECTION, visibility_profile: :operator)["data"]
      refute_includes viewer_intro["__schema"]["types"].map { |t| t["name"] }, "AuditLog"
      assert_includes operator_intro["__schema"]["types"].map { |t| t["name"] }, "AuditLog"
      assert_equal ["total"], viewer_intro["__type"]["fields"].map { |f| f["name"] }
      assert_equal ["costBreakdown", "total"], operator_intro["__type"]["fields"].map { |f| f["name"] }.sort

      # Profile caches stay per-schema and per-profile:
      assert_equal [:guest, :staff], SiteAlphaSchema.visibility.cached_profiles.keys.sort
      assert_equal [:operator, :viewer], SiteBetaSchema.visibility.cached_profiles.keys.sort
      refute SiteAlphaSchema.visibility.cached_profiles[:guest].equal?(SiteAlphaSchema.visibility.cached_profiles[:staff])
    end
  end

  it "defaults to preload: true for Rails.env.staging?" do
    if defined?(Rails)
      prev_rails = Rails
      Object.send :remove_const, :Rails
    end
    mock_env = OpenStruct.new(:staging? => true)
    Object.const_set(:Rails, OpenStruct.new(env: mock_env))
    schema = Class.new(GraphQL::Schema) do
      use GraphQL::Schema::Visibility
    end
    assert Rails.env.staging?
    assert schema.visibility.preload?

    mock_env[:staging?] = false
    mock_env[:test?] = true

    schema = Class.new(GraphQL::Schema) do
      use GraphQL::Schema::Visibility
    end
    assert Rails.env.test?
    refute Rails.env.staging?
    refute schema.visibility.preload?
  ensure
    Object.send(:remove_const, :Rails)
    if prev_rails
      Object.const_set(:Rails, prev_rails)
    end
  end
end
