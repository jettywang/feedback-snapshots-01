# frozen_string_literal: true
require "spec_helper"

describe "GraphQL::Schema.authorization_error_strategy" do
  module PublicAuthorizationErrorTest
    SENSITIVE_PK = "SECRET-PK-42"
    SENSITIVE_TITLE = "TOP-SECRET-TITLE"
    PUBLIC_MESSAGE = "You are not authorized to access this resource"

    class InternalDocument < GraphQL::Schema::Object
      field :id, ID, null: false, hash_key: :id
      field :title, String, null: false, hash_key: :title

      def self.authorized?(object, context)
        super && !context[:denied_ids].include?(object[:id])
      end
    end

    class Folder < GraphQL::Schema::Object
      field :name, String, null: false, hash_key: :name
      field :document, InternalDocument, null: true, hash_key: :document
    end

    class Query < GraphQL::Schema::Object
      field :document, InternalDocument, null: true, hash_key: :document
      field :documents, [InternalDocument, null: true], hash_key: :documents
      field :folder, Folder, null: true, hash_key: :folder
    end

    DENIED_DOCUMENT = { id: SENSITIVE_PK, title: SENSITIVE_TITLE }.freeze
    ROOT_VALUE = {
      document: DENIED_DOCUMENT,
      documents: [
        { id: "doc-1", title: "First" },
        DENIED_DOCUMENT,
        { id: "doc-3", title: "Third" },
      ],
      folder: { name: "Folder", document: DENIED_DOCUMENT },
    }.freeze

    class PublicSchema < GraphQL::Schema
      query(Query)
      authorization_error_strategy(:public)
    end

    class PublicNextSchema < PublicSchema
      use GraphQL::Execution::Next, as_default: true
    end

    class LegacySchema < GraphQL::Schema
      query(Query)
    end

    class AuthorizedField < GraphQL::Schema::Field
      def authorized?(object, _args, context)
        super && !context[:deny_field]
      end
    end

    class GuardedQuery < GraphQL::Schema::Object
      field_class AuthorizedField
      field :value, String, null: true

      def value
        "field-value"
      end

      def self.authorized?(object, context)
        super && !context[:deny_root]
      end
    end

    class RaisingResolver < GraphQL::Schema::Resolver
      type String, null: true

      def authorized?
        raise GraphQL::UnauthorizedError.new("internal: record #{SENSITIVE_PK}")
      end

      def resolve
        "resolver-value"
      end
    end

    class ResolverQuery < GraphQL::Schema::Object
      field :guarded, resolver: RaisingResolver
    end

    class ResolverSchema < GraphQL::Schema
      query(ResolverQuery)
      authorization_error_strategy(:public)
    end

    class GuardedSchema < GraphQL::Schema
      query(GuardedQuery)
      authorization_error_strategy(:public)
    end
  end

  def execute(schema, query_str)
    schema.execute(
      query_str,
      root_value: PublicAuthorizationErrorTest::ROOT_VALUE,
      context: { denied_ids: [PublicAuthorizationErrorTest::SENSITIVE_PK] },
    )
  end

  def assert_public_error(result, expected_path)
    errors = result["errors"]
    assert_equal 1, errors.size, "Expected one error for #{expected_path.inspect}"
    error = errors.first
    assert_equal PublicAuthorizationErrorTest::PUBLIC_MESSAGE, error["message"]
    assert_equal expected_path, error["path"]
    assert_equal({ "code" => "UNAUTHORIZED" }, error["extensions"])

    refute_includes result.to_h.inspect, PublicAuthorizationErrorTest::SENSITIVE_PK
    refute_includes result.to_h.inspect, PublicAuthorizationErrorTest::SENSITIVE_TITLE
    refute_includes result.to_h.inspect, "InternalDocument"
  end

  def assert_internal_record(result, expected_path)
    records = result.query.context.unauthorized_errors
    assert_equal 1, records.size
    record = records.first
    assert_instance_of GraphQL::UnauthorizedError, record
    assert_equal PublicAuthorizationErrorTest::SENSITIVE_PK, record.object[:id]
    assert_equal "InternalDocument", record.type.graphql_name
    assert_equal expected_path, record.path

    public_error = result.query.context.errors.find { |err| err.is_a?(GraphQL::PublicUnauthorizedError) }
    refute_nil public_error
    assert_same record, public_error.original_error
    refute_includes public_error.to_h.inspect, PublicAuthorizationErrorTest::SENSITIVE_PK
  end

  def run_assertions(schema)
    # A regular field returns a denied object
    result = execute(schema, "{ document { id title } }")
    assert_equal({ "document" => nil }, result["data"])
    assert_public_error(result, ["document"])
    assert_internal_record(result, ["document"])

    # A denied object inside a list is replaced with `nil` at its index
    result = execute(schema, "{ documents { id title } }")
    assert_equal(
      {
        "documents" => [
          { "id" => "doc-1", "title" => "First" },
          nil,
          { "id" => "doc-3", "title" => "Third" },
        ],
      },
      result["data"],
    )
    assert_public_error(result, ["documents", 1])
    assert_internal_record(result, ["documents", 1])

    # A denied object behind a nullable intermediate field
    result = execute(schema, "{ folder { name document { id title } } }")
    assert_equal(
      { "folder" => { "name" => "Folder", "document" => nil } },
      result["data"],
    )
    assert_public_error(result, ["folder", "document"])
    assert_internal_record(result, ["folder", "document"])
  end

  it "returns public errors from the default runtime" do
    run_assertions(PublicAuthorizationErrorTest::PublicSchema)
  end

  it "returns public errors from the Next runtime" do
    run_assertions(PublicAuthorizationErrorTest::PublicNextSchema)
  end

  it "keeps the default (custom) strategy unchanged" do
    result = execute(PublicAuthorizationErrorTest::LegacySchema, "{ document { id title } }")
    assert_nil result["errors"]
    assert_equal({ "document" => nil }, result["data"])
    assert_empty result.query.context.unauthorized_errors
    assert_equal :custom, PublicAuthorizationErrorTest::LegacySchema.authorization_error_strategy
  end

  it "inherits the strategy in subclasses" do
    assert_equal :public, PublicAuthorizationErrorTest::PublicNextSchema.authorization_error_strategy
  end

  it "audits authorization errors raised by resolvers, without leaking their message" do
    result = PublicAuthorizationErrorTest::ResolverSchema.execute("{ guarded }")
    assert_equal(
      {
        "errors" => [
          {
            "message" => PublicAuthorizationErrorTest::PUBLIC_MESSAGE,
            "locations" => [{ "line" => 1, "column" => 3 }],
            "path" => ["guarded"],
            "extensions" => { "code" => "UNAUTHORIZED" },
          },
        ],
        "data" => { "guarded" => nil },
      },
      result.to_h,
    )
    records = result.query.context.unauthorized_errors
    assert_equal 1, records.size
    assert_equal "internal: record #{PublicAuthorizationErrorTest::SENSITIVE_PK}", records.first.message
    assert_equal ["guarded"], records.first.path
  end

  it "handles denied fields and denied root types" do
    result = PublicAuthorizationErrorTest::GuardedSchema.execute("{ value }", context: { deny_field: true })
    assert_equal({ "value" => nil }, result["data"])
    assert_equal ["value"], result["errors"].first["path"]
    assert_equal ["GraphQL::UnauthorizedFieldError"], result.query.context.unauthorized_errors.map { |e| e.class.name }

    result = PublicAuthorizationErrorTest::GuardedSchema.execute("{ value }", context: { deny_root: true })
    assert_nil result["data"]
    assert_equal PublicAuthorizationErrorTest::PUBLIC_MESSAGE, result["errors"].first["message"]
    assert_equal ["GraphQL::UnauthorizedError"], result.query.context.unauthorized_errors.map { |e| e.class.name }
  end

  it "rejects unknown strategies" do
    assert_raises(ArgumentError) do
      Class.new(GraphQL::Schema) { authorization_error_strategy(:unknown) }
    end
  end
end
