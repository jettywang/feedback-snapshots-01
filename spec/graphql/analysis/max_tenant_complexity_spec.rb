# frozen_string_literal: true
require "spec_helper"

describe GraphQL::Analysis::MaxTenantComplexity do
  class TenantComplexitySchema < GraphQL::Schema
    RESOLVED_TENANTS = []

    class Item < GraphQL::Schema::Object
      field :name, String
      field :price, Integer
    end

    class Query < GraphQL::Schema::Object
      field :items, [Item], null: false, complexity: 5

      def items
        TenantComplexitySchema::RESOLVED_TENANTS << context[:tenant_id]
        [{ name: "apple", price: 3 }]
      end
    end

    query(Query)
    complexity_cost_calculation_mode(:future)
  end

  # `items` costs 5 and each selected `Item` field costs 1,
  # so each of these queries has a complexity of 7.
  FRAGMENT_QUERY = <<~GRAPHQL
    fragment ItemFields on Item { name price }
    query GetItems { items { ...ItemFields } }
  GRAPHQL

  INLINE_FRAGMENT_QUERY = <<~GRAPHQL
    query GetInlineItems { items { ... on Item { name price } } }
  GRAPHQL

  TENANT_BUDGET = 10

  before do
    TenantComplexitySchema::RESOLVED_TENANTS.clear
  end

  def query_opts(tenant, query_string = FRAGMENT_QUERY)
    { query: query_string, context: { tenant_id: tenant } }
  end

  def analyze_tenants(query_opts_list, max_tenant_complexity: TENANT_BUDGET, tenant_complexity_isolation: true, schema: TenantComplexitySchema)
    queries = query_opts_list.map do |opts|
      GraphQL::Query.new(schema, opts[:query], context: opts[:context])
    end
    multiplex = GraphQL::Execution::Multiplex.new(
      schema: schema,
      queries: queries,
      context: {},
      max_complexity: nil,
      max_tenant_complexity: max_tenant_complexity,
      tenant_complexity_isolation: tenant_complexity_isolation,
    )
    GraphQL::Analysis.analyze_multiplex(multiplex, [GraphQL::Analysis::MaxTenantComplexity])
    queries
  end

  describe "analysis values" do
    it "calculates the same complexity for fragment spreads and inline fragments on list fields" do
      [FRAGMENT_QUERY, INLINE_FRAGMENT_QUERY].each do |query_string|
        query = GraphQL::Query.new(TenantComplexitySchema, query_string, context: { tenant_id: "a" })
        complexity = GraphQL::Analysis.analyze_query(query, [GraphQL::Analysis::QueryComplexity]).first
        assert_equal 7, complexity
      end
    end

    it "attributes query costs to tenants and reports exact remaining budgets" do
      queries = analyze_tenants([query_opts("a"), query_opts("a")])

      assert_equal [], queries[0].analysis_errors
      expected_message = 'Query has complexity of 7, which exceeds the remaining tenant complexity budget of 3 for tenant "a" (max tenant complexity of 10)'
      assert_equal [expected_message], queries[1].analysis_errors.map(&:message)
      assert_equal queries[1], queries[1].analysis_errors.first.query
    end

    it "accepts two batches with the same total cost but different attribution differently" do
      same_tenant_queries = analyze_tenants([query_opts("a"), query_opts("a")])
      split_tenant_queries = analyze_tenants([query_opts("a"), query_opts("b")])

      assert_equal [[], ["Query has complexity of 7, which exceeds the remaining tenant complexity budget of 3 for tenant \"a\" (max tenant complexity of 10)"]], same_tenant_queries.map { |q| q.analysis_errors.map(&:message) }
      assert_equal [[], []], split_tenant_queries.map { |q| q.analysis_errors.map(&:message) }
    end

    it "admits queries which exactly exhaust the tenant budget" do
      queries = analyze_tenants([query_opts("a"), query_opts("a")], max_tenant_complexity: 14)
      assert_equal [[], []], queries.map { |q| q.analysis_errors.map(&:message) }

      over_budget_queries = analyze_tenants([query_opts("a"), query_opts("a")], max_tenant_complexity: 13)
      assert_equal [[], ["Query has complexity of 7, which exceeds the remaining tenant complexity budget of 6 for tenant \"a\" (max tenant complexity of 13)"]], over_budget_queries.map { |q| q.analysis_errors.map(&:message) }
    end

    it "rejects the whole multiplex with tenant totals when isolation is disabled" do
      queries = analyze_tenants([query_opts("a"), query_opts("b"), query_opts("a")], tenant_complexity_isolation: false)
      expected_message = 'Tenant "a" has complexity of 14, which exceeds max tenant complexity of 10'
      assert_equal [expected_message], queries[0].analysis_errors.map(&:message)
      assert_equal [expected_message], queries[1].analysis_errors.map(&:message)
      assert_equal [expected_message], queries[2].analysis_errors.map(&:message)
    end
  end

  describe "with tenant_complexity_isolation" do
    it "executes resolvers for compliant queries only and returns a scoped error for the rest" do
      results = TenantComplexitySchema.multiplex(
        [query_opts("a"), query_opts("a")],
        max_tenant_complexity: TENANT_BUDGET,
        tenant_complexity_isolation: true,
      )

      assert_equal({ "data" => { "items" => [{ "name" => "apple", "price" => 3 }] } }, results[0].to_h)
      assert_equal(
        { "errors" => [{ "message" => 'Query has complexity of 7, which exceeds the remaining tenant complexity budget of 3 for tenant "a" (max tenant complexity of 10)' }] },
        results[1].to_h,
      )
      assert_equal ["a"], TenantComplexitySchema::RESOLVED_TENANTS
    end

    it "executes all resolvers when the same total cost is attributed to different tenants" do
      results = TenantComplexitySchema.multiplex(
        [query_opts("a"), query_opts("b", INLINE_FRAGMENT_QUERY)],
        max_tenant_complexity: TENANT_BUDGET,
        tenant_complexity_isolation: true,
      )

      expected_data = { "data" => { "items" => [{ "name" => "apple", "price" => 3 }] } }
      assert_equal expected_data, results[0].to_h
      assert_equal expected_data, results[1].to_h
      assert_equal ["a", "b"], TenantComplexitySchema::RESOLVED_TENANTS
    end
  end

  describe "without tenant_complexity_isolation" do
    it "rejects the whole multiplex and executes no resolvers when a tenant exceeds the budget" do
      results = TenantComplexitySchema.multiplex(
        [query_opts("a"), query_opts("a")],
        max_tenant_complexity: TENANT_BUDGET,
      )

      expected_error = { "errors" => [{ "message" => 'Tenant "a" has complexity of 14, which exceeds max tenant complexity of 10' }] }
      assert_equal expected_error, results[0].to_h
      assert_equal expected_error, results[1].to_h
      assert_equal [], TenantComplexitySchema::RESOLVED_TENANTS
    end
  end

  describe "batch total limit" do
    it "enforces max_complexity for the whole batch alongside per-tenant budgets" do
      results = TenantComplexitySchema.multiplex(
        [query_opts("a"), query_opts("b")],
        max_tenant_complexity: TENANT_BUDGET,
        tenant_complexity_isolation: true,
        max_complexity: 13,
      )

      expected_error = { "errors" => [{ "message" => "Query has complexity of 14, which exceeds max complexity of 13" }] }
      assert_equal expected_error, results[0].to_h
      assert_equal expected_error, results[1].to_h
      assert_equal [], TenantComplexitySchema::RESOLVED_TENANTS
    end

    it "runs the batch when both the tenant budgets and the batch total are within limits" do
      results = TenantComplexitySchema.multiplex(
        [query_opts("a"), query_opts("b")],
        max_tenant_complexity: TENANT_BUDGET,
        max_complexity: 14,
      )

      expected_data = { "data" => { "items" => [{ "name" => "apple", "price" => 3 }] } }
      assert_equal expected_data, results[0].to_h
      assert_equal expected_data, results[1].to_h
      assert_equal ["a", "b"], TenantComplexitySchema::RESOLVED_TENANTS
    end
  end

  describe "schema-level configuration" do
    let(:configured_schema) {
      Class.new(TenantComplexitySchema) do
        max_tenant_complexity 10
        tenant_complexity_isolation true
      end
    }

    it "uses the schema defaults when no run options are given" do
      results = configured_schema.multiplex([query_opts("a"), query_opts("a")])

      assert_equal({ "data" => { "items" => [{ "name" => "apple", "price" => 3 }] } }, results[0].to_h)
      assert_equal(
        { "errors" => [{ "message" => 'Query has complexity of 7, which exceeds the remaining tenant complexity budget of 3 for tenant "a" (max tenant complexity of 10)' }] },
        results[1].to_h,
      )
      assert_equal ["a"], TenantComplexitySchema::RESOLVED_TENANTS
    end

    it "lets callers override the schema defaults per run" do
      results = configured_schema.multiplex(
        [query_opts("a"), query_opts("a")],
        tenant_complexity_isolation: false,
      )

      expected_error = { "errors" => [{ "message" => 'Tenant "a" has complexity of 14, which exceeds max tenant complexity of 10' }] }
      assert_equal expected_error, results[0].to_h
      assert_equal expected_error, results[1].to_h
      assert_equal [], TenantComplexitySchema::RESOLVED_TENANTS
    end
  end

  describe "custom tenant attribution" do
    it "uses the schema's tenant_complexity_key_for to group queries" do
      custom_key_schema = Class.new(TenantComplexitySchema) do
        def self.tenant_complexity_key_for(query)
          query.context[:tenant]
        end
      end

      # With the default `:tenant_id` key these queries would belong to
      # different tenants; the custom key groups them together instead.
      results = custom_key_schema.multiplex(
        [
          { query: FRAGMENT_QUERY, context: { tenant: "x", tenant_id: "a" } },
          { query: FRAGMENT_QUERY, context: { tenant: "x", tenant_id: "b" } },
        ],
        max_tenant_complexity: TENANT_BUDGET,
        tenant_complexity_isolation: true,
      )

      assert_equal({ "data" => { "items" => [{ "name" => "apple", "price" => 3 }] } }, results[0].to_h)
      assert_equal(
        { "errors" => [{ "message" => 'Query has complexity of 7, which exceeds the remaining tenant complexity budget of 3 for tenant "x" (max tenant complexity of 10)' }] },
        results[1].to_h,
      )
      assert_equal ["a"], TenantComplexitySchema::RESOLVED_TENANTS
    end
  end
end
