# frozen_string_literal: true
require "spec_helper"

describe GraphQL::Schema::Preflight do
  module PreflightTest
    # A tiny in-memory store, standing in for a database.
    STORE = {}
    # Every `resolve` call records here, so tests can prove preflight never writes.
    WRITES = []
    # `{ user_id => Set[post_id] }`, so a test can revoke access after preflight.
    PERMISSIONS = {}

    def self.reset!(posts, permissions)
      STORE.clear
      posts.each { |p| STORE[p[:id]] = p.dup }
      PERMISSIONS.clear
      permissions.each { |user_id, ids| PERMISSIONS[user_id] = Set.new(ids) }
      WRITES.clear
      nil
    end

    class PostType < GraphQL::Schema::Object
      field :id, ID, null: false
      field :title, String, null: false

      def self.authorized?(obj, ctx)
        super && (ctx[:admin] || (PERMISSIONS[ctx[:user_id]]&.include?(obj[:id])))
      end
    end

    class UpdatePost < GraphQL::Schema::Mutation
      argument :post_id, ID, required: true, loads: PostType
      argument :title, String, required: true

      field :ok, Boolean, null: false

      def authorized?(post:, title:)
        super && PERMISSIONS[context[:user_id]]&.include?(post[:id])
      end

      def resolve(post:, title:)
        WRITES << [:update, post[:id], title]
        post[:title] = title
        { ok: true }
      end
    end

    class DeletePost < GraphQL::Schema::Mutation
      argument :post_id, ID, required: true, loads: PostType

      field :ok, Boolean, null: false

      def resolve(post:)
        WRITES << [:delete, post[:id]]
        STORE.delete(post[:id])
        { ok: true }
      end
    end

    class RelayRename < GraphQL::Schema::RelayClassicMutation
      argument :post_id, ID, required: true, loads: PostType
      argument :title, String, required: true

      field :ok, Boolean, null: false

      def resolve(post:, title:)
        WRITES << [:relay_rename, post[:id], title]
        post[:title] = title
        { ok: true }
      end
    end

    class Mutation < GraphQL::Schema::Object
      field :update_post, mutation: UpdatePost
      field :delete_post, mutation: DeletePost
      field :relay_rename, mutation: RelayRename
    end

    class Query < GraphQL::Schema::Object
      field :nothing, String, null: true
    end

    class Schema < GraphQL::Schema
      query Query
      mutation Mutation

      def self.object_from_id(id, _ctx)
        STORE[id]
      end

      def self.resolve_type(_abs_type, _obj, _ctx)
        PostType
      end
    end
  end

  def setup
    PreflightTest.reset!(
      [
        { id: "1", title: "First", owner: "u1" },
        { id: "2", title: "Second", owner: "u1" },
        { id: "3", title: "Secret", owner: "u2" },
      ],
      { "u1" => ["1", "2"], "u2" => ["3"] },
    )
  end

  def batch_document
    <<~GRAPHQL
      mutation Batch($titleA: String!, $titleB: String!) {
        a: updatePost(postId: "1", title: $titleA) { ok }
        b: updatePost(postId: "2", title: $titleB) { ok }
        c: deletePost(postId: "2") { ok }
      }
    GRAPHQL
  end

  def run_batch(context: { user_id: "u1" })
    PreflightTest::Schema.preflight(
      batch_document,
      context: context,
      variables: { "titleA" => "First (updated)", "titleB" => "Second (updated)" },
    )
  end

  describe "a batch of legitimate updates" do
    it "authorizes each field, loads its objects, and performs no writes" do
      setup
      batch = run_batch

      assert_equal ["a", "b", "c"], batch.keys
      assert_equal [true, true, true], batch.map(&:authorized?)
      assert_equal false, batch.writes?
      assert_equal [], PreflightTest::WRITES, "preflight must not call `resolve`"

      assert_equal({ id: "1", title: "First", owner: "u1" }, batch["a"].arguments[:post])
      assert_equal "Second (updated)", batch["b"].arguments[:title]
      assert_equal({ id: "2", title: "Second", owner: "u1" }, batch["c"].arguments[:post])

      # The in-memory records are untouched:
      assert_equal "First", PreflightTest::STORE["1"][:title]
      assert_equal "Second", PreflightTest::STORE["2"][:title]
      assert PreflightTest::STORE.key?("2"), "delete should not have run"
    end

    it "returns deterministic results for the same document, context, and data" do
      setup
      first = run_batch.to_h
      second = run_batch.to_h
      assert_equal first, second
      assert_equal first, PreflightTest::Schema.preflight(
        batch_document,
        context: { user_id: "u1" },
        variables: { "titleA" => "First (updated)", "titleB" => "Second (updated)" },
      ).to_h
    end

    it "supports Relay Classic mutations by flattening `input:` like execution does" do
      setup
      batch = PreflightTest::Schema.preflight(<<~GRAPHQL, context: { user_id: "u1" })
        mutation { relayRename(input: { postId: "1", title: "Relayed" }) { ok } }
      GRAPHQL

      assert_equal true, batch["relayRename"].authorized?
      assert_equal "Relayed", batch["relayRename"].arguments[:title]
      assert_equal [], PreflightTest::WRITES
    end
  end

  describe "a batch with one unauthorized object" do
    it "denies only that field and still writes nothing" do
      setup

      # Post "3" belongs to u2, so u1 can't update it:
      batch = PreflightTest::Schema.preflight(<<~GRAPHQL, context: { user_id: "u1" })
        mutation {
          ok: updatePost(postId: "1", title: "Allowed") { ok }
          denied: updatePost(postId: "3", title: "Nope") { ok }
        }
      GRAPHQL

      assert_equal true, batch["ok"].authorized?
      assert_equal false, batch["denied"].authorized?
      assert_equal true, batch["denied"].denied?
      assert_equal ["An instance of Hash failed Post's authorization check"], batch["denied"].errors

      assert_equal [], PreflightTest::WRITES
      assert_equal "Secret", PreflightTest::STORE["3"][:title]
    end

    it "keeps the batch authorized list separate from denied fields" do
      setup
      batch = run_batch
      assert_equal ["a", "b", "c"], batch.authorized.map(&:response_key)
      assert_equal [], batch.denied
    end
  end

  describe "revoking permission after preflight" do
    it "does not keep a preflight result valid as a permanent authorization" do
      setup
      batch = run_batch
      result = batch["a"]
      assert_equal true, result.authorized?

      # Permission is revoked after the check:
      PreflightTest::PERMISSIONS["u1"].delete("1")

      # The old result is still a snapshot of the old check...
      assert_equal true, result.checked?
      # ...but it must not be reused as an authorization token:
      fresh = result.recheck!(context: { user_id: "u1" })
      assert_equal false, fresh.authorized?
      assert_equal false, fresh.checked?

      # And the old result is spent:
      assert_equal true, result.consumed?
      assert_equal :recheck, result.consumed_reason
      assert_equal false, result.authorized?
    end

    it "invalidates a result once it has been consumed" do
      setup
      result = run_batch["b"]
      assert_equal true, result.authorized?
      assert_equal true, result.consume!
      assert_equal false, result.authorized?
      assert_equal false, result.consume!, "consuming twice should be a no-op"
      assert_equal false, run_batch.writes?
    end

    it "becomes invalid when it is older than `preflight_max_age`" do
      schema = Class.new(PreflightTest::Schema) do
        preflight_max_age(0)
      end
      result = schema.preflight(<<~GRAPHQL, context: { user_id: "u1" }).fetch("a")
        mutation { a: updatePost(postId: "1", title: "Old") { ok } }
      GRAPHQL

      assert_equal false, result.authorized?
      assert_equal true, result.checked?
    ensure
      PreflightTest.reset!(
        [{ id: "1", title: "First", owner: "u1" }],
        { "u1" => ["1"] },
      )
    end
  end

  describe "document handling" do
    it "rejects non-mutation operations" do
      setup
      err = assert_raises ArgumentError do
        PreflightTest::Schema.preflight("{ nothing }", context: { user_id: "u1" })
      end
      assert_includes err.message, "mutation"
    end

    it "reports validation errors without running any hooks" do
      setup
      batch = PreflightTest::Schema.preflight(<<~GRAPHQL, context: { user_id: "u1" })
        mutation { updatePost(postId: "1") { ok } }
      GRAPHQL

      result = batch["updatePost"]
      assert_equal false, result.authorized?
      assert result.errors.any?, "expected a validation error"
      assert_equal [], PreflightTest::WRITES
    end

    it "limits how many root fields a batch may check" do
      setup
      err = assert_raises ArgumentError do
        PreflightTest::Schema.preflight(
          "mutation { a: deletePost(postId: \"1\") { ok } }",
          context: { user_id: "u1" },
          max_fields: 0,
        )
      end
      assert_includes err.message, "at most 0 root fields"
    end
  end

  describe "top-level fragments and directives" do
    it "expands fragments and ignores fields excluded by @skip / @include" do
      setup
      batch = PreflightTest::Schema.preflight(<<~GRAPHQL, context: { user_id: "u1" })
        mutation {
          ...BatchFields
          hidden: updatePost(postId: "1", title: "Hidden") @skip(if: true) { ok }
          alsoHidden: updatePost(postId: "2", title: "Also hidden") @include(if: false) { ok }
        }
        fragment BatchFields on Mutation {
          a: updatePost(postId: "1", title: "From fragment") { ok }
        }
      GRAPHQL

      assert_equal ["a"], batch.keys
      assert_equal true, batch["a"].authorized?
      assert_equal "From fragment", batch["a"].arguments[:title]
      assert_equal [], PreflightTest::WRITES
    end

    it "reports a repeated response key with conflicting arguments as invalid" do
      setup
      batch = PreflightTest::Schema.preflight(<<~GRAPHQL, context: { user_id: "u1" })
        mutation {
          x: updatePost(postId: "1", title: "First") { ok }
          x: updatePost(postId: "2", title: "Second") { ok }
        }
      GRAPHQL

      assert_equal ["x"], batch.keys
      assert_equal false, batch["x"].authorized?
      assert_match(/argument conflict/, batch["x"].errors.first)
      assert_equal [], PreflightTest::WRITES
    end
  end

  describe "non-resolver fields" do
    it "runs the field's own `authorized?` and reports a denied field" do
      setup
      guarded_field = Class.new(GraphQL::Schema::Field) do
        def authorized?(obj, args, ctx)
          super && ctx[:allow_field] == true
        end
      end

      query_type = Class.new(GraphQL::Schema::Object) do
        graphql_name "PreflightFieldQuery"
        field :nothing, String, null: true
      end

      mutation_type = Class.new(GraphQL::Schema::Object) do
        graphql_name "PreflightFieldMutation"
        field_class guarded_field
        field :touch, GraphQL::Types::Boolean, null: false, resolver_method: :touch
        define_method(:touch) { true }
      end

      schema = Class.new(GraphQL::Schema) do
        query(query_type)
        mutation(mutation_type)
      end

      denied = schema.preflight("mutation { touch }", context: { allow_field: false })
      assert_equal false, denied["touch"].authorized?

      allowed = schema.preflight("mutation { touch }", context: { allow_field: true })
      assert_equal true, allowed["touch"].authorized?
    end
  end

  describe "the result snapshot" do
    it "exposes warnings against treating it as a token" do
      setup
      h = run_batch["a"].to_h
      assert_equal false, h[:resolved]
      assert_equal false, h[:consumed]
      assert_equal true, h[:authorized]

      result = run_batch["a"]
      result.consume!
      assert_equal false, result.to_h[:authorized]
      assert_equal true, result.to_h[:consumed]
    end
  end
end
