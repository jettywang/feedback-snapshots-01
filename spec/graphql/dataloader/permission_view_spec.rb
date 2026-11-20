# frozen_string_literal: true
require "spec_helper"

describe "Permission-scoped Dataloader sources" do
  # All queries in a multiplex share one `GraphQL::Dataloader` instance, so a
  # Source's cache is shared, too. To keep permission-constrained results from
  # leaking between identities, pass a permission "view" as a batch parameter
  # and canonicalize equivalent views in `.batch_key_for`.
  class PermissionedRecordSource < GraphQL::Dataloader::Source
    # In-memory backend: `id => { "name" => ..., "secret" => ... }`
    BACKEND = {
      1 => { "name" => "Project X", "secret" => "launch-codes" },
      2 => { "name" => "Project Y", "secret" => "vault-combo" },
    }

    class << self
      def fetch_log
        @fetch_log ||= []
      end

      def reset!
        fetch_log.clear
      end
    end

    def initialize(view:)
      @view = view
    end

    # Equivalent permission views (the same permissions, in any order) share a
    # source instance -- and its cache. Anything else gets its own instance, so
    # its results are never read from (or written to) another view's cache.
    def self.batch_key_for(view:)
      view.is_a?(Array) ? [:view, *view.sort] : view
    end

    def fetch(ids)
      view_key = self.class.batch_key_for(view: @view)
      self.class.fetch_log << [view_key, ids]
      ids.map do |id|
        record = BACKEND.fetch(id)
        # The loaded data depends on the view, so a leaked cache entry
        # would be visible in the results below.
        if @view.is_a?(Array) && @view.include?("secret:read")
          "#{record["name"]}:#{record["secret"]}"
        else
          record["name"]
        end
      end
    end
  end

  class PermissionViewSchema < GraphQL::Schema
    class Query < GraphQL::Schema::Object
      field :secure_record, String, null: true do
        argument :id, Integer, required: true
      end

      def secure_record(id:)
        # When no permission view is given, fall back to an identity-specific
        # scope so nothing is shared with other viewers.
        view = context[:permission_view] || "user:#{context[:user_id]}"
        dataloader.with(PermissionedRecordSource, view: view).load(id)
      end
    end

    query(Query)
    use GraphQL::Dataloader
  end

  it "shares results only between equivalent permission views" do
    PermissionedRecordSource.reset!
    res = PermissionViewSchema.multiplex([
      # Same permission view (given in different orders), different identities:
      { query: "{ r1: secureRecord(id: 1) r2: secureRecord(id: 2) }", context: { user_id: 1, permission_view: ["name:read", "secret:read"] } },
      { query: "{ r1: secureRecord(id: 1) }", context: { user_id: 2, permission_view: ["secret:read", "name:read"] } },
      # A different permission view:
      { query: "{ r1: secureRecord(id: 1) }", context: { user_id: 3, permission_view: ["name:read"] } },
      # No permission view specified:
      { query: "{ r1: secureRecord(id: 1) }", context: { user_id: 4 } },
      { query: "{ r1: secureRecord(id: 1) }", context: { user_id: 5 } },
    ])

    shared_value = res[0]["data"]["r1"]
    assert_equal "Project X:launch-codes", shared_value
    assert_equal "Project Y:vault-combo", res[0]["data"]["r2"]

    # The equivalent view got the same (cached) results, even though it's another identity:
    assert_equal shared_value, res[1]["data"]["r1"]

    # Other views don't see the shared view's cached results:
    assert_equal "Project X", res[2]["data"]["r1"]
    assert_equal "Project X", res[3]["data"]["r1"]
    assert_equal "Project X", res[4]["data"]["r1"]

    # The equivalent views were fetched together in one batched call,
    # and every other view fetched (and cached) on its own:
    assert_equal [
      [[:view, "name:read", "secret:read"], [1, 2]],
      [[:view, "name:read"], [1]],
      ["user:4", [1]],
      ["user:5", [1]],
    ], PermissionedRecordSource.fetch_log
  end

  it "shares the fallback scope for repeated requests from the same identity" do
    PermissionedRecordSource.reset!
    res = PermissionViewSchema.multiplex([
      { query: "{ r1: secureRecord(id: 1) }", context: { user_id: 4 } },
      { query: "{ r1: secureRecord(id: 1) r2: secureRecord(id: 2) }", context: { user_id: 4 } },
    ])

    assert_equal "Project X", res[0]["data"]["r1"]
    assert_equal "Project X", res[1]["data"]["r1"]
    assert_equal "Project Y", res[1]["data"]["r2"]

    # Same identity, same fallback scope: still batched and cached together.
    assert_equal [
      ["user:4", [1, 2]],
    ], PermissionedRecordSource.fetch_log
  end
end
