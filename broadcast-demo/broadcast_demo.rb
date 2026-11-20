# frozen_string_literal: true
# Run from the repo root:  ruby -Ilib broadcast-demo/broadcast_demo.rb
require "graphql"
require "json"

# ---------------------------------------------------------------------------
# Pure in-memory subscription backend with broadcast support.
# Events are bucketed by topic -> fingerprint -> [subscription_ids].
# One fingerprint bucket is executed ONCE and the same result is delivered
# to every subscriber in the bucket (mirrors ActionCableSubscriptions).
# ---------------------------------------------------------------------------
class InMemorySubscriptions < GraphQL::Subscriptions
  attr_reader :deliveries, :executions

  def initialize(**rest)
    super
    @queries = {}
    @events = Hash.new { |h, k| h[k] = Hash.new { |h2, fp| h2[fp] = [] } }
    @deliveries = Hash.new { |h, k| h[k] = [] } # user => [payload, ...]
    @executions = []                            # users whose context ran an update
  end

  def write_subscription(query, events)
    subscription_id = query.context[:subscription_id] = build_id
    @queries[subscription_id] = query
    events.each { |ev| @events[ev.topic][ev.fingerprint] << subscription_id }
  end

  def read_subscription(subscription_id)
    query = @queries[subscription_id]
    return nil unless query
    {
      query_string: query.query_string,
      operation_name: query.operation_name,
      variables: query.provided_variables,
      context: {
        current_user: query.context[:current_user],
        current_group_id: query.context[:current_group_id],
      },
    }
  end

  def delete_subscription(subscription_id)
    @queries.delete(subscription_id)
    @events.each_value do |by_fp|
      by_fp.each_value { |ids| ids.delete(subscription_id) }
      by_fp.reject! { |_, ids| ids.empty? }
    end
    @events.reject! { |_, by_fp| by_fp.empty? }
  end

  def execute_all(event, object)
    @events[event.topic].each do |_fingerprint, sub_ids|
      # Broadcastable events share one fingerprint bucket: execute once,
      # deliver the SAME result to everyone in the bucket.
      result = execute_update(sub_ids.first, event, object)
      next if result.nil?
      sub_ids.each { |sub_id| deliver(sub_id, result) }
    end
  end

  def deliver(subscription_id, result)
    user = @queries[subscription_id]&.context&.[](:current_user)
    @deliveries[user] << result.to_h if user
  end

  def execute_update(subscription_id, event, object)
    query = @queries[subscription_id]
    @executions << query.context[:current_user] if query
    super
  end

  def subscriber_count = @queries.size

  def subscription_ids_for(user:, query_string: nil)
    @queries.select { |_, q|
      q.context[:current_user] == user && (query_string.nil? || q.query_string == query_string)
    }.keys
  end

  def reset!
    @queries.clear
    @events.clear
    @deliveries.clear
    @executions.clear
  end

  def reset_log!
    @deliveries.clear
    @executions.clear
  end
end

# ---------------------------------------------------------------------------
# Domain state: group membership that can change in the background.
# ---------------------------------------------------------------------------
GROUP_MEMBERS = { "g1" => ["alice", "bob"], "g2" => ["carol"] }
MODERATORS = ["alice"]

Message = Struct.new(:body, :author, keyword_init: true)

# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------
class TickerType < GraphQL::Schema::Object
  field :symbol, String, null: false, broadcastable: true
  field :price, Float, null: false, broadcastable: true
end

class MessageType < GraphQL::Schema::Object
  # Same value for every viewer of the group -> safe to share within the scope.
  field :body, String, null: false, broadcastable: true
  # Viewer-specific -> must be computed per subscriber.
  field :viewer_can_delete, Boolean, null: false, broadcastable: false

  def viewer_can_delete
    user = context[:current_user]
    MODERATORS.include?(user) || object.author == user
  end
end

class TickerUpdated < GraphQL::Schema::Subscription
  field :ticker, TickerType, null: false, broadcastable: true

  def update
    { ticker: object }
  end
end

class GroupMessageAdded < GraphQL::Schema::Subscription
  # Only subscribers whose context[:current_group_id] matches the trigger's
  # scope: value share a topic. This is what keeps g1 and g2 apart.
  subscription_scope :current_group_id

  field :message, MessageType, null: false, broadcastable: true

  def update
    # Re-check membership on every update. In a broadcast this runs ONCE
    # with the first subscriber's context; per-user it runs for everyone.
    unless GROUP_MEMBERS.fetch(context[:current_group_id], []).include?(context[:current_user])
      unsubscribe
    end
    { message: object }
  end
end

class SubscriptionType < GraphQL::Schema::Object
  field :ticker_updated, subscription: TickerUpdated, broadcastable: true
  field :group_message_added, subscription: GroupMessageAdded, broadcastable: true
end

class QueryType < GraphQL::Schema::Object
  field :noop, String, null: true
  def noop = "noop"
end

class DemoSchema < GraphQL::Schema
  query QueryType
  subscription SubscriptionType
  use InMemorySubscriptions, broadcast: true, default_broadcastable: false
end

BACKEND = DemoSchema.subscriptions

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def subscribe(user:, group: nil, query:)
  DemoSchema.execute(query, context: { current_user: user, current_group_id: group })
end

def show(title)
  puts "\n=== #{title} ==="
  puts "update executions run with context of: #{BACKEND.executions.inspect}"
  BACKEND.deliveries.each do |user, payloads|
    payloads.each { |p| puts "  delivered to #{user}: #{JSON.generate(p)}" }
  end
  puts "  (no deliveries)" if BACKEND.deliveries.empty?
  puts "active subscribers: #{BACKEND.subscriber_count}"
end

PUBLIC_Q = <<~GRAPHQL
  subscription { tickerUpdated { ticker { symbol price } } }
GRAPHQL

GROUP_Q_BROADCASTABLE = <<~GRAPHQL
  subscription { groupMessageAdded { message { body } } }
GRAPHQL

GROUP_Q_VIEWER_SPECIFIC = <<~GRAPHQL
  subscription { groupMessageAdded { message { body viewerCanDelete } } }
GRAPHQL

puts "broadcastable?(public query)           => #{BACKEND.broadcastable?(PUBLIC_Q)}"
puts "broadcastable?(group, body only)       => #{BACKEND.broadcastable?(GROUP_Q_BROADCASTABLE)}"
puts "broadcastable?(group, viewerCanDelete) => #{BACKEND.broadcastable?(GROUP_Q_VIEWER_SPECIFIC)}"

# ---------------------------------------------------------------------------
# Scenario A: public subscription, no scope. Everyone shares one execution.
# ---------------------------------------------------------------------------
%w[alice bob carol].each { |u| subscribe(user: u, query: PUBLIC_Q) }
BACKEND.reset_log!
BACKEND.trigger(:ticker_updated, {}, { symbol: "XYZ", price: 101.5 })
show("A. public subscription, 3 subscribers, 1 trigger -> 1 execution, 3 identical payloads")
BACKEND.reset!

# ---------------------------------------------------------------------------
# Scenario B: group-scoped, broadcastable fields. Same group shares one
# execution; other groups get nothing (different topic via scope).
# ---------------------------------------------------------------------------
subscribe(user: "alice", group: "g1", query: GROUP_Q_BROADCASTABLE)
subscribe(user: "bob",   group: "g1", query: GROUP_Q_BROADCASTABLE)
subscribe(user: "carol", group: "g2", query: GROUP_Q_BROADCASTABLE)
BACKEND.reset_log!
BACKEND.trigger(:group_message_added, {}, Message.new(body: "hi g1", author: "alice"), scope: "g1")
show("B. group g1 broadcast (carol is in g2 -> different topic, gets nothing)")
BACKEND.reset!

# ---------------------------------------------------------------------------
# Scenario C: same query shape + viewerCanDelete (broadcastable: false).
# Same shape, but each subscriber needs their own computation.
# ---------------------------------------------------------------------------
subscribe(user: "alice", group: "g1", query: GROUP_Q_VIEWER_SPECIFIC)
subscribe(user: "bob",   group: "g1", query: GROUP_Q_VIEWER_SPECIFIC)
BACKEND.reset_log!
BACKEND.trigger(:group_message_added, {}, Message.new(body: "hi again", author: "alice"), scope: "g1")
show("C. viewer-specific field -> per-user execution, different payloads")
BACKEND.reset!

# ---------------------------------------------------------------------------
# Scenario D: background permission change.
# D1: broadcastable query -> membership re-check runs ONCE (alice's context),
#     bob keeps receiving data he is no longer allowed to see. LEAK.
# ---------------------------------------------------------------------------
subscribe(user: "alice", group: "g1", query: GROUP_Q_BROADCASTABLE)
subscribe(user: "bob",   group: "g1", query: GROUP_Q_BROADCASTABLE)
GROUP_MEMBERS["g1"].delete("bob") # bob is kicked out of the group
BACKEND.reset_log!
BACKEND.trigger(:group_message_added, {}, Message.new(body: "g1 secrets", author: "alice"), scope: "g1")
show("D1. bob removed from g1 in background -> broadcast still leaks to bob")

# D2: app-side fix for broadcastable queries: delete the subscription when
# permissions change (the backend cannot know).
BACKEND.subscription_ids_for(user: "bob").each { |id| BACKEND.delete_subscription(id) }
BACKEND.reset_log!
BACKEND.trigger(:group_message_added, {}, Message.new(body: "g1 secrets 2", author: "alice"), scope: "g1")
show("D2. app deleted bob's subscription on permission change -> no leak")
BACKEND.reset!

# D3: alternative fix: keep the query non-broadcastable so each user's
# context re-runs `update`, where `unsubscribe` kicks bob out automatically.
GROUP_MEMBERS["g1"] << "bob"
subscribe(user: "alice", group: "g1", query: GROUP_Q_VIEWER_SPECIFIC)
subscribe(user: "bob",   group: "g1", query: GROUP_Q_VIEWER_SPECIFIC)
GROUP_MEMBERS["g1"].delete("bob") # kicked again
BACKEND.reset_log!
BACKEND.trigger(:group_message_added, {}, Message.new(body: "g1 secrets 3", author: "alice"), scope: "g1")
show("D3. non-broadcastable query -> per-user update unsubscribes bob")
BACKEND.reset!
