# frozen_string_literal: true
require "spec_helper"

describe GraphQL::Tracing::LimitedTrace do
  # A simplified trace stand-in: it captures limited events into a queue
  # instead of sending them to an observability platform.
  module LimitedQueueTrace
    include GraphQL::Tracing::LimitedTrace

    def emit_limited_event(event_name, attributes)
      LimitedTraceSpecSchema::EVENT_QUEUE << [event_name, attributes]
    end
  end

  class LimitedTraceSpecSchema < GraphQL::Schema
    EVENT_QUEUE = []

    # Stands in for a database record whose field values must not leak
    class SecretRecord
      attr_reader :name, :email

      def initialize(name:, email:)
        @name = name
        @email = email
      end
    end

    class User < GraphQL::Schema::Object
      field :name, String
      field :email, String
    end

    class LockedUser < GraphQL::Schema::Object
      field :name, String

      def self.authorized?(object, context)
        false
      end
    end

    class Query < GraphQL::Schema::Object
      field :user, User do
        argument :name, String
      end

      def user(name:)
        SecretRecord.new(name: name, email: "test-user@example.com")
      end

      field :locked_user, LockedUser do
        argument :name, String
      end

      def locked_user(name:)
        SecretRecord.new(name: name, email: "locked-user@example.com")
      end
    end

    query(Query)
    trace_with(LimitedQueueTrace)
  end

  def events
    LimitedTraceSpecSchema::EVENT_QUEUE
  end

  def run_query(document, variables: {})
    LimitedTraceSpecSchema::EVENT_QUEUE.clear
    LimitedTraceSpecSchema.execute(document, variables: variables)
  end

  def event_names
    events.map(&:first)
  end

  def assert_phase_boundaries(phase)
    begin_name = "graphql.#{phase}.begin"
    end_name = "graphql.#{phase}.end"
    begins = events.select { |name, _| name == begin_name }
    ends = events.select { |name, _| name == end_name }
    assert begins.any?, "expected a #{begin_name} event"
    assert_equal begins.length, ends.length, "expected matching #{phase} boundaries"
    assert event_names.index(begin_name) < event_names.rindex(end_name),
      "expected #{begin_name} to precede #{end_name}"
    (begins + ends).each do |_, attributes|
      assert_equal phase, attributes["phase"]
      assert_includes ["begin", "end"], attributes["boundary"]
    end
  end

  def refute_sensitive_data(*sensitive_values)
    queue_dump = events.inspect
    sensitive_values.each do |value|
      refute_includes queue_dump, value, "expected trace queue not to include #{value.inspect}"
    end
  end

  describe "a normal query" do
    it "emits chainable phase boundaries without variable values or record fields" do
      result = run_query(
        "query FetchUser($name: String!) { user(name: $name) { name email } }",
        variables: { "name" => "s3cr3t-user" },
      )

      assert_equal "s3cr3t-user", result["data"]["user"]["name"]
      assert_equal "test-user@example.com", result["data"]["user"]["email"]

      assert_phase_boundaries("parse")
      assert_phase_boundaries("validate")
      assert_phase_boundaries("analyze_query")
      assert_phase_boundaries("execute_query")
      assert_phase_boundaries("execute_field")
      assert_phase_boundaries("authorized")

      validate_end = events.find { |name, _| name == "graphql.validate.end" }
      assert_equal true, validate_end[1]["valid"]
      assert_equal 0, validate_end[1]["errors_count"]

      field_events = events.select { |name, _| name == "graphql.execute_field.begin" }
      assert_includes field_events.map { |_, attrs| attrs["field"] }, "Query.user"
      user_event = field_events.find { |_, attrs| attrs["field"] == "Query.user" }
      assert_equal({ "name" => "[REDACTED]" }, user_event[1]["arguments"])

      email_event = field_events.find { |_, attrs| attrs["field"] == "User.email" }
      assert_equal "LimitedTraceSpecSchema::User", email_event[1]["object_class"]

      authorized_ends = events.select { |name, _| name == "graphql.authorized.end" }
      assert authorized_ends.all? { |_, attrs| attrs["authorized"] == true }

      refute_sensitive_data("s3cr3t-user", "test-user@example.com")
    end
  end

  describe "a query that fails validation" do
    it "reports the invalid boundary and stops before execution" do
      result = run_query(
        "query FetchUser($name: String!) { user(name: $name) { notAField } }",
        variables: { "name" => "s3cr3t-user" },
      )

      assert result["errors"].any?
      assert_nil result["data"]

      assert_phase_boundaries("parse")
      assert_phase_boundaries("validate")

      validate_end = events.find { |name, _| name == "graphql.validate.end" }
      assert_equal false, validate_end[1]["valid"]
      assert validate_end[1]["errors_count"] > 0
      assert validate_end[1]["error_messages"].first.is_a?(String)

      refute_includes event_names, "graphql.execute_field.begin"
      refute_includes event_names, "graphql.authorized.begin"

      refute_sensitive_data("s3cr3t-user", "test-user@example.com")
    end
  end

  describe "a query that fails authorization" do
    it "keeps the authorized phase and boundary without the rejected object" do
      result = run_query(
        "query FetchLocked($name: String!) { lockedUser(name: $name) { name } }",
        variables: { "name" => "s3cr3t-user" },
      )

      assert_nil result["data"].fetch("lockedUser")

      assert_phase_boundaries("authorized")

      locked_events = events.select do |name, attrs|
        name.start_with?("graphql.authorized.") && attrs["type"] == "LockedUser"
      end
      assert_equal ["graphql.authorized.begin", "graphql.authorized.end"], locked_events.map(&:first)
      assert_equal false, locked_events.last[1]["authorized"]
      assert_equal "LimitedTraceSpecSchema::SecretRecord", locked_events.last[1]["object_class"]

      refute_sensitive_data("s3cr3t-user", "locked-user@example.com")
    end
  end
end
