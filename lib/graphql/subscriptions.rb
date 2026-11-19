# frozen_string_literal: true
#--
# typed: true
require "securerandom"
require "graphql/subscriptions/broadcast_analyzer"
require "graphql/subscriptions/event"
require "graphql/subscriptions/serialize"
require "graphql/subscriptions/action_cable_subscriptions"
require "graphql/subscriptions/default_subscription_resolve_extension"

module GraphQL
  class Subscriptions
    # Raised when either:
    # - the triggered `event_name` doesn't match a field in the schema; or
    # - one or more arguments don't match the field arguments
    class InvalidTriggerError < GraphQL::Error
    end

    # Raised when either:
    # - An initial subscription didn't have a value for `context[subscription_scope]`
    # - Or, an update didn't pass `.trigger(..., scope:)`
    # When raised, the initial subscription or update fails completely.
    class SubscriptionScopeMissingError < GraphQL::Error
    end

    # The pre-update authorization check allowed this update. This is the default.
    AUTHORIZED = :authorized

    # The pre-update authorization check couldn't confirm permission right now.
    # The update isn't delivered, but the subscription is kept so a later update can recover.
    DEFERRED = :deferred

    # The pre-update authorization check confirmed that the subscriber may no longer receive updates.
    # The update isn't delivered and the subscription is removed.
    REVOKED = :revoked

    # See [GraphQL::Subscriptions](rdoc-ref:GraphQL::Subscriptions) for the base options; concrete implementations may add options.
    def self.use(defn, options = {})
      schema = defn.is_a?(Class) ? defn : defn.target

      if schema.subscriptions(inherited: false)
        raise ArgumentError, "Can't reinstall subscriptions. #{schema} is using #{schema.subscriptions}, can't also add #{self}"
      end

      options[:schema] = schema
      schema.subscriptions = self.new(**options)
      schema.add_subscription_extension_if_necessary
      nil
    end

    # **Parameters**
    #
    # - `schema` (`Class`) — the GraphQL schema this manager belongs to
    # - `validate_update` (`Boolean`) — If false, then validation is skipped when executing updates
    # - `authorize_update` (`Boolean, Symbol, #call`) — Opt in to [authorize_update?](rdoc-ref:#authorize_update?), or provide a callable (or method name) to use instead
    #
    # :call-seq:
    #   initialize(Class schema:, bool validate_update:, broadcast:, default_broadcastable:, bool | Symbol | #call authorize_update:, **rest)
    def initialize(schema:, validate_update: true, broadcast: false, default_broadcastable: false, authorize_update: nil, **rest)
      if broadcast
        schema.query_analyzer(Subscriptions::BroadcastAnalyzer)
      end
      @default_broadcastable = default_broadcastable
      @schema = schema
      @validate_update = validate_update
      @authorize_update = authorize_update
    end

    # **Returns**
    #
    # - `Boolean` — Used when fields don't have `broadcastable:` explicitly set
    attr_reader :default_broadcastable

    # Fetch subscriptions matching this field + arguments pair
    # And pass them off to the queue.
    #
    # **Parameters**
    #
    # - `event_name` (`String`)
    # - `args` (`Hash<String, Symbol => Object>`) — Arguments passed to the subscription resolver
    # - `object` (`Object`)
    # - `scope` (`Symbol, String`)
    # - `context` (`Hash`)
    #
    # **Returns**
    #
    # - `void`
    #
    # :call-seq:
    #   trigger(String event_name, Hash[String | Symbol, Object] args, Object object, Symbol | String scope:, Hash context:) -> void
    def trigger(event_name, args, object, scope: nil, context: {})
      # Make something as context-like as possible, even though there isn't a current query:
      dummy_query = @schema.query_class.new(@schema, "{ __typename }", validate: false, context: context)
      context = dummy_query.context
      event_name = event_name.to_s

      # Try with the verbatim input first:
      field = dummy_query.types.field(@schema.subscription, event_name) # rubocop:disable Development/ContextIsPassedCop

      if field.nil?
        # And if it wasn't found, normalize it:
        normalized_event_name = normalize_name(event_name)
        field = dummy_query.types.field(@schema.subscription, normalized_event_name) # rubocop:disable Development/ContextIsPassedCop
        if field.nil?
          raise InvalidTriggerError, "No subscription matching trigger: #{event_name} (looked for #{@schema.subscription.graphql_name}.#{normalized_event_name})"
        end
      else
        # Since we found a field, the original input was already normalized
        normalized_event_name = event_name
      end

      # Normalize symbol-keyed args to strings, try camelizing them
      # Should this accept a real context somehow?
      normalized_args = normalize_arguments(normalized_event_name, field, args, @schema.null_context)

      event = Subscriptions::Event.new(
        name: normalized_event_name,
        arguments: normalized_args,
        field: field,
        scope: scope,
        context: context,
      )
      execute_all(event, object)
    end

    # `event` was triggered on `object`, and `subscription_id` was subscribed,
    # so it should be updated.
    #
    # Load `subscription_id`'s GraphQL data, re-evaluate the query and return the result.
    #
    # **Parameters**
    #
    # - `subscription_id` (`String`)
    # - `event` (`GraphQL::Subscriptions::Event`) — The event which was triggered
    # - `object` (`Object`) — The value for the subscription field
    #
    # **Returns**
    #
    # - `GraphQL::Query::Result`
    #
    # :call-seq:
    #   execute_update(String subscription_id, GraphQL::Subscriptions::Event event, Object object) -> GraphQL::Query::Result
    def execute_update(subscription_id, event, object)
      # Lookup the saved data for this subscription
      query_data = read_subscription(subscription_id)
      if query_data.nil?
        delete_subscription(subscription_id)
        return nil
      end

      # Fetch the required keys from the saved data
      query_string = query_data.fetch(:query_string)
      variables = query_data.fetch(:variables)
      context = query_data.fetch(:context)
      operation_name = query_data.fetch(:operation_name)
      execute_options = {
        query: query_string,
        context: context,
        subscription_topic: event.topic,
        operation_name: operation_name,
        variables: variables,
        root_value: object,
      }

       # merge event's and query's context together
      context.merge!(event.context) unless event.context.nil? || context.nil?

      case authorize_update_for(subscription_id, event, execute_options)
      when REVOKED
        # The check completed and confirmed that this subscriber may no longer receive updates:
        delete_subscription(subscription_id)
        return nil
      when DEFERRED
        # The check couldn't be completed right now. Don't send anything, but keep the
        # subscription so that a later update can try again.
        return nil
      end

      execute_options[:validate] = validate_update?(**execute_options)
      result = @schema.execute(**execute_options)
      subscriptions_context = result.context.namespace(:subscriptions)
      if subscriptions_context[:no_update]
        result = nil
      end

      if subscriptions_context[:unsubscribed] && !subscriptions_context[:final_update]
        # `unsubscribe` was called, clean up on our side
        # The transport should also send `{more: false}` to client
        delete_subscription(subscription_id)
        result = nil
      end

      result
    end

    # Define this method to customize whether to validate
    # this subscription when executing an update.
    #
    # **Returns**
    #
    # - `Boolean` — defaults to `true`, or false if `validate: false` is provided.
    #
    # :call-seq:
    #   validate_update?(query:, context:, root_value:, subscription_topic:, operation_name:, variables:) -> bool
    def validate_update?(query:, context:, root_value:, subscription_topic:, operation_name:, variables:)
      @validate_update
    end

    # Define this method to re-check permissions before each update is executed.
    # It is only called when `authorize_update:` is passed to `use(...)` (or when this
    # method is overridden in a `GraphQL::Subscriptions` subclass), so existing
    # applications keep their current behavior by default.
    #
    # This is useful for long-lived subscriptions, where a viewer's permissions may
    # change after the initial subscription was accepted. The check runs before the
    # update query is executed, so no application data is fetched or delivered for
    # a subscriber that fails it.
    #
    # Return one of:
    #
    # - `AUTHORIZED` (or `true`) — deliver the update and keep the subscription.
    # - `DEFERRED` (or `nil`) — don't deliver this update, but keep the subscription.
    #   Use this when permission can't be confirmed right now (for example, an
    #   authorization service is temporarily unavailable); a later update may succeed.
    # - `REVOKED` (or `false`) — don't deliver this update and delete the subscription.
    #   Use this only when permission was definitively removed.
    #
    # Any other return value is treated as `DEFERRED`, so an unhandled value never
    # sends data to a subscriber whose permission wasn't confirmed.
    #
    # **Parameters**
    #
    # - `subscription_id` (`String`) — the subscription being updated
    # - `event` (`GraphQL::Subscriptions::Event`) — the event which was triggered
    # - `query` (`String`) — the original subscription query string
    # - `context` (`Hash`) — the saved context, merged with the event's context
    # - `variables` (`Hash`)
    # - `operation_name` (`String, nil`)
    # - `root_value` (`Object`) — the value passed to `.trigger(...)`
    # - `subscription_topic` (`String`)
    #
    # **Returns**
    #
    # - `Symbol, Boolean, nil` — `AUTHORIZED`, `DEFERRED`, or `REVOKED`
    #
    # :call-seq:
    #   authorize_update?(String subscription_id:, GraphQL::Subscriptions::Event event:, String query:, Hash context:, Hash variables:, String | nil operation_name:, Object root_value:, String subscription_topic:) -> Symbol | bool | nil
    def authorize_update?(subscription_id:, event:, query:, context:, variables:, operation_name:, root_value:, subscription_topic:)
      AUTHORIZED
    end

    # **Returns**
    #
    # - `Boolean` — whether [authorize_update?](rdoc-ref:#authorize_update?) is configured
    #
    # :call-seq:
    #   authorize_update_enabled?() -> bool
    def authorize_update_enabled?
      if !defined?(@authorize_update_enabled)
        @authorize_update_enabled =
          case @authorize_update
          when nil
            authorize_update_overridden?
          when false
            false
          else
            true
          end
      end
      @authorize_update_enabled
    end

    # Run the update query for this subscription and deliver it
    # See [execute_update](rdoc-ref:#execute_update)
    # See [deliver](rdoc-ref:#deliver)
    #
    # **Returns**
    #
    # - `void`
    #
    # :call-seq:
    #   execute(subscription_id, event, object) -> void
    def execute(subscription_id, event, object)
      res = execute_update(subscription_id, event, object)
      if !res.nil?
        deliver(subscription_id, res)

        if res.context.namespace(:subscriptions)[:unsubscribed]
          # `unsubscribe` was called, clean up on our side
          # The transport should also send `{more: false}` to client
          delete_subscription(subscription_id)
        end
      end

    end

    # Event `event` occurred on `object`,
    # Update all subscribers.
    #
    # **Parameters**
    #
    # - `event` (`Subscriptions::Event`)
    # - `object` (`Object`)
    #
    # **Returns**
    #
    # - `void`
    #
    # :call-seq:
    #   execute_all(Subscriptions::Event event, Object object) -> void
    def execute_all(event, object)
      raise GraphQL::RequiredImplementationMissingError
    end

    # The system wants to send an update to this subscription.
    # Read its data and return it.
    #
    # **Parameters**
    #
    # - `subscription_id` (`String`)
    #
    # **Returns**
    #
    # - `Hash` — Containing required keys
    #
    # :call-seq:
    #   read_subscription(String subscription_id) -> Hash
    def read_subscription(subscription_id)
      raise GraphQL::RequiredImplementationMissingError
    end

    # A subscription query was re-evaluated, returning `result`.
    # The result should be send to `subscription_id`.
    #
    # **Parameters**
    #
    # - `subscription_id` (`String`)
    # - `result` (`Hash`)
    #
    # **Returns**
    #
    # - `void`
    #
    # :call-seq:
    #   deliver(String subscription_id, Hash result) -> void
    def deliver(subscription_id, result)
      raise GraphQL::RequiredImplementationMissingError
    end

    # `query` was executed and found subscriptions to `events`.
    # Update the database to reflect this new state.
    #
    # **Parameters**
    #
    # - `query` (`GraphQL::Query`)
    # - `events` (`Array<GraphQL::Subscriptions::Event>`)
    #
    # **Returns**
    #
    # - `void`
    #
    # :call-seq:
    #   write_subscription(GraphQL::Query query, Array[GraphQL::Subscriptions::Event] events) -> void
    def write_subscription(query, events)
      raise GraphQL::RequiredImplementationMissingError
    end

    # A subscription was terminated server-side.
    # Clean up the database.
    #
    # **Parameters**
    #
    # - `subscription_id` (`String`)
    #
    # **Returns**
    #
    # - `Object` — void.
    #
    # :call-seq:
    #   delete_subscription(String subscription_id) -> Object
    def delete_subscription(subscription_id)
      raise GraphQL::RequiredImplementationMissingError
    end

    # **Returns**
    #
    # - `String` — A new unique identifier for a subscription
    #
    # :call-seq:
    #   build_id() -> String
    def build_id
      SecureRandom.uuid
    end

    # Convert a user-provided event name or argument
    # to the equivalent in GraphQL.
    #
    # By default, it converts the identifier to camelcase.
    # Override this in a subclass to change the transformation.
    #
    # **Parameters**
    #
    # - `event_or_arg_name` (`String, Symbol`)
    #
    # **Returns**
    #
    # - `String`
    #
    # :call-seq:
    #   normalize_name(String | Symbol event_or_arg_name) -> String
    def normalize_name(event_or_arg_name)
      Schema::Member::BuildType.camelize(event_or_arg_name.to_s)
    end

    # **Returns**
    #
    # - `Boolean` — if true, then a query like this one would be broadcasted
    #
    # :call-seq:
    #   broadcastable?(query_str, **query_options) -> bool
    def broadcastable?(query_str, **query_options)
      query = @schema.query_class.new(@schema, query_str, **query_options)
      if !query.valid?
        raise "Invalid query: #{query.validation_errors.map(&:to_h).inspect}"
      end
      GraphQL::Analysis.analyze_query(query, @schema.query_analyzers)
      query.context.namespace(:subscriptions)[:subscription_broadcastable]
    end

    # Called during execution when a new `subscription ...` operation is received
    #
    # **Parameters**
    #
    # - `query` (`GraphQL::Query`)
    #
    # **Returns**
    #
    # - `void`
    #
    # :call-seq:
    #   initialize_subscriptions(GraphQL::Query query) -> void
    def initialize_subscriptions(query)
      subs_namespace = query.context.namespace(:subscriptions)
      subs_namespace[:events] = []
      subs_namespace[:subscriptions] = {}
      nil
    end

    # Called during execution when a subscription operation has finished
    #
    # **Parameters**
    #
    # - `query` (`GraphQL::Query`)
    #
    # **Returns**
    #
    # - `void`
    #
    # :call-seq:
    #   finish_subscriptions(GraphQL::Query query) -> void
    def finish_subscriptions(query)
      if (events = query.context.namespace(:subscriptions)[:events]) && !events.empty?
        write_subscription(query, events)
      end
      nil
    end

    def finalizer
      Finalizer.new(self)
    end

    class Finalizer
      include Execution::Finalizer
      def initialize(subscriptions)
        @subscriptions = subscriptions
      end

      def finalize_graphql_result(query, result_data, result_key)
        @subscriptions.finish_subscriptions(query)
      end
    end

    private

    # Run the configured pre-update authorization check and normalize its result.
    # Returns `AUTHORIZED`, `DEFERRED`, or `REVOKED`.
    def authorize_update_for(subscription_id, event, execute_options)
      unless authorize_update_enabled?
        return AUTHORIZED
      end

      check =
        if @authorize_update.is_a?(Symbol) || @authorize_update.is_a?(String)
          method(@authorize_update)
        elsif @authorize_update.respond_to?(:call)
          @authorize_update
        else
          method(:authorize_update?)
        end

      if check.nil?
        return AUTHORIZED
      end

      auth_result = check.call(
        subscription_id: subscription_id,
        event: event,
        query: execute_options[:query],
        context: execute_options[:context],
        variables: execute_options[:variables],
        operation_name: execute_options[:operation_name],
        root_value: execute_options[:root_value],
        subscription_topic: execute_options[:subscription_topic],
      )

      # Allow lazy values (eg, Promise) to resolve before interpreting the result:
      if @schema.lazy?(auth_result)
        auth_result = @schema.sync_lazy(auth_result)
      end

      normalize_update_authorization(auth_result)
    end

    def normalize_update_authorization(auth_result)
      case auth_result
      when AUTHORIZED, true
        AUTHORIZED
      when REVOKED, false
        REVOKED
      else
        # `DEFERRED`, `nil`, and any unrecognized value mean "not confirmed".
        # Fail closed: don't send data, but keep the subscription.
        DEFERRED
      end
    end

    def authorize_update_overridden?
      method(:authorize_update?).owner != GraphQL::Subscriptions
    end

    # Recursively normalize `args` as belonging to `arg_owner`:
    # - convert symbols to strings,
    # - if needed, camelize the string (using [normalize name](rdoc-ref:#normalize_name))
    #
    # **Parameters**
    #
    # - `arg_owner` (`GraphQL::Field, GraphQL::BaseType`)
    # - `args` (`Hash, Array, Any`) — some GraphQL input value to coerce as `arg_owner`
    #
    # **Returns**
    #
    # - `Any` — normalized arguments value
    #
    # :call-seq:
    #   normalize_arguments(event_name, GraphQL::Field | GraphQL::BaseType arg_owner, Hash | Array | Any args, context) -> Any
    def normalize_arguments(event_name, arg_owner, args, context)
      case arg_owner
      when GraphQL::Schema::Field, Class
        return args if args.nil?

        arg_owner = arg_owner #: as GraphQL::Schema::Field | GraphQL::Schema::Member::type_definition
        if arg_owner.is_a?(Class) && !arg_owner.kind.input_object?
          # it's a type, but not an input object
          return args
        end
        arg_owner = arg_owner #: as GraphQL::Schema::Field | singleton(GraphQL::Schema::InputObject)
        normalized_args = {}
        missing_arg_names = []
        args.each do |k, v|
          arg_name = k.to_s
          arg_defn = arg_owner.get_argument(arg_name, context)
          if arg_defn
            normalized_arg_name = arg_name
          else
            normalized_arg_name = normalize_name(arg_name)
            arg_defn = arg_owner.get_argument(normalized_arg_name, context)
          end

          if arg_defn
            if arg_defn.loads
              normalized_arg_name = arg_defn.keyword.to_s
            end
            normalized = normalize_arguments(event_name, arg_defn.type, v, context)
            normalized_args[normalized_arg_name] = normalized
          else
            # Couldn't find a matching argument definition
            missing_arg_names << arg_name
          end
        end

        # Backfill default values so that trigger arguments
        # match query arguments.
        arg_owner.arguments(context).each do |_name, arg_defn|
          if arg_defn.default_value? && !normalized_args.key?(arg_defn.name)
            default_value = arg_defn.default_value
            # We don't have an underlying "object" here, so it can't call methods.
            # This is broken.
            normalized_args[arg_defn.name] = arg_defn.prepare_value(nil, default_value, context: context)
          end
        end

        if !missing_arg_names.empty?
          arg_owner_name = if arg_owner.is_a?(GraphQL::Schema::Field)
            arg_owner.path
          else
            arg_owner.graphql_name
          end
          raise InvalidTriggerError, "Can't trigger Subscription.#{event_name}, received undefined arguments: #{missing_arg_names.join(", ")}. (Should match arguments of #{arg_owner_name}.)"
        end

        normalized_args
      when GraphQL::Schema::List
        args&.map { |a| normalize_arguments(event_name, arg_owner.of_type, a, context) }
      when GraphQL::Schema::NonNull
        normalize_arguments(event_name, arg_owner.of_type, args, context)
      else
        args
      end
    end
  end
end
