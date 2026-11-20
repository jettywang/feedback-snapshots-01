# frozen_string_literal: true
#--
# typed: true

module GraphQL
  module Tracing
    # A limited observability strategy for sending GraphQL trace data to
    # third-party observability platforms without leaking application data.
    #
    # When this module is mixed in, it emits lifecycle events made of
    # _metadata only_:
    #
    # - Each event carries a `phase` (for example, `"validate"` or `"authorized"`)
    #   and a `boundary` (`"begin"` or `"end"`), so phases of execution can be
    #   correlated -- including authorization failures, whose `authorized.end`
    #   event reports `authorized: false`.
    # - Argument values, variable values, result payloads, and application
    #   objects are never included. Arguments are replaced by redaction
    #   placeholders keyed by argument name; objects are represented by their
    #   class names; validation errors are represented by their messages only
    #   (never their `extensions`, which may contain provided values).
    #
    # To use it, mix it into a trace class and implement
    # {#emit_limited_event} to deliver events to your platform:
    #
    # @example Sending limited events to an observability platform
    #   class ObservabilityTrace < GraphQL::Tracing::Trace
    #     include GraphQL::Tracing::LimitedTrace
    #
    #     def emit_limited_event(event_name, attributes)
    #       MyObservabilityClient.record(event_name, attributes)
    #     end
    #   end
    #
    #   class MySchema < GraphQL::Schema
    #     trace_with ObservabilityTrace
    #   end
    module LimitedTrace
      # @param limited_redaction [String] Placeholder emitted in place of argument values
      def initialize(limited_redaction: "[REDACTED]", **_options)
        @limited_redaction = limited_redaction
        super
      end

      # Called for each limited event. Override this in the including trace
      # class to deliver events to an observability platform.
      #
      # @param event_name [String] For example, `"graphql.authorized.end"`
      # @param attributes [Hash{String => Object}] Metadata-only event payload
      # @return [void]
      def emit_limited_event(event_name, attributes)
      end

      def execute_multiplex(multiplex:)
        emit_limited_event("graphql.execute_multiplex.begin", {
          "phase" => "execute_multiplex",
          "boundary" => "begin",
          "multiplex_id" => multiplex.object_id,
          "query_count" => multiplex.queries.length,
        })
        super
      ensure
        emit_limited_event("graphql.execute_multiplex.end", {
          "phase" => "execute_multiplex",
          "boundary" => "end",
          "multiplex_id" => multiplex.object_id,
        })
      end

      def parse(query_string:)
        emit_limited_event("graphql.parse.begin", {
          "phase" => "parse",
          "boundary" => "begin",
          "query_string_bytes" => query_string.bytesize,
        })
        super
      ensure
        emit_limited_event("graphql.parse.end", {
          "phase" => "parse",
          "boundary" => "end",
        })
      end

      def begin_validate(query, validate)
        emit_limited_event("graphql.validate.begin", limited_query_attributes(query).merge({
          "phase" => "validate",
          "boundary" => "begin",
          "validate" => validate,
        }))
        super
      end

      def end_validate(query, validate, errors)
        errors ||= []
        emit_limited_event("graphql.validate.end", limited_query_attributes(query).merge({
          "phase" => "validate",
          "boundary" => "end",
          "valid" => errors.empty?,
          "errors_count" => errors.length,
          "error_messages" => limited_validation_errors(errors),
        }))
        super
      end

      def analyze_query(query:)
        emit_limited_event("graphql.analyze_query.begin", limited_query_attributes(query).merge({
          "phase" => "analyze_query",
          "boundary" => "begin",
        }))
        super
      ensure
        emit_limited_event("graphql.analyze_query.end", limited_query_attributes(query).merge({
          "phase" => "analyze_query",
          "boundary" => "end",
        }))
      end

      def execute_query(query:)
        emit_limited_event("graphql.execute_query.begin", limited_query_attributes(query).merge({
          "phase" => "execute_query",
          "boundary" => "begin",
        }))
        super
      ensure
        emit_limited_event("graphql.execute_query.end", limited_query_attributes(query).merge({
          "phase" => "execute_query",
          "boundary" => "end",
        }))
      end

      def begin_execute_field(field, object, arguments, query)
        emit_limited_event("graphql.execute_field.begin", limited_query_attributes(query).merge({
          "phase" => "execute_field",
          "boundary" => "begin",
          "field" => field.path,
          "object_class" => limited_object(object),
          "arguments" => limited_arguments(arguments),
        }))
        super
      end

      def end_execute_field(field, object, arguments, query, result)
        emit_limited_event("graphql.execute_field.end", limited_query_attributes(query).merge({
          "phase" => "execute_field",
          "boundary" => "end",
          "field" => field.path,
          "object_class" => limited_object(object),
          "arguments" => limited_arguments(arguments),
        }))
        super
      end

      def begin_authorized(type, object, context)
        emit_limited_event("graphql.authorized.begin", limited_query_attributes(context.query).merge({
          "phase" => "authorized",
          "boundary" => "begin",
          "type" => limited_type_name(type),
          "object_class" => limited_object(object),
        }))
        super
      end

      def end_authorized(type, object, context, authorized_result)
        attributes = limited_query_attributes(context.query).merge({
          "phase" => "authorized",
          "boundary" => "end",
          "type" => limited_type_name(type),
          "object_class" => limited_object(object),
        })
        if authorized_result == true || authorized_result == false
          attributes["authorized"] = authorized_result
        end
        emit_limited_event("graphql.authorized.end", attributes)
        super
      end

      def begin_resolve_type(type, value, context)
        emit_limited_event("graphql.resolve_type.begin", limited_query_attributes(context.query).merge({
          "phase" => "resolve_type",
          "boundary" => "begin",
          "type" => limited_type_name(type),
          "value_class" => limited_object(value),
        }))
        super
      end

      def end_resolve_type(type, value, context, resolved_type)
        attributes = limited_query_attributes(context.query).merge({
          "phase" => "resolve_type",
          "boundary" => "end",
          "type" => limited_type_name(type),
          "value_class" => limited_object(value),
        })
        if resolved_type
          attributes["resolved_type"] = limited_type_name(resolved_type)
        end
        emit_limited_event("graphql.resolve_type.end", attributes)
        super
      end

      # Redact a set of field arguments, keeping only schema-defined keys.
      #
      # @param arguments [Hash, GraphQL::Execution::Interpreter::Arguments, Object]
      # @return [Hash{String => String}, String] Argument keys mapped to the redaction placeholder
      def limited_arguments(arguments)
        case arguments
        when Hash
          redact_keys(arguments)
        when GraphQL::Execution::Interpreter::Arguments
          redact_keys(arguments.keyword_arguments)
        else
          @limited_redaction
        end
      end

      # @param object [Object] An application object being traced
      # @return [String] The object's class name, never the object itself
      def limited_object(object)
        object.class.name || "anonymous"
      end

      # Validation error messages describe the query document and the schema,
      # not application data. `extensions` are deliberately excluded because
      # they may contain provided values (for example, from invalid variables).
      #
      # @param errors [Array]
      # @return [Array<String>]
      def limited_validation_errors(errors)
        Array(errors).map do |err|
          err.respond_to?(:message) ? err.message : err.to_s
        end
      end

      private

      def redact_keys(arguments_hash)
        arguments_hash.each_with_object({}) do |(key, _value), memo|
          memo[key.to_s] = @limited_redaction
        end
      end

      def limited_type_name(type)
        if type.respond_to?(:graphql_name)
          type.graphql_name
        else
          type.to_s
        end
      end

      def limited_query_attributes(query)
        attributes = { "query_id" => query.object_id }
        if (operation = query.selected_operation)
          attributes["operation_type"] = operation.operation_type
          if (operation_name = operation.name)
            attributes["operation_name"] = operation_name
          end
        end
        attributes
      end
    end
  end
end
