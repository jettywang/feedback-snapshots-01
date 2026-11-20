# frozen_string_literal: true
#--
# typed: true

module GraphQL
  class Schema
    # Checks a batch of mutation updates without running them.
    #
    # A backend page often submits several updates at once. Before applying any of them,
    # the service can use `Schema.preflight` to ask the schema's authorization hooks
    # about every update in the batch:
    #
    # ```ruby
    # batch = MySchema.preflight(mutation_string, context: { current_user: viewer })
    #
    # batch.each do |result|
    #   if result.authorized?
    #     # Apply this update outside of preflight (or call the mutation for real).
    #   else
    #     # Reject it and report `result.errors`.
    #   end
    # end
    # ```
    #
    # ## What runs
    #
    # For each top-level mutation field, preflight:
    #
    # 1. Coerces the arguments (including variables).
    # 2. Calls `ready?`, just like execution.
    # 3. Resolves `loads:` arguments through the schema's normal hooks
    #    ([Schema.object_from_id] or a `load_*` method) and runs each loaded object's
    #    `.authorized?` check.
    # 4. Runs argument authorization, the mutation's `#authorized?`, and the mutation
    #    class's `.authorized?`.
    #
    # It **never calls `resolve`** (or `call_resolve`), so no write happens. `loads:` hooks
    # and `ready?` / `authorized?` still run, so keep those hooks read-only.
    #
    # ## Results are not authorization tokens
    #
    # A {Result} is a snapshot of one check. It is single-use:
    #
    # - {Result#consume!} marks it spent.
    # - {Result#recheck!} spends the old result and runs a fresh check (use this right
    #   before applying a change, because permissions or records may have changed).
    # - {Result#authorized?} is `false` once the result is spent, or once it's older than
    #   [Schema.preflight_max_age].
    #
    # Don't cache {Result#to_h} and treat it as "this user may do this later". It is only
    # a record of what was true during that check.
    class Preflight
      # The default limit on top-level fields. Keeps a hostile or buggy request from
      # doing unbounded `loads:` work.
      DEFAULT_MAX_FIELDS = 50

      # The default limit on how long a result may be reused before {Result#recheck!} is required.
      DEFAULT_MAX_AGE = 30 # seconds

      # One root field's dry-run check.
      class Result
        # **Returns**
        #
        # - `String, nil` — the GraphQL field name, for example `"updatePost"`
        attr_reader :field_name

        # **Returns**
        #
        # - `String` — the response key (which may be an alias)
        attr_reader :response_key

        # **Returns**
        #
        # - `Array<String>` — messages from the failed hooks. These are *not* added to a
        #   server response, since preflight is a side-channel check.
        attr_reader :errors

        # **Returns**
        #
        # - `Hash{Symbol => Object}` — the loaded Ruby arguments (including `loads:` objects),
        #   in the same shape the mutation would receive in `resolve`
        attr_reader :arguments

        # **Returns**
        #
        # - `true, false, nil` — the result of `ready?`, or `nil` if it wasn't a plain boolean
        attr_reader :ready_value

        # **Returns**
        #
        # - `Object, nil` — the early-return value from `[false, data]`, if a hook returned one
        attr_reader :early_return

        # **Returns**
        #
        # - `Symbol, nil` — why this result was consumed (`:used`, `:recheck`), or `nil`
        attr_reader :consumed_reason

        def initialize(schema:, query:, field:, ast_node:, response_key:, arguments:, authorized:, ready_value:, errors:, early_return:, checked_at:)
          @schema = schema
          @query = query
          @field = field
          @ast_node = ast_node
          @field_name = field ? field.graphql_name : nil
          @response_key = response_key
          @arguments = arguments
          @authorized = authorized
          @ready_value = ready_value
          @errors = errors
          @early_return = early_return
          @checked_at = checked_at
          @consumed_at = nil
          @consumed_reason = nil
          @resolved = false
        end

        attr_reader :field, :ast_node

        # Did every check pass, and is this result still usable?
        #
        # **Returns**
        #
        # - `Boolean`
        def authorized?
          @authorized && !consumed? && fresh?
        end

        # Was this check denied, spent, or stale?
        #
        # **Returns**
        #
        # - `Boolean`
        def denied?
          !authorized?
        end

        # Was the *original check* successful? Unlike {#authorized?}, this doesn't change
        # when the result is consumed. Use it only for reporting, never to apply a change.
        #
        # **Returns**
        #
        # - `Boolean`
        def checked?
          @authorized
        end

        # Has this result been spent by {#consume!} or {#recheck!}?
        def consumed?
          !@consumed_at.nil?
        end

        # Is this result still inside `Schema.preflight_max_age`?
        def fresh?
          max_age = @schema.preflight_max_age
          max_age.nil? || (monotonic_now - @checked_at) < max_age
        end

        # `true` because preflight never calls the resolver. Included so that callers can
        # record "did this check write anything?" without guessing.
        def resolved?
          @resolved
        end

        alias :executed? :resolved?

        # Mark this result spent. After this, {#authorized?} is `false`.
        #
        # **Returns**
        #
        # - `Boolean` — `true` if this call consumed it, `false` if it was already spent
        def consume!(reason: :used)
          if consumed?
            false
          else
            @consumed_at = monotonic_now
            @consumed_reason = reason
            true
          end
        end

        # Re-run the checks with the *current* permissions and records.
        #
        # This consumes `self`, then runs a new preflight for the same response key with
        # `context` and `variables`. Pass a fresh context when permissions may have changed:
        #
        # ```ruby
        # if result.authorized? && result.recheck!(context: fresh_context).authorized?
        #   # apply
        # end
        # ```
        #
        # **Parameters**
        #
        # - `context` (`Hash, nil`) — a fresh context; by default, the same values as the original check
        # - `variables` (`Hash, nil`) — defaults to the variables provided for the original check
        #
        # **Returns**
        #
        # - `Result`
        #
        # :call-seq:
        #   recheck!(context: nil, variables: nil) -> Result
        def recheck!(context: nil, variables: nil)
          consume!(reason: :recheck)
          new_context = context.nil? ? @query.context.to_h : context
          new_variables = variables.nil? ? @query.provided_variables : variables
          batch = @schema.preflight(
            @query.query_string,
            context: new_context,
            variables: new_variables,
            operation_name: @query.selected_operation_name,
          )
          fresh_result = batch[@response_key]
          if fresh_result.nil?
            raise KeyError, "Expected a preflight result for #{@response_key.inspect}, but got these keys: #{batch.keys.inspect}"
          end
          fresh_result
        end

        # A plain, deterministic Hash for logs and tests. It contains `authorized?` as of
        # now, plus `checked` and `consumed` metadata, so reusing it later doesn't silently
        # look valid. There are no timestamps here, so equal checks produce equal Hashes.
        #
        # **Returns**
        #
        # - `Hash{Symbol => Object}`
        #
        # :call-seq:
        #   to_h() -> Hash[Symbol, Object]
        def to_h
          {
            field: @field_name,
            response_key: @response_key,
            authorized: authorized?,
            checked: @authorized,
            consumed: consumed?,
            consumed_reason: @consumed_reason,
            resolved: @resolved,
            errors: @errors.dup,
            early_return: @early_return,
          }
        end

        def inspect
          "#<GraphQL::Schema::Preflight::Result #{@response_key} authorized=#{authorized?} checked=#{@authorized} consumed=#{consumed?} errors=#{@errors.inspect}>"
        end

        private

        def monotonic_now
          Process.clock_gettime(Process::CLOCK_MONOTONIC)
        end
      end

      # The whole document's results. It is Enumerable, and also supports lookup by
      # response key.
      class Batch
        include Enumerable

        def initialize(results)
          @results = results
        end

        # **Returns**
        #
        # - `Hash<String => Result>` — one entry per top-level field, in document order
        attr_reader :results

        def each(&block)
          @results.each_value(&block)
        end

        # **Parameters**
        #
        # - `response_key` (`String`)
        #
        # **Returns**
        #
        # - `Result`
        #
        # **Raises**
        #
        # - `KeyError` — if `response_key` isn't one of the checked fields
        def fetch(response_key)
          @results.fetch(response_key)
        end

        # **Parameters**
        #
        # - `response_key` (`String`)
        #
        # **Returns**
        #
        # - `Result, nil` — the result for `response_key`, or `nil`
        def [](response_key)
          @results[response_key]
        end

        def keys
          @results.keys
        end

        def size
          @results.size
        end

        def empty?
          @results.empty?
        end

        # Did anything in this batch write data? Always `false` for a preflight batch
        # (kept explicit so callers and logs can assert it).
        def writes?
          @results.each_value.any?(&:resolved?)
        end

        # **Returns**
        #
        # - `Array<Result>` — results which passed, in document order
        def authorized
          select(&:authorized?)
        end

        # **Returns**
        #
        # - `Array<Result>` — results which failed, in document order
        def denied
          reject(&:authorized?)
        end

        # `{ response_key => Result#to_h }`, for logs.
        def to_h
          @results.each_with_object({}) do |(key, result), memo|
            memo[key] = result.to_h
          end
        end
      end

      # **Parameters**
      #
      # - `schema` (`Class<GraphQL::Schema>`)
      # - `query_string_or_document` (`String, GraphQL::Language::Nodes::Document`) — a document whose selected operation is a mutation
      # - `context` (`Hash, GraphQL::Query::Context`)
      # - `variables` (`Hash`)
      # - `operation_name` (`String, nil`)
      # - `max_fields` (`Integer`) — reject documents with more root fields than this
      #
      # :call-seq:
      #   initialize(Class schema, String | GraphQL::Language::Nodes::Document query_string_or_document, context: nil, variables: nil, operation_name: nil, max_fields: 50) -> void
      def initialize(schema, query_string_or_document, context: nil, variables: nil, operation_name: nil, max_fields: DEFAULT_MAX_FIELDS)
        @schema = schema
        @query_string = query_string_or_document.is_a?(String) ? query_string_or_document : nil
        @document = query_string_or_document.is_a?(GraphQL::Language::Nodes::Document) ? query_string_or_document : nil
        @context_values = context
        @variables = variables || {}
        @operation_name = operation_name
        @max_fields = max_fields
      end

      # Run the checks.
      #
      # **Returns**
      #
      # - `Batch`
      #
      # :call-seq:
      #   run() -> Batch
      def run
        query = @schema.query_class.new(
          @schema,
          @query_string,
          document: @document,
          context: @context_values,
          variables: @variables,
          operation_name: @operation_name,
          validate: true,
        )

        operation = query.selected_operation
        operation_type = operation ? operation.operation_type : nil

        if operation && operation_type != "mutation"
          raise ArgumentError, "Preflight only accepts mutation operations, but this document's operation is #{operation_type || "query"}."
        end

        if operation.nil? || !query.valid?
          return Batch.new(build_failure_results(query, operation))
        end

        field_nodes = root_field_nodes(query, operation)
        if field_nodes.size > @max_fields
          raise ArgumentError, "Preflight accepts at most #{@max_fields} root fields, but this document has #{field_nodes.size}. Split the batch or raise `max_fields:`."
        end

        results = {}
        checked_at = Process.clock_gettime(Process::CLOCK_MONOTONIC)
        field_nodes.each do |ast_node|
          response_key = ast_node.alias || ast_node.name
          # The runtime merges repeated response keys into one result; check it once.
          next if results.key?(response_key)
          results[response_key] = preflight_field(query, ast_node, response_key, checked_at)
        end
        Batch.new(results)
      end

      private

      # Expand top-level fragment spreads / inline fragments (and skip `@skip` / `@include`d
      # fields) so the batch covers exactly the fields that execution would run.
      def root_field_nodes(query, operation)
        nodes = []
        seen_fragments = {}
        collect_root_field_nodes(query, operation.selections, query.schema.mutation, nodes, seen_fragments)
        nodes
      end

      def collect_root_field_nodes(query, selections, parent_type, nodes, seen_fragments)
        selections.each do |ast_node|
          next if !GraphQL::Execution::DirectiveChecks.include?(ast_node.directives, query)

          case ast_node
          when GraphQL::Language::Nodes::Field
            nodes << ast_node
          when GraphQL::Language::Nodes::InlineFragment
            if ast_node.type.nil? || root_type_condition?(query, ast_node.type.name, parent_type)
              collect_root_field_nodes(query, ast_node.selections, parent_type, nodes, seen_fragments)
            end
          when GraphQL::Language::Nodes::FragmentSpread
            frag_defn = query.fragments[ast_node.name]
            next if frag_defn.nil? || seen_fragments[frag_defn.name]
            if frag_defn.type.nil? || root_type_condition?(query, frag_defn.type.name, parent_type)
              seen_fragments[frag_defn.name] = true
              collect_root_field_nodes(query, frag_defn.selections, parent_type, nodes, seen_fragments)
            end
          end
        end
      end

      def root_type_condition?(query, type_name, parent_type)
        if type_name == parent_type.graphql_name
          true
        else
          condition_type = query.types.type(type_name)
          if condition_type.nil?
            false
          elsif condition_type.kind.abstract?
            query.types.possible_types(condition_type).include?(parent_type)
          else
            condition_type == parent_type
          end
        end
      end

      # If the document didn't validate, no hook can run. Report every parsed root field
      # (or one synthetic entry if the document couldn't be parsed at all).
      def build_failure_results(query, operation)
        errors = query.validation_errors.map(&:message)
        if errors.empty?
          context_errors = query.context.errors.map(&:message)
          errors = context_errors.empty? ? ["Invalid mutation document"] : context_errors
        end

        results = {}
        checked_at = Process.clock_gettime(Process::CLOCK_MONOTONIC)
        field_nodes = operation ? operation.selections.select { |n| n.is_a?(GraphQL::Language::Nodes::Field) } : []
        if field_nodes.empty?
          results["__preflight__"] = build_result(query, nil, nil, "__preflight__", {}, false, nil, errors, nil, checked_at)
        else
          field_nodes.each do |ast_node|
            response_key = ast_node.alias || ast_node.name
            results[response_key] = build_result(query, nil, ast_node, response_key, {}, false, nil, errors, nil, checked_at)
          end
        end
        results
      end

      def preflight_field(query, ast_node, response_key, checked_at)
        field = query.types.field(query.schema.mutation, ast_node.name)
        if field.nil?
          return build_result(query, field, ast_node, response_key, {}, false, nil, ["Field '#{ast_node.name}' doesn't exist on type 'Mutation'"], nil, checked_at)
        end

        # Run inside the query's Dataloader so `loads:` and hooks can batch (or fail clearly)
        # the same way they do during real execution. (This is a no-op for `NullDataloader`.)
        dataloader = query.context.dataloader
        if dataloader.is_a?(GraphQL::Dataloader::NullDataloader)
          preflight_field_in_dataloader(query, field, ast_node, response_key, checked_at)
        else
          dataloader.run_isolated do
            preflight_field_in_dataloader(query, field, ast_node, response_key, checked_at)
          end
        end
      end

      def preflight_field_in_dataloader(query, field, ast_node, response_key, checked_at)
        errors = []
        ready_value = nil
        early_return = nil

        begin
          raw_arguments = query.schema.sync_lazy(query.arguments_for(ast_node, field))
        rescue GraphQL::ExecutionError, GraphQL::RuntimeError => err
          return build_result(query, field, ast_node, response_key, {}, false, nil, [err.message], nil, checked_at)
        end

        if raw_arguments.is_a?(GraphQL::ExecutionError)
          return build_result(query, field, ast_node, response_key, {}, false, nil, [raw_arguments.message], nil, checked_at)
        end

        if !raw_arguments.respond_to?(:keyword_arguments)
          return build_result(query, field, ast_node, response_key, {}, false, nil, ["Arguments were not coerced"], nil, checked_at)
        end

        runtime_arguments = raw_arguments.keyword_arguments
        if !field.extras.empty?
          runtime_arguments = runtime_arguments.merge(extras_for(field, ast_node, query, response_key))
        end

        resolver_class = field.resolver
        resolver_instance = resolver_class && resolver_class.new(object: nil, context: query.context, field: field)

        if resolver_instance
          # Make an accidental `resolve` call fail loudly instead of writing data:
          forbid_resolution!(resolver_instance)
          hook_arguments = flatten_single_input(resolver_instance, runtime_arguments)

          begin
            ready_value = query.schema.sync_lazy(invoke_ready(resolver_instance, hook_arguments))
          rescue GraphQL::UnauthorizedError, GraphQL::ExecutionError => err
            return build_result(query, field, ast_node, response_key, {}, false, nil, [err.message], nil, checked_at)
          rescue StandardError => err
            return build_result(query, field, ast_node, response_key, {}, false, nil, ["#{err.class}: #{err.message}"], nil, checked_at)
          end

          if ready_value.is_a?(Array)
            is_ready, ready_early_return = ready_value
            if is_ready == false
              return build_result(query, field, ast_node, response_key, {}, false, false, [], ready_early_return, checked_at)
            else
              return build_result(query, field, ast_node, response_key, {}, false, nil, ["`ready?` returned #{ready_value.inspect} (expected `true`, `false` or `[false, data]`)"], nil, checked_at)
            end
          elsif !ready_value
            return build_result(query, field, ast_node, response_key, {}, false, false, [], nil, checked_at)
          end

          loaded_arguments = begin
            query.schema.sync_lazy(resolver_instance.send(:load_arguments, hook_arguments))
          rescue GraphQL::UnauthorizedError => err
            return build_result(query, field, ast_node, response_key, {}, false, ready_value, [authorization_error_message(err)], nil, checked_at)
          rescue GraphQL::ExecutionError => err
            return build_result(query, field, ast_node, response_key, {}, false, ready_value, [err.message], nil, checked_at)
          rescue StandardError => err
            return build_result(query, field, ast_node, response_key, {}, false, ready_value, ["#{err.class}: #{err.message}"], nil, checked_at)
          end

          if !loaded_arguments.is_a?(Hash)
            return build_result(query, field, ast_node, response_key, {}, false, ready_value, ["Arguments were not loaded (got #{loaded_arguments.class})"], nil, checked_at)
          end

          begin
            GraphQL::Schema::Validator.validate!(resolver_class.validators, resolver_instance.object, query.context, loaded_arguments, as: field)
          rescue GraphQL::Schema::Validator::ValidationFailedError => err
            return build_result(query, field, ast_node, response_key, loaded_arguments, false, ready_value, [err.message], nil, checked_at)
          end

          mutation_authorized = begin
            query.schema.sync_lazy(invoke_authorized(resolver_instance, loaded_arguments))
          rescue GraphQL::UnauthorizedError => err
            return build_result(query, field, ast_node, response_key, loaded_arguments, false, ready_value, [authorization_error_message(err)], nil, checked_at)
          rescue GraphQL::ExecutionError => err
            return build_result(query, field, ast_node, response_key, loaded_arguments, false, ready_value, [err.message], nil, checked_at)
          rescue StandardError => err
            return build_result(query, field, ast_node, response_key, loaded_arguments, false, ready_value, ["#{err.class}: #{err.message}"], nil, checked_at)
          end

          if mutation_authorized.is_a?(Array)
            mutation_ok, mutation_early_return = mutation_authorized
            if mutation_ok == false
              return build_result(query, field, ast_node, response_key, loaded_arguments, false, ready_value, [], mutation_early_return, checked_at)
            else
              return build_result(query, field, ast_node, response_key, loaded_arguments, false, ready_value, ["`authorized?` returned #{mutation_authorized.inspect} (expected `true`, `false` or `[false, data]`)"], nil, checked_at)
            end
          elsif !mutation_authorized
            return build_result(query, field, ast_node, response_key, loaded_arguments, false, ready_value, [], nil, checked_at)
          end
        else
          loaded_arguments = runtime_arguments
        end

        # For resolver-backed fields this delegates to the mutation class's `.authorized?(obj, ctx)`,
        # exactly like `Field#resolve` does. For other fields, it authorizes the arguments
        # (using the loaded values, as execution does).
        field_authorized = begin
          if field.authorizes?(query.context)
            query.schema.sync_lazy(field.authorized?(nil, loaded_arguments, query.context))
          else
            true
          end
        rescue GraphQL::UnauthorizedError => err
          errors << authorization_error_message(err)
          false
        rescue GraphQL::ExecutionError => err
          errors << err.message
          false
        rescue StandardError => err
          errors << "#{err.class}: #{err.message}"
          false
        end

        build_result(query, field, ast_node, response_key, loaded_arguments, !!field_authorized, ready_value, errors, early_return, checked_at)
      end

      def build_result(query, field, ast_node, response_key, loaded_arguments, authorized, ready_value, errors, early_return, checked_at)
        Result.new(
          schema: @schema, query: query, field: field, ast_node: ast_node,
          response_key: response_key, arguments: loaded_arguments,
          authorized: authorized, ready_value: ready_value,
          errors: errors.dup.freeze, early_return: early_return,
          checked_at: checked_at,
        )
      end

      # Guards against a bug (or a hook) calling `resolve` during preflight. Writes belong
      # after a fresh `recheck!`.
      def forbid_resolution!(resolver_instance)
        resolver_class = resolver_instance.class
        guard = proc do |*_args, **_kwargs|
          raise GraphQL::Error, "Preflight must not call `resolve` (#{resolver_class}). Apply the change after a fresh `recheck!` instead."
        end
        resolver_instance.define_singleton_method(:call_resolve, &guard)
        resolver_instance.define_singleton_method(:resolve, &guard)
      end

      # `HasSingleInputArgument` (Relay Classic mutations) flattens `input:` before `ready?` /
      # `authorized?` run. Do the same here, and drop `client_mutation_id` like `RelayClassicMutation`
      # does before calling the hooks.
      def flatten_single_input(resolver_instance, runtime_arguments)
        if resolver_instance.is_a?(GraphQL::Schema::HasSingleInputArgument) && (input = runtime_arguments[:input])
          input_kwargs = if input.respond_to?(:to_kwargs)
            input.to_kwargs
          elsif input.respond_to?(:to_h)
            input.to_h
          else
            {}
          end
          # Extras (like `:lookahead`) are top-level arguments to the field, but
          # `HasSingleInputArgument#flatten_arguments` moves them into the input hash.
          runtime_arguments.each do |key, value|
            if key != :input
              input_kwargs[key] = value
            end
          end
          # The runtime's RelayClassicMutation strips this before calling `resolve`; hooks see
          # the same arguments, so strip it here, too.
          input_kwargs.delete(:client_mutation_id)
          input_kwargs
        else
          runtime_arguments
        end
      end

      def invoke_ready(resolver_instance, hook_arguments)
        if hook_arguments.empty?
          resolver_instance.send(:ready?)
        else
          resolver_instance.send(:ready?, **hook_arguments)
        end
      end

      def invoke_authorized(resolver_instance, loaded_arguments)
        if loaded_arguments.empty?
          resolver_instance.authorized?
        else
          resolver_instance.authorized?(**loaded_arguments)
        end
      end

      def extras_for(field, ast_node, query, response_key)
        extras = {}
        field.extras.each do |extra|
          extras[extra] = case extra
          when :ast_node
            ast_node
          when :lookahead
            GraphQL::Execution::Lookahead.new(query: query, ast_nodes: [ast_node], field: field)
          when :path
            [response_key]
          when :parent
            nil
          when :execution_errors
            GraphQL::Execution::Interpreter::ExecutionErrors.new(query.context, ast_node, [response_key])
          else
            field.fetch_extra(extra, query.context)
          end
        end
        extras
      end

      def authorization_error_message(err)
        message = err.message
        if message.nil? || message.empty?
          object = err.respond_to?(:object) ? err.object : nil
          "An instance of #{object.class} failed authorization"
        else
          message
        end
      end
    end
  end
end
