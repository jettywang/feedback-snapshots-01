# frozen_string_literal: true
#--
# typed: true
module GraphQL
  module Analysis
    # A multiplex analyzer which enforces a complexity budget for each tenant
    # across all queries in a multiplex (a batch of queries). Queries are
    # attributed to tenants with [Schema.tenant_complexity_key_for](rdoc-ref:GraphQL::Schema.tenant_complexity_key_for),
    # which reads `query.context[:tenant_id]` by default.
    #
    # The budget is configured with [Schema.max_tenant_complexity](rdoc-ref:GraphQL::Schema.max_tenant_complexity)
    # and may be overridden for each run with `Schema.multiplex(..., max_tenant_complexity: ...)`.
    # It is enforced alongside the whole-batch budget (`max_complexity`), so a
    # batch is limited by tenant and by batch total at the same time.
    #
    # By default, when any tenant exceeds the budget, the whole multiplex is
    # rejected. Callers may instead opt into independent processing of
    # compliant queries with `tenant_complexity_isolation: true` (or
    # [Schema.tenant_complexity_isolation](rdoc-ref:GraphQL::Schema.tenant_complexity_isolation)):
    # then, queries are admitted in batch order until a tenant's budget is
    # exhausted, and only the exceeding queries are rejected with a
    # [GraphQL::AnalysisError](rdoc-ref:GraphQL::AnalysisError) scoped to them.
    class MaxTenantComplexity < QueryComplexity
      def result
        max_tenant_complexity = subject.max_tenant_complexity
        return if max_tenant_complexity.nil?

        complexities_by_query = calculate_complexities_by_query

        if subject.tenant_complexity_isolation
          reject_exceeding_queries(complexities_by_query, max_tenant_complexity)
        else
          reject_exceeding_tenants(complexities_by_query, max_tenant_complexity)
        end
      end

      private

      # Admit queries in batch order until each tenant's budget is exhausted;
      # only queries which exceed their tenant's remaining budget are rejected.
      def reject_exceeding_queries(complexities_by_query, max_tenant_complexity)
        errors = nil
        remaining_by_tenant = Hash.new { |h, k| h[k] = max_tenant_complexity }
        subject.queries.each do |query|
          complexity = complexities_by_query[query]
          next if complexity.nil?

          tenant = subject.schema.tenant_complexity_key_for(query)
          remaining = remaining_by_tenant[tenant]
          if complexity > remaining
            errors ||= []
            errors << GraphQL::AnalysisError.new(
              "Query has complexity of #{complexity}, which exceeds the remaining tenant complexity budget of #{remaining} for tenant #{tenant.inspect} (max tenant complexity of #{max_tenant_complexity})",
              query: query,
            )
          else
            remaining_by_tenant[tenant] = remaining - complexity
          end
        end
        errors
      end

      # Reject the whole multiplex when any tenant's total exceeds the budget.
      def reject_exceeding_tenants(complexities_by_query, max_tenant_complexity)
        totals_by_tenant = Hash.new(0)
        complexities_by_query.each do |query, complexity|
          tenant = subject.schema.tenant_complexity_key_for(query)
          totals_by_tenant[tenant] += complexity
        end

        errors = nil
        totals_by_tenant.each do |tenant, total|
          if total > max_tenant_complexity
            errors ||= []
            errors << GraphQL::AnalysisError.new(
              "Tenant #{tenant.inspect} has complexity of #{total}, which exceeds max tenant complexity of #{max_tenant_complexity}"
            )
          end
        end
        errors
      end

      # **Returns**
      #
      # - `Hash{GraphQL::Query => Numeric}` — The analyzed complexity of each valid query in the multiplex
      def calculate_complexities_by_query
        mode = subject.schema.complexity_cost_calculation_mode_for(subject.context)
        if mode.nil?
          subject.logger.warn <<~MESSAGE
            GraphQL-Ruby's complexity cost system is getting some "breaking fixes" in a future version. See the migration notes at https://graphql-ruby.org/api-doc/#{GraphQL::VERSION}/GraphQL/Schema.html#complexity_cost_calculation_mode_for-class_method

            To opt into the future behavior, configure your schema (#{subject.schema.name ? subject.schema.name : subject.schema.ancestors}) with:

              complexity_cost_calculation_mode(:future) # or `:legacy`, `:compare`

          MESSAGE
          mode = :legacy
        elsif ![:future, :legacy, :compare].include?(mode)
          raise ArgumentError, "Expected `:future`, `:legacy`, `:compare`, or `nil` from `#{subject.schema}.complexity_cost_calculation_mode_for` but got: #{mode.inspect}"
        end

        complexities_by_query = {}.compare_by_identity
        @complexities_on_type_by_query.each do |query, scopes_stack|
          complexities_by_query[query] = if mode == :compare
            future_complexity = merged_max_complexity_for_scopes(query, [scopes_stack.first], :future)
            legacy_complexity = merged_max_complexity_for_scopes(query, [scopes_stack.first], :legacy)
            if future_complexity != legacy_complexity
              subject.schema.legacy_complexity_cost_calculation_mismatch(query, future_complexity, legacy_complexity)
            end
            future_complexity
          else
            merged_max_complexity_for_scopes(query, [scopes_stack.first], mode)
          end
        end
        complexities_by_query
      end
    end
  end
end
