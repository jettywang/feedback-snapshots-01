# frozen_string_literal: true
#--
# typed: strict
module GraphQL
  class AnalysisError < GraphQL::ExecutionError
    # When this error is returned by a multiplex analyzer, it is only
    # added to this specific query instead of to all queries in the multiplex.
    #
    # **Returns**
    #
    # - `GraphQL::Query, nil` — The query this error is scoped to, or `nil` if it applies to the whole multiplex
    attr_reader :query

    def initialize(message, query: nil, **kwargs)
      @query = query
      super(message, **kwargs)
    end
  end
end
