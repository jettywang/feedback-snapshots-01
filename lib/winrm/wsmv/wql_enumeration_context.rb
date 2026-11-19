# Copyright 2016 Shawn Neal <sneal@sneal.net>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

require 'securerandom'
require_relative '../exceptions'
require_relative 'wql_token_registry'

module WinRM
  module WSMV
    # Identifies one WQL enumeration. The context is immutable with respect to
    # endpoint/resource URI/namespace/query identity and mutable only for the
    # continuation token state.
    class WqlEnumerationContext
      WMI_RESOURCE_URI_PREFIX = 'http://schemas.microsoft.com/wbem/wsman/1/wmi/'.freeze
      DEFAULT_MAX_NO_PROGRESS_PULLS = 10
      DEFAULT_MAX_PULLS = 1_000

      attr_reader :endpoint, :namespace, :resource_uri, :query_id, :wql,
                  :max_no_progress_pulls, :max_pulls, :state, :current_token,
                  :pull_count, :failure_reason, :last_error

      def self.normalize_endpoint(endpoint)
        endpoint.nil? ? '' : endpoint.to_s
      end

      def initialize(endpoint:, namespace:, wql: nil, query_id: nil, registry: nil,
                     max_no_progress_pulls: DEFAULT_MAX_NO_PROGRESS_PULLS,
                     max_pulls: DEFAULT_MAX_PULLS)
        @endpoint = self.class.normalize_endpoint(endpoint)
        @namespace = namespace
        @resource_uri = "#{WMI_RESOURCE_URI_PREFIX}#{namespace}"
        @wql = wql
        @query_id = query_id || SecureRandom.uuid
        @registry = registry || WqlTokenRegistry.default
        @max_no_progress_pulls = max_no_progress_pulls
        @max_pulls = max_pulls
        @state = :new
        @current_token = nil
        @seen_tokens = {}
        @seen_pages = {}
        @pull_count = 0
        @no_progress_pulls = 0
        @failure_reason = nil
        @last_error = nil
      end

      def active?
        @state == :enumerating || @state == :pulling
      end

      def complete?
        @state == :complete
      end

      def failed?
        @state == :failed
      end

      def finished?
        complete? || failed?
      end

      def bind_initial(token, page_digest: nil)
        if token.nil? || token.to_s.empty?
          fail!(:missing_context)
          raise WqlEnumerationIncompleteError,
                "query #{@query_id} received neither EndOfSequence nor an EnumerationContext"
        end

        @registry.claim(@endpoint, token, self)
        remember(token)
        @seen_pages[[token, page_digest]] = true unless page_digest.nil?
        @state = :enumerating
        token
      end

      def complete!
        @state = :complete
        @current_token = nil
        @registry.release_context(self)
      end

      # Verifies that +token+ may still be redeemed by this query. Called
      # before any rows from the page are ingested so a token owned by
      # another live query cannot contaminate this result set.
      def check_token_ownership!(token)
        @registry.claim(@endpoint, token, self)
      end

      def assert_current_token!(token)
        return token if token.to_s == @current_token.to_s

        fail!(:stale_token)
        raise WqlContextMismatchError,
              "query #{@query_id} refused to pull with token #{token.inspect}; " \
              "its current token is #{@current_token.inspect}"
      end

      # Counts the Pull about to be sent and enforces a hard ceiling so a
      # server that keeps minting fresh empty pages cannot loop forever.
      def before_pull!
        if @pull_count >= @max_pulls
          fail!(:pull_limit)
          raise WqlEnumerationLimitError,
                "query #{@query_id} stopped after #{@pull_count} Pull requests without EndOfSequence"
        end

        @pull_count += 1
      end

      # Records the result of a Pull response. Returns :complete, :advanced,
      # :no_progress (a page that delivered no new rows) or :duplicate (an
      # exact replay of a page already consumed for the same token).
      #
      # Ownership of the response token is verified *before* any state changes:
      # a token already belonging to another live query raises instead of
      # being adopted.
      #
      # A response carrying EndOfSequence is the only way to finish
      # successfully, even when the page also contains rows. A missing token is
      # never treated as an implicit end of the enumeration.
      #
      # WS-Enumeration normally returns the same context token on every Pull,
      # so repetition alone is not an error. Progress is measured by newly
      # delivered rows; a repeated token with only empty or already-consumed
      # pages is what eventually trips the bounded no-progress budget.
      def record_response(token:, end_of_sequence:, rows: 0, page_digest: nil)
        return finish_successfully if end_of_sequence

        raise_missing_context if token.nil? || token.to_s.empty?

        @registry.claim(@endpoint, token, self)
        duplicate = duplicate_page?(token, page_digest)
        new_token = remember_page(token, page_digest)

        # A replay is not new data even though it carries rows; counting it as
        # progress would make a replay loop unbounded.
        return mark_duplicate if duplicate

        return mark_advanced if rows.to_i.positive? || new_token

        note_no_progress!
        :no_progress
      end

      # True when this exact page body was already received for +token+.
      # A replay is not legal pagination: its rows were already delivered, so
      # callers skip re-adding them while still letting the response count as
      # no progress. That keeps the loop bounded and the result free of
      # duplicated rows, without affecting genuinely new pages.
      def duplicate_page?(token, page_digest)
        return false if token.nil? || page_digest.nil?

        @seen_pages.key?([token, page_digest])
      end

      def finish_successfully
        complete!
        :complete
      end

      def raise_missing_context
        fail!(:missing_context)
        raise WqlEnumerationIncompleteError,
              "query #{@query_id} received a Pull page without EndOfSequence or EnumerationContext"
      end

      def remember_page(token, page_digest)
        new_token = !@seen_tokens.key?(token)
        @seen_pages[[token, page_digest]] = true unless page_digest.nil?
        remember(token)
        new_token
      end

      def mark_advanced
        @no_progress_pulls = 0
        @state = :pulling
        :advanced
      end

      def mark_duplicate
        note_no_progress!
        :duplicate
      end

      def fail!(reason, error = nil)
        @state = :failed
        @failure_reason = reason
        @last_error = error
        @registry.release_context(self)
      end

      def to_h
        {
          query_id: @query_id,
          endpoint: @endpoint,
          namespace: @namespace,
          resource_uri: @resource_uri,
          state: @state,
          complete: complete?,
          pull_count: @pull_count,
          current_token: @current_token
        }
      end

      private

      def note_no_progress!
        @no_progress_pulls += 1
        return if @no_progress_pulls < @max_no_progress_pulls

        fail!(:stalled)
        raise WqlEnumerationStalledError,
              "query #{@query_id} stopped after #{@no_progress_pulls} non-advancing Pull pages " \
              "(token #{@current_token.inspect})"
      end

      def remember(token)
        @seen_tokens[token] = true
        @current_token = token
      end
    end
  end
end
