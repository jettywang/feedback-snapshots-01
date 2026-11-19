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

require 'thread'
require_relative '../exceptions'

module WinRM
  module WSMV
    # Tracks which WQL enumeration currently owns a continuation token.
    #
    # A WS-Enumeration context is scoped to one endpoint, resource URI/namespace
    # and one in-flight query. A token is therefore *not* a standalone bearer
    # credential: while the query that received it is still running, no other
    # query may redeem it, on the same endpoint and resource URI. Ownership is
    # released when the query finishes, so a later query that legitimately
    # receives an identical token from its own Enumerate response is not
    # penalised.
    class WqlTokenRegistry
      Owner = Struct.new(:query_id, :endpoint, :resource_uri, :context) do
        def active?
          !context.nil? && context.active?
        end

        def describe
          "#{query_id} (endpoint=#{endpoint} resource_uri=#{resource_uri})"
        end
      end

      class << self
        def default
          @default ||= new
        end

        def reset_default!
          @default = new
        end
      end

      def initialize
        @owners = {}
        @mutex = Mutex.new
      end

      # Associates +token+ with +context+ and returns the context. Raises when
      # another still-live query owns the token for this endpoint and resource.
      def claim(endpoint, token, context)
        return context if token.nil? || token.to_s.empty?

        key = key_for(endpoint, context.resource_uri, token)
        @mutex.synchronize do
          owner = @owners[key]
          if owner && owner.query_id != context.query_id && owner.active?
            raise WqlContextMismatchError.new(
              "enumeration token #{token.inspect} belongs to #{owner.describe}, " \
              "not query #{context.query_id} (endpoint=#{context.endpoint} " \
              "resource_uri=#{context.resource_uri})"
            )
          end

          @owners[key] = Owner.new(context.query_id, context.endpoint, context.resource_uri, context)
        end
        context
      end

      def owner(endpoint, resource_uri, token)
        return nil if token.nil? || token.to_s.empty?

        @mutex.synchronize { @owners[key_for(endpoint, resource_uri, token)] }
      end

      # Drops every claim held by +context+. A token received by a finished
      # query is not replayable, but a new query may independently obtain a
      # token with the same bytes from its own Enumerate response.
      def release_context(context)
        @mutex.synchronize do
          @owners.delete_if do |_key, owner|
            owner.query_id == context.query_id && owner.endpoint == context.endpoint &&
              owner.resource_uri == context.resource_uri
          end
        end
      end

      def clear!
        @mutex.synchronize { @owners.clear }
      end

      def size
        @mutex.synchronize { @owners.size }
      end

      private

      def key_for(endpoint, resource_uri, token)
        [WqlEnumerationContext.normalize_endpoint(endpoint), resource_uri.to_s, token.to_s]
      end
    end
  end
end
