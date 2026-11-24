# Licensed to Elasticsearch B.V. under one or more contributor
# license agreements. See the NOTICE file distributed with
# this work for additional information regarding copyright
# ownership. Elasticsearch B.V. licenses this file to you under
# the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.

module Elastic
  module Transport
    module Transport
      # A factual record of what happened during a single connection attempt.
      #
      # A receipt is created from the {Connections::Connection} that the
      # transport actually used for an attempt, never from data the server put
      # in the response body. The body is allowed to claim any service name
      # (for instance through an error's +root_cause+); the +node+ attributes
      # here describe the connection the request was sent to, so operations
      # can always correlate an error with the real endpoint that answered.
      #
      # Every attempt gets a brand new receipt. On a retry the previous
      # receipt is left untouched and a fresh one is started, so fields from
      # an earlier response can never leak into the result of a later one.
      #
      # The status is one of:
      #
      # * {UNREACHABLE} - the connection itself failed (refused, timed out,
      #   DNS resolution error, ...). No complete response was received.
      # * {PARSE_ERROR} - the node answered, but the response body could not
      #   be parsed.
      # * {FAILURE} - the node answered with a complete response whose status
      #   code indicates failure (>= 300).
      # * {SUCCESS} - the node answered with a complete, successful response.
      #
      class NodeReceipt
        # The connection could not be established or produced no complete
        # response.
        #
        # @return [Symbol]
        UNREACHABLE = :unreachable

        # The node answered, but the response payload could not be parsed.
        #
        # @return [Symbol]
        PARSE_ERROR = :parse_error

        # The node answered with a complete response carrying a failing
        # HTTP status (>= 300).
        #
        # @return [Symbol]
        FAILURE = :failure

        # The node answered with a complete, successful HTTP response.
        #
        # @return [Symbol]
        SUCCESS = :success

        # All valid terminal statuses, in the order an attempt moves through
        # them.
        #
        # @return [Array<Symbol>]
        STATUSES = [UNREACHABLE, PARSE_ERROR, FAILURE, SUCCESS].freeze

        # @return [Integer] 1-based number of the attempt this receipt records.
        attr_reader :attempt

        # @return [Hash] A frozen copy of the actual connection's host
        #   information (protocol, host, port, ...). Credentials are not
        #   copied, so the receipt is safe to log.
        attr_reader :node

        # @return [Symbol] One of {STATUSES}.
        attr_reader :status

        # @return [Integer, nil] The HTTP status returned by the node, or
        #   +nil+ when no complete response was received ({UNREACHABLE}).
        attr_reader :http_status

        # @return [Exception, nil] The exception that terminated the attempt,
        #   when it did not succeed.
        attr_reader :error

        # @param connection [Connections::Connection] The connection actually
        #   used for this attempt.
        # @param attempt [Integer] 1-based attempt number.
        #
        def initialize(connection, attempt)
          @attempt = attempt
          @node = extract_node(connection)
          @status = nil
          @http_status = nil
          @error = nil
        end

        # Marks the attempt as unable to reach the node.
        #
        # @param error [Exception] The connection level error.
        # @return [self]
        #
        def mark_unreachable!(error)
          @status = UNREACHABLE
          @http_status = nil
          @error = error
          self
        end

        # Marks the attempt as having received a complete response that the
        # transport could not parse.
        #
        # @param error [Exception] The parse error.
        # @param http_status [Integer, nil] The HTTP status, when available.
        # @return [self]
        #
        def mark_parse_error!(error, http_status = nil)
          @status = PARSE_ERROR
          @http_status = http_status
          @error = error
          self
        end

        # Marks the attempt as having received a complete response whose
        # HTTP status code indicates failure.
        #
        # @param http_status [Integer] The failing HTTP status code.
        # @param error [Exception, nil] The error raised for the response.
        # @return [self]
        #
        def mark_failure!(http_status, error = nil)
          @status = FAILURE
          @http_status = http_status
          @error = error
          self
        end

        # Marks the attempt as having received a complete, successful
        # response.
        #
        # @param http_status [Integer] The successful HTTP status code.
        # @return [self]
        #
        def mark_success!(http_status)
          @status = SUCCESS
          @http_status = http_status
          @error = nil
          self
        end

        # @return [Boolean] Whether the node returned a complete response,
        #   even if that response was a failure or could not be parsed.
        #
        def responded?
          status != UNREACHABLE
        end

        # @return [Boolean] Whether the attempt ended in a successful
        #   response.
        #
        def success?
          status == SUCCESS
        end

        # @return [Boolean] Whether the attempt never got a complete
        #   response.
        #
        def unreachable?
          status == UNREACHABLE
        end

        # @return [Boolean] Whether the node answered but the body could not
        #   be parsed.
        #
        def parse_error?
          status == PARSE_ERROR
        end

        # @return [Boolean] Whether the node answered with a failing status.
        #
        def failure?
          status == FAILURE
        end

        # @return [String]
        #
        def inspect
          "#<#{self.class.name} attempt=#{attempt} node=#{node.inspect} " \
            "status=#{status.inspect} http_status=#{http_status.inspect}>"
        end

        private

        # Builds a credential-free, frozen description of the connection the
        # request was actually sent to.
        #
        def extract_node(connection)
          host = connection.host
          node = {
            protocol: host[:protocol],
            host: host[:host],
            port: host[:port],
            path: host[:path]
          }
          node[:attributes] = host[:attributes] if host.key?(:attributes)
          node.freeze
        end
      end

      # Mixin for transport errors that may carry a {NodeReceipt}.
      #
      # Including it leaves the original error class, message and structure
      # untouched; it only adds optional accessors used to correlate the
      # raised error with the connection that actually produced it.
      #
      module NodeReceiptError
        # @return [NodeReceipt, nil] Receipt of the attempt that raised.
        attr_accessor :node_receipt

        # @return [Array<NodeReceipt>] Receipts of every attempt, oldest first.
        def node_receipts
          @node_receipts ||= []
        end
      end
    end
  end
end
