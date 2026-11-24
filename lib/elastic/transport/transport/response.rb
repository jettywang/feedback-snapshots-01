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
      # Wraps the response from Elasticsearch.
      # It provides `body`, `status` and `headers` methods.
      #
      # When node receipts are enabled (see {NodeReceipt}), the response also
      # carries the factual receipt of the connection that produced it in
      # `node_receipt`, plus every receipt collected across retries in
      # `node_receipts`. Both stay `nil` when the feature is disabled, so the
      # default behaviour of the class is unchanged.
      class Response
        attr_reader :status, :body, :headers

        # @return [NodeReceipt, nil] Receipt of the attempt that produced this
        #   response.
        attr_accessor :node_receipt

        # @return [Array<NodeReceipt>] Receipts of every attempt, oldest first.
        #   Empty when node receipts are disabled.
        attr_accessor :node_receipts

        # @param status  [Integer] Response status code
        # @param body    [String]  Response body
        # @param headers [Hash]    Response headers
        def initialize(status, body, headers = {})
          @status, @body, @headers = status, body, headers
          @body = body.force_encoding('UTF-8') if body.respond_to?(:force_encoding) && !body.frozen?
          @node_receipts = []
        end
      end
    end
  end
end
