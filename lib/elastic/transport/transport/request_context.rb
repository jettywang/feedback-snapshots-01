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
      # State for one attempt of one request: which connection generation
      # served it, and which header *names* were sent or withheld.
      #
      # Values are deliberately not stored, so anything that publishes a
      # request context cannot leak a credential. The connection itself keeps
      # the values until it is rebuilt.
      #
      # @api private
      class RequestContext
        attr_reader :request_id, :attempt, :connection_generation,
                    :sent_header_names, :withheld_header_names, :started_at

        def initialize(request_id:, attempt:)
          @request_id = request_id
          @attempt = attempt
          @started_at = Time.now
          @sent_header_names = []
          @withheld_header_names = []
        end

        def connection_generation=(generation)
          @connection_generation = generation
        end

        # Records the headers that are really handed to the adapter. Only the
        # names are kept.
        def record_sent_headers(headers)
          @sent_header_names = header_names(headers)
        end

        def record_withheld_headers(names)
          @withheld_header_names = Array(names).map(&:to_s).sort
        end

        # Fields that are safe to publish in logs, traces and telemetry.
        #
        # @return [Hash]
        def to_h
          {
            request_id: request_id,
            attempt: attempt,
            connection_generation: connection_generation,
            header_names: sent_header_names,
            withheld_header_names: withheld_header_names
          }
        end

        private

        def header_names(headers)
          return [] if headers.nil?

          headers.map { |name, _| name.to_s.downcase }.sort
        end
      end
    end
  end
end
