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

require 'timeout'

module Elastic
  module Transport
    module Transport
      # Generic client error
      #
      class Error < StandardError; end

      # Reloading connections timeout (1 sec by default)
      #
      class SnifferTimeoutError < Timeout::Error; end

      # Raised when the configurable congestion protection rejects an attempt
      # because a total retry budget or a node-level quota is exhausted.
      #
      # The error is an Elastic::Transport::Transport::Error, so existing
      # rescue clauses keep working, and exposes when quota recovers.
      #
      class CongestionLimitExceeded < Error
        # @return [Float, nil] seconds until the next quota token is available
        attr_reader :retry_after

        def initialize(message = nil, retry_after: nil)
          @retry_after = retry_after
          super(message)
        end
      end

      # Elastic server error (HTTP status 5xx)
      #
      class ServerError < Error; end

      module Errors; end

      HTTP_STATUSES = {
        300 => 'MultipleChoices',
        301 => 'MovedPermanently',
        302 => 'Found',
        303 => 'SeeOther',
        304 => 'NotModified',
        305 => 'UseProxy',
        307 => 'TemporaryRedirect',
        308 => 'PermanentRedirect',

        400 => 'BadRequest',
        401 => 'Unauthorized',
        402 => 'PaymentRequired',
        403 => 'Forbidden',
        404 => 'NotFound',
        405 => 'MethodNotAllowed',
        406 => 'NotAcceptable',
        407 => 'ProxyAuthenticationRequired',
        408 => 'RequestTimeout',
        409 => 'Conflict',
        410 => 'Gone',
        411 => 'LengthRequired',
        412 => 'PreconditionFailed',
        413 => 'RequestEntityTooLarge',
        414 => 'RequestURITooLong',
        415 => 'UnsupportedMediaType',
        416 => 'RequestedRangeNotSatisfiable',
        417 => 'ExpectationFailed',
        418 => 'ImATeapot',
        421 => 'TooManyConnectionsFromThisIP',
        426 => 'UpgradeRequired',
        429 => 'TooManyRequests',
        450 => 'BlockedByWindowsParentalControls',
        494 => 'RequestHeaderTooLarge',
        497 => 'HTTPToHTTPS',
        499 => 'ClientClosedRequest',

        500 => 'InternalServerError',
        501 => 'NotImplemented',
        502 => 'BadGateway',
        503 => 'ServiceUnavailable',
        504 => 'GatewayTimeout',
        505 => 'HTTPVersionNotSupported',
        506 => 'VariantAlsoNegotiates',
        510 => 'NotExtended'
      }.freeze

      ERRORS = HTTP_STATUSES.each_with_object({}) do |error, sum|
        status, name = error
        sum[status] = Errors.const_set name, Class.new(ServerError)
        sum
      end
    end
  end
end
