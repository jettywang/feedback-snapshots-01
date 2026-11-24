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
    # Wrapper object for Open Telemetry objects and associated config.
    #
    # Span attributes are governed by the shared {PublishingPolicy}: request
    # bodies are never attached to a span, URLs are stripped of credentials and
    # error messages are sanitized. The legacy body-capture environment
    # variables are therefore no longer consulted.
    #
    # @api private
    class OpenTelemetry
      OTEL_TRACER_NAME = 'elasticsearch-api'.freeze
      # Valid values for the enabled config are 'true' and 'false'. Default is 'true'.
      ENV_VARIABLE_ENABLED = 'OTEL_RUBY_INSTRUMENTATION_ELASTICSEARCH_ENABLED'.freeze

      # Initialize the Open Telemetry wrapper object. Takes the options originally passed to
      # Client#initialize.
      def initialize(opts)
        @tracer = tracer_provider(opts).tracer(OTEL_TRACER_NAME, Elastic::Transport::VERSION)
      end
      attr_accessor :tracer

      def tracer_provider(opts)
        opts[:opentelemetry_tracer_provider] || ::OpenTelemetry.tracer_provider
      end
    end
  end
end
