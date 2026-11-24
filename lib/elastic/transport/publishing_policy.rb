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

require 'securerandom'

module Elastic
  module Transport
    # Single publication policy shared by the curl-style tracer, the logger and
    # OpenTelemetry spans. Every value that leaves the process through one of
    # these sinks passes through the same allow-list/redaction rules, so
    # credentials, request bodies and sensitive response fields can never be
    # handed to an external maintainer.
    #
    # The policy only transforms what is published. The actual request is still
    # sent with the original connection parameters, headers and body.
    #
    # @api private
    class PublishingPolicy
      REDACTED = '<REDACTED>'.freeze
      OMITTED = '[OMITTED]'.freeze

      # Hash/JSON keys whose values are redacted in published response bodies.
      # Patterns use `*` as a wildcard, mirroring the OpenTelemetry sanitizer.
      DEFAULT_SENSITIVE_KEY_PATTERNS =
        %w[password passwd pwd secret *key *token* *session* *credit* *card* *auth* set-cookie].freeze

      # Request headers that never leave the process in clear text. The match
      # is case-insensitive and `*` is a wildcard.
      SENSITIVE_HEADER_PATTERNS =
        ['authorization', 'proxy-authorization', 'set-cookie', '*cookie*', '*token*', '*secret*', '*auth*'].freeze

      SENSITIVE_HEADER_REGEXPS = SENSITIVE_HEADER_PATTERNS.map do |pattern|
        source = pattern.split('*').map { |part| Regexp.escape(part) }.join('.*')
        Regexp.new(source, Regexp::IGNORECASE)
      end.freeze

      attr_reader :sensitive_key_patterns

      # @option options [Array<String,Regexp>] :sensitive_keys Additional response
      #   body key patterns whose values must be redacted.
      def initialize(options = {})
        @sensitive_key_patterns = compile(DEFAULT_SENSITIVE_KEY_PATTERNS) +
                                 compile(Array(options[:sensitive_keys]))
      end

      # Generates the correlation identifier shared by every published record
      # of a single logical request (including all of its retries).
      def self.request_id
        SecureRandom.hex(8)
      end

      # Stable identifier of the node an attempt was sent to.
      def self.node_id(connection)
        host = connection&.host
        return 'unknown-node' if host.nil? || host.is_a?(String) && host.empty?
        return host.to_s if host.is_a?(String)
        return 'unknown-node' unless host.respond_to?(:[])

        "#{host[:protocol]}://#{host[:host]}:#{host[:port]}"
      rescue StandardError
        host.to_s
      end

      # Removes userinfo (username and password) from a URL string.
      def sanitize_url(url)
        url.to_s.gsub(%r{//[^/@]+@}, "//#{REDACTED_USERINFO}@")
      end

      # Returns a copy of the headers with every sensitive header redacted.
      def sanitize_headers(headers)
        return headers unless headers.respond_to?(:each_pair)

        headers.each_with_object({}) do |(key, value), result|
          result[key] = sensitive_header?(key) ? REDACTED : value
        end
      end

      # Request bodies are never published.
      def sanitize_request_body(_body)
        OMITTED
      end

      # Redacts sensitive values from a response body. JSON strings are parsed
      # and redacted; anything else is omitted because its contents cannot be
      # inspected safely.
      def sanitize_response_body(body, serializer = nil)
        return if body.nil? || (body.respond_to?(:empty?) && body.empty?)

        parsed = parse_body(body, serializer)
        return OMITTED unless parsed.is_a?(Hash) || parsed.is_a?(Array)

        redact(deep_dup(parsed))
      end

      # Strips embedded URL credentials and sensitive key/value pairs from a
      # free-form error message before it is logged or attached to a span.
      def sanitize_error_message(message)
        sanitized = message.to_s.gsub(%r{//[^/@\s]+@}, "//#{REDACTED_USERINFO}@")
        sanitized.gsub(JSON_PAIR_REGEXP) do |pair|
          key = Regexp.last_match(1)
          if sensitive_key?(key)
            %("#{key}":"#{REDACTED}")
          else
            pair
          end
        end
      end

      private

      REDACTED_USERINFO = ":#{REDACTED}".freeze
      JSON_PAIR_REGEXP = /"([^"]+)"\s*:\s*"(?:[^"\\]|\\.)*"/.freeze

      def compile(patterns)
        patterns.map do |pattern|
          next pattern if pattern.is_a?(Regexp)

          source = pattern.split('*').map { |part| Regexp.escape(part) }.join('.*')
          Regexp.new(source, Regexp::IGNORECASE)
        end
      end

      def sensitive_header?(key)
        SENSITIVE_HEADER_REGEXPS.any? { |regex| regex.match?(key.to_s) }
      end

      def sensitive_key?(key)
        @sensitive_key_patterns.any? { |regex| regex.match?(key.to_s) }
      end

      def parse_body(body, serializer)
        case body
        when Hash, Array
          body
        when String
          return if serializer.nil?

          begin
            serializer.load(body)
          rescue StandardError
            nil
          end
        end
      end

      def redact(obj)
        case obj
        when Hash
          obj.each_pair do |key, value|
            obj[key] = sensitive_key?(key) ? REDACTED : redact(value)
          end
        when Array
          obj.map { |item| redact(item) }
        else
          obj
        end
      end

      def deep_dup(obj)
        case obj
        when Hash
          obj.each_with_object({}) { |(key, value), result| result[key] = deep_dup(value) }
        when Array
          obj.map { |item| deep_dup(item) }
        else
          obj
        end
      end
    end
  end
end
