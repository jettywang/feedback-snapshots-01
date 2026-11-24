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

require 'digest'

module Elastic
  module Transport
    module Transport
      # Rules for deciding which request headers may appear in logs, traces and
      # other diagnostics, and for deriving a stable identity ("generation") from
      # the headers and credentials a connection was built with.
      #
      # Header names are case-sensitive in Manticore and Curb, and distinct only
      # by case in Faraday, so every merge goes through {#merge_headers}, which
      # keeps a single entry per header name regardless of case.
      #
      # @api private
      module HeaderPolicy
        # Placeholder written instead of a private header value.
        REDACTED = '<REDACTED>'.freeze

        # Header names whose value is a credential and must never be published.
        SENSITIVE_HEADERS = %w[
          authorization
          proxy-authorization
          cookie
          set-cookie
          x-api-key
          api-key
        ].freeze

        # Catches service-private headers such as `X-Service-Token` or
        # `X-Client-Secret` without matching public ones such as
        # `x-elastic-client-meta` or `Elastic-Api-Version`.
        SENSITIVE_HEADER_PATTERN =
          /(?:\A|[-_])(?:auth|token|secret|password|passwd|credential|api[-_]?key|session)(?:\z|[-_])/i.freeze

        # @param name [String, Symbol] Header name.
        # @return [Boolean] true when the header value is a credential.
        def sensitive_header?(name)
          normalized = name.to_s.downcase
          SENSITIVE_HEADERS.include?(normalized) || normalized.match?(SENSITIVE_HEADER_PATTERN)
        end

        # Returns a copy of the headers with private values replaced by a
        # placeholder. The original hash is never modified.
        #
        # @param headers [Hash, nil]
        # @param placeholder [String]
        # @return [Hash, nil]
        def redacted_headers(headers, placeholder = REDACTED, extra_sensitive = [])
          return nil if headers.nil?

          extra = extra_sensitive.map { |name| name.to_s.downcase }

          headers.each_with_object({}) do |(name, value), result|
            result[name] = if sensitive_header?(name) || extra.include?(name.to_s.downcase)
                             placeholder
                           else
                             value
                           end
          end
        end

        # Merges header sources case-insensitively. Later sources win, and the
        # spelling of the winning name is kept, so a connection does not end up
        # with both `content-type` and `Content-Type`.
        #
        # @param sources [Array<Hash, nil>]
        # @return [Hash]
        def merge_headers(*sources)
          result = {}
          names = {}

          sources.compact.each do |source|
            source.each do |name, value|
              normalized = name.to_s.downcase
              if names.key?(normalized)
                result.delete(names[normalized])
              end
              # Keep the caller's key type: Faraday turns symbol keys such as
              # :foo_bar into `Foo-Bar`, and other adapters expect the spelling
              # they were given.
              names[normalized] = name
              result[name] = value
            end
          end

          result
        end

        # Normalizes headers to sorted `[lower-case-name, value]` pairs.
        #
        # @param headers [Hash, nil]
        # @return [Array<Array(String, String)>]
        def canonical_headers(headers)
          return [] if headers.nil?

          headers.map do |name, value|
            header_value = value.is_a?(Array) ? value.join(', ') : value.to_s
            [name.to_s.downcase, header_value]
          end.sort_by(&:first)
        end

        # Names only, sorted and lower-cased. Safe to publish.
        #
        # @param headers [Hash, nil]
        # @return [Array<String>]
        def header_names(headers)
          canonical_headers(headers).map(&:first)
        end

        # A shortened digest identifying a header/credential configuration. It
        # lets a response and a log line name the generation that served a
        # request without exposing any header value.
        #
        # @param headers [Hash, nil]
        # @param context [Hash] Additional identity material, for example the
        #   target protocol, host and credentials.
        # @return [String]
        def headers_fingerprint(headers, context = {})
          parts = canonical_headers(headers)
          context.sort_by { |key, _| key.to_s }.each do |key, value|
            parts << ["context:#{key}", value.to_s]
          end

          digest = Digest::SHA256.hexdigest(parts.map { |key, value| "#{key}\u0000#{value}" }.join("\u0001"))
          digest[0, 16]
        end

        module_function :sensitive_header?, :redacted_headers, :merge_headers,
                        :canonical_headers, :header_names, :headers_fingerprint
      end
    end
  end
end
