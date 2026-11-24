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

require 'uri'

module Elastic
  module Transport
    module Transport
      # Restricts every request to the service entries explicitly approved in the `:allowed_endpoints` option.
      #
      # A search client can share a domain and a port with another service, the two being separated by a path
      # prefix. The allowlist pins the transport to the entries of the service it belongs to. The same host and
      # port may be approved under several path prefixes, so the application can migrate from one entry to
      # another. Connection building, connection re-selection after a failure and the adapter send all use
      # {#admitted?}, so a connection discovered by sniffing, selected on retry or handed to the adapter can never
      # leave the approved set.
      #
      module EndpointAdmission
        # Raised when a request or connection points at an entry that isn't in `:allowed_endpoints`.
        #
        class EndpointNotAllowed < Error; end

        private

        # Normalizes the configured entries once, so every admission check compares against the same values.
        #
        def normalized_allowed_endpoints
          @normalized_allowed_endpoints ||= Array(options[:allowed_endpoints]).map do |entry|
            normalize_endpoint(entry)
          end
        end

        # Turns a String, URI or Hash entry into the `[scheme, host, port, path]` shape used for comparison.
        #
        def normalize_endpoint(entry)
          case entry
          when String
            uri = URI.parse(entry)
            raise ArgumentError, "allowed_endpoints entry is missing a host: #{entry}" unless uri.host

            [uri.scheme, uri.host, uri.port, normalized_path(uri.path)]
          when URI
            raise ArgumentError, "allowed_endpoints entry is missing a host: #{entry}" unless entry.host

            [entry.scheme, entry.host, entry.port, normalized_path(entry.path)]
          when Hash
            host = entry[:host] || entry[:hostname]
            raise ArgumentError, "allowed_endpoints entry is missing a host: #{entry.inspect}" unless host

            scheme = entry[:scheme] || entry[:protocol] || Base::DEFAULT_PROTOCOL
            port = (entry[:port] || Base::DEFAULT_PORT).to_i
            [scheme, host, port, normalized_path(entry[:path])]
          else
            raise ArgumentError,
                  "allowed_endpoints entries must be a String, URI or Hash -- #{entry.class} given."
          end
        end

        # The single judgment shared by connection build, re-selection and the adapter send.
        #
        # @param url [String,URI] The complete URL the request would actually use.
        # @return [Boolean]
        #
        def admitted?(url)
          return true unless options[:allowed_endpoints]

          uri = url.is_a?(URI) ? url : URI.parse(url.to_s)
          actual = [uri.scheme, uri.host, uri.port.to_i, normalized_path(uri.path)]
          normalized_allowed_endpoints.any? { |entry| endpoint_match?(entry, actual) }
        end

        # An entry matches when scheme, host and port are identical and the request path stays under the
        # approved prefix. An empty prefix approves every path on the host, which keeps a host without a proxy
        # path working while a prefixed entry stays scoped to its service.
        #
        def endpoint_match?(allowed, actual)
          allowed_scheme, allowed_host, allowed_port, allowed_path = allowed
          scheme, host, port, path = actual

          allowed_scheme == scheme &&
            allowed_host == host &&
            allowed_port == port &&
            path_allowed?(allowed_path, path)
        end

        def path_allowed?(allowed_path, path)
          return true if allowed_path.nil? || allowed_path.empty?

          path == allowed_path || path.start_with?(allowed_path + '/')
        end

        def normalized_path(path)
          return nil if path.nil? || path.empty?

          path = path.chomp('/')
          path.empty? ? nil : path
        end

        def ensure_endpoint_allowed!(url)
          return if admitted?(url)

          raise EndpointNotAllowed,
                "Refusing to send a request to #{sanitize_url(url.to_s)}: it is not listed in allowed_endpoints"
        end

        # Admission check for a connection being built or rebuilt. Uses the same judgment as the request path,
        # so an entry introduced through sniffing or re-selection can't enter the pool outside the allowlist.
        #
        def ensure_connection_endpoint_allowed!(host)
          ensure_endpoint_allowed!(__full_url(host))
        end
      end
    end
  end
end
