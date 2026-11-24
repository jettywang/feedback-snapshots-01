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

require 'manticore'

module Elastic
  module Transport
    module Transport
      module HTTP
        # Alternative HTTP transport implementation for JRuby,
        # using the [_Manticore_](https://github.com/cheald/manticore) client,
        #
        # @example HTTP
        #
        #     require 'elasticsearch/transport/transport/http/manticore'
        #
        #     client = Elasticsearch::Client.new transport_class: Elasticsearch::Transport::Transport::HTTP::Manticore
        #
        #     client.transport.connections.first.connection
        #     => #<Manticore::Client:0x56bf7ca6 ...>
        #
        #     client.info['status']
        #     => 200
        #
        #  @example HTTPS (All SSL settings are optional,
        #                  see http://www.rubydoc.info/gems/manticore/Manticore/Client:initialize)
        #
        #     require 'elasticsearch/transport/transport/http/manticore'
        #
        #     client = Elasticsearch::Client.new \
        #       url: 'https://elasticsearch.example.com',
        #       transport_class: Elasticsearch::Transport::Transport::HTTP::Manticore,
        #       ssl: {
        #         truststore: '/tmp/truststore.jks',
        #         truststore_password: 'password',
        #         keystore: '/tmp/keystore.jks',
        #         keystore_password: 'secret',
        #       }
        #
        #     client.transport.connections.first.connection
        #     => #<Manticore::Client:0xdeadbeef ...>
        #
        #     client.info['status']
        #     => 200
        #
        # @see Transport::Base
        #
        class Manticore
          include Base

          def initialize(arguments = {}, &block)
            @request_options = { headers: {} }
            @manticore = build_client(arguments[:options] || {})
            super(arguments, &block)
            # A client may set headers between construction and the first
            # request; rebuild the merged request defaults once more so they
            # are included.
            __refresh_request_headers
          end

          # Should just be run once at startup
          def build_client(options = {})
            client_options = options[:transport_options] || {}
            client_options[:ssl] = options[:ssl] || {}
            @manticore = ::Manticore::Client.new(client_options)
          end

          # Performs the request by invoking {Transport::Base#perform_request} with a block.
          #
          # @return [Response]
          # @see    Transport::Base#perform_request
          #
          def perform_request(method, path, params = {}, body = nil, headers = nil, opts = {})
            super do |connection, url, attempt_headers|
              capture_otel_span_attributes(connection, url)
              body = body ? __convert_to_json(body) : nil
              # Manticore shares one client, so the connection-specific headers
              # (including its private ones) come from the connection snapshot
              # rather than from a per-connection client object.
              request_headers = HeaderPolicy.merge_headers(
                connection.headers,
                attempt_headers.nil? ? headers : attempt_headers
              )
              body, headers = compress_request(body, parse_headers(request_headers))
              params[:body] = body if body
              params[:headers] = headers if headers

              case method
              when 'GET'
                resp = connection.connection.get(url, params)
              when 'HEAD'
                resp = connection.connection.head(url, params)
              when 'PUT'
                resp = connection.connection.put(url, params)
              when 'POST'
                resp = connection.connection.post(url, params)
              when 'DELETE'
                resp = connection.connection.delete(url, params)
              else
                raise ArgumentError.new "Method #{method} not supported"
              end
              Response.new(resp.code, resp.read_body, resp.headers)
            end
          end

          # Builds and returns a collection of connections.
          # Each connection is a Manticore::Client
          #
          # @return [Connections::Collection]
          #
          def __build_connections
            # Start from the current profile on every build: Manticore keeps
            # one client, so headers left from a previous configuration would
            # otherwise keep being sent after a rebuild.
            profile_for_build = header_profile
            @request_options = {
              headers: HeaderPolicy.merge_headers(
                default_headers,
                profile_for_build[:public]
              )
            }

            Connections::Collection.new(
              connections: hosts.map do |configured_host|
                host = configured_host.dup
                host[:attributes] = host[:attributes].dup if host[:attributes].is_a?(Hash)
                host[:protocol] = host[:scheme] || DEFAULT_PROTOCOL
                host[:port] ||= DEFAULT_PORT

                host.delete(:user)     # auth is not supported here.
                host.delete(:password) # use the headers

                host_profile = connection_header_profile(host)
                approved = approved_host?(host)
                connection = Connections::Connection.new(host: host, connection: @manticore)
                connection.with_header_profile(
                  host_profile[:all],
                  host_profile[:private],
                  withheld: host_profile[:withheld],
                  allowed: approved
                )
              end,
              selector_class: options[:selector_class],
              selector: options[:selector]
            )
          end

          # Recomputes the request-level default headers (Content-Type, User-Agent
          # and the connection's public headers) from the current options.
          #
          # @api private
          #
          def __refresh_request_headers
            profile = header_profile
            @request_options[:headers] = HeaderPolicy.merge_headers(
              default_headers,
              profile[:public]
            )
          end

          # Content-Type and User-Agent defaults Manticore needs on every
          # request. They are not private, so they live in @request_options.
          #
          # @api private
          #
          def default_headers
            {
              CONTENT_TYPE_STR => DEFAULT_CONTENT_TYPE,
              USER_AGENT_STR => user_agent_header
            }
          end

          # Closes all connections by marking them as dead
          # and closing the underlying HttpClient instances
          #
          # @return [Connections::Collection]
          #
          def __close_connections
            # The Manticore adapter uses a single long-lived instance
            # of Manticore::Client, so we don't close the connections.
          end

          # Returns an array of implementation specific connection errors.
          #
          # @return [Array]
          #
          def host_unreachable_exceptions
            [
              ::Manticore::Timeout,
              ::Manticore::SocketException,
              ::Manticore::ClientProtocolException,
              ::Manticore::ResolutionFailure
            ]
          end

          private

          # Faraday and Curb read the pinned CA when a connection is built, so rebuilding connections is enough.
          # Manticore reads it once, when the Manticore::Client is built in initialize, so the client is built again.
          def __rebuild_pinned_connections
            @manticore.close
            build_client(options)
            super
          end

          def parse_headers(headers)
            request_headers = @request_options.fetch(:headers, {})
            headers = HeaderPolicy.merge_headers(request_headers, headers || {})
            headers[ACCEPT_ENCODING] = GZIP if use_compression?
            headers.empty? ? nil : headers
          end

          def user_agent_header
            @user_agent_header ||= begin
              meta = ["RUBY_VERSION: #{JRUBY_VERSION}"]
              if RbConfig::CONFIG && RbConfig::CONFIG['host_os']
                meta << "#{RbConfig::CONFIG['host_os'].split('_').first[/[a-z]+/i].downcase} #{RbConfig::CONFIG['target_cpu']}"
              end
              meta << "Manticore #{::Manticore::VERSION}"
              "elasticsearch-ruby/#{VERSION} (#{meta.join('; ')})"
            end
          end
        end
      end
    end
  end
end
