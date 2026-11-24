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
      module Connections
        # Wraps the connection information and logic.
        #
        # The Connection instance wraps the host information (hostname, port, attributes, etc),
        # as well as the "session" (a transport client object, such as a {HTTP::Faraday} instance).
        #
        # It provides methods to construct and properly encode the URLs and paths for passing them
        # to the transport client object.
        #
        # It provides methods to handle connection livecycle (dead, alive, healthy).
        #
        class Connection
          DEFAULT_RESURRECT_TIMEOUT = 60

          attr_reader :host, :connection, :options, :failures, :dead_since,
                      :headers, :approved_headers, :generation, :withheld_header_names

          # @option arguments [Hash]   :host       Host information (example: `{host: 'localhost', port: 9200}`)
          # @option arguments [Object] :connection The transport-specific physical connection or "session"
          # @option arguments [Hash]   :options    Options (usually passed in from transport)
          # @option arguments [Hash]   :headers    Header profile this connection was built with. Private
          #                                        headers are frozen here, so a later rebuild can't
          #                                        change what an in-flight request sends.
          # @option arguments [Hash]   :approved_headers Private header names this connection may send,
          #                                        with the approved value.
          #
          def initialize(arguments={})
            host = arguments[:host]
            @host       = host.is_a?(Hash) ? Redacted.new(host) : host
            @connection = arguments[:connection]
            @options    = arguments[:options] || {}
            @state_mutex = Mutex.new

            @options[:resurrect_timeout] ||= DEFAULT_RESURRECT_TIMEOUT
            @headers         = (arguments[:headers] || {}).dup.freeze
            @approved_headers = (arguments[:approved_headers] || {}).dup.freeze
            @withheld_header_names = Array(arguments[:withheld_header_names]).map(&:to_s).sort.freeze
            @private_headers_allowed = arguments.fetch(:private_headers_allowed, true)
            @generation      = arguments[:generation] || __compute_generation(host, @headers)
            @dead = false
            @failures = 0
          end

          # Attaches the header snapshot and approval list after the adapter
          # has built the physical connection. Returns self so it can be called
          # inline from a transport's build loop.
          #
          # @param headers [Hash] every header this connection will send
          # @param approved [Hash] the private subset it is approved to send
          # @param withheld [Array<String>] private header names withheld from it
          # @param allowed [Boolean] whether it may receive request-scoped private headers
          # @return [self]
          #
          def with_header_profile(headers, approved, withheld: [], allowed: true)
            @headers = headers.dup.freeze
            @approved_headers = approved.dup.freeze
            @withheld_header_names = Array(withheld).map(&:to_s).sort.freeze
            @private_headers_allowed = allowed
            @generation = __compute_generation(host, @headers)
            self
          end

          # True when this connection may receive private headers attached to a
          # single request. False when the host was not approved for the
          # transport's private headers; it stays usable with public headers.
          #
          # @return [Boolean]
          #
          def private_headers_allowed?
            @private_headers_allowed
          end

          # True when this connection is approved to send the named header.
          #
          # @param name [String, Symbol]
          # @return [Boolean]
          #
          def approved_header?(name)
            normalized = name.to_s.downcase
            approved_headers.any? { |approved, _| approved.to_s.downcase == normalized }
          end

          # Returns the complete endpoint URL with host, port, path and serialized parameters.
          #
          # @return [String]
          #
          def full_url(path, params = {})
            url  = "#{host[:protocol]}://"
            url += "#{CGI.escape(host[:user])}:#{CGI.escape(host[:password])}@" if host[:user]
            url += "#{host[:host]}:#{host[:port]}"
            url += "#{host[:path]}" if host[:path]
            full_path = full_path(path, params)
            url += '/' unless full_path.match?(/^\//)
            url += full_path
          end

          # Returns the complete endpoint path with serialized parameters.
          #
          # @return [String]
          #
          def full_path(path, params={})
            path + (params.empty? ? '' : "?#{::Faraday::Utils::ParamsHash[params].to_query}")
          end

          # Returns true when this connection has been marked dead, false otherwise.
          #
          # @return [Boolean]
          #
          def dead?
            @dead || false
          end

          # Marks this connection as dead, incrementing the `failures` counter and
          # storing the current time as `dead_since`.
          #
          # @return [self]
          #
          def dead!
            @state_mutex.synchronize do
              @dead       = true
              @failures  += 1
              @dead_since = Time.now
            end
            self
          end

          # Marks this connection as alive, ie. it is eligible to be returned from the pool by the selector.
          #
          # @return [self]
          #
          def alive!
            @state_mutex.synchronize do
              @dead     = false
            end
            self
          end

          # Marks this connection as healthy, ie. a request has been successfully performed with it.
          #
          # @return [self]
          #
          def healthy!
            @state_mutex.synchronize do
              @dead     = false
              @failures = 0
            end
            self
          end

          # Marks this connection as alive, if the required timeout has passed.
          #
          # @return [self,nil]
          # @see    DEFAULT_RESURRECT_TIMEOUT
          # @see    #resurrectable?
          #
          def resurrect!
            alive! if resurrectable?
          end

          # Returns true if the connection is eligible to be resurrected as alive, false otherwise.
          #
          # @return [Boolean]
          #
          def resurrectable?
            @state_mutex.synchronize {
              Time.now > @dead_since + ( @options[:resurrect_timeout] * 2 ** (@failures-1) )
            }
          end

          # Equality operator based on protocol, host, port, attributes and the
          # header/credential generation. The generation keeps a connection
          # whose private headers or credentials changed from surviving a
          # rebuild, which would send the old values on new requests.
          #
          # @return [Boolean]
          #
          def ==(other)
            return false unless other.respond_to?(:host)

            self.host[:protocol] == other.host[:protocol] && \
            self.host[:host] == other.host[:host] && \
            self.host[:port].to_i == other.host[:port].to_i && \
            self.host[:attributes] == other.host[:attributes] && \
            (!other.respond_to?(:generation) || self.generation == other.generation)
          end

          # @return [String]
          #
          def to_s
            "<#{self.class.name} host: #{host} generation: #{generation} " \
              "(#{dead? ? 'dead since ' + dead_since.to_s : 'alive'})>"
          end

          private

          # A short digest of what this connection will send. Only the digest
          # is public; credentials never leave the connection.
          def __compute_generation(raw_host, headers)
            host_details = if raw_host.is_a?(Hash)
                             {
                               protocol: raw_host[:protocol] || raw_host[:scheme],
                               host: raw_host[:host],
                               port: raw_host[:port],
                               user: raw_host[:user],
                               password: raw_host[:password]
                             }
                           else
                             { host: raw_host }
                           end
            HeaderPolicy.headers_fingerprint(headers, host_details)
          end
        end
      end
    end
  end
end
