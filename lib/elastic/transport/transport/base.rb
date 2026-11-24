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
      # @abstract Module with common functionality for transport implementations.
      #
      module Base
        include Loggable
        include CaFingerprint

        DEFAULT_PORT             = 9200
        DEFAULT_PROTOCOL         = 'http'.freeze
        DEFAULT_RELOAD_AFTER     = 10_000 # Requests
        DEFAULT_RESURRECT_AFTER  = 60     # Seconds
        DEFAULT_MAX_RETRIES      = 3      # Requests
        DEFAULT_SERIALIZER_CLASS = Serializer::MultiJson
        SANITIZED_PASSWORD       = '*' * (rand(14) + 1)
        NODE_TRUST_OPTION        = :node_trust
        MAX_STALE_CONNECTIONS    = 32
        MAX_RETIRED_CONNECTIONS  = 32

        attr_reader   :hosts, :options, :connections, :counter, :last_request_at, :protocol,
                      :node_trust, :retired_connections, :stale_connections
        attr_accessor :serializer, :sniffer, :logger, :tracer,
                      :reload_connections, :reload_after,
                      :resurrect_after

        # Creates a new transport object
        #
        # @param arguments [Hash] Settings and options for the transport
        # @param block     [Proc] Lambda or Proc which can be evaluated in the context of the "session" object
        #
        # @option arguments [Array] :hosts   An Array of normalized hosts information
        # @option arguments [Array] :options A Hash with options (usually passed by {Client})
        #
        # @see Client#initialize
        #
        def initialize(arguments = {}, &block)
          @state_mutex = Mutex.new
          @ca_pin_mutex = Mutex.new

          @hosts       = arguments[:hosts]   || []
          @options     = arguments[:options] || {}
          @options[:http] ||= {}
          @options[:retry_on_status] ||= []
          @options[:delay_on_retry]  ||= 0

          @node_trust = NodeTrust.new(__node_trust_policy(arguments))
          if @node_trust.configured? && @options[:ca_fingerprint]
            raise ArgumentError, 'node_trust can\'t be combined with ca_fingerprint'
          end
          __validate_node_trust! if @node_trust.configured?

          @retired_connections = []
          @stale_connections   = []

          validate_ca_fingerprint_options! if @options[:ca_fingerprint]
          @block       = block
          @compression = !!@options[:compression]
          @connections = __build_connections

          @serializer  = options[:serializer] || ( options[:serializer_class] ? options[:serializer_class].new(self) : DEFAULT_SERIALIZER_CLASS.new(self))
          @protocol    = options[:protocol] || DEFAULT_PROTOCOL

          @logger      = options[:logger]
          @tracer      = options[:tracer]

          @sniffer     = options[:sniffer_class] ? options[:sniffer_class].new(self) : Sniffer.new(self)
          @counter     = 0
          @counter_mtx = Mutex.new
          @last_request_at = Time.now
          @reload_connections = options[:reload_connections]
          @reload_after    = options[:reload_connections].is_a?(Integer) ? options[:reload_connections] : DEFAULT_RELOAD_AFTER
          @resurrect_after = options[:resurrect_after] || DEFAULT_RESURRECT_AFTER
          @retry_on_status = Array(options[:retry_on_status]).map(&:to_i)
        end

        # Returns a connection from the connection pool by delegating to {Connections::Collection#get_connection}.
        #
        # Resurrects dead connection if the `resurrect_after` timeout has passed.
        # Increments the counter and performs connection reloading if the `reload_connections` option is set.
        #
        # @return [Connections::Connection]
        # @see    Connections::Collection#get_connection
        #
        def get_connection(options = {})
          __refresh_node_trust!
          resurrect_dead_connections! if Time.now > @last_request_at + @resurrect_after

          @counter_mtx.synchronize { @counter += 1 }
          reload_connections! if reload_connections && (counter % reload_after).zero?
          connections.get_connection(options)
        end

        # Reconciles the pool with the currently approved per-node trust policy.
        #
        # @return [self]
        #
        def refresh_trust!
          __refresh_node_trust!(force: true)
          self
        end

        # Reloads and replaces the connection collection based on cluster information
        #
        # @see Sniffer#hosts
        #
        def reload_connections!
          hosts = sniffer.hosts
          __rebuild_connections(hosts: hosts, options: options)
          self
        rescue SnifferTimeoutError
          log_error('[SnifferTimeoutError] Timeout when reloading connections.')
          self
        end

        # Tries to "resurrect" all eligible dead connections
        #
        # @see Connections::Connection#resurrect!
        #
        def resurrect_dead_connections!
          return connections.dead.each(&:resurrect!) unless @node_trust.configured?

          entries = @node_trust.entries(force: true)
          @state_mutex.synchronize do
            connections.dead.each do |connection|
              next if connection.retired?

              entry = @node_trust.entry_for(connection.host, entries)
              current = entry&.version
              # A policy that no longer lists the node isn't an approval to fall back to whatever
              # the transport trusts by default; keep the last approved settings in that case.
              connection.mark_stale! if entry && (connection.stale? || connection.trust_version != current)
              next unless connection.resurrectable?

              if connection.stale?
                # The certificate generation changed while the node was dead. Don't let the old
                # connection rejoin: build one with the trust policy that is effective now.
                replacement = __build_connection_for(connection.host, entries)
                replacement.trust!(current)
                replacement.alive!
                __archive_stale(connection)
                # Replacement keeps the node's position, so round-robin order doesn't shift when
                # one dead node comes back after a certificate change.
                @connections.replace(connection, replacement)
              else
                connection.resurrect!
              end
            end
          end
        end

        # Rebuilds the connections collection in the transport.
        #
        # The methods *adds* new connections from the passed hosts to the collection,
        # and *removes* all connections not contained in the passed hosts.
        #
        # @return [Connections::Collection]
        # @api private
        #
        def __rebuild_connections(arguments = {})
          @state_mutex.synchronize do
            @hosts       = arguments[:hosts]    || []
            @options     = arguments[:options]  || {}

            __close_connections

            # Re-check the policy before rebuilding (the throttled request-path check may be
            # fresh but stale), then build through __build_connections, which Manticore overrides.
            @node_trust.entries(force: true) if @node_trust.configured?
            desired = __build_connections.all
            former = @connections.all
            removed = former.reject { |connection| desired.any? { |new_connection| new_connection == connection } }
            removed.each do |connection|
              # A node that left the cluster is retired, which is a different state from a failure.
              connection.retire!
              unless @retired_connections.include?(connection)
                @retired_connections << connection
                @retired_connections.shift while @retired_connections.size > MAX_RETIRED_CONNECTIONS
              end
            end

            ordered = desired.map do |new_connection|
              old = former.find { |connection| connection == new_connection }
              if old && !old.retired? && old.trust_version == new_connection.trust_version
                next old
              end
              __archive_stale(old) if old

              retired = @retired_connections.find { |connection| connection == new_connection }
              if retired
                @retired_connections.delete(retired)
                if retired.trust_version == new_connection.trust_version
                  # The node was removed and came back with the same approved trust generation.
                  next retired.revive!
                end
                # The node came back with a new certificate while it was gone.
                __archive_stale(retired)
              end

              new_connection
            end

            # The selector holds the collection, not its list, so replacing the list keeps custom
            # selectors working and restores the sniffer's node order.
            @connections.replace_all(ordered)
            @connections
          end
        end

        # Builds and returns a collection of connections
        #
        # The adapters have to implement the {Base#__build_connection} method.
        #
        # @return [Connections::Collection]
        # @api    private
        #
        def __build_connections
          Connections::Collection.new(
            connections: __connections_from_host,
            selector_class: options[:selector_class],
            selector: options[:selector]
          )
        end

        # Helper function: Maps over hosts, sets protocol, port and user/password and builds connections
        #
        # @return [Array<Connection>
        # @api    private
        #
        def __connections_from_host
          entries = @node_trust.entries
          hosts.map do |host|
            host[:protocol] = host[:scheme] || options[:scheme] || options[:http][:scheme] || DEFAULT_PROTOCOL
            host[:port] ||= options[:port] || options[:http][:port] || DEFAULT_PORT
            if (options[:user] || options[:http][:user]) && !host[:user]
              host[:user] ||= options[:user] || options[:http][:user]
              host[:password] ||= options[:password] || options[:http][:password]
            end

            # Hosts added after the pin (reload, sniffing) would otherwise get no protection
            raise Error, 'CA fingerprinting can\'t be configured over http' if @ca_file && host[:protocol] != 'https'

            if @node_trust.configured? && __node_trust_uses_ca?(host, entries) && host[:protocol] != 'https'
              raise Error, 'node_trust with certificate authorities can\'t be configured over http'
            end

            connection = __build_connection(host, __connection_options_for(host, entries), @block)
            connection.trust!(@node_trust.entry_for(host, entries)&.version)
            connection
          end
        end

        # @abstract Build and return a connection.
        #           A transport implementation *must* implement this method.
        #           See {HTTP::Faraday#__build_connection} for an example.
        #
        # @return [Connections::Connection]
        # @api    private
        #
        def __build_connection(host, options = {}, block = nil)
          raise NoMethodError, 'Implement this method in your class'
        end

        # Closes the connections collection
        #
        # @api private
        #
        def __close_connections
          # A hook point for specific adapters when they need to close connections
        end

        # Log request and response information
        #
        # @api private
        #
        def __log_response(method, path, params, body, url, response, json, took, duration)
          if logger
            sanitized_url = sanitize_url(url.to_s)
            log_info "#{method.to_s.upcase} #{sanitized_url} " +
                         "[status:#{response.status}, request:#{sprintf('%.3fs', duration)}, query:#{took}]"
            log_debug "> #{__convert_to_json(body)}" if body
            log_debug "< #{response.body}"
          end
        end

        # Trace the request in the `curl` format
        #
        # @api private
        #
        def __trace(method, path, params, headers, body, url, response, json, took, duration)
          trace_url  = "http://localhost:9200/#{path}?pretty" +
              (params.empty? ? '' : "&#{::Faraday::Utils::ParamsHash[params].to_query}")
          trace_body = body ? " -d '#{__convert_to_json(body, :pretty => true)}'" : ''
          trace_command = "curl -X #{method.to_s.upcase}"
          trace_command += " -H '#{headers.collect { |k, v| "#{k}: #{v}" }.join(", ")}'" if headers && !headers.empty?
          trace_command += " '#{trace_url}'#{trace_body}\n"
          tracer.info trace_command
          tracer.debug "# #{Time.now.iso8601} [#{response.status}] (#{format('%.3f', duration)}s)\n#"
          tracer.debug json ? serializer.dump(json, pretty: true).gsub(/^/, '# ').sub(/\}$/, "\n# }")+"\n" : "# #{response.body}\n"
        end

        # Raise error specific for the HTTP response status or a generic server error
        #
        # @api private
        #
        def __raise_transport_error(response)
          error = ERRORS[response.status] || ServerError
          message = "[#{response.status}] #{response.body}"
          capture_otel_error_attributes(message)
          raise error.new message
        end

        # Converts any non-String object to JSON
        #
        # @api private
        #
        def __convert_to_json(obj = nil, options = {})
          obj.is_a?(String) ? obj : serializer.dump(obj, options)
        end

        # Returns a full URL based on information from host
        #
        # @param host [Hash] Host configuration passed in from {Client}
        #
        # @api private
        def __full_url(host)
          url  = "#{host[:protocol]}://"
          url += "#{CGI.escape(host[:user])}:#{CGI.escape(host[:password])}@" if host[:user]
          url += host[:host]
          url += ":#{host[:port]}" if host[:port]
          url += host[:path] if host[:path]
          url
        end

        # Performs a request to Elasticsearch, while handling logging, tracing, marking dead connections,
        # retrying the request and reloading the connections.
        #
        # @abstract The transport implementation has to implement this method either in full,
        #           or by invoking this method with a block. See {HTTP::Faraday#perform_request} for an example.
        #
        # @param method [String] Request method
        # @param path   [String] The API endpoint
        # @param params [Hash]   Request parameters (will be serialized by {Connections::Connection#full_url})
        # @param body   [Hash]   Request body (will be serialized by the {#serializer})
        # @param headers [Hash]   Request headers (will be serialized by the {#serializer})
        # @param block  [Proc]   Code block to evaluate, passed from the implementation
        #
        # @return [Response]
        # @raise  [NoMethodError] If no block is passed
        # @raise  [ServerError]   If request failed on server
        # @raise  [Error]         If no connection is available
        #
        def perform_request(method, path, params = {}, body = nil, headers = nil, opts = {}, &block)
          raise NoMethodError, 'Implement this method in your transport class' unless block_given?

          pin_ca_certificate! if options[:ca_fingerprint]
          start = Time.now
          tries = 0
          reload_on_failure = opts.fetch(:reload_on_failure, @options[:reload_on_failure])
          delay_on_retry = opts.fetch(:delay_on_retry, @options[:delay_on_retry])
          max_retries = max_retries(opts) || max_retries(options)
          params = params.clone
          # Transforms ignore status codes to Integer
          ignore = Array(params.delete(:ignore)).compact.map(&:to_i)

          begin
            sleep(delay_on_retry / 1000.0) if tries > 0
            tries += 1
            connection = get_connection or raise Error.new('Cannot get new connection from pool.')

            if connection.connection.respond_to?(:params) &&
               connection.connection.params.respond_to?(:to_hash)
              params = connection.connection.params.merge(params.to_hash)
            end

            url = connection.full_url(path, params)
            response = block.call(connection, url)
            connection.healthy! if connection.failures.positive?

            # Raise an exception so we can catch it for `retry_on_status`
            __raise_transport_error(response) if response.status.to_i >= 300 &&
                                                 @retry_on_status.include?(response.status.to_i)
          rescue Elastic::Transport::Transport::ServerError => e
            raise e unless response && @retry_on_status.include?(response.status)

            log_warn "[#{e.class}] Attempt #{tries} to get response from #{url}"
            if tries <= (max_retries || DEFAULT_MAX_RETRIES)
              retry
            else
              message = "[#{e.class}] Cannot get response from #{url} after #{tries} tries"
              log_fatal(message)
              capture_otel_error_attributes(message)
              raise e
            end
          rescue *host_unreachable_exceptions => e
            log_error "[#{e.class}] #{e.message} #{connection.host.inspect}"

            connection.dead!

            if reload_on_failure && tries < connections.all.size
              log_warn "[#{e.class}] Reloading connections (attempt #{tries} of #{connections.all.size})"
              reload_connections! and retry
            end

            exception = Elastic::Transport::Transport::Error.new(e.message)

            unless max_retries
              capture_otel_error_attributes(exception.message)
              raise exception
            end

            log_warn "[#{e.class}] Attempt #{tries} connecting to #{connection.host.inspect}"
            if tries <= max_retries
              retry
            else
              message = "[#{e.class}] Cannot connect to #{connection.host.inspect} after #{tries} tries"
              log_fatal(message)
              capture_otel_error_attributes(message)
              raise exception
            end
          rescue Exception => e
            message = "[#{e.class}] #{e.message} (#{connection.host.inspect if connection})"
            log_fatal message
            capture_otel_error_attributes(message)
            raise e
          end #/begin

          duration = Time.now - start

          if response.status.to_i >= 300
            __log_response(method, path, params, body, url, response, nil, 'N/A', duration)
            __trace(method, path, params, connection_headers(connection), body, url, response, nil, 'N/A', duration) if tracer

            # Log the failure only when `ignore` doesn't match the response status
            log_fatal("[#{response.status}] #{response.body}") unless ignore.include?(response.status.to_i)
            __raise_transport_error response unless ignore.include?(response.status.to_i)
          end

          if response.body &&
             !response.body.empty? &&
             response.headers &&
             response.headers['content-type'] =~ /json/
            json = serializer.load(response.body)
          end
          took = (json['took'] ? sprintf('%.3fs', json['took'] / 1000.0) : 'n/a') rescue 'n/a'
          __log_response(method, path, params, body, url, response, json, took, duration) unless ignore.include?(response.status.to_i)
          __trace(method, path, params, connection_headers(connection), body, url, response, nil, 'N/A', duration) if tracer
          log_warn(response.headers['warning']) if response.headers&.[]('warning')

          if opentelemetry? && response.status
            ::OpenTelemetry::Trace.current_span&.set_attribute('db.response.status_code', response.status)
          end

          Response.new response.status, json || response.body, response.headers
        ensure
          @last_request_at = Time.now
        end

        # @abstract Returns an Array of connection errors specific to the transport implementation.
        #           See {HTTP::Faraday#host_unreachable_exceptions} for an example.
        #
        # @return [Array]
        #
        def host_unreachable_exceptions
          [Errno::ECONNREFUSED]
        end

        private

        # Every entry must carry a trust anchor. An entry with only verification switches would
        # quietly use the host's default trust store while looking like an approved node policy.
        #
        def __validate_node_trust!
          @node_trust.entries.each_pair do |key, entry|
            next if entry.trust_material?

            raise ArgumentError,
                  "node_trust for #{key.inspect} has no trust anchor; " \
                  'pass :ca_file, :ca_path or :cert_store'
          end
        end

        # @return [Object, nil] The raw per-node trust policy passed to the transport.
        #
        def __node_trust_policy(arguments)
          return arguments[NODE_TRUST_OPTION] if arguments.key?(NODE_TRUST_OPTION)

          @options[NODE_TRUST_OPTION]
        end

        # Merges the node's approved SSL settings into a copy of the transport options.
        #
        # @return [Hash]
        #
        def __connection_options_for(host, entries = @node_trust.entries)
          base = options[:transport_options] || {}
          ssl = @node_trust.ssl_for(host, entries)
          return base if ssl.nil? || ssl.empty?

          unsupported = ssl.keys - __supported_node_trust_keys
          if unsupported.any?
            raise ArgumentError,
                  "#{self.class.name} can't apply #{unsupported.join(', ')} per node; use :ca_file or :ca_path"
          end
          inherited = base[:ssl] || {}
          # A node with its own trust anchor must not also trust the transport-wide one.
          if (ssl.keys & NodeTrust::TRUST_KEYS).any?
            inherited = inherited.reject { |key, _| NodeTrust::TRUST_KEYS.include?(key) }
          end
          if ssl.key?(:verify_hostname) && !__verify_hostname_supported?
            raise ArgumentError, "#{self.class.name} can't apply :verify_hostname per node"
          end
          base.merge(ssl: inherited.merge(ssl))
        end

        # SSL settings the adapter can apply to an individual connection.
        #
        # @api private
        #
        def __supported_node_trust_keys
          NodeTrust::TRUST_KEYS + NodeTrust::VERIFY_KEYS
        end

        # Whether the adapter can verify host names together with the other SSL settings picked
        # here. Faraday 1 has no `verify_hostname` option, so setting it would fail inside Faraday.
        #
        def __verify_hostname_supported?
          true
        end

        # Whether the node's approved settings include a certificate authority. A policy that only
        # changes verification switches doesn't turn http into https.
        #
        def __node_trust_uses_ca?(host, entries)
          ssl = @node_trust.ssl_for(host, entries)
          ssl && (ssl.keys & NodeTrust::TRUST_KEYS).any?
        end

        # @return [Connections::Connection]
        #
        def __build_connection_for(host, entries = @node_trust.entries)
          __build_connection(host, __connection_options_for(host, entries), @block)
        end

        # Reconciles connections with the currently approved trust policy.
        #
        # A live connection whose node now has a different certificate generation is replaced
        # immediately with a connection that uses the new trust material. A dead connection is only
        # marked stale here; it is rebuilt with the current policy when it is due to resurrect.
        #
        def __refresh_node_trust!(force: false)
          return unless @node_trust.configured?

          entries = @node_trust.entries(force: force)
          @state_mutex.synchronize do
            @connections.all.each do |connection|
              next if connection.retired?

              entry = @node_trust.entry_for(connection.host, entries)
              current = entry&.version
              # Without an entry the connection keeps the settings it was built with.
              next if entry.nil? || (connection.trust_version == current && !connection.stale?)

              connection.mark_stale!
              next if connection.dead?

              replacement = __build_connection_for(connection.host, entries)
              replacement.trust!(current)
              __archive_stale(connection)
              @connections.replace(connection, replacement)
            end
          end
        end

        # Archives a superseded connection without closing it: another thread may still be inside a
        # request on it. It is unreachable from the pool, so its client is released by GC once that
        # request finishes.
        def __archive_stale(connection)
          connection.mark_stale!
          unless @stale_connections.include?(connection)
            @stale_connections << connection
            # Keep the archive bounded: a long-lived client rotating certificates must not retain
            # every client it ever built. Dropped entries are released by GC.
            @stale_connections.shift while @stale_connections.size > MAX_STALE_CONNECTIONS
          end
          connection
        end

        USER_AGENT_STR = 'User-Agent'.freeze
        USER_AGENT_REGEX = /user-?_?agent/.freeze
        ACCEPT_ENCODING = 'Accept-Encoding'.freeze
        CONTENT_ENCODING = 'Content-Encoding'.freeze
        CONTENT_TYPE_STR = 'Content-Type'.freeze
        CONTENT_TYPE_REGEX = /content-?_?type/i.freeze
        DEFAULT_CONTENT_TYPE = 'application/json'.freeze
        GZIP = 'gzip'.freeze
        GZIP_FIRST_TWO_BYTES = '1f8b'.freeze
        HEX_STRING_DIRECTIVE = 'H*'.freeze
        RUBY_ENCODING = '1.9'.respond_to?(:force_encoding)

        def max_retries(opts)
          opts[:retry_on_failure] == true ? DEFAULT_MAX_RETRIES : opts[:retry_on_failure]
        end

        def compress_request(body, headers)
          if body
            headers ||= {}

            if gzipped?(body)
              headers[CONTENT_ENCODING] = GZIP
            elsif use_compression?
              headers[CONTENT_ENCODING] = GZIP
              gzip = Zlib::GzipWriter.new(StringIO.new)
              gzip << body
              body = gzip.close.string
            else
              headers.delete(CONTENT_ENCODING)
            end
          elsif headers
            headers.delete(CONTENT_ENCODING)
          end

          [body, headers]
        end

        def decompress_response(body)
          return body unless gzipped?(body)

          io = StringIO.new(body)
          gzip_reader = if RUBY_ENCODING
                          Zlib::GzipReader.new(io, encoding: 'ASCII-8BIT')
                        else
                          Zlib::GzipReader.new(io)
                        end
          gzip_reader.read
        end

        def gzipped?(body)
          return unless body && !body.empty?

          body[0..1].unpack(HEX_STRING_DIRECTIVE)[0] == GZIP_FIRST_TWO_BYTES
        end

        def use_compression?
          @compression
        end

        def apply_headers(client, options)
          headers = options[:headers].clone || {}
          headers[CONTENT_TYPE_STR] = find_value(headers, CONTENT_TYPE_REGEX) || DEFAULT_CONTENT_TYPE
          headers[USER_AGENT_STR] = find_value(headers, USER_AGENT_REGEX) || user_agent_header(client)
          client.headers[ACCEPT_ENCODING] = GZIP if use_compression?
          client.headers.merge!(headers)
        end

        def find_value(hash, regex)
          key_value = hash.find { |k, _| k.to_s.downcase =~ regex }
          if key_value
            hash.delete(key_value[0])
            key_value[1]
          end
        end

        def user_agent_header(_client)
          @user_agent ||= begin
            meta = ["RUBY_VERSION: #{RUBY_VERSION}"]
            if RbConfig::CONFIG && RbConfig::CONFIG['host_os']
              meta << "#{RbConfig::CONFIG['host_os'].split('_').first[/[a-z]+/i].downcase} #{RbConfig::CONFIG['target_cpu']}"
            end
            "elastic-transport-ruby/#{VERSION} (#{meta.join('; ')})"
          end
        end

        def connection_headers(connection)
          if defined?(Elastic::Transport::Transport::HTTP::Manticore) &&
             instance_of?(Elastic::Transport::Transport::HTTP::Manticore)
            @request_options[:headers]
          else
            connection.connection.headers
          end
        end

        def sanitize_url(url)
          url.to_s.gsub(/\/\/(.+):(.+)@/, '//' + '\1:' + SANITIZED_PASSWORD + '@')
        end

        def opentelemetry?
          defined?(::OpenTelemetry)
        end

        def capture_otel_span_attributes(connection, url)
          if opentelemetry?
            ::OpenTelemetry::Trace.current_span&.set_attribute('url.full', sanitize_url(url))
            ::OpenTelemetry::Trace.current_span&.set_attribute('server.address', connection.host[:host])
            ::OpenTelemetry::Trace.current_span&.set_attribute('server.port', connection.host[:port].to_i)
          end
        end

        def capture_otel_error_attributes(error)
          if opentelemetry?
            ::OpenTelemetry::Trace.current_span&.set_attribute('error.type', error)
          end
        end
      end
    end
  end
end
