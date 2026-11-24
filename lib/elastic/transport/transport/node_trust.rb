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

require 'openssl'

module Elastic
  module Transport
    module Transport
      # Holds the trust configuration approved for individual nodes.
      #
      # Entries are keyed by node `id` or `name` (as returned by the sniffer), by `host:port`, by bare
      # host, or by `:default`. A value is either an SSL options hash or a hash with `:ssl` and an
      # optional `:version`.
      #
      # Every entry has a revision: its `:version` when given, otherwise a digest of its trust
      # material. Connections remember the revision they were built with, so a certificate update is
      # detected without relying on the node to fail a request first. Callers rotating a
      # `cert_store` in place should pass a new `:version`: the contents of a store can't be read back.
      #
      # The policy is read live, so a Hash can be updated between requests, and a lambda can return
      # the currently approved configuration.
      #
      class NodeTrust
        # How often a policy is checked for changed certificate files on the request path. Explicit
        # refreshes, sniffer rebuilds and resurrections re-read it regardless.
        DEFAULT_REFRESH_INTERVAL = 1.0

        # Trust anchors an adapter can apply to an individual connection. Manticore's truststore
        # is absent because it has a single client for every host.
        TRUST_KEYS = %i[ca_file ca_path cert_store].freeze
        # SSL options an entry may set besides a trust anchor.
        VERIFY_KEYS = %i[verify verify_hostname verify_mode].freeze
        VERIFY_OFF = [false, :none, :disable].freeze
        DEFAULT_KEY = 'default'.freeze

        Entry = Struct.new(:ssl, :version) do
          # @return [Boolean] true when the entry carries an actual trust anchor.
          def trust_material?
            ssl.keys.any? { |key| TRUST_KEYS.include?(key) }
          end
        end

        # @param policies [Hash, #call, nil] Approved trust settings, keyed by node identity, or a
        #   callable returning them.
        # @param refresh_interval [Numeric] Seconds between checks of certificate files on the
        #   request path. `0` checks on every request.
        def initialize(policies = nil, refresh_interval: DEFAULT_REFRESH_INTERVAL)
          @policies = policies
          @refresh_interval = refresh_interval.to_f
          @entries_mutex = Mutex.new
          @entries_signature = nil
          @entries_shallow = nil
          @entries_cache = {}.freeze
          @entries_checked_at = nil
        end


        # @return [Boolean] true when a policy was passed.
        #
        def configured?
          !@policies.nil?
        end

        # @param force [Boolean] Re-read the policy even if it was checked within the refresh
        #   interval.
        #
        # @return [Hash{String => Entry}] The current entries, keyed by node identity.
        #
        # A change to the policy Hash or callable result is picked up immediately. A certificate
        # file rotated on disk is detected by mtime and size, which needs at least one stat per
        # node; that check is throttled to keep it off the hot path. Callers that must see a file
        # change immediately pass `force: true` (as `Base#refresh_trust!` does).
        #
        def entries(force: false)
          raw = source
          now = Time.now
          shallow = self.class.signature(raw, stat: false)
          cached = @entries_mutex.synchronize do
            [@entries_signature, @entries_shallow, @entries_cache, @entries_checked_at]
          end

          policy_changed = cached[1] != shallow
          file_check_due = force || cached[3].nil? || (now - cached[3]) >= @refresh_interval
          return cached[2] if !policy_changed && !file_check_due

          signature = self.class.signature(raw, stat: true)
          return cached[2] if !policy_changed && !force && cached[0] == signature

          snapshot = self.class.normalize(raw).freeze
          @entries_mutex.synchronize do
            # A slower thread must not replace a snapshot built from a newer policy.
            if @entries_shallow.nil? || @entries_shallow == shallow || policy_changed
              @entries_signature = signature
              @entries_shallow = shallow
              @entries_cache = snapshot
              @entries_checked_at = now
            end
          end
          snapshot
        end

        # @param host [Hash] Host information.
        # @param entries [Hash, nil] A snapshot from {#entries}, to avoid resolving the policy repeatedly.
        #
        # @return [Entry, nil] The most specific entry for the host, or the `default` entry.
        #
        def entry_for(host, entries = self.entries)
          keys_for(host).each do |key|
            entry = entries[key]
            return entry if entry
          end
          entries[DEFAULT_KEY]
        end

        # @param host [Hash] Host information.
        #
        # @return [Hash, nil] The approved SSL options for the host, or nil when it has no entry.
        #
        def ssl_for(host, entries = self.entries)
          entry_for(host, entries)&.ssl
        end

        # @param host [Hash] Host information.
        #
        # @return [Array<String>] Identities which can refer to the host, most specific first.
        #
        def keys_for(host)
          keys = []
          keys << host[:id] if host[:id]
          keys << host[:name] if host[:name]
          keys << "#{host[:host]}:#{host[:port]}" if host[:host]
          keys << host[:host] if host[:host]
          keys.map(&:to_s).reject(&:empty?).uniq
        end

        class << self
          # Normalizes a raw policy into String-keyed {Entry} values.
          #
          # @api private
          #
          def normalize(policies)
            return {} if policies.nil?
            return {} if policies.is_a?(Hash) && policies.empty?

            unless policies.respond_to?(:each_pair)
              raise ArgumentError, 'node_trust must be a Hash of node identity => trust settings'
            end

            policies.each_pair.each_with_object({}) do |(key, value), entries|
              next if value.nil?

              entries[key.to_s] = build_entry(key, value)
            end
          end

          # Change detector for a raw policy. With `stat: true`, file-backed trust settings are
          # reduced to their path, mtime and size, so rotating a certificate on disk changes the
          # signature without reading the file. With `stat: false`, only the paths are compared,
          # which catches edits to the policy itself without touching the filesystem.
          #
          # The result is a nested Array of comparable values, so two signatures can be compared
          # with `==`.
          #
          # @api private
          #
          def signature(policies, stat: true)
            fingerprint(nil, policies, stat)
          end

          private

          # The policy is applied by the transport, which knows its adapter, so only the keys that
          # are shared by every adapter are rejected here.
          def validate_supported!(key, ssl)
            supported = TRUST_KEYS + VERIFY_KEYS
            unsupported = ssl.keys - supported
            return if unsupported.empty?

            raise ArgumentError,
                  "node_trust for #{key.inspect} has unsupported settings: #{unsupported.join(', ')}"
          end

          def fingerprint(key, value, stat)
            case value
            when Hash
              value.each_pair.map { |k, setting| [k.to_s, fingerprint(k, setting, stat)] }.sort_by(&:first)
            when Array
              value.map { |setting| fingerprint(key, setting, stat) }
            when String
              path_fingerprint(key, value, stat) || value
            when Numeric, Symbol, true, false, nil
              value.inspect
            else
              # A replaced cert_store or other object is a new trust configuration even though its
              # class name is unchanged.
              [value.class.name, value.object_id]
            end
          end

          def path_fingerprint(key, value, stat)
            return unless %i[ca_file ca_path].include?(key.to_s.to_sym)
            return [value] unless stat

            if File.directory?(value)
              [value, Dir.glob(File.join(value, '*')).sort.map { |f| [f, File.mtime(f).to_f, File.size(f)] }]
            elsif File.file?(value)
              [value, File.mtime(value).to_f, File.size(value)]
            end
          end

          def build_entry(key, value)
            unless value.respond_to?(:each_pair)
              raise ArgumentError, "Trust settings for node #{key.inspect} must be a Hash"
            end

            wrapper = value.key?(:ssl) || value.key?('ssl')
            ssl = wrapper ? (value[:ssl] || value['ssl']) : value
            version = value[:version] || value['version']

            unless ssl.respond_to?(:each_pair)
              raise ArgumentError, "SSL settings for node #{key.inspect} must be a Hash"
            end

            ssl = ssl.each_pair.each_with_object({}) do |(option, setting), normalized|
              next if option.to_s == 'version'

              normalized[option.to_sym] = setting
            end
            ssl.freeze

            validate_ssl!(key, ssl)
            validate_supported!(key, ssl)

            # An explicit version is authoritative: it is how a caller announces an approved
            # certificate generation. Without one, the material itself identifies the generation.
            Entry.new(ssl, (version || revision(ssl)).to_s).freeze
          end

          # One node may not carry two different trust anchors, and may not turn verification off.
          def validate_ssl!(key, ssl)
            anchors = ssl.keys & TRUST_KEYS
            if anchors.size > 1
              raise ArgumentError,
                    "node_trust for #{key.inspect} has more than one trust anchor: #{anchors.join(', ')}"
            end

            if VERIFY_OFF.include?(ssl[:verify])
              raise ArgumentError, "node_trust for #{key.inspect} can't disable certificate verification"
            end
          end

          # The content of the trust settings when the caller didn't name a generation.
          def revision(ssl)
            parts = ssl.keys.sort_by(&:to_s).map do |key|
              "#{key}=#{digest_value(key, ssl[key])}"
            end
            OpenSSL::Digest::SHA256.hexdigest(parts.join("\n"))
          end

          def digest_value(key, value)
            case key
            when :ca_file
              value.is_a?(String) && File.file?(value) ? OpenSSL::Digest::SHA256.file(value).hexdigest : value.inspect
            when :ca_path
              if value.is_a?(String) && File.directory?(value)
                OpenSSL::Digest::SHA256.hexdigest(Dir.glob(File.join(value, '*')).sort.map { |f| [f, File.mtime(f).to_i] }.inspect)
              else
                value.inspect
              end
            when :cert_store
              # A store's contents cannot be read back, so identity is the best available signal.
              # Pass a new :version when rotating one in place.
              "cert_store:#{value.object_id}"
            else
              value.inspect
            end
          end
        end

        private

        def source
          @policies.respond_to?(:call) ? @policies.call : @policies
        end
      end
    end
  end
end
