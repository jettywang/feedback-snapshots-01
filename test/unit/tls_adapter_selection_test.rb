# frozen_string_literal: true

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

require 'test_helper'
require 'fileutils'
require 'openssl'
require 'tempfile'

unless JRUBY
  class TlsCurbEasyDouble
    attr_accessor :url, :cacert, :headers, :put_data, :ca_path, :cert_store,
                  :ssl_verify_peer, :ssl_verify_host

    def initialize
      @headers = {}
      @ssl_verify_peer = true
      @ssl_verify_host = 2
    end

    def set(key, value)
      headers[key] = value
    end

    def ssl_verify_peer?
      !!@ssl_verify_peer
    end

    def ssl_verify_host?
      @ssl_verify_host.to_i != 0
    end

    def http(_verb); end

    def header_str
      "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 11\r\n\r\n"
    end

    def response_code
      200
    end

    def body_str
      '{"ok":true}'
    end
  end

  begin
    require 'curb'
  rescue LoadError
    module Curl
      CURB_VERSION = '0.0-tls-selection-double'.freeze

      Easy = ::TlsCurbEasyDouble

      module Err
        class HostResolutionError < StandardError; end
        class ConnectionFailedError < StandardError; end
        class GotNothingError < StandardError; end
        class RecvError < StandardError; end
        class SendError < StandardError; end
        class TimeoutError < StandardError; end
      end
    end
  end

  require 'elastic/transport/transport/http/curb'
end

module Elastic
  module Transport
    class TlsCallResponse < Struct.new(:status, :body, :headers); end

    module TlsSelectionExamples
      HOST_A = 'a.tls-selection.invalid'
      HOST_B = 'b.tls-selection.invalid'
      PORT = 9443

      def setup
        @tempfiles = []
        @tempdirs = []
        @calls = []
        @rebuilt = []
        @scripts = {}
        @curb_handles = []
        setup_curb_constructor if adapter == :curb
      end

      def teardown
        @tempfiles.each { |file| file.close! rescue nil }
        @tempdirs.each { |dir| FileUtils.remove_entry(dir) rescue nil }
        super
      end

      def test_default_trust_reaches_the_real_adapter_and_records_url_and_instance
        ssl = default_ssl
        transport = build_transport(ssl: ssl, hosts: [host_a])
        handle = transport.connections.first.connection

        assert_trust_options(handle, ssl, stage: 'initial adapter construction')

        response = transport.perform_request('GET', '_search', { q: 'default-ca' })

        assert_equal 200, response.status
        assert_equal 1, @calls.size
        call = @calls.first
        assert_equal :get, call[:method]
        assert_equal "https://#{HOST_A}:#{PORT}/_search?q=default-ca", call[:url]
        assert_same handle, call[:adapter]
        assert_same current_handle(transport), call[:adapter]
        assert_trust_options(call[:adapter], ssl, stage: 'request adapter instance')
      end

      def test_default_then_explicit_override_rebuilds_same_address_and_uses_new_instance
        default = default_ssl
        explicit = explicit_ssl
        transport = build_transport(ssl: default, hosts: [host_a])
        original = transport.connections.first.connection

        default_response = transport.perform_request('GET', '_search', { q: 'default-ca' })
        assert_equal 200, default_response.status
        default_call = @calls.first
        assert_same original, default_call[:adapter]
        assert_equal "https://#{HOST_A}:#{PORT}/_search?q=default-ca", default_call[:url]
        assert_trust_options(original, default, stage: 'legitimate default connection')

        transport.options[:transport_options] = { ssl: explicit }
        discovery_host = host_a
        transport.sniffer.define_singleton_method(:hosts) { [discovery_host] }
        transport.reload_connections!

        assert_equal 1, @rebuilt.size
        replacement = @rebuilt.first[:wrapper].connection
        assert_trust_options(replacement, explicit, stage: 'discovery rebuild construction')

        response = transport.perform_request('GET', '_doc/1', { refresh: true })

        assert_equal 200, response.status
        assert_equal 2, @calls.size
        override_call = @calls.last
        assert_equal "https://#{HOST_A}:#{PORT}/_doc/1?refresh=true", override_call[:url]
        assert_same replacement, override_call[:adapter]
        refute_same original, override_call[:adapter]
        assert_same current_handle(transport), override_call[:adapter]
        assert_trust_options(override_call[:adapter], explicit, stage: 'explicit override request instance')
      end

      def test_failure_reselects_another_node_and_discovery_rebuild_records_trust
        ssl = explicit_ssl
        transport = build_transport(ssl: ssl, hosts: [host_a, host_b])
        handle_a = transport.connections[0].connection
        handle_b = transport.connections[1].connection
        fail_next_call(handle_a)
        discovery_hosts = [host_a, host_b]

        transport.sniffer.define_singleton_method(:hosts) { discovery_hosts }
        response = transport.perform_request('GET', '_search', { q: 'reselect' })

        assert_equal 200, response.status
        assert_equal 2, @calls.size

        failed_call, selected_call = @calls
        assert_same handle_a, failed_call[:adapter]
        assert_equal "https://#{HOST_A}:#{PORT}/_search?q=reselect", failed_call[:url]

        assert_same handle_b, selected_call[:adapter]
        assert_equal "https://#{HOST_B}:#{PORT}/_search?q=reselect", selected_call[:url]
        assert_same current_handle(transport), selected_call[:adapter]
        assert_trust_options(selected_call[:adapter], ssl, stage: 'failover request instance')

        assert_equal 2, @rebuilt.size
        @rebuilt.each do |record|
          assert_trust_options(
            record[:wrapper].connection,
            ssl,
            stage: "discovery rebuild for #{record[:host][:host]}"
          )
        end

        # Equal host wrappers are retained, so the successful failover still uses the original B handle.
        refute_includes @rebuilt.map { |record| record[:wrapper].connection }, selected_call[:adapter]
      end

      def test_resurrected_dead_node_uses_its_original_trust_and_url
        ssl = explicit_ssl
        transport = build_transport(ssl: ssl, hosts: [host_a])
        connection = transport.connections.first
        handle = connection.connection
        connection.dead!
        connection.define_singleton_method(:resurrectable?) { true }

        transport.resurrect_dead_connections!

        refute_predicate connection, :dead?
        response = transport.perform_request('GET', '_cat/nodes')

        assert_equal 200, response.status
        call = @calls.last
        assert_same handle, call[:adapter]
        assert_equal "https://#{HOST_A}:#{PORT}/_cat/nodes", call[:url]
        assert_same current_handle(transport), call[:adapter]
        assert_trust_options(call[:adapter], ssl, stage: 'resurrected request instance')
      end

      def test_verification_disable_override_is_observable_at_adapter_boundary
        ssl = { verify: false }
        ssl[:verify_hostname] = false if adapter == :curb || faraday_hostname_option?
        transport = build_transport(ssl: ssl, hosts: [host_a])
        handle = transport.connections.first.connection

        assert_trust_options(handle, ssl, stage: 'verification override construction')
        transport.perform_request('GET', '/')

        assert_trust_options(@calls.first[:adapter], ssl, stage: 'verification override request')
        assert_equal "https://#{HOST_A}:#{PORT}/", @calls.first[:url]
      end

      def test_hostname_only_override_is_observable_at_adapter_boundary
        ssl = { verify: true }
        ssl[:verify_hostname] = false if adapter == :curb || faraday_hostname_option?
        transport = build_transport(ssl: ssl, hosts: [host_a])
        handle = transport.connections.first.connection

        assert_trust_options(handle, ssl, stage: 'hostname override construction')
        transport.perform_request('GET', '/')

        assert_trust_options(@calls.first[:adapter], ssl, stage: 'hostname override request')
      end

      private

      def adapter
        raise NotImplementedError
      end

      def adapter_class
        case adapter
        when :faraday
          Elastic::Transport::Transport::HTTP::Faraday
        when :curb
          Elastic::Transport::Transport::HTTP::Curb
        else
          raise ArgumentError, "Unknown adapter #{adapter}"
        end
      end

      def setup_curb_constructor
        @curb_handles = Array.new(8) { TlsCurbEasyDouble.new }
        Curl::Easy.stubs(:new).returns(*@curb_handles)
      end

      def build_transport(ssl:, hosts:, options: {})
        arguments = {
          reload_on_failure: true,
          retry_on_failure: 1,
          http: { scheme: 'https' },
          transport_options: { ssl: ssl }
        }.merge(options)

        transport = adapter_class.new(hosts: hosts.map(&:dup), options: arguments)
        instrument_transport(transport)
        transport
      end

      def instrument_transport(transport)
        test = self

        transport.define_singleton_method(:__build_connection) do |host, build_options = {}, block = nil|
          wrapper = super(host, build_options, block)
          test.send(:record_rebuilt_connection, wrapper, host, build_options)
          test.send(:instrument_handle, wrapper.connection)
          wrapper
        end

        transport.connections.all.each do |wrapper|
          instrument_handle(wrapper.connection)
        end
      end

      def record_rebuilt_connection(wrapper, host, options)
        @rebuilt << { wrapper: wrapper, host: host, options: options }
      end

      def instrument_handle(handle)
        @scripts[handle.object_id] ||= []
        test = self

        case adapter
        when :faraday
          handle.define_singleton_method(:run_request) do |method, url, body, headers|
            test.send(:dispatch_faraday_call, self, method, url, body, headers)
          end
        when :curb
          handle.define_singleton_method(:http) do |verb|
            test.send(:dispatch_curb_call, self, verb)
          end
          handle.define_singleton_method(:header_str) do
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 11\r\n\r\n"
          end
          handle.define_singleton_method(:response_code) { 200 }
          handle.define_singleton_method(:body_str) { '{"ok":true}' }
        end
      end

      def fail_next_call(handle)
        @scripts[handle.object_id] << :failure
      end

      def dispatch_faraday_call(handle, method, url, body, headers)
        record_call(handle, method, url, body: body, headers: headers)
        if next_action(handle) == :failure
          raise ::Faraday::ConnectionFailed.new('stubbed unreachable TLS selection node')
        end

        TlsCallResponse.new(200, '{"ok":true}', { 'content-type' => 'application/json' })
      end

      def dispatch_curb_call(handle, verb)
        record_call(handle, verb, handle.url)
        if next_action(handle) == :failure
          raise ::Curl::Err::ConnectionFailedError.new('stubbed unreachable TLS selection node')
        end

        :ok
      end

      def record_call(handle, method, url, extras = {})
        @calls << {
          adapter: handle,
          method: method.to_s.downcase.to_sym,
          url: url.to_s
        }.merge(extras)
      end

      def next_action(handle)
        (@scripts[handle.object_id] ||= []).shift
      end

      def current_handle(transport)
        transport.connections.get_connection.connection
      end

      def host_a
        { scheme: 'https', host: HOST_A, port: PORT }
      end

      def host_b
        { scheme: 'https', host: HOST_B, port: PORT }
      end

      def default_ssl
        ca = certificate_authority('default')
        { verify: true, ca_file: ca[:path], cert_store: ca[:store] }
      end

      def explicit_ssl
        ca = certificate_authority('explicit')
        ca_path = Dir.mktmpdir('tls-selection-ca-path')
        @tempdirs << ca_path

        {
          verify: true,
          ca_file: ca[:path],
          ca_path: ca_path,
          cert_store: ca[:store]
        }.tap do |ssl|
          ssl[:verify_hostname] = true if faraday_hostname_option?
        end
      end

      def certificate_authority(name)
        key = OpenSSL::PKey::RSA.new(2048)
        subject = OpenSSL::X509::Name.parse("/CN=tls-selection-#{name}")
        certificate = OpenSSL::X509::Certificate.new
        certificate.version = 2
        certificate.serial = rand(2**63)
        certificate.subject = subject
        certificate.issuer = subject
        certificate.public_key = key.public_key
        certificate.not_before = Time.now - 60
        certificate.not_after = Time.now + 3600

        extensions = OpenSSL::X509::ExtensionFactory.new
        extensions.subject_certificate = certificate
        extensions.issuer_certificate = certificate
        certificate.add_extension(extensions.create_extension('basicConstraints', 'CA:TRUE', true))
        certificate.sign(key, OpenSSL::Digest::SHA256.new)

        file = Tempfile.new(["tls-selection-#{name}-ca", '.pem'])
        file.binmode
        file.write(certificate.to_pem)
        file.flush
        @tempfiles << file

        store = OpenSSL::X509::Store.new
        store.add_cert(certificate)

        { path: file.path, store: store, certificate: certificate }
      end

      def faraday_hostname_option?
        defined?(::Faraday::SSLOptions) &&
          ::Faraday::SSLOptions.members.include?(:verify_hostname)
      end

      def assert_trust_options(handle, ssl, stage:)
        case adapter
        when :faraday
          assert_faraday_trust_options(handle, ssl, stage)
        when :curb
          assert_curb_trust_options(handle, ssl, stage)
        end
      end

      def assert_faraday_trust_options(handle, ssl, stage)
        if ssl[:verify] == false
          assert_equal(false, handle.ssl.verify?, "#{stage}: Faraday verify: false was not applied")
        else
          assert_equal(
            true,
            handle.ssl.verify?,
            "#{stage}: Faraday SSL verification is not enabled"
          )
        end

        if ssl.key?(:ca_file)
          assert_equal(
            ssl[:ca_file],
            handle.ssl.ca_file,
            "#{stage}: Faraday did not receive ssl.ca_file on #{handle.class}"
          )
        end

        if ssl[:ca_path]
          assert_equal(
            ssl[:ca_path],
            handle.ssl.ca_path,
            "#{stage}: Faraday did not receive ssl.ca_path"
          )
        end

        if ssl[:cert_store]
          assert_same(
            ssl[:cert_store],
            handle.ssl.cert_store,
            "#{stage}: Faraday did not receive the configured OpenSSL cert_store"
          )
        end

        if ssl.key?(:verify_hostname) && faraday_hostname_option?
          assert_equal(
            ssl[:verify_hostname],
            handle.ssl.verify_hostname,
            "#{stage}: Faraday did not receive ssl.verify_hostname"
          )
        end
      end

      def assert_curb_trust_options(handle, ssl, stage)
        if ssl.key?(:ca_file)
          assert_equal(
            ssl[:ca_file],
            handle.cacert,
            "#{stage}: Curb did not map ssl.ca_file to Curl::Easy#cacert"
          )
        else
          assert_nil(
            handle.cacert,
            "#{stage}: expected default Curb CA selection, but a ca_file was mapped"
          )
        end

        if ssl[:verify] == false
          assert_equal(
            false,
            handle.ssl_verify_peer,
            "#{stage}: Curb did not map verify: false to ssl_verify_peer=false"
          )
          assert_equal(
            0,
            handle.ssl_verify_host,
            "#{stage}: Curb did not map verify: false to ssl_verify_host=0"
          )
        else
          refute_equal(
            false,
            handle.ssl_verify_peer,
            "#{stage}: Curb peer verification was turned off"
          )

          if ssl[:verify_hostname] == false
            assert_equal(
              0,
              handle.ssl_verify_host,
              "#{stage}: Curb did not map verify_hostname: false to ssl_verify_host=0"
            )
          else
            refute_equal(
              0,
              handle.ssl_verify_host,
              "#{stage}: Curb hostname verification was turned off"
            )
          end
        end
      end
    end

    class FaradayTlsSelectionTest < Minitest::Test
      include TlsSelectionExamples

      private

      def adapter
        :faraday
      end
    end

    unless JRUBY
      class CurbTlsSelectionTest < Minitest::Test
        include TlsSelectionExamples

        def test_curb_has_no_offline_observation_point_for_ca_path_or_cert_store
          ssl = explicit_ssl
          transport = build_transport(ssl: ssl, hosts: [host_a])
          easy = transport.connections.first.connection

          assert_equal ssl[:ca_file], easy.cacert
          assert_nil(
            easy.ca_path,
            'Observation gap: HTTP::Curb does not map ssl.ca_path to a Curl::Easy setter'
          )
          assert_nil(
            easy.cert_store,
            'Observation gap: HTTP::Curb does not map ssl.cert_store to a Curl::Easy setter'
          )
        end

        private

        def adapter
          :curb
        end
      end
    end
  end
end
