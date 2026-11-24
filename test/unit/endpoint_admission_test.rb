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

# Records the final URL Faraday actually sends, through Faraday's middleware instrumentation interface.
#
class UrlRecorder < Faraday::Middleware
  # One recorder per service, so the request logs of the two services behind the shared domain stay separate.
  #
  def self.registries
    @registries ||= Hash.new { |hash, key| hash[key] = [] }
  end

  def initialize(app, service = nil)
    super(app)
    @service = service
  end

  def on_complete(env)
    UrlRecorder.registries[@service] << env.url.to_s
  end
end

class Elastic::Transport::Transport::EndpointAdmissionTest < Minitest::Test
  SHARED_HOST = 'shared.example.com'.freeze
  PORT = 9200
  SERVICE_A = "http://#{SHARED_HOST}:#{PORT}/service-a".freeze
  SERVICE_A_V2 = "http://#{SHARED_HOST}:#{PORT}/service-a-v2".freeze
  SERVICE_B = "http://#{SHARED_HOST}:#{PORT}/service-b".freeze

  def setup
    UrlRecorder.registries.clear
  end

  def build_client(hosts, allowed_endpoints, extra_options = {})
    service = extra_options.delete(:service)
    Elastic::Transport::Client.new(
      {
        hosts: Array(hosts),
        allowed_endpoints: Array(allowed_endpoints),
        adapter: :test
      }.merge(extra_options)
    ) do |connection|
      connection.use(UrlRecorder, service)
    end
  end

  # Reaches the Stubs object of the in-process Faraday test adapter for a connection.
  #
  def stubs(connection)
    connection.connection.builder.app.app.instance_variable_get(:@stubs)
  end

  context 'allowed_endpoints' do
    should 'send a request through the explicitly approved proxy path and record its final URL' do
      client = build_client(SERVICE_A, SERVICE_A, service: :service_a)
      stubs(client.transport.connections.first).get('/service-a/_search') { [200, {}, '{}'] }

      response = client.perform_request('GET', '/_search')

      assert_equal 200, response.status
      assert_equal ['http://shared.example.com:9200/service-a/_search'],
                   UrlRecorder.registries[:service_a]
    end

    should 're-select an approved second entry after the first entry fails to connect' do
      client = build_client(
        [SERVICE_A, SERVICE_A_V2],
        [SERVICE_A, SERVICE_A_V2],
        retry_on_failure: 2,
        service: :service_a
      )

      client.transport.connections.all.each do |connection|
        if connection.host[:path] == '/service-a'
          stubs(connection).get(//) { raise Faraday::ConnectionFailed, 'entry moved' }
        else
          stubs(connection).get(//) { [200, {}, '{}'] }
        end
      end

      response = client.perform_request('GET', '/_search')

      assert_equal 200, response.status
      assert_equal ['http://shared.example.com:9200/service-a-v2/_search'],
                   UrlRecorder.registries[:service_a]
    end

    should 'refuse an unapproved target at construction without the adapter sending anything' do
      assert_raises(Elastic::Transport::Transport::EndpointAdmission::EndpointNotAllowed) do
        build_client('http://shared.example.com:9200/service-evil', SERVICE_A, service: :service_a)
      end

      assert_empty UrlRecorder.registries[:service_a]
    end

    should 'keep business requests out of the records of the other service on the shared domain' do
      search_client = build_client(SERVICE_A, SERVICE_A, service: :service_a)
      other_client = build_client(SERVICE_B, SERVICE_B, service: :service_b)

      stubs(search_client.transport.connections.first).get('/service-a/_search') { [200, {}, '{}'] }
      stubs(other_client.transport.connections.first).get('/service-b/_search') { [200, {}, '{}'] }

      search_client.perform_request('GET', '/_search')

      assert_equal ['http://shared.example.com:9200/service-a/_search'],
                   UrlRecorder.registries[:service_a]
      assert_empty UrlRecorder.registries[:service_b]
    end

    should 'block a request-time URL that escapes the approved prefix before it is sent' do
      client = build_client(SERVICE_A, SERVICE_A, service: :service_a)
      transport = client.transport
      connection = transport.connections.first
      connection.host[:path] = '/service-evil'

      assert_raises(Elastic::Transport::Transport::EndpointAdmission::EndpointNotAllowed) do
        transport.perform_request('GET', '/_search')
      end
      assert_empty UrlRecorder.registries[:service_a]
    end

    should 'match on scheme, host, port and path prefix together' do
      transport = build_client(SERVICE_A, SERVICE_A).transport

      assert transport.send(:admitted?, 'http://shared.example.com:9200/service-a/_search')
      refute transport.send(:admitted?, 'https://shared.example.com:9200/service-a/_search')
      refute transport.send(:admitted?, 'http://shared.example.com:9300/service-a/_search')
      refute transport.send(:admitted?, 'http://other.example.com:9200/service-a/_search')
      # A prefix must end at a path segment, so /service-a can't reach /service-abusive
      refute transport.send(:admitted?, 'http://shared.example.com:9200/service-abusive/_search')
    end

    should 'accept a host without a proxy path and an entry given as a URI or Hash' do
      transport = build_client(
        'http://shared.example.com:9200',
        [
          URI.parse('http://shared.example.com:9200/'),
          { scheme: 'http', host: 'shared.example.com', port: 9200 }
        ]
      ).transport

      assert transport.send(:admitted?, 'http://shared.example.com:9200/_search')
    end

    should 'raise ArgumentError for a malformed allowed_endpoints entry' do
      assert_raises(ArgumentError) do
        build_client(SERVICE_A, '/relative-path')
      end
      assert_raises(ArgumentError) do
        build_client(SERVICE_A, [{ port: 9200 }])
      end
      assert_raises(ArgumentError) do
        build_client(SERVICE_A, [1234])
      end
    end

    should 'fail closed when allowed_endpoints is an empty list' do
      assert_raises(Elastic::Transport::Transport::EndpointAdmission::EndpointNotAllowed) do
        build_client(SERVICE_A, [])
      end
    end

    should 'not allow allowed_endpoints together with a custom transport instance' do
      custom = Object.new
      assert_raises(ArgumentError) do
        Elastic::Transport::Client.new(
          hosts: SERVICE_A,
          allowed_endpoints: [SERVICE_A],
          transport: custom
        )
      end
    end
  end
end
