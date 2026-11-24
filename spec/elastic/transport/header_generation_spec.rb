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

require 'spec_helper'
require 'stringio'

module HeaderGenerationHelpers
  AUTHORIZATION_A = 'Basic c2VydmljZS1hOnNlY3JldC1h'.freeze
  PRIVATE_A = 'service-a-token-9f2c'.freeze
  PRIVATE_B = 'service-b-token-41d7'.freeze
  SIGNATURE = 'x-service-signature'.freeze
  ADAPTER_KEY = :recording_generation

  # Faraday adapter that records every request and answers with a body naming
  # the service it reached, so a response can be tied to the connection that
  # produced it.
  class RecordingAdapter < Faraday::Adapter
    Request = Struct.new(:method, :url, :headers, :body)

    class << self
      attr_accessor :requests

      def reset!
        self.requests = []
      end

      def record(env)
        requests << Request.new(env.method, env.url.to_s, env.request_headers.to_hash, env.body)
      end
    end

    def call(env)
      super
      self.class.record(env)
      service = env.url.host.include?('service-b') ? 'service-b' : 'service-a'
      save_response(env, 200, %({"service":"#{service}","path":"#{env.url.path}"}),
                    { 'Content-Type' => 'application/json' })
    end
  end
end

# End-to-end checks with two synthetic services and a recording Faraday
# adapter. Every assertion is about what the adapter received, not about an
# options hash.
RSpec.describe 'elastic-transport header generations' do
  include HeaderGenerationHelpers

  before(:all) do
    Faraday::Adapter.register_middleware(
      HeaderGenerationHelpers::ADAPTER_KEY => HeaderGenerationHelpers::RecordingAdapter
    )
  end

  after(:all) do
    if Faraday::Adapter.respond_to?(:unregister_middleware)
      Faraday::Adapter.unregister_middleware(HeaderGenerationHelpers::ADAPTER_KEY)
    end
  end

  before { recorder.reset! }
  after { recorder.reset! }

  let(:recorder) { HeaderGenerationHelpers::RecordingAdapter }
  let(:authorization) { HeaderGenerationHelpers::AUTHORIZATION_A }
  let(:private_a) { HeaderGenerationHelpers::PRIVATE_A }
  let(:private_b) { HeaderGenerationHelpers::PRIVATE_B }
  let(:signature) { HeaderGenerationHelpers::SIGNATURE }

  def build_client(arguments = {})
    Elastic::Transport::Client.new(arguments.merge(
      adapter: HeaderGenerationHelpers::ADAPTER_KEY,
      enable_meta_header: false
    ))
  end

  def headers_of(request)
    request.headers.each_with_object({}) { |(name, value), result| result[name.to_s.downcase] = value }
  end

  def rebuild(client, hosts:)
    client.transport.__rebuild_connections(hosts: hosts, options: client.transport.options)
  end

  describe 'two services sharing configuration' do
    it 'gives each service only its own private headers' do
      client_a = build_client(
        hosts: [{ host: 'service-a.test', port: 9200, scheme: 'http' }],
        transport_options: {
          headers: { 'X-Service-Token' => private_a, signature => 'sig-for-a', 'X-Trace' => 'trace-1' }
        }
      )
      client_b = build_client(
        hosts: [{ host: 'service-b.test', port: 9200, scheme: 'http' }],
        transport_options: {
          headers: { 'X-Service-Token' => private_b, signature => 'sig-for-b', 'X-Trace' => 'trace-2' }
        }
      )

      client_a.perform_request('GET', '/_cluster/health')
      client_b.perform_request('GET', '/_cluster/health')

      a = headers_of(recorder.requests[0])
      b = headers_of(recorder.requests[1])
      expect(a['x-service-token']).to eq(private_a)
      expect(a[signature]).to eq('sig-for-a')
      expect(b['x-service-token']).to eq(private_b)
      expect(b[signature]).to eq('sig-for-b')
      expect(a['x-trace']).to eq('trace-1')
      expect(b['x-trace']).to eq('trace-2')
    end

    it 'does not write the meta header into the shared options hash' do
      options = { transport_options: { headers: { 'X-Service-Token' => private_a } } }
      snapshot = Marshal.load(Marshal.dump(options))

      Elastic::Transport::Client.new(
        hosts: [{ host: 'service-a.test', port: 9200 }],
        adapter: HeaderGenerationHelpers::ADAPTER_KEY
      ).tap { |client| client.perform_request('GET', '/') }

      expect(options).to eq(snapshot)
    end

    it 'does not mutate a host hash passed by the caller' do
      host = { host: 'service-a.test', port: '9200' }
      build_client(hosts: [host])

      expect(host).to eq(host: 'service-a.test', port: '9200')
    end
  end

  describe 'node rollover' do
    it 'uses the new credentials on connections built after a rebuild' do
      client = build_client(hosts: [{ host: 'service-a-1.test', port: 9200 }])
      client.perform_request('GET', '/first')
      first_generation = client.transport.connections.first.generation

      client.transport.options[:transport_options][:headers] =
        client.transport.options[:transport_options][:headers].merge('X-Service-Token' => private_b)
      rebuild(client, hosts: [{ host: 'service-a-2.test', port: 9200 }])
      client.perform_request('GET', '/second')

      expect(headers_of(recorder.requests.last)['x-service-token']).to eq(private_b)
      expect(client.transport.connections.first.generation).not_to eq(first_generation)
    end

    it 'replaces a connection whose private headers changed' do
      client = build_client(hosts: [{ host: 'service-a-1.test', port: 9200 }])
      old_connection = client.transport.connections.first

      client.transport.options[:transport_options][:headers] =
        client.transport.options[:transport_options][:headers].merge('X-Service-Token' => private_b)
      rebuild(client, hosts: [{ host: 'service-a-1.test', port: 9200 }])

      new_connection = client.transport.connections.first
      expect(new_connection).not_to be(old_connection)
      expect(new_connection.headers['X-Service-Token']).to eq(private_b)
    end

    it 'leaves an in-flight request on the header snapshot of its connection' do
      client = build_client(
        hosts: [{ host: 'service-a-1.test', port: 9200 }],
        transport_options: { headers: { 'X-Service-Token' => private_a } }
      )
      held = client.transport.connections.first

      client.transport.options[:transport_options][:headers] =
        client.transport.options[:transport_options][:headers].merge('X-Service-Token' => private_b)
      rebuild(client, hosts: [{ host: 'service-a-2.test', port: 9200 }])

      expect(client.transport.request_headers_for_attempt(held, {})['X-Service-Token']).to eq(private_a)
    end
  end

  describe 'protocol retries and resurrection' do
    it 'keeps a node in service when its protocol changes' do
      client = build_client(
        hosts: [{ host: 'service-a-1.test', port: 9200, scheme: 'http' }],
        transport_options: { headers: { 'X-Service-Token' => private_a } }
      )
      client.perform_request('GET', '/http')

      rebuild(client, hosts: [{ host: 'service-a-1.test', port: 9200, scheme: 'https' }])
      client.perform_request('GET', '/https')

      expect(recorder.requests.last.url).to start_with('https://')
      expect(headers_of(recorder.requests.last)['x-service-token']).to eq(private_a)
    end

    it 'resurrects a dead node with the current credential profile' do
      client = build_client(hosts: [{ host: 'service-a-1.test', port: 9200 }])
      connection = client.transport.connections.first
      connection.dead!
      connection.instance_variable_set(:@dead_since, Time.now - 10_000)

      client.transport.options[:transport_options][:headers] =
        client.transport.options[:transport_options][:headers].merge('X-Service-Token' => private_b)
      rebuild(client, hosts: [{ host: 'service-a-1.test', port: 9200 }])
      client.transport.resurrect_dead_connections!
      client.perform_request('GET', '/after-resurrect')

      expect(headers_of(recorder.requests.last)['x-service-token']).to eq(private_b)
    end
  end

  describe 'request-scoped private headers' do
    it 'withholds them from a host that is not approved, and keeps that host usable' do
      client = build_client(
        hosts: [
          { host: 'service-a.test', port: 9200 },
          { host: 'service-b.test', port: 9200 }
        ],
        approved_hosts: ['service-a.test:9200'],
        transport_options: { headers: { 'X-Service-Token' => private_a } }
      )
      selector = Elastic::Transport::Transport::Connections::Selector::RoundRobin.new(
        connections: client.transport.connections
      )
      client.transport.connections.instance_variable_set(:@selector, selector)

      4.times { |i| client.perform_request('GET', "/req-#{i}") }

      expect(recorder.requests.size).to eq(4)
      recorder.requests.each do |request|
        headers = headers_of(request)
        if request.url.include?('service-b')
          expect(headers).not_to have_key('x-service-token')
          expect(headers).not_to have_key('authorization')
        else
          expect(headers['x-service-token']).to eq(private_a)
        end
      end
    end

    it 'withholds a private header passed per request from an unapproved host' do
      client = build_client(
        hosts: [{ host: 'service-b.test', port: 9200 }],
        approved_hosts: ['service-a.test:9200']
      )
      client.perform_request('GET', '/', {}, nil, { 'Authorization' => authorization })

      expect(headers_of(recorder.requests.last)).not_to have_key('authorization')
    end

    it 'sends a private header passed per request to an approved host' do
      client = build_client(hosts: [{ host: 'service-a.test', port: 9200 }])
      client.perform_request('GET', '/', {}, nil, { 'Authorization' => authorization })

      expect(headers_of(recorder.requests.last)['authorization']).to eq(authorization)
    end

    it 'withholds a declared-private request header from an unapproved host' do
      client = build_client(
        hosts: [{ host: 'service-b.test', port: 9200 }],
        approved_hosts: ['service-a.test:9200'],
        private_headers: ['X-Service-Signature']
      )
      client.perform_request('GET', '/', {}, nil, { signature => 'sig-for-b' })

      expect(headers_of(recorder.requests.last)).not_to have_key(signature)
    end
  end

  describe 'diagnostics' do
    it 'redacts private values in logs and traces' do
      log_io = StringIO.new
      trace_io = StringIO.new
      client = build_client(
        hosts: [{ host: 'service-a.test', port: 9200 }],
        logger: Logger.new(log_io),
        tracer: Logger.new(trace_io),
        private_headers: ['X-Service-Signature'],
        transport_options: { headers: { 'X-Service-Token' => private_a, signature => 'sig-for-a' } }
      )
      client.perform_request('POST', '/_search', {}, { query: { match_all: {} } },
                             { 'Authorization' => authorization })

      output = log_io.string + trace_io.string
      expect(output).not_to include(private_a)
      expect(output).not_to include(authorization)
      expect(output).not_to include('sig-for-a')
      expect(trace_io.string).to include('Authorization: <REDACTED>')
      expect(trace_io.string).to include('X-Service-Token: <REDACTED>')
      expect(trace_io.string).to include("#{signature}: <REDACTED>")
    end

    it 'returns generation and header names on the response, without values' do
      client = build_client(
        hosts: [{ host: 'service-a.test', port: 9200 }],
        transport_options: { headers: { 'X-Service-Token' => private_a } }
      )
      response = client.perform_request('GET', '/info')

      context = response.request_context
      expect(context).not_to be_nil
      expect(context.connection_generation).to eq(client.transport.connections.first.generation)
      expect(context.to_h[:header_names]).to include('x-service-token')
      expect(context.to_h.to_s).not_to include(private_a)
    end

    it 'correlates each response with the URL and body it came from' do
      client = build_client(hosts: [{ host: 'service-a.test', port: 9200 }])
      first = client.perform_request('GET', '/first')
      second = client.perform_request('GET', '/second')

      expect(first.body['path']).to eq('/first')
      expect(second.body['path']).to eq('/second')
      expect(first.request_context.request_id).not_to eq(second.request_context.request_id)
      expect(recorder.requests.map(&:url)).to eq(
        ['http://service-a.test:9200/first', 'http://service-a.test:9200/second']
      )
    end
  end
end
