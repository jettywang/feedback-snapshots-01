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
require 'faraday/adapter/test'

class Elastic::Transport::RetryNonIdempotentTest < Minitest::Test
  NODES = ['http://node1.example:9200', 'http://node2.example:9200'].freeze
  SEARCH_PATH = '/_search'.freeze
  SECURITY_PATH = '/_security/user/alice'.freeze

  # Faraday middleware that records every attempt as [method, host] before it
  # reaches the test adapter, so landing node, disconnect and retry order are
  # observable even when the adapter subsequently raises.
  class RecordingMiddleware < Faraday::Middleware
    def initialize(app, order)
      super(app)
      @order = order
    end

    def call(env)
      @order << [env.method, env.url.host]
      @app.call(env)
    end
  end

  # Builds a client whose Faraday connection is driven by the given test stubs.
  # Every request is recorded in `order` as [method, host] so the landing node,
  # disconnect and retry sequence can be asserted after the call.
  def build_client(stubs, order, options = {})
    Elastic::Transport::Client.new(
      { hosts: NODES, retry_on_failure: 2, adapter: :test }.merge(options)
    ) do |connection|
      connection.use RecordingMiddleware, order
      connection.adapter :test, stubs
    end
  end

  def disconnect!(exception_class = Faraday::ConnectionFailed)
    raise exception_class, 'connection reset by peer'
  end

  context 'an idempotent query (GET) when a node disconnects' do
    setup do
      @stubs = Faraday::Adapter::Test::Stubs.new
      @order = []
      @stubs.get(SEARCH_PATH) { disconnect! }
      @stubs.get(SEARCH_PATH) { [200, { 'Content-Type' => 'application/json' }, '{"hits":[]}'] }
      @client = build_client(@stubs, @order)
    end

    should 'fail over, retry on the next node and return the response' do
      response = @client.perform_request('GET', SEARCH_PATH)

      assert_equal 200, response.status
      assert_equal 2, @order.size
      assert_equal :get, @order.first.first
      refute_equal @order.first.last, @order.last.last

      failed_host, recovered_host = @order.map(&:last)
      failed = @client.transport.connections.all.find { |c| c.host[:host] == failed_host }
      recovered = @client.transport.connections.all.find { |c| c.host[:host] == recovered_host }
      assert_predicate failed, :dead?
      refute_predicate recovered, :dead?
    end
  end

  context 'a non-idempotent security change (POST) when a node disconnects' do
    setup do
      @stubs = Faraday::Adapter::Test::Stubs.new
      @order = []
      @stubs.post(SECURITY_PATH) { disconnect! }
      @stubs.post(SECURITY_PATH) { [200, {}, '{"created":true}'] }
      @client = build_client(@stubs, @order)
    end

    should 'send the request once and raise UnknownResultError instead of retrying' do
      error = assert_raises(Elastic::Transport::Transport::UnknownResultError) do
        @client.perform_request('POST', SECURITY_PATH, {}, { password: 'secret', roles: [] })
      end

      failed_host = @order.first.last
      assert_equal :post, error.method
      assert_equal SECURITY_PATH, error.path
      assert_equal failed_host, error.connection.host[:host]
      assert_equal [[:post, failed_host]], @order
      assert_predicate @client.transport.connections.all.find { |c| c.host[:host] == failed_host }, :dead?
    end

    should 'return the unknown result to the caller for reconciliation' do
      raised = nil
      begin
        @client.perform_request('POST', SECURITY_PATH, {}, { password: 'secret' })
      rescue Elastic::Transport::Transport::UnknownResultError => e
        raised = e
      end

      refute_nil raised
      assert_kind_of Elastic::Transport::Transport::Error, raised
      assert_match(/POST/, raised.message)
      assert_match(/#{Regexp.escape(SECURITY_PATH)}/, raised.message)
      assert_match(/#{Regexp.escape(@order.first.last)}/, raised.message)
      assert_match(/Verify the result/, raised.message)
    end
  end

  context 'a non-idempotent security change (POST) when the server returns 503' do
    setup do
      @stubs = Faraday::Adapter::Test::Stubs.new
      @order = []
      @stubs.post(SECURITY_PATH) { [503, { 'Content-Type' => 'application/json' }, '{"error":"busy"}'] }
      @client = build_client(@stubs, @order)
    end

    should 'raise a server error, distinct from a disconnect and an unknown result' do
      assert_raises(Elastic::Transport::Transport::Errors::ServiceUnavailable) do
        @client.perform_request('POST', SECURITY_PATH, {}, { password: 'secret' })
      end
      assert_equal 1, @order.size
      assert_equal :post, @order.first.first
    end
  end

  context 'retry behaviour explicitly declared by the application' do
    should 'retry a non-idempotent request when opted in per request on the transport' do
      stubs = Faraday::Adapter::Test::Stubs.new
      order = []
      stubs.post(SECURITY_PATH) { disconnect! }
      stubs.post(SECURITY_PATH) { [200, {}, '{"created":true}'] }
      client = build_client(stubs, order)

      response = client.transport.perform_request(
        'POST', SECURITY_PATH, {}, { password: 'secret' }, nil, retry_non_idempotent: true
      )

      assert_equal 200, response.status
      assert_equal 2, order.size
      assert_equal %i[post post], order.map(&:first)
      refute_equal order.first.last, order.last.last
    end

    should 'retry a non-idempotent request when opted in on the client' do
      stubs = Faraday::Adapter::Test::Stubs.new
      order = []
      stubs.post(SECURITY_PATH) { disconnect!(Faraday::TimeoutError) }
      stubs.post(SECURITY_PATH) { [200, {}, '{"created":true}'] }
      client = build_client(stubs, order, retry_non_idempotent: true)

      response = client.perform_request('POST', SECURITY_PATH, {}, { password: 'secret' })

      assert_equal 200, response.status
      assert_equal 2, order.size
      assert_equal %i[post post], order.map(&:first)
      refute_equal order.first.last, order.last.last
    end
  end

  context 'the three failure outcomes are handled separately' do
    should 'treat an idempotent disconnect as a retryable transport error' do
      stubs = Faraday::Adapter::Test::Stubs.new
      stubs.get(SEARCH_PATH) { disconnect! }
      client = build_client(stubs, [], retry_on_failure: false)

      assert_raises(Elastic::Transport::Transport::Error) do
        client.perform_request('GET', SEARCH_PATH)
      end
    end

    should 'treat a non-idempotent disconnect as an unknown result' do
      stubs = Faraday::Adapter::Test::Stubs.new
      stubs.post(SECURITY_PATH) { disconnect! }
      client = build_client(stubs, [])

      assert_raises(Elastic::Transport::Transport::UnknownResultError) do
        client.perform_request('POST', SECURITY_PATH, {}, { password: 'secret' })
      end
    end

    should 'treat a 5xx response as a server error' do
      stubs = Faraday::Adapter::Test::Stubs.new
      stubs.post(SECURITY_PATH) { [500, { 'Content-Type' => 'application/json' }, '{}'] }
      client = build_client(stubs, [])

      assert_raises(Elastic::Transport::Transport::Errors::InternalServerError) do
        client.perform_request('POST', SECURITY_PATH, {}, { password: 'secret' })
      end
    end
  end

  context 'logging the unknown result' do
    should 'correlate the failure with the previously selected node and keep credentials out' do
      stubs = Faraday::Adapter::Test::Stubs.new
      stubs.post(SECURITY_PATH) { disconnect! }
      logger = Logger.new(io = StringIO.new)
      client = build_client(stubs, [], logger: logger)

      assert_raises(Elastic::Transport::Transport::UnknownResultError) do
        client.perform_request('POST', SECURITY_PATH, {}, { password: 'secret' })
      end

      output = io.string
      assert_match(/POST/, output)
      assert_match(/#{Regexp.escape(SECURITY_PATH)}/, output)
      assert_match(/node[12]\.example/, output)
      refute_match(/secret/, output)
    end
  end
end
