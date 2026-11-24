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
require 'webmock/minitest'
require 'stringio'
require 'logger'

# Minimal in-process OpenTelemetry stand-in. The real SDK is not part of the
# local test bundle; this double implements only the surface the transport
# touches so the telemetry publication path can be exercised end to end.
module OpenTelemetry
  class Span
    attr_reader :attributes

    def initialize
      @attributes = {}
    end

    def set_attribute(key, value)
      @attributes[key] = value
    end
    alias []= set_attribute
  end

  class Tracer
    attr_accessor :latest_span

    def in_span(_name)
      existing = OpenTelemetry::Trace.current_span
      return yield existing if existing

      @latest_span = Span.new
      OpenTelemetry::Trace.with_span(@latest_span) { yield @latest_span }
    end
  end

  module Trace
    @current_span = nil

    class << self
      attr_accessor :current_span

      def with_span(span)
        previous = @current_span
        @current_span = span
        yield span
      ensure
        @current_span = previous
      end
    end
  end

  class << self
    def tracer_provider
      self
    end

    def tracer(_name, _version)
      Tracer.new
    end
  end
end

class PublishingAcceptanceTest < Minitest::Test
  include WebMock::API

  NODE_ONE = 'http://node-1.example:9200'.freeze
  NODE_TWO = 'http://node-2.example:9201'.freeze
  FICTIONAL_USER = 'elastic'.freeze
  FICTIONAL_PASSWORD = 'fictional-secret-password'.freeze
  FICTIONAL_TOKEN = 'fictional-secret-token'.freeze

  def setup
    @log_io = StringIO.new
    @trace_io = StringIO.new
    @logger = Logger.new(@log_io)
    @logger.level = Logger::DEBUG
    @tracer = Logger.new(@trace_io)
    @tracer.level = Logger::DEBUG

    @client = Elastic::Transport::Client.new(
      hosts: [
        "#{NODE_ONE}/",
        "#{NODE_TWO}/"
      ],
      user: FICTIONAL_USER,
      password: FICTIONAL_PASSWORD,
      retry_on_failure: 1,
      logger: @logger,
      tracer: @tracer,
      transport_options: { headers: { 'Authorization' => "Bearer #{FICTIONAL_TOKEN}" } }
    )

    # First attempt hits node 1 and fails to connect; the retry succeeds on
    # node 2 with a body containing sensitive and non-sensitive fields.
    stub_request(:post, %r{\A#{NODE_ONE}/}).to_raise(Errno::ECONNREFUSED)
    stub_request(:post, %r{\A#{NODE_TWO}/}).to_return(
      status: 200,
      headers: { 'Content-Type' => 'application/json' },
      body: '{"took":12,"status":"green","password":"leak-from-response","nodes":{"api_token":"leak-token","ok":true}}'
    )
  end

  def teardown
    WebMock.reset!
  end

  def test_one_synthetic_request_fails_over_to_the_second_node
    @span = OpenTelemetry::Span.new
    response = OpenTelemetry::Trace.with_span(@span) do
      @client.perform_request(
        'POST', '_search', {}, { query: { match_all: {} } }, { 'Content-Type' => 'application/json' }
      )
    end

    assert_equal 200, response.status
    assert_requested(:post, %r{\A#{NODE_ONE}/}, times: 1)
    assert_requested(:post, %r{\A#{NODE_TWO}/}, times: 1)
  end

  def test_the_actual_request_keeps_the_original_connection_parameters
    OpenTelemetry::Trace.with_span(OpenTelemetry::Span.new) do
      @client.perform_request('POST', '_search', {}, { query: { match_all: {} } })
    end

    assert_requested(:post, %r{\A#{NODE_TWO}/}) do |request|
      # Credentials travel as an Authorization header on the wire.
      request.headers['Authorization'] == "Bearer #{FICTIONAL_TOKEN}" &&
        request.body == '{"query":{"match_all":{}}}'
    end
  end

  def test_the_retry_is_recoverable_from_the_curl_style_trace
    perform

    trace = @trace_io.string
    assert_match(/# request:[0-9a-f]{16} attempt:1 node:http:\/\/node-1\.example:9200/, trace)
    assert_match(/# request:([0-9a-f]{16}) attempt:2 node:http:\/\/node-2\.example:9201/, trace)
    request_ids = trace.scan(/request:([0-9a-f]{16})/).flatten.uniq
    assert_equal 1, request_ids.size, 'both attempts must share one correlation id'
    assert_match(/curl -X POST/, trace)
    assert_match(/Authorization: #{Elastic::Transport::PublishingPolicy::REDACTED}/, trace)
    refute_includes trace, FICTIONAL_PASSWORD
    refute_includes trace, FICTIONAL_TOKEN
    refute_includes trace, 'match_all', 'the query body must never appear in a trace'
    refute_includes trace, 'leak-from-response'
    refute_includes trace, 'leak-token'
  end

  def test_the_retry_is_recoverable_from_the_logs
    perform

    logs = @log_io.string
    assert_match(%r{node-1\.example:9200.*attempt:1}, logs)
    assert_match(%r{node-2\.example:9201.*attempt:2}, logs)
    assert_match(/Attempt 1 connecting/, logs)
    refute_includes logs, FICTIONAL_PASSWORD
    refute_includes logs, FICTIONAL_TOKEN
    refute_includes logs, 'match_all'
    refute_includes logs, 'leak-from-response'
    refute_includes logs, 'leak-token'
    assert_includes logs, '[OMITTED]'
  end

  def test_the_retry_is_recoverable_from_telemetry
    perform

    attributes = @span.attributes
    # Each attempt records the node it was sent to; the last value is the
    # successful retry, and the history shows which node failed first.
    assert_equal 'http://node-2.example:9201', attributes['elastic.attempt.node']
    assert_equal 2, attributes['elastic.attempt.number']
    assert_equal 200, attributes['db.response.status_code']
    assert_match(%r{\Ahttp://:<REDACTED>@node-2\.example:9201}, attributes['url.full'])
    refute_includes attributes['url.full'].to_s, FICTIONAL_PASSWORD
    assert_nil attributes['db.query.text']
    refute_match(/#{FICTIONAL_PASSWORD}|#{FICTIONAL_TOKEN}/, attributes['error.type'].to_s)
  end

  def test_the_failed_attempt_is_recoverable_from_the_telemetry_error
    perform_without_outer_span

    attributes = @client.instance_variable_get(:@otel).tracer.latest_span.attributes
    assert_match(/Connection refused/, attributes['error.type'])
    refute_includes attributes['error.type'].to_s, FICTIONAL_PASSWORD
    refute_includes attributes['error.type'].to_s, FICTIONAL_TOKEN
    assert_equal 'http://node-1.example:9200', attributes['error.attempt.node']
    assert_equal 1, attributes['error.attempt.number']
    assert_equal 2, attributes['elastic.attempt.number']
    assert_equal 'http://node-2.example:9201', attributes['elastic.attempt.node']
  end

  def test_no_shared_output_contains_the_fictional_credentials
    perform

    [@log_io.string, @trace_io.string].each do |output|
      refute_includes output, FICTIONAL_PASSWORD
      refute_includes output, FICTIONAL_TOKEN
    end
    @span.attributes.each_value do |value|
      refute_includes value.to_s, FICTIONAL_PASSWORD
      refute_includes value.to_s, FICTIONAL_TOKEN
    end
  end

  private

  def perform
    @span = OpenTelemetry::Span.new
    OpenTelemetry::Trace.with_span(@span) do
      @client.perform_request('POST', '_search', {}, { query: { match_all: {} } })
    end
  end

  def perform_without_outer_span
    @client.perform_request('POST', '_search', {}, { query: { match_all: {} } })
  end
end
