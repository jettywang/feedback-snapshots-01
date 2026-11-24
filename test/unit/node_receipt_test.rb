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

module Elastic
  module Transport
    module Transport
      class NodeReceiptTest < Minitest::Test
        def connection(host_overrides = {})
          host = { protocol: 'http', host: 'node-a', port: 9200, path: nil,
                   user: 'elastic', password: 'secret' }.merge(host_overrides)
          Connections::Connection.new(host: host, connection: Object.new)
        end

        context 'NodeReceipt' do
          should 'record the actual connection, without credentials' do
            receipt = NodeReceipt.new(connection, 1)
            assert_equal 'http', receipt.node[:protocol]
            assert_equal 'node-a', receipt.node[:host]
            assert_equal 9200, receipt.node[:port]
            refute receipt.node.key?(:user)
            refute receipt.node.key?(:password)
            assert receipt.node.frozen?
            assert_equal 1, receipt.attempt
            assert_nil receipt.status
          end

          should 'move through the unreachable state' do
            receipt = NodeReceipt.new(connection, 1)
            error = ::Faraday::ConnectionFailed.new('refused')
            receipt.mark_unreachable!(error)

            assert_equal NodeReceipt::UNREACHABLE, receipt.status
            assert receipt.unreachable?
            refute receipt.responded?
            assert_nil receipt.http_status
            assert_equal error, receipt.error
          end

          should 'move through the parse error state' do
            receipt = NodeReceipt.new(connection, 2)
            error = MultiJSON::ParseError.new('bad json')
            receipt.mark_parse_error!(error, 200)

            assert_equal NodeReceipt::PARSE_ERROR, receipt.status
            assert receipt.parse_error?
            assert receipt.responded?
            assert_equal 200, receipt.http_status
            assert_equal error, receipt.error
          end

          should 'move through the failure state' do
            receipt = NodeReceipt.new(connection, 1)
            receipt.mark_failure!(503)

            assert_equal NodeReceipt::FAILURE, receipt.status
            assert receipt.failure?
            assert receipt.responded?
            assert_equal 503, receipt.http_status
          end

          should 'move through the success state' do
            receipt = NodeReceipt.new(connection, 3)
            receipt.mark_success!(200)

            assert_equal NodeReceipt::SUCCESS, receipt.status
            assert receipt.success?
            assert receipt.responded?
            assert_equal 200, receipt.http_status
            assert_nil receipt.error
          end
        end
      end

      # Integration of node receipts with the Faraday transport and the retry
      # loop in Base#perform_request. The Faraday test adapter is driven by
      # ordered stubs, and the stub blocks read the real connection host from
      # the request env so the receipt can be checked against connection facts
      # rather than anything the body claims.
      class NodeReceiptTransportTest < Minitest::Test
        include HTTP

        JSON_HEADERS = { 'Content-Type' => 'application/json' }.freeze

        def build_transport(hosts, options, &block)
          Faraday.new(hosts: hosts, options: options) do |faraday|
            faraday.adapter(:test, block.call)
          end
        end

        def two_hosts
          [{ host: 'node-a.example', port: 9200 }, { host: 'node-b.example', port: 9200 }]
        end

        context 'with node_receipt enabled' do
          should 'distinguish an unreachable first node from a successful second node that returns the same value' do
            stubs = ::Faraday::Adapter::Test::Stubs.new do |s|
              s.get('/index/_doc/1') do |env|
                raise ::Faraday::ConnectionFailed, "Connection refused - #{env.url.host}"
              end
              s.get('/index/_doc/1') do |_env|
                [200, JSON_HEADERS, '{"found":true,"_source":{"served_by":"shared-cluster"}}']
              end
            end
            transport = build_transport(two_hosts,
                                        { node_receipt: true, retry_on_failure: 1 }) { stubs }

            response = transport.perform_request('GET', '/index/_doc/1')

            assert_equal 2, response.node_receipts.size
            first, second = response.node_receipts

            assert_equal 1, first.attempt
            assert_equal 'node-a.example', first.node[:host]
            assert_equal NodeReceipt::UNREACHABLE, first.status
            assert first.unreachable?
            assert_nil first.http_status
            assert_instance_of ::Faraday::ConnectionFailed, first.error

            assert_equal 2, second.attempt
            assert_equal 'node-b.example', second.node[:host]
            assert_equal NodeReceipt::SUCCESS, second.status
            assert second.success?
            assert_equal 200, second.http_status

            assert_equal second, response.node_receipt
            # The body claims one service, the receipt reports the real node.
            assert_equal 'shared-cluster', response.body['_source']['served_by']
            assert_equal 'node-b.example', response.node_receipt.node[:host]
            stubs.verify_stubbed_calls
          end

          should 'distinguish an explicit failure from a later success across two real services' do
            stubs = ::Faraday::Adapter::Test::Stubs.new do |s|
              s.get('/search') do |_env|
                [503, JSON_HEADERS, '{"error":{"root_cause":[{"service":"shared-cluster"}]}}']
              end
              s.get('/search') do |_env|
                [200, JSON_HEADERS, '{"ok":true,"served_by":"shared-cluster"}']
              end
            end
            transport = build_transport(two_hosts,
                                        { node_receipt: true, retry_on_status: 503 }) { stubs }

            response = transport.perform_request('GET', '/search')
            first, second = response.node_receipts

            assert_equal 'node-a.example', first.node[:host]
            assert_equal NodeReceipt::FAILURE, first.status
            assert first.failure?
            assert first.responded?
            assert_equal 503, first.http_status

            assert_equal 'node-b.example', second.node[:host]
            assert_equal NodeReceipt::SUCCESS, second.status
            assert_equal 200, second.http_status
            assert_equal second, response.node_receipt
            stubs.verify_stubbed_calls
          end

          should 'record a parse error while keeping the original parser exception for the caller' do
            stubs = ::Faraday::Adapter::Test::Stubs.new do |s|
              s.get('/broken') { [200, JSON_HEADERS, 'this-is-not-json{'] }
            end
            transport = build_transport([{ host: 'node-a.example', port: 9200 }],
                                        { node_receipt: true }) { stubs }

            error = assert_raises(MultiJSON::ParseError) do
              transport.perform_request('GET', '/broken')
            end

            assert_equal NodeReceipt::PARSE_ERROR, error.node_receipt.status
            assert error.node_receipt.parse_error?
            assert_equal 'node-a.example', error.node_receipt.node[:host]
            assert_equal 200, error.node_receipt.http_status
            assert_equal 1, error.node_receipts.size
          end

          should 'attach the failure receipt to the structured transport error' do
            stubs = ::Faraday::Adapter::Test::Stubs.new do |s|
              s.get('/boom') { [500, JSON_HEADERS, '{"error":"boom"}'] }
            end
            transport = build_transport([{ host: 'node-a.example', port: 9200 }],
                                        { node_receipt: true }) { stubs }

            error = assert_raises(Errors::InternalServerError) do
              transport.perform_request('GET', '/boom')
            end

            assert_equal NodeReceipt::FAILURE, error.node_receipt.status
            assert_equal 'node-a.example', error.node_receipt.node[:host]
            assert_equal 500, error.node_receipt.http_status
            assert_equal 1, error.node_receipts.size
            # The original structured error is unchanged for the business.
            assert_equal '[500] {"error":"boom"}', error.message
          end

          should 'not leak fields from a failed attempt into the final receipt on retry' do
            stubs = ::Faraday::Adapter::Test::Stubs.new do |s|
              s.get('/retry') do |env|
                raise ::Faraday::ConnectionFailed, "refused #{env.url.host}"
              end
              s.get('/retry') { [200, JSON_HEADERS, '{"ok":true}'] }
            end
            transport = build_transport(two_hosts,
                                        { node_receipt: true, retry_on_failure: 1 }) { stubs }

            response = transport.perform_request('GET', '/retry')
            receipts = response.node_receipts

            assert_equal 2, receipts.size
            assert receipts.map(&:object_id).uniq.size == receipts.size
            assert_nil response.node_receipt.error
            assert_equal 200, response.node_receipt.http_status
            assert_equal NodeReceipt::SUCCESS, response.node_receipt.status
            stubs.verify_stubbed_calls
          end

          should 'record every attempt when retries are exhausted' do
            stubs = ::Faraday::Adapter::Test::Stubs.new do |s|
              3.times do
                s.get('/down') do |env|
                  raise ::Faraday::ConnectionFailed, "refused #{env.url.host}"
                end
              end
            end
            transport = build_transport(two_hosts,
                                        { node_receipt: true, retry_on_failure: 2 }) { stubs }

            error = assert_raises(Error) do
              transport.perform_request('GET', '/down')
            end

            assert_equal 3, error.node_receipts.size
            assert(error.node_receipts.all? { |r| r.status == NodeReceipt::UNREACHABLE })
            assert(error.node_receipts.all? { |r| r.http_status.nil? })
            assert_equal %w[node-a.example node-b.example node-a.example],
                         error.node_receipts.map { |r| r.node[:host] }
            assert_equal error.node_receipts.last, error.node_receipt
          end

          should 'mark an ignored failing status as a failure receipt' do
            stubs = ::Faraday::Adapter::Test::Stubs.new do |s|
              s.get('/missing') { [404, JSON_HEADERS, '{"error":"not_found"}'] }
            end
            transport = build_transport([{ host: 'node-a.example', port: 9200 }],
                                        { node_receipt: true }) { stubs }

            response = transport.perform_request('GET', '/missing', ignore: 404)

            assert_equal 404, response.status
            assert_equal NodeReceipt::FAILURE, response.node_receipt.status
            assert_equal 404, response.node_receipt.http_status
          end
        end

        context 'with node_receipt disabled (the default)' do
          should 'expose no receipt on a normal response' do
            stubs = ::Faraday::Adapter::Test::Stubs.new do |s|
              s.get('/ok') { [200, JSON_HEADERS, '{"ok":true}'] }
            end
            transport = build_transport([{ host: 'node-a.example', port: 9200 }], {}) { stubs }

            response = transport.perform_request('GET', '/ok')

            assert_nil response.node_receipt
            assert_equal [], response.node_receipts
          end

          should 'raise the same structured error without receipt accessors changing its type' do
            stubs = ::Faraday::Adapter::Test::Stubs.new do |s|
              s.get('/boom') { [500, JSON_HEADERS, '{"error":"boom"}'] }
            end
            transport = build_transport([{ host: 'node-a.example', port: 9200 }], {}) { stubs }

            assert_raises(Errors::InternalServerError) do
              transport.perform_request('GET', '/boom')
            end
          end

          should 'allow enabling receipts per request' do
            stubs = ::Faraday::Adapter::Test::Stubs.new do |s|
              s.get('/ok') { [200, JSON_HEADERS, '{"ok":true}'] }
            end
            transport = build_transport([{ host: 'node-a.example', port: 9200 }], {}) { stubs }

            response = transport.perform_request('GET', '/ok', {}, nil, nil, node_receipt: true)

            assert_equal NodeReceipt::SUCCESS, response.node_receipt.status
            assert_equal 'node-a.example', response.node_receipt.node[:host]
          end
        end
      end
    end
  end
end
