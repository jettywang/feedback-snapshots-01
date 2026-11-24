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

class Elastic::Transport::PublishingPolicyTest < Minitest::Test
  def setup
    @policy = Elastic::Transport::PublishingPolicy.new
    @serializer = Elastic::Transport::Transport::Serializer::MultiJson.new(nil)
  end

  def test_sanitize_url_strips_userinfo
    sanitized = @policy.sanitize_url('http://elastic:fictional-secret@node-1:9200/_search')
    refute_includes sanitized, 'fictional-secret'
    refute_includes sanitized, 'elastic:'
    assert_includes sanitized, 'node-1:9200/_search'
  end

  def test_sanitize_url_keeps_urls_without_userinfo_untouched
    url = 'http://node-1:9200/_search'
    assert_equal url, @policy.sanitize_url(url)
  end

  def test_sanitize_headers_redacts_authorization
    headers = {
      'Authorization' => 'Basic ZWxhc3RpYzpmaWN0aW9uYWwtc2VjcmV0',
      'Content-Type' => 'application/json',
      'X-Api-Token' => 'fictional-secret'
    }

    published = @policy.sanitize_headers(headers)
    assert_equal Elastic::Transport::PublishingPolicy::REDACTED, published['Authorization']
    assert_equal Elastic::Transport::PublishingPolicy::REDACTED, published['X-Api-Token']
    assert_equal 'application/json', published['Content-Type']
    # The original headers used on the wire are untouched.
    assert_equal 'Basic ZWxhc3RpYzpmaWN0aW9uYWwtc2VjcmV0', headers['Authorization']
    assert_equal 'fictional-secret', headers['X-Api-Token']
  end

  def test_request_body_is_always_omitted
    assert_equal Elastic::Transport::PublishingPolicy::OMITTED,
                 @policy.sanitize_request_body('{"query":{"match_all":{}}}')
  end

  def test_sanitize_response_body_redacts_sensitive_keys_recursively
    body = '{"hits":{"total":1},"password":"fictional-secret","user":{"api_token":"abc123","name":"ok"}}'

    published = @policy.sanitize_response_body(body, @serializer)
    refute_includes published.to_json, 'fictional-secret'
    refute_includes published.to_json, 'abc123'
    assert_equal Elastic::Transport::PublishingPolicy::REDACTED, published['password']
    assert_equal Elastic::Transport::PublishingPolicy::REDACTED, published['user']['api_token']
    assert_equal 1, published['hits']['total']
    assert_equal 'ok', published['user']['name']
  end

  def test_sanitize_response_body_does_not_mutate_the_input
    body = '{"password":"fictional-secret"}'
    original = body.dup.freeze

    @policy.sanitize_response_body(original, @serializer)

    assert_equal '{"password":"fictional-secret"}', original
  end

  def test_sanitize_response_body_omits_unparseable_strings
    assert_equal Elastic::Transport::PublishingPolicy::OMITTED,
                 @policy.sanitize_response_body('not-json', @serializer)
  end

  def test_sanitize_response_body_honours_extra_sensitive_keys
    policy = Elastic::Transport::PublishingPolicy.new(sensitive_keys: ['internal_case_id'])
    body = '{"internal_case_id":"CASE-42","status":"open"}'

    published = policy.sanitize_response_body(body, @serializer)

    assert_equal Elastic::Transport::PublishingPolicy::REDACTED, published['internal_case_id']
    assert_equal 'open', published['status']
  end

  def test_sanitize_error_message_strips_credentials_and_sensitive_pairs
    message = 'connection failed for http://elastic:fictional-secret@node-1:9200 body={"password":"leaked"}'

    published = @policy.sanitize_error_message(message)

    refute_includes published, 'fictional-secret'
    refute_includes published, 'leaked'
    assert_includes published, 'node-1:9200'
  end

  def test_request_id_is_unique_and_correlation_length
    ids = Array.new(5) { Elastic::Transport::PublishingPolicy.request_id }

    assert_equal ids.size, ids.uniq.size
    ids.each { |id| assert_match(/\A[0-9a-f]{16}\z/, id) }
  end

  def test_node_id_identifies_host_port_and_protocol
    connection = Struct.new(:host).new(
      Elastic::Transport::Redacted.new(protocol: 'http', host: 'node-2', port: 9201)
    )

    assert_equal 'http://node-2:9201', Elastic::Transport::PublishingPolicy.node_id(connection)
  end

  def test_node_id_handles_uncooperative_connections
    assert_equal 'unknown-node', Elastic::Transport::PublishingPolicy.node_id(nil)
    string_host = Struct.new(:host).new('node-1')
    assert_equal 'node-1', Elastic::Transport::PublishingPolicy.node_id(string_host)
  end
end
