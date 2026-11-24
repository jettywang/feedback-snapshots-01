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

class Elastic::Transport::Transport::HeaderPolicyTest < Minitest::Test
  Policy = Elastic::Transport::Transport::HeaderPolicy

  context 'recognising credential headers' do
    should 'match standard authentication headers regardless of case' do
      %w[Authorization authorization PROXY-AUTHORIZATION Cookie Set-Cookie X-Api-Key API-Key].each do |name|
        assert Policy.sensitive_header?(name), "#{name} should be private"
      end
    end

    should 'match service-private headers' do
      %w[x-service-token X-Client-Secret X-Auth-Header session-token x-credential x-api-key-id].each do |name|
        assert Policy.sensitive_header?(name), "#{name} should be private"
      end
    end

    should 'leave public headers alone' do
      %w[content-type user-agent accept-encoding x-elastic-client-meta elastic-api-version].each do |name|
        refute Policy.sensitive_header?(name), "#{name} should be public"
      end
    end
  end

  context 'merging headers' do
    should 'keep a single entry per case-insensitive name' do
      merged = Policy.merge_headers({ 'Content-Type' => 'a' }, { 'content-type' => 'b' })
      assert_equal 1, merged.size
      assert_equal 'b', merged.values.first
    end

    should 'let later sources win' do
      merged = Policy.merge_headers({ 'X-A' => '1' }, nil, { 'X-A' => '2' })
      assert_equal '2', merged['X-A']
    end

    should 'not modify its sources' do
      first = { 'X-A' => '1' }
      second = { 'X-B' => '2' }
      Policy.merge_headers(first, second)
      assert_equal({ 'X-A' => '1' }, first)
      assert_equal({ 'X-B' => '2' }, second)
    end
  end

  context 'redacting headers' do
    should 'replace private values and keep public ones' do
      redacted = Policy.redacted_headers(
        'Authorization' => 'Basic abc',
        'X-Service-Token' => 'secret',
        'Content-Type' => 'application/json'
      )

      assert_equal Policy::REDACTED, redacted['Authorization']
      assert_equal Policy::REDACTED, redacted['X-Service-Token']
      assert_equal 'application/json', redacted['Content-Type']
    end

    should 'redact names the caller declared private' do
      redacted = Policy.redacted_headers({ 'X-Signature' => 'abc' }, Policy::REDACTED, ['x-signature'])
      assert_equal Policy::REDACTED, redacted['X-Signature']
    end

    should 'not modify the source hash' do
      source = { 'Authorization' => 'Basic abc' }
      Policy.redacted_headers(source)
      assert_equal 'Basic abc', source['Authorization']
    end
  end

  context 'fingerprinting' do
    should 'be stable for the same headers and context' do
      first = Policy.headers_fingerprint({ 'X-A' => '1' }, host: 'a')
      second = Policy.headers_fingerprint({ 'x-a' => '1' }, host: 'a')
      assert_equal first, second
    end

    should 'change when a header value changes' do
      first = Policy.headers_fingerprint({ 'X-A' => '1' })
      second = Policy.headers_fingerprint({ 'X-A' => '2' })
      refute_equal first, second
    end

    should 'change when the target context changes' do
      first = Policy.headers_fingerprint({ 'X-A' => '1' }, host: 'a')
      second = Policy.headers_fingerprint({ 'X-A' => '1' }, host: 'b')
      refute_equal first, second
    end

    should 'not contain a credential value' do
      value = Policy.headers_fingerprint({ 'Authorization' => 'Basic verysecret' })
      refute_includes value, 'verysecret'
      assert_match(/\A[0-9a-f]{16}\z/, value)
    end
  end
end
