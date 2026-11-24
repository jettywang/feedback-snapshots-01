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
require 'tmpdir'
require 'fileutils'

class Elastic::Transport::Transport::BaseTest < Minitest::Test

  class EmptyTransport
    include Elastic::Transport::Transport::Base
  end

  class DummyTransport
    include Elastic::Transport::Transport::Base
    def __build_connection(host, options={}, block=nil)
      Elastic::Transport::Transport::Connections::Connection.new :host => host, :connection => Object.new
    end
  end

  class DummyTransportPerformer < DummyTransport
    def perform_request(method, path, params={}, body=nil, &block); super; end
  end

  # Exposes the per-connection SSL options it is asked to build with, the way an adapter copies
  # them onto its client.
  class TrustAwareTransport < DummyTransport
    def __build_connection(host, options = {}, block = nil)
      ssl = options[:ssl] || {}
      super(host, options, block).tap do |connection|
        connection.define_singleton_method(:ssl_source) { ssl[:ca_file] }
        connection.define_singleton_method(:ssl_options) { ssl }
      end
    end
  end

  class DummySerializer
    def initialize(*); end
  end

  class DummySniffer
    def initialize(*); end
  end

  def build_trust_transport(policy, hosts = nil)
    build_trust_transport_with(policy, hosts: hosts)
  end

  def build_trust_transport_with(policy, hosts: nil, transport_options: nil)
    hosts ||= [
      { id: 'node-a', host: 'node-a.test', port: 9200, scheme: 'https' },
      { id: 'node-b', host: 'node-b.test', port: 9200, scheme: 'https' }
    ]
    options = { node_trust: policy, resurrect_after: 0 }
    options[:transport_options] = transport_options if transport_options
    TrustAwareTransport.new(hosts: hosts, options: options)
  end

  context "Transport::Base" do
    should "raise exception when it doesn't implement __build_connection" do
      assert_raise NoMethodError do
        EmptyTransport.new.__build_connection({ :host => 'foo'}, {})
      end
    end

    should "build connections on initialization" do
      DummyTransport.any_instance.expects(:__build_connections)
      transport = DummyTransport.new
    end

    should "have default serializer" do
      transport = DummyTransport.new
      assert_instance_of Elastic::Transport::Transport::Base::DEFAULT_SERIALIZER_CLASS, transport.serializer
    end

    should "have custom serializer" do
      transport = DummyTransport.new :options => { :serializer_class => DummySerializer }
      assert_instance_of DummySerializer, transport.serializer

      transport = DummyTransport.new :options => { :serializer => DummySerializer.new }
      assert_instance_of DummySerializer, transport.serializer
    end

    should "have default sniffer" do
      transport = DummyTransport.new
      assert_instance_of Elastic::Transport::Transport::Sniffer, transport.sniffer
    end

    should "have custom sniffer" do
      transport = DummyTransport.new :options => { :sniffer_class => DummySniffer }
      assert_instance_of DummySniffer, transport.sniffer
    end

    context "when combining the URL" do
      setup do
        @transport   = DummyTransport.new
        @basic_parts = { :protocol => 'http', :host => 'myhost', :port => 8080 }
      end

      should "combine basic parts" do
        assert_equal 'http://myhost:8080', @transport.__full_url(@basic_parts)
      end

      should "combine path" do
        assert_equal 'http://myhost:8080/api', @transport.__full_url(@basic_parts.merge :path => '/api')
      end

      should "combine authentication credentials" do
        assert_equal 'http://U:P@myhost:8080', @transport.__full_url(@basic_parts.merge :user => 'U', :password => 'P')
      end

      should "escape the username and password" do
        assert_equal 'http://user%40domain:foo%2Fbar@myhost:8080',
                     @transport.__full_url(@basic_parts.merge :user => 'user@domain', :password => 'foo/bar')
      end
    end
  end

  context "getting a connection" do
    setup do
      @transport = DummyTransportPerformer.new :options => { :reload_connections => 5 }
      @transport.stubs(:connections).returns(stub :get_connection => Object.new)
      @transport.stubs(:sniffer).returns(stub :hosts => [])
    end

    should "get a connection" do
      assert_not_nil @transport.get_connection
    end

    should "increment the counter" do
      assert_equal 0, @transport.counter
      3.times { @transport.get_connection }
      assert_equal 3, @transport.counter
    end

    should "reload connections when it hits the threshold" do
      @transport.expects(:reload_connections!).twice
      12.times { @transport.get_connection }
      assert_equal 12, @transport.counter
    end

    should "not reload connections by default" do
      @transport = DummyTransportPerformer.new
      @transport.stubs(:connections).returns(stub :get_connection => Object.new)
      @transport.expects(:reload_connections!).never

      10_010.times { @transport.get_connection }
      assert_equal 10_010, @transport.counter
    end

    should "not reload connections when the option is set to false" do
      @transport = DummyTransportPerformer.new :options => { :reload_connections => false }
      @transport.stubs(:connections).returns(stub :get_connection => Object.new)
      @transport.expects(:reload_connections!).never

      10_010.times { @transport.get_connection }
      assert_equal 10_010, @transport.counter
    end
  end

  context "performing a request" do
    setup do
      @transport = DummyTransportPerformer.new
    end

    should "raise an error when no block is passed" do
      assert_raise NoMethodError do
        @transport.peform_request 'GET', '/'
      end
    end

    should "get the connection" do
      @transport.expects(:get_connection).returns(stub_everything :failures => 1)
      @transport.perform_request 'GET', '/' do; Elastic::Transport::Transport::Response.new 200, 'OK'; end
    end

    should "raise an error when no connection is available" do
      @transport.expects(:get_connection).returns(nil)
      assert_raise Elastic::Transport::Transport::Error do
        @transport.perform_request 'GET', '/' do; Elastic::Transport::Transport::Response.new 200, 'OK'; end
      end
    end

    should "call the passed block" do
      x = 0
      @transport.expects(:get_connection).returns(stub_everything :failures => 1)

      @transport.perform_request 'GET', '/' do |connection, url|
        x += 1
        Elastic::Transport::Transport::Response.new 200, 'OK'
      end

      assert_equal 1, x
    end

    should "deserialize a response JSON body" do
      @transport.expects(:get_connection).returns(stub_everything :failures => 1)
      @transport.serializer.expects(:load).returns({'foo' => 'bar'})

      response = @transport.perform_request 'GET', '/' do
                   Elastic::Transport::Transport::Response.new 200, '{"foo":"bar"}', {"content-type" => 'application/json'}
                 end

      assert_instance_of Elastic::Transport::Transport::Response, response
      assert_equal 'bar', response.body['foo']
    end

    should "not deserialize a response string body" do
      @transport.expects(:get_connection).returns(stub_everything :failures => 1)
      @transport.serializer.expects(:load).never
      response = @transport.perform_request 'GET', '/' do
                   Elastic::Transport::Transport::Response.new 200, 'FOOBAR', {"content-type" => 'text/plain'}
                 end

      assert_instance_of Elastic::Transport::Transport::Response, response
      assert_equal 'FOOBAR', response.body
    end

    should "not deserialize an empty response body" do
      @transport.expects(:get_connection).returns(stub_everything :failures => 1)
      @transport.serializer.expects(:load).never
      response = @transport.perform_request 'GET', '/' do
                   Elastic::Transport::Transport::Response.new 200, '', {"content-type" => 'application/json'}
                 end

      assert_instance_of Elastic::Transport::Transport::Response, response
      assert_equal '', response.body
    end

    should "serialize non-String objects" do
      @transport.serializer.expects(:dump).times(3)
      @transport.__convert_to_json({:foo => 'bar'})
      @transport.__convert_to_json([1, 2, 3])
      @transport.__convert_to_json(nil)
    end

    should "not serialize a String object" do
      @transport.serializer.expects(:dump).never
      @transport.__convert_to_json('{"foo":"bar"}')
    end

    should "raise an error for HTTP status 404" do
      @transport.expects(:get_connection).returns(stub_everything :failures => 1)
      assert_raise Elastic::Transport::Transport::Errors::NotFound do
        @transport.perform_request 'GET', '/' do
          Elastic::Transport::Transport::Response.new 404, 'NOT FOUND'
        end
      end
    end

    should "raise an error for HTTP status 404 with application/json content type" do
      @transport.expects(:get_connection).returns(stub_everything :failures => 1)
      assert_raise Elastic::Transport::Transport::Errors::NotFound do
        @transport.perform_request 'GET', '/' do
          Elastic::Transport::Transport::Response.new 404, 'NOT FOUND', {"content-type" => 'application/json'}
        end
      end
    end

    should "raise an error on server failure" do
      @transport.expects(:get_connection).returns(stub_everything :failures => 1)
      assert_raise Elastic::Transport::Transport::Errors::InternalServerError do
        @transport.perform_request 'GET', '/' do
          Elastic::Transport::Transport::Response.new 500, 'ERROR'
        end
      end
    end

    should "raise an error on connection failure" do
      @transport.expects(:get_connection).returns(stub_everything :failures => 1)

      block = lambda { |a,b| raise Elastic::Transport::Transport::Error }

      assert_raise Elastic::Transport::Transport::Error do
        @transport.perform_request 'GET', '/', &block
      end
    end

    should 'raise TooManyRequestsError on 429' do
      @transport.expects(:get_connection).returns(stub_everything :failures => 1)
      assert_raise Elastic::Transport::Transport::Errors::TooManyRequests do
        @transport.perform_request 'GET', '/' do
          Elastic::Transport::Transport::Response.new 429, 'ERROR'
        end
      end
    end

    should "not raise an error when the :ignore argument has been passed" do
      @transport.stubs(:get_connection).returns(stub_everything :failures => 1)

      assert_raise Elastic::Transport::Transport::Errors::BadRequest do
        @transport.perform_request 'GET', '/' do
          Elastic::Transport::Transport::Response.new 400, 'CLIENT ERROR'
        end
      end

      # No `BadRequest` error
      @transport.perform_request 'GET', '/', :ignore => 400 do
        Elastic::Transport::Transport::Response.new 400, 'CLIENT ERROR'
      end
    end

    should "mark the connection as dead on failure" do
      c = stub_everything :failures => 1
      @transport.expects(:get_connection).returns(c)

      block = lambda { |a, b| raise Errno::ECONNREFUSED }

      c.expects(:dead!)

      assert_raise( Elastic::Transport::Transport::Error ) { @transport.perform_request 'GET', '/', &block }
    end
  end

  context "performing a request with reload connections on connection failures" do
    setup do
      fake_collection = stub_everything :get_connection => stub_everything(:failures => 1),
                                        :all            => stub_everything(:size => 2)
      @transport = DummyTransportPerformer.new :options => { :reload_on_failure => 2 }
      @transport.stubs(:connections).
                 returns(fake_collection)
      @block = lambda { |c, u| puts "UNREACHABLE" }
    end

    should "reload connections when host is unreachable" do
      @block.expects(:call).times(2).
        raises(Errno::ECONNREFUSED).
            then.returns(stub_everything :failures => 1)

      @transport.expects(:reload_connections!).returns([])

      @transport.perform_request('GET', '/', &@block)
      assert_equal 2, @transport.counter
    end
  end

  context "performing a request with retry on connection failures" do
    setup do
      @transport = DummyTransportPerformer.new :options => { :retry_on_failure => true }
      @transport.stubs(:connections).returns(stub :get_connection => stub_everything(:failures => 1))
      @block = Proc.new { |c, u| puts "UNREACHABLE" }
    end

    should "retry DEFAULT_MAX_RETRIES when host is unreachable" do
      @block.expects(:call).times(4).
            raises(Errno::ECONNREFUSED).
            then.raises(Errno::ECONNREFUSED).
            then.raises(Errno::ECONNREFUSED).
            then.returns(stub_everything :failures => 1)

      assert_nothing_raised do
        @transport.perform_request('GET', '/', &@block)
        assert_equal 4, @transport.counter
      end
    end

    should "raise an error after max tries" do
      @block.expects(:call).times(4).
        raises(Errno::ECONNREFUSED).
            then.raises(Errno::ECONNREFUSED).
            then.raises(Errno::ECONNREFUSED).
            then.raises(Errno::ECONNREFUSED).
            then.returns(stub_everything :failures => 1)

      assert_raise Elastic::Transport::Transport::Error do
        @transport.perform_request('GET', '/', &@block)
      end
    end
  end

  context "performing a request with retry on status" do
    setup do
      DummyTransportPerformer.any_instance.stubs(:connections).returns(stub :get_connection => stub_everything(:failures => 1))

      logger = Logger.new(STDERR)
      logger.level = Logger::DEBUG
      DummyTransportPerformer.any_instance.stubs(:logger).returns(logger)
      @block = Proc.new { |c, u| puts "ERROR" }
    end

    should "not retry when the status code does not match" do
      @transport = DummyTransportPerformer.new :options => { :retry_on_status => 500 }
      assert_equal [500], @transport.instance_variable_get(:@retry_on_status)

      @block.expects(:call).
             returns(Elastic::Transport::Transport::Response.new 400, 'Bad Request').
             times(1)

      @transport.logger.
          expects(:warn).
          with( regexp_matches(/Attempt \d to get response/) ).
          never

      assert_raise Elastic::Transport::Transport::Errors::BadRequest do
        @transport.perform_request('GET', '/', {}, nil, &@block)
      end
    end

    should "retry when the status code does match" do
      @transport = DummyTransportPerformer.new :options => { :retry_on_status => 500 }
      assert_equal [500], @transport.instance_variable_get(:@retry_on_status)

      @block.expects(:call).
             returns(Elastic::Transport::Transport::Response.new 500, 'Internal Error').
             times(4)

      @transport.logger.
          expects(:warn).
          with( regexp_matches(/Attempt \d to get response/) ).
          times(4)

      assert_raise Elastic::Transport::Transport::Errors::InternalServerError do
        @transport.perform_request('GET', '/', &@block)
      end
    end
  end

  context "logging" do
    setup do
      @transport = DummyTransportPerformer.new :options => { :logger => Logger.new('/dev/null') }

      fake_connection = stub :full_url => 'localhost:9200/_search?size=1',
                             :host     => 'localhost',
                             :connection => stub_everything,
                             :failures => 0,
                             :healthy! => true

      @transport.stubs(:get_connection).returns(fake_connection)
      @transport.serializer.stubs(:load).returns 'foo' => 'bar'
      @transport.serializer.stubs(:dump).returns '{"foo":"bar"}'
    end

    should "log the request and response" do
      @transport.logger.expects(:info).  with do |line|
        line =~ %r|POST localhost\:9200/_search\?size=1 \[status\:200, request:.*s, query:n/a\]|
      end
      @transport.logger.expects(:debug). with '> {"foo":"bar"}'
      @transport.logger.expects(:debug). with '< {"foo":"bar"}'

      @transport.perform_request 'POST', '_search', {:size => 1}, {:foo => 'bar'} do
                   Elastic::Transport::Transport::Response.new 200, '{"foo":"bar"}'
                 end
    end

    should "sanitize password in the URL" do
      fake_connection = stub :full_url => 'http://user:password@localhost:9200/_search?size=1',
                             :host     => 'localhost',
                             :connection => stub_everything,
                             :failures => 0,
                             :healthy! => true
      @transport.stubs(:get_connection).returns(fake_connection)

      @transport.logger.expects(:info).with do |message|
        assert_match(/http:\/\/user:\*{1,15}@localhost\:9200/, message)
        true
      end


      @transport.perform_request('GET', '/') {Elastic::Transport::Transport::Response.new 200, '{"foo":"bar"}' }
    end

    should "log a failed Elasticsearch request as fatal" do
      @block = Proc.new { |c, u| puts "ERROR" }
      @block.expects(:call).returns(Elastic::Transport::Transport::Response.new 500, 'ERROR')

      @transport.expects(:__log_response)
      @transport.logger.expects(:fatal)

      assert_raise Elastic::Transport::Transport::Errors::InternalServerError do
        @transport.perform_request('POST', '_search', &@block)
      end
    end

    should "not log a failed Elasticsearch request as fatal" do
      @block = Proc.new { |c, u| puts "ERROR" }
      @block.expects(:call).returns(Elastic::Transport::Transport::Response.new 500, 'ERROR')

      @transport.expects(:__log_response).once
      @transport.logger.expects(:fatal).never

      # No `BadRequest` error
      @transport.perform_request('POST', '_search', :ignore => 500, &@block)
    end

    should "log and re-raise a Ruby exception" do
      @block = Proc.new { |c, u| puts "ERROR" }
      @block.expects(:call).raises(Exception)

      @transport.expects(:__log_response).never
      @transport.logger.expects(:fatal)

      assert_raise(Exception) { @transport.perform_request('POST', '_search', &@block) }
    end
  end

  context "tracing" do
    setup do
      @transport = DummyTransportPerformer.new :options => { :tracer => Logger.new('/dev/null') }

      fake_connection = stub :full_url => 'localhost:9200/_search?size=1',
                             :host     => 'localhost',
                             :connection => stub_everything,
                             :failures => 0,
                             :healthy! => true

      @transport.stubs(:get_connection).returns(fake_connection)
      @transport.serializer.stubs(:load).returns 'foo' => 'bar'
      @transport.serializer.stubs(:dump).returns <<-JSON.gsub(/^      /, '')
      {
        "foo" : {
          "bar" : {
            "bam" : true
          }
        }
      }
      JSON
    end

    should "trace the request" do
      @transport.tracer.expects(:info).  with do |message|
        message == <<-CURL.gsub(/^            /, '')
            curl -X POST 'http://localhost:9200/_search?pretty&size=1' -d '{
              "foo" : {
                "bar" : {
                  "bam" : true
                }
              }
            }
            '
          CURL
      end.once

      @transport.perform_request 'POST', '_search', {:size => 1}, {:q => 'foo'} do
                   Elastic::Transport::Transport::Response.new 200, '{"foo":"bar"}'
                 end
    end

    should "trace a failed Elasticsearch request" do
      @block = Proc.new { |c, u| puts "ERROR" }
      @block.expects(:call).returns(Elastic::Transport::Transport::Response.new 500, 'ERROR')

      @transport.expects(:__trace)

      assert_raise Elastic::Transport::Transport::Errors::InternalServerError do
        @transport.perform_request('POST', '_search', &@block)
      end
    end

  end

  context "reloading connections" do
    setup do
      @transport = DummyTransport.new :options => { :logger => Logger.new('/dev/null') }
    end

    should "rebuild connections" do
      @transport.sniffer.expects(:hosts).returns([])
      @transport.expects(:__rebuild_connections)
      @transport.reload_connections!
    end

    should "log error and continue when timing out while sniffing hosts" do
      @transport.sniffer.expects(:hosts).raises(Elastic::Transport::Transport::SnifferTimeoutError)
      @transport.logger.expects(:error)
      assert_nothing_raised do
        @transport.reload_connections!
      end
    end

    should "keep existing connections" do
      @transport.__rebuild_connections :hosts => [ { :host => 'node1', :port => 1 } ], :options => { :http => {} }
      assert_equal 1, @transport.connections.size

      old_connection_id = @transport.connections.first.object_id

      @transport.__rebuild_connections :hosts => [ { :host => 'node1', :port => 1 },
                                                   { :host => 'node2', :port => 2 } ],
                                       :options => { :http => {} }

      assert_equal 2, @transport.connections.size
      assert_equal old_connection_id, @transport.connections.first.object_id
    end

    should "remove dead connections" do
      @transport.__rebuild_connections :hosts => [ { :host => 'node1', :port => 1 },
                                                   { :host => 'node2', :port => 2 } ],
                                       :options => { :http => {} }
      assert_equal 2, @transport.connections.size

      @transport.connections[1].dead!

      @transport.__rebuild_connections :hosts => [ { :host => 'node1', :port => 1 } ], :options => { :http => {} }

      assert_equal 1, @transport.connections.size
      assert_equal 1, @transport.connections.all.size
    end

    should "not duplicate connections" do
      @transport.__rebuild_connections :hosts => [ { :host => 'node1', :port => 1 },
                                                   { :host => 'node2', :port => 2 } ],
                                       :options => { :http => {} }
      assert_equal 2, @transport.connections.size

      @transport.connections[0].dead!

      @transport.__rebuild_connections :hosts => [ { :host => 'node1', :port => 1 },
                                                   { :host => 'node2', :port => 2 } ],
                                       :options => { :http => {} }

      assert_equal 2, @transport.connections.all.size
      assert_equal 1, @transport.connections.size
    end
  end

  context "rebuilding connections" do
    setup do
      @transport = DummyTransport.new
    end

    should "close connections" do
      @transport.expects(:__close_connections)
      @transport.__rebuild_connections :hosts => [ { :scheme => 'http', :host => 'foo', :port => 1 } ], :options => { :http => {} }
    end

    should "should replace the connections" do
      assert_equal 0, @transport.connections.size

      @transport.__rebuild_connections :hosts => [{ :scheme => 'http', :host => 'foo', :port => 1 }],
                                       :options => { :http => {} }

      assert_equal 1, @transport.connections.size
    end
  end

  context "resurrecting connections" do
    setup do
      @transport = DummyTransportPerformer.new
    end

    should "delegate to dead connections" do
      @transport.connections.expects(:dead).returns([])
      @transport.resurrect_dead_connections!
    end

    should "not resurrect connections until timeout" do
      @transport.connections.expects(:get_connection).returns(stub_everything :failures => 1).times(5)
      @transport.expects(:resurrect_dead_connections!).never
      5.times { @transport.get_connection }
    end

    should "resurrect connections after timeout" do
      @transport.connections.expects(:get_connection).returns(stub_everything :failures => 1).times(5)
      @transport.expects(:resurrect_dead_connections!)

      4.times { @transport.get_connection }

      now = Time.now + 60*2
      Time.stubs(:now).returns(now)

      @transport.get_connection
    end

    should "mark connection healthy if it succeeds" do
      c = stub_everything(:failures => 1)
      @transport.expects(:get_connection).returns(c)
      c.expects(:healthy!)

      @transport.perform_request('GET', '/') { |connection, url| Elastic::Transport::Transport::Response.new 200, 'OK' }
    end
  end

  context "per-node trust" do
    setup do
      @dir = Dir.mktmpdir
      @node_a = File.join(@dir, 'node-a.pem')
      @node_b = File.join(@dir, 'node-b.pem')
      File.write(@node_a, 'CA A, generation 1')
      File.write(@node_b, 'CA B, generation 1')
    end

    teardown do
      FileUtils.remove_entry(@dir)
    end

    should "give each connection the trust material approved for its own node" do
      transport = build_trust_transport(
        'node-a' => { ssl: { ca_file: @node_a }, version: 1 },
        'node-b' => { ssl: { ca_file: @node_b }, version: 7 }
      )

      a, b = transport.connections.all
      assert_equal @node_a, a.ssl_source
      assert_equal @node_b, b.ssl_source
      assert_equal '1', a.trust_version
      assert_equal '7', b.trust_version
    end

    should "not write the node's trust settings into the transport options" do
      policy = { 'node-a' => { ca_file: @node_a } }
      transport = build_trust_transport(policy)
      refute transport.options[:transport_options]
      refute_includes transport.options.keys, :ca_file
      assert_equal({ ca_file: @node_a }, policy['node-a'], 'the caller\'s policy is not modified')
    end

    should "replace only the connection whose approved certificate changed" do
      policy = {
        'node-a' => { ssl: { ca_file: @node_a }, version: 1 },
        'node-b' => { ssl: { ca_file: @node_b }, version: 1 }
      }
      transport = build_trust_transport(policy)
      original = transport.connections.all.dup

      policy['node-a'] = { ssl: { ca_file: @node_a }, version: 2 }
      transport.refresh_trust!

      a = transport.connections.all.find { |c| c.host[:id] == 'node-a' }
      b = transport.connections.all.find { |c| c.host[:id] == 'node-b' }
      assert_equal @node_a, a.ssl_source
      assert_equal '2', a.trust_version
      assert_same original[1], b, 'the unchanged node keeps its connection'
      refute_same original[0], a
      assert original[0].stale?
      refute original[1].stale?
    end

    should "rebuild a dead connection with the current policy when it is resurrected" do
      policy = {
        'node-a' => { ssl: { ca_file: @node_a }, version: 1 },
        'node-b' => { ssl: { ca_file: @node_b }, version: 1 }
      }
      transport = build_trust_transport(policy)
      dead = transport.connections.all.first
      alive = transport.connections.all.last
      dead.dead!
      later = Time.now + 120
      Time.stubs(:now).returns(later)

      # The certificate was rotated while node-a was down.
      File.write(@node_a, 'CA A, generation 2')
      policy['node-a'] = { ssl: { ca_file: @node_a }, version: 2 }

      transport.resurrect_dead_connections!

      resurrected = transport.connections.all.find { |c| c.host[:id] == 'node-a' }
      refute_same dead, resurrected
      assert_equal '2', resurrected.trust_version
      refute resurrected.dead?
      assert dead.stale?
      assert_same alive, transport.connections.all.find { |c| c.host[:id] == 'node-b' }
      assert_equal 2, transport.connections.all.size
    end

    should "resurrect a dead connection when its approved certificate didn't change" do
      transport = build_trust_transport(
        'node-a' => { ssl: { ca_file: @node_a }, version: 1 },
        'node-b' => { ssl: { ca_file: @node_b }, version: 1 }
      )
      dead = transport.connections.all.first
      dead.dead!
      later = Time.now + 120
      Time.stubs(:now).returns(later)

      transport.resurrect_dead_connections!

      assert_same dead, transport.connections.all.find { |c| c.host[:id] == 'node-a' }
      refute dead.dead?
      refute dead.stale?
    end

    should "retire a removed node without treating it as a failure, and revive it on return" do
      policy = {
        'node-a' => { ssl: { ca_file: @node_a }, version: 1 },
        'node-b' => { ssl: { ca_file: @node_b }, version: 1 }
      }
      hosts = [
        { id: 'node-a', host: 'node-a.test', port: 9200, scheme: 'https' },
        { id: 'node-b', host: 'node-b.test', port: 9200, scheme: 'https' }
      ]
      transport = build_trust_transport(policy, hosts)
      removed = transport.connections.all.last

      hosts.pop
      transport.__rebuild_connections(hosts: hosts, options: transport.options)

      assert_equal 1, transport.connections.all.size
      assert_equal 1, transport.retired_connections.size
      assert removed.retired?
      assert_equal 0, removed.failures, 'removal is not a node failure'
      assert_equal :retired, removed.status

      # The node returns with the same approved certificate generation.
      hosts << { id: 'node-b', host: 'node-b.test', port: 9200, scheme: 'https' }
      transport.__rebuild_connections(hosts: hosts, options: transport.options)

      assert_equal 2, transport.connections.all.size
      assert_empty transport.retired_connections
      assert_same removed, transport.connections.all.last
      refute removed.retired?
      assert_equal :alive, removed.status
    end

    should "rebuild a returning node whose certificate changed while it was removed" do
      policy = {
        'node-a' => { ssl: { ca_file: @node_a }, version: 1 },
        'node-b' => { ssl: { ca_file: @node_b }, version: 1 }
      }
      hosts = [
        { id: 'node-a', host: 'node-a.test', port: 9200, scheme: 'https' },
        { id: 'node-b', host: 'node-b.test', port: 9200, scheme: 'https' }
      ]
      transport = build_trust_transport(policy, hosts)
      retired = transport.connections.all.last

      hosts.pop
      transport.__rebuild_connections(hosts: hosts, options: transport.options)

      policy['node-b'] = { ssl: { ca_file: @node_b }, version: 2 }
      hosts << { id: 'node-b', host: 'node-b.test', port: 9200, scheme: 'https' }
      transport.__rebuild_connections(hosts: hosts, options: transport.options)

      b = transport.connections.all.last
      refute_same retired, b
      assert_equal '2', b.trust_version
      assert retired.stale?
      assert_empty transport.retired_connections
    end

    should "not use a dead connection rebuilt for a new policy before its resurrection time" do
      policy = {
        'node-a' => { ssl: { ca_file: @node_a }, version: 1 },
        'node-b' => { ssl: { ca_file: @node_b }, version: 1 }
      }
      transport = build_trust_transport(policy)
      dead = transport.connections.all.first
      dead.dead!

      # A live request notices the new policy but must not bring the dead node back early.
      policy['node-a'] = { ssl: { ca_file: @node_a }, version: 2 }
      transport.refresh_trust!

      assert dead.stale?
      assert dead.dead?
      assert_equal :stale, dead.status
      assert_equal 2, transport.connections.all.size
      assert_equal 1, transport.connections.size, 'only node-b is selectable'
      assert_equal 'node-b', transport.get_connection.host[:id]
    end

    should "resurrect the connection separately from the trust change" do
      policy = {
        'node-a' => { ssl: { ca_file: @node_a }, version: 1 },
        'node-b' => { ssl: { ca_file: @node_b }, version: 1 }
      }
      transport = build_trust_transport(policy)
      dead = transport.connections.all.first
      dead.dead!

      policy['node-a'] = { ssl: { ca_file: @node_a }, version: 2 }
      later = Time.now + 121
      Time.stubs(:now).returns(later)
      transport.get_connection

      a = transport.connections.all.find { |c| c.host[:id] == 'node-a' }
      refute_same dead, a
      refute a.dead?
      assert_equal '2', a.trust_version
      assert dead.stale?
    end

    should "raise when a node entry sets an SSL option the adapter can't apply" do
      error = assert_raises(ArgumentError) do
        build_trust_transport('node-a' => { ca_file: @node_a, min_version: 'TLS1_2' })
      end
      assert_match(/unsupported settings: min_version/, error.message)
    end

    should "keep round-robin selecting the surviving connection after a rotation" do
      policy = {
        'node-a' => { ssl: { ca_file: @node_a }, version: 1 },
        'node-b' => { ssl: { ca_file: @node_b }, version: 1 }
      }
      transport = build_trust_transport(policy)
      selected = 4.times.map { transport.get_connection.host[:id] }
      assert_equal %w[node-a node-b node-a node-b], selected

      policy['node-b'] = { ssl: { ca_file: @node_b }, version: 2 }
      selected = 4.times.map { transport.get_connection.host[:id] }
      assert_equal %w[node-a node-b node-a node-b], selected
    end

    should "raise when an entry has no trust anchor" do
      error = assert_raises(ArgumentError) do
        build_trust_transport('node-a' => { ssl: { verify_hostname: false } })
      end
      assert_match(/has no trust anchor/, error.message)
    end

    should "raise when an entry carries two trust anchors" do
      error = assert_raises(ArgumentError) do
        build_trust_transport('node-a' => { ssl: { ca_file: @node_a, ca_path: @dir } })
      end
      assert_match(/more than one trust anchor/, error.message)
    end

    should "raise when an entry disables verification" do
      error = assert_raises(ArgumentError) do
        build_trust_transport('node-a' => { ssl: { ca_file: @node_a, verify: false } })
      end
      assert_match(/can't disable certificate verification/, error.message)
    end

    should "raise for trust material on an http host" do
      error = assert_raises(Elastic::Transport::Transport::Error) do
        build_trust_transport(
          { 'node-a' => { ca_file: @node_a } },
          [{ id: 'node-a', host: 'node-a.test', port: 9200 }]
        )
      end
      assert_match(/can't be configured over http/, error.message)
    end

    should "prefer the node's own trust anchor over the transport-wide one" do
      transport = TrustAwareTransport.new(
        hosts: [{ id: 'node-a', host: 'node-a.test', port: 9200, scheme: 'https' }],
        options: {
          node_trust: { 'node-a' => { ca_file: @node_a } },
          transport_options: { ssl: { ca_file: @node_b, verify_hostname: false } }
        }
      )
      ssl = transport.connections.all.first.ssl_options
      assert_equal @node_a, ssl[:ca_file]
      assert_equal false, ssl[:verify_hostname]
    end

    should "inherit the transport-wide SSL settings for nodes without an entry" do
      transport = build_trust_transport_with(
        { 'node-a' => { ca_file: @node_a } },
        transport_options: { ssl: { ca_file: @node_b } }
      )
      a = transport.connections.all.find { |c| c.host[:id] == 'node-a' }
      b = transport.connections.all.find { |c| c.host[:id] == 'node-b' }
      assert_equal @node_a, a.ssl_source
      assert_equal @node_b, b.ssl_source
    end

    should "keep a default entry for nodes without their own" do
      transport = build_trust_transport(
        'node-a' => { ca_file: @node_a },
        'default' => { ca_file: @node_b }
      )
      a = transport.connections.all.find { |c| c.host[:id] == 'node-a' }
      b = transport.connections.all.find { |c| c.host[:id] == 'node-b' }
      assert_equal @node_a, a.ssl_source
      assert_equal @node_b, b.ssl_source
    end

    should "resolve host:port and bare host entries" do
      transport = build_trust_transport(
        'node-a.test:9200' => { ca_file: @node_a },
        'node-b.test' => { ca_file: @node_b }
      )
      assert_equal @node_a, transport.connections.all.first.ssl_source
      assert_equal @node_b, transport.connections.all.last.ssl_source
    end

    should "raise when combined with ca_fingerprint" do
      error = assert_raises(ArgumentError) do
        TrustAwareTransport.new(
          hosts: [{ id: 'node-a', host: 'node-a.test', port: 9200, scheme: 'https' }],
          options: { ca_fingerprint: 'ABC', node_trust: { 'node-a' => { ca_file: @node_a } } }
        )
      end
      assert_match(/ca_fingerprint/, error.message)
    end

    should "keep the last approved trust when a node loses its entry" do
      policy = { 'node-a' => { ssl: { ca_file: @node_a }, version: 1 } }
      transport = build_trust_transport(policy)
      before = transport.connections.all.first

      policy.delete('node-a')
      transport.refresh_trust!

      assert_same before, transport.connections.all.first
      refute before.stale?
    end

    should "pick up a policy Hash that is updated in place" do
      policy = { 'node-a' => { ssl: { ca_file: @node_a }, version: 1 } }
      transport = build_trust_transport(policy)

      policy['node-a'] = { ssl: { ca_file: @node_a }, version: 2 }
      transport.refresh_trust!

      a = transport.connections.all.find { |c| c.host[:id] == 'node-a' }
      assert_equal '2', a.trust_version
    end

    should "accept a callable policy" do
      current = { 'node-a' => { ssl: { ca_file: @node_a }, version: 1 } }
      transport = TrustAwareTransport.new(
        hosts: [{ id: 'node-a', host: 'node-a.test', port: 9200, scheme: 'https' }],
        options: { node_trust: -> { current } }
      )
      assert_equal '1', transport.connections.all.first.trust_version

      current = { 'node-a' => { ssl: { ca_file: @node_a }, version: 5 } }
      transport.refresh_trust!
      assert_equal '5', transport.connections.all.first.trust_version
    end

    should "notice a certificate rotated on disk without an explicit version" do
      policy = { 'node-a' => { ca_file: @node_a } }
      transport = build_trust_transport(policy)
      before = transport.connections.all.first

      # Different content *and* a new mtime, as a rewritten CA file has.
      File.write(@node_a, 'CA A, generation 2')
      File.utime(Time.now + 5, Time.now + 5, @node_a)
      transport.refresh_trust!

      after = transport.connections.all.first
      refute_same before, after
      refute_equal before.trust_version, after.trust_version
    end

    should "notice a certificate rotated on disk while serving requests" do
      policy = { 'node-a' => { ca_file: @node_a } }
      transport = build_trust_transport(policy)
      transport.get_connection
      before = transport.connections.all.first

      File.write(@node_a, 'CA A, generation 2')
      File.utime(Time.now + 5, Time.now + 5, @node_a)
      later = Time.now + 2
      Time.stubs(:now).returns(later)
      transport.get_connection

      after = transport.connections.all.first
      refute_same before, after
      refute_equal before.trust_version, after.trust_version
    end

    should "pick up an in-place policy edit without waiting for the file check interval" do
      policy = { 'node-a' => { ssl: { ca_file: @node_a }, version: 1 } }
      transport = build_trust_transport(policy)
      transport.get_connection

      policy['node-a'] = { ssl: { ca_file: @node_a }, version: 2 }
      transport.get_connection

      assert_equal '2', transport.connections.all.first.trust_version
    end

    should "treat a replaced cert_store as a new generation" do
      store = OpenSSL::X509::Store.new
      replacement = OpenSSL::X509::Store.new
      policy = { 'node-a' => { ssl: { cert_store: store } } }
      transport = build_trust_transport(policy)

      policy['node-a'] = { ssl: { cert_store: replacement } }
      transport.refresh_trust!

      store_seen = transport.connections.all.first.ssl_options[:cert_store]
      assert_same replacement, store_seen
      refute_same store, store_seen
    end
  end

  context "per-node trust with a custom selector" do
    class RecordingSelector
      include Elastic::Transport::Transport::Connections::Selector::Base
      attr_reader :pools

      def initialize(arguments = {})
        super
        @pools = [arguments[:connections]]
      end

      def select(_options = {})
        connections.to_a.find { |connection| !connection.dead? }
      end
    end

    setup do
      @dir = Dir.mktmpdir
      @ca = File.join(@dir, 'ca.pem')
      File.write(@ca, 'CA')
    end

    teardown do
      FileUtils.remove_entry(@dir)
    end

    should "build through the adapter hook so transports that override __build_connections still work" do
      transport = Class.new(TrustAwareTransport) do
        attr_reader :built, :builds

        def __build_connections
          @builds = (@builds || 0) + 1
          @built = super
        end
      end.new(
        hosts: [{ id: 'node-a', host: 'node-a.test', port: 9200, scheme: 'https' }],
        options: { node_trust: { 'node-a' => { ca_file: @ca } } }
      )
      builds_before = transport.builds

      transport.__rebuild_connections(
        hosts: [{ id: 'node-a', host: 'node-a.test', port: 9200, scheme: 'https' }],
        options: transport.options
      )

      assert_equal builds_before + 1, transport.builds
      assert_equal transport.built.all.first, transport.connections.all.first
    end

    should "keep the selector pointed at the live pool across rebuilds and rotations" do
      hosts = [
        { id: 'node-a', host: 'node-a.test', port: 9200, scheme: 'https' },
        { id: 'node-b', host: 'node-b.test', port: 9200, scheme: 'https' }
      ]
      policy = {
        'node-a' => { ssl: { ca_file: @ca }, version: 1 },
        'node-b' => { ssl: { ca_file: @ca }, version: 1 }
      }
      transport = TrustAwareTransport.new(
        hosts: hosts,
        options: { node_trust: policy, selector_class: RecordingSelector, resurrect_after: 0 }
      )
      selector = transport.connections.selector
      assert_same transport.connections, selector.connections

      transport.__rebuild_connections(hosts: hosts, options: transport.options)
      assert_same selector, transport.connections.selector
      assert_same transport.connections, selector.connections

      policy['node-a'] = { ssl: { ca_file: @ca }, version: 2 }
      transport.refresh_trust!
      assert_same selector, transport.connections.selector
      assert_same transport.connections, selector.connections
      # The custom strategy always picks the first live node; the important part is that the pool
      # it reads still contains the rebuilt connection.
      assert_equal %w[node-a node-a], 2.times.map { transport.get_connection.host[:id] }
      assert_equal '2', transport.connections.all.first.trust_version
    end
  end

  context "errors" do
    should "raise highest-level Error exception for any ServerError" do
      assert_kind_of Elastic::Transport::Transport::Error, Elastic::Transport::Transport::ServerError.new
    end
  end
end
