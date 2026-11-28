# frozen_string_literal: true

require File.expand_path(File.dirname(__FILE__) + '/test_helper')
require File.expand_path(File.dirname(__FILE__) + '/net_connect_scope_helper')

describe 'WebMock net-connect scopes' do
  before do
    @config = WebMock::Config.instance
    @original_config = {
      allow_net_connect: @config.allow_net_connect,
      allow_localhost: @config.allow_localhost,
      allow: @config.allow,
      net_http_connect_on_start: @config.net_http_connect_on_start
    }
    WebMock.disable_net_connect!
    RecordingHttpAdapter.reset!
    @allowed_host = 'allowed.example.test'
    @rejected_host = 'rejected.example.test'
    @allowed_uri = "http://#{@allowed_host}:80/widgets"
    @rejected_uri = "http://#{@rejected_host}:80/widgets"
    @allowed_stub = stub_http_request(:get, @allowed_uri).to_return(body: 'allowed stub')
    @rejected_stub = stub_http_request(:get, @rejected_uri).to_return(body: 'rejected stub')
  end

  after do
    WebMock.reset!
    RecordingHttpAdapter.reset!
    @original_config.each do |key, value|
      @config.public_send("#{key}=", value)
    end
  end

  def client_for(uri)
    RecordingHttp::Client.new(Addressable::URI.parse(uri))
  end

  def connections(host)
    RecordingHttpAdapter.connections_for(host)
  end

  describe 'scope permission rules' do
    it 'reports the scope-wide switch without a URI' do
      WebMock.disable_net_connect_scope do
        refute WebMock.net_connect_allowed?
      end

      WebMock.allow_net_connect_scope do
        assert WebMock.net_connect_allowed?
      end
    end

    it 'honours allow_localhost only inside the scope' do
      WebMock.allow_net_connect!
      WebMock.disable_net_connect_scope(allow_localhost: true) do
        assert WebMock.net_connect_allowed?('http://127.0.0.1:3000/health')
        assert WebMock.net_connect_allowed?('http://localhost:3000/health')
        refute WebMock.net_connect_allowed?('http://remote.example.test/')
      end

      assert WebMock.net_connect_allowed?('http://remote.example.test/')
    end

    it 'closes an explicitly opened scope and returns to global rules' do
      scope = WebMock.disable_net_connect_scope(allow: @allowed_host)
      scope.activate do
        assert WebMock.net_connect_allowed?(@allowed_uri)
        refute WebMock.net_connect_allowed?(@rejected_uri)
        scope.close
        refute WebMock.net_connect_allowed?(@allowed_uri)
      end
    end
  end

  describe 'first-request adapter lifecycle' do
    it 'connects for the allow group and refuses the reject group inside one scope' do
      WebMock.disable_net_connect_scope(allow: @allowed_host) do
        allowed = client_for(@allowed_uri).start
        response = allowed.request(:get, '/live')

        assert_equal true, response[:real]
        assert_equal [{ host: @allowed_host, port: 80, phase: :request }],
                     connections(@allowed_host)

        rejected = client_for(@rejected_uri).start
        assert_raises(WebMock::NetConnectNotAllowedError) do
          rejected.request(:get, '/live')
        end
        assert_empty connections(@rejected_host)
      end
    end

    it 'keeps each concurrent scope to its own allow group' do
      scope_a = WebMock.disable_net_connect_scope(allow: @allowed_host)
      scope_b = WebMock.disable_net_connect_scope(allow: @rejected_host)

      scope_a.activate do
        assert WebMock.net_connect_allowed?(@allowed_uri)
        refute WebMock.net_connect_allowed?(@rejected_uri)
      end

      scope_b.activate do
        assert WebMock.net_connect_allowed?(@rejected_uri)
        refute WebMock.net_connect_allowed?(@allowed_uri)
      end
    ensure
      scope_a&.close
      scope_b&.close
    end

    it 'preserves the other scope when one scope is closed' do
      scope_a = WebMock.disable_net_connect_scope(allow: @allowed_host)
      scope_b = WebMock.disable_net_connect_scope(allow: @rejected_host)

      scope_a.close

      assert scope_a.closed?
      assert scope_b.open?
      scope_b.activate do
        assert WebMock.net_connect_allowed?(@rejected_uri)
        refute WebMock.net_connect_allowed?(@allowed_uri)
      end
    ensure
      scope_b&.close
    end

    it 'does not touch the global configuration or the other scope rules' do
      WebMock.disable_net_connect!(allow: 'global.example.test')
      global_allow = WebMock::Config.instance.allow

      scope_a = WebMock.disable_net_connect_scope(allow: @allowed_host)
      scope_b = WebMock.disable_net_connect_scope(allow: @rejected_host)
      scope_a.close

      assert_equal global_allow, WebMock::Config.instance.allow
      assert_nil WebMock::Config.instance.allow_localhost

      scope_b.activate do
        assert WebMock.net_connect_allowed?(@rejected_uri)
      end
      scope_b.close

      assert WebMock.net_connect_allowed?('http://global.example.test/')
      refute WebMock.net_connect_allowed?(@allowed_uri)
    end
  end

  describe 'pre-connect adapter lifecycle' do
    it 'records the connect intention on start only for the allowed group' do
      WebMock.disable_net_connect_scope(
        allow: @allowed_host, net_http_connect_on_start: @allowed_host
      ) do
        allowed = client_for(@allowed_uri)
        allowed.start
        assert_equal [{ host: @allowed_host, port: 80, phase: :start }],
                     connections(@allowed_host)

        rejected = client_for(@rejected_uri)
        rejected.start
        assert_empty connections(@rejected_host)
      end
    end

    it 'honours a host-specific connect-on-start allowlist in a scope' do
      WebMock.disable_net_connect_scope(
        allow: @allowed_host, net_http_connect_on_start: @allowed_host
      ) do
        client_for(@allowed_uri).start
        client_for(@rejected_uri).start

        assert_equal :start, connections(@allowed_host).first&.fetch(:phase)
        assert_empty connections(@rejected_host)
      end
    end

    it 'does not connect on start by default, even when the request is allowed' do
      WebMock.disable_net_connect_scope(allow: @allowed_host) do
        client = client_for(@allowed_uri)
        client.start

        assert_empty connections(@allowed_host)

        client.request(:get, '/live')
        assert_equal [:request], connections(@allowed_host).map { |record| record[:phase] }
      end
    end

    it 'isolates connect-on-start rules between concurrent scopes' do
      scope_a = WebMock.disable_net_connect_scope(
        allow: @allowed_host, net_http_connect_on_start: @allowed_host
      )
      scope_b = WebMock.disable_net_connect_scope(
        allow: @rejected_host, net_http_connect_on_start: @rejected_host
      )

      begin
        scope_a.activate { client_for(@allowed_uri).start }
        scope_b.activate do
          client_for(@rejected_uri).start

          assert_equal :start, connections(@allowed_host).first&.fetch(:phase)
          assert_equal :start, connections(@rejected_host).first&.fetch(:phase)

          # Closing the other scope must not reset this scope's connect rules.
          scope_a.close
          assert scope_a.closed?
          assert scope_b.open?
          assert WebMock.net_http_connect_on_start?(
            Addressable::URI.parse(@rejected_uri)
          )
          refute WebMock.net_http_connect_on_start?(
            Addressable::URI.parse(@allowed_uri)
          )
        end
      ensure
        scope_a.close
        scope_b.close
      end
    end
  end

  describe 'existing stub behaviour' do
    it 'still answers stubs without recording a connection inside a scope' do
      WebMock.disable_net_connect_scope(allow: @allowed_host) do
        response = client_for(@allowed_uri).start.request(:get, '/widgets')

        assert_equal false, response[:real]
        assert_equal 'allowed stub', response[:body]
        assert_empty connections(@allowed_host)
        assert_requested(:get, @allowed_uri, times: 1)
      end
    end

    it 'keeps stubs registered in one scope available after the other closes' do
      scope_a = WebMock.disable_net_connect_scope(allow: @allowed_host)
      scope_b = WebMock.disable_net_connect_scope(allow: @rejected_host)
      scope_a.close

      scope_b.activate do
        response = client_for(@rejected_uri).start.request(:get, '/widgets')
        assert_equal 'rejected stub', response[:body]
      end
    ensure
      scope_b&.close
    end

    it 'falls back to global rules when no scope is active' do
      WebMock.allow_net_connect!
      response = client_for(@allowed_uri).start.request(:get, '/live')
      assert_equal true, response[:real]
    end
  end
end
