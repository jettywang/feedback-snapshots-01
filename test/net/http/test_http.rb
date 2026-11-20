# coding: US-ASCII
# frozen_string_literal: false
require 'test/unit'
require 'net/http'
require 'stringio'
require 'timeout'
require_relative 'utils'

class TestNetHTTP < Test::Unit::TestCase

  def test_class_Proxy
    no_proxy_class = Net::HTTP.Proxy nil

    assert_equal Net::HTTP, no_proxy_class

    proxy_class = Net::HTTP.Proxy 'proxy.example', 8000, 'user', 'pass'

    assert_not_equal Net::HTTP, proxy_class

    assert_operator proxy_class, :<, Net::HTTP

    assert_equal 'proxy.example', proxy_class.proxy_address
    assert_equal 8000,            proxy_class.proxy_port
    assert_equal 'user',          proxy_class.proxy_user
    assert_equal 'pass',          proxy_class.proxy_pass

    http = proxy_class.new 'hostname.example'

    assert_not_predicate http, :proxy_from_env?


    proxy_class = Net::HTTP.Proxy 'proxy.example'
    assert_equal 'proxy.example', proxy_class.proxy_address
    assert_equal 80,              proxy_class.proxy_port
  end

  def test_class_Proxy_from_ENV
    TestNetHTTPUtils.clean_http_proxy_env do
      ENV['http_proxy']      = 'http://proxy.example:8000'

      # These are ignored on purpose.  See Bug 4388 and Feature 6546
      ENV['http_proxy_user'] = 'user'
      ENV['http_proxy_pass'] = 'pass'

      proxy_class = Net::HTTP.Proxy :ENV

      assert_not_equal Net::HTTP, proxy_class

      assert_operator proxy_class, :<, Net::HTTP

      assert_nil proxy_class.proxy_address
      assert_nil proxy_class.proxy_user
      assert_nil proxy_class.proxy_pass

      assert_not_equal 8000, proxy_class.proxy_port

      http = proxy_class.new 'hostname.example'

      assert http.proxy_from_env?
    end
  end

  def test_addr_port
    http = Net::HTTP.new 'hostname.example', nil, nil
    addr_port = http.__send__ :addr_port
    assert_equal 'hostname.example', addr_port

    http.use_ssl = true
    addr_port = http.__send__ :addr_port
    assert_equal 'hostname.example:80', addr_port

    http = Net::HTTP.new '203.0.113.1', nil, nil
    addr_port = http.__send__ :addr_port
    assert_equal '203.0.113.1', addr_port

    http.use_ssl = true
    addr_port = http.__send__ :addr_port
    assert_equal '203.0.113.1:80', addr_port

    http = Net::HTTP.new '2001:db8::1', nil, nil
    addr_port = http.__send__ :addr_port
    assert_equal '[2001:db8::1]', addr_port

    http.use_ssl = true
    addr_port = http.__send__ :addr_port
    assert_equal '[2001:db8::1]:80', addr_port

  end

  def test_edit_path
    http = Net::HTTP.new 'hostname.example', nil, nil

    edited = http.send :edit_path, '/path'

    assert_equal '/path', edited

    http.use_ssl = true

    edited = http.send :edit_path, '/path'

    assert_equal '/path', edited
  end

  def test_edit_path_proxy
    http = Net::HTTP.new 'hostname.example', nil, 'proxy.example'

    edited = http.send :edit_path, '/path'

    assert_equal 'http://hostname.example/path', edited

    http.use_ssl = true

    edited = http.send :edit_path, '/path'

    assert_equal '/path', edited
  end

  def test_proxy_address
    TestNetHTTPUtils.clean_http_proxy_env do
      http = Net::HTTP.new 'hostname.example', nil, 'proxy.example'
      assert_equal 'proxy.example', http.proxy_address

      http = Net::HTTP.new 'hostname.example', nil
      assert_equal nil, http.proxy_address
    end
  end

  def test_proxy_address_no_proxy
    TestNetHTTPUtils.clean_http_proxy_env do
      http = Net::HTTP.new 'hostname.example', nil, 'proxy.com', nil, nil, nil, 'example'
      assert_nil http.proxy_address

      http = Net::HTTP.new '10.224.1.1', nil, 'proxy.com', nil, nil, nil, 'example,10.224.0.0/22'
      assert_nil http.proxy_address
    end
  end

  def test_proxy_from_env_ENV
    TestNetHTTPUtils.clean_http_proxy_env do
      ENV['http_proxy'] = 'http://proxy.example:8000'

      assert_equal false, Net::HTTP.proxy_class?
      http = Net::HTTP.new 'hostname.example'

      assert_equal true, http.proxy_from_env?
    end
  end

  def test_proxy_address_ENV
    TestNetHTTPUtils.clean_http_proxy_env do
      ENV['http_proxy'] = 'http://proxy.example:8000'

      http = Net::HTTP.new 'hostname.example'

      assert_equal 'proxy.example', http.proxy_address
    end
  end

  def test_proxy_eh_no_proxy
    TestNetHTTPUtils.clean_http_proxy_env do
      assert_equal false, Net::HTTP.new('hostname.example', nil, nil).proxy?
    end
  end

  def test_proxy_eh_ENV
    TestNetHTTPUtils.clean_http_proxy_env do
      ENV['http_proxy'] = 'http://proxy.example:8000'

      http = Net::HTTP.new 'hostname.example'

      assert_equal true, http.proxy?
    end
  end

  def test_proxy_eh_ENV_with_user
    TestNetHTTPUtils.clean_http_proxy_env do
      ENV['http_proxy'] = 'http://foo:bar@proxy.example:8000'

      http = Net::HTTP.new 'hostname.example'

      assert_equal true, http.proxy?
      assert_equal 'foo', http.proxy_user
      assert_equal 'bar', http.proxy_pass
    end
  end

  def test_proxy_eh_ENV_with_urlencoded_user
    TestNetHTTPUtils.clean_http_proxy_env do
      ENV['http_proxy'] = 'http://Y%5CX:R%25S%5D%20%3FX@proxy.example:8000'

      http = Net::HTTP.new 'hostname.example'

      assert_equal true, http.proxy?
      assert_equal "Y\\X", http.proxy_user
      assert_equal "R%S] ?X", http.proxy_pass
    end
  end

  def test_proxy_eh_ENV_none_set
    TestNetHTTPUtils.clean_http_proxy_env do
      assert_equal false, Net::HTTP.new('hostname.example').proxy?
    end
  end

  def test_proxy_eh_ENV_no_proxy
    TestNetHTTPUtils.clean_http_proxy_env do
      ENV['http_proxy'] = 'http://proxy.example:8000'
      ENV['no_proxy']   = 'hostname.example'

      assert_equal false, Net::HTTP.new('hostname.example').proxy?
    end
  end

  def test_proxy_port
    TestNetHTTPUtils.clean_http_proxy_env do
      http = Net::HTTP.new 'example', nil, 'proxy.example'
      assert_equal 'proxy.example', http.proxy_address
      assert_equal 80, http.proxy_port
      http = Net::HTTP.new 'example', nil, 'proxy.example', 8000
      assert_equal 8000, http.proxy_port
      http = Net::HTTP.new 'example', nil
      assert_equal nil, http.proxy_port
    end
  end

  def test_proxy_port_ENV
    TestNetHTTPUtils.clean_http_proxy_env do
      ENV['http_proxy'] = 'http://proxy.example:8000'

      http = Net::HTTP.new 'hostname.example'

      assert_equal 8000, http.proxy_port
    end
  end

  def test_newobj
    TestNetHTTPUtils.clean_http_proxy_env do
      ENV['http_proxy'] = 'http://proxy.example:8000'

      http = Net::HTTP.newobj 'hostname.example'

      assert_equal false, http.proxy?
    end
  end

  def test_failure_message_includes_failed_domain_and_port
    # hostname to be included in the error message
    host = Struct.new(:to_s).new("<example>")
    port = 2119
    # hack to let TCPSocket.open fail
    def host.to_str; raise SocketError, "open failure"; end
    uri = Struct.new(:scheme, :hostname, :port).new("http", host, port)
    assert_raise_with_message(SocketError, /#{host}:#{port}/) do
      TestNetHTTPUtils.clean_http_proxy_env{ Net::HTTP.get(uri) }
    end
  end

  def test_default_configuration
    Net::HTTP.default_configuration = { open_timeout: 5 }
    http = Net::HTTP.new 'hostname.example'
    assert_equal 5, http.open_timeout
    assert_equal 60, http.read_timeout

    http.open_timeout = 10
    assert_equal 10, http.open_timeout
  ensure
    Net::HTTP.default_configuration = nil
  end

  def test_require_does_not_load_resolv
    assert_separately([], <<~'RUBY')
      require 'net/http'
      assert_nil defined?(Resolv)
    RUBY
  end

end

module TestNetHTTP_version_1_1_methods

  def test_s_start
    begin
      h = Net::HTTP.start(config('host'), config('port'))
    ensure
      h&.finish
    end
    assert_equal config('host'), h.address
    assert_equal config('port'), h.port
    assert_equal true, h.instance_variable_get(:@proxy_from_env)

    begin
      h = Net::HTTP.start(config('host'), config('port'), :ENV)
    ensure
      h&.finish
    end
    assert_equal config('host'), h.address
    assert_equal config('port'), h.port
    assert_equal true, h.instance_variable_get(:@proxy_from_env)

    begin
      h = Net::HTTP.start(config('host'), config('port'), nil)
    ensure
      h&.finish
    end
    assert_equal config('host'), h.address
    assert_equal config('port'), h.port
    assert_equal false, h.instance_variable_get(:@proxy_from_env)
  end

  def test_s_get
    assert_equal $test_net_http_data,
        Net::HTTP.get(config('host'), '/', config('port'))

    assert_equal $test_net_http_data, Net::HTTP.get(
      URI.parse("http://#{config('host')}:#{config('port')}")
    )
    assert_equal $test_net_http_data, Net::HTTP.get(
      URI.parse("http://#{config('host')}:#{config('port')}"), "Accept" => "text/plain"
    )
  end

  def test_s_get_response
    res = Net::HTTP.get_response(
      URI.parse("http://#{config('host')}:#{config('port')}")
    )
    assert_equal "application/octet-stream", res["Content-Type"]
    assert_equal $test_net_http_data, res.body

    res = Net::HTTP.get_response(
      URI.parse("http://#{config('host')}:#{config('port')}"), "Accept" => "text/plain"
    )
    assert_equal "text/plain", res["Content-Type"]
    assert_equal $test_net_http_data, res.body
  end

  def test_head
    start {|http|
      res = http.head('/')
      assert_kind_of Net::HTTPResponse, res
      assert_equal $test_net_http_data_type, res['Content-Type']
      unless self.is_a?(TestNetHTTP_v1_2_chunked)
        assert_equal $test_net_http_data.size, res['Content-Length'].to_i
      end
    }
  end

  def test_get
    start {|http|
      _test_get__get http
      _test_get__iter http
      _test_get__chunked http
    }
  end

  def _test_get__get(http)
    res = http.get('/')
    assert_kind_of Net::HTTPResponse, res
    assert_kind_of String, res.body
    unless self.is_a?(TestNetHTTP_v1_2_chunked)
      assert_not_nil res['content-length']
      assert_equal $test_net_http_data.size, res['content-length'].to_i
    end
    assert_equal $test_net_http_data_type, res['Content-Type']
    assert_equal $test_net_http_data.size, res.body.size
    assert_equal $test_net_http_data, res.body

    assert_nothing_raised {
      http.get('/', { 'User-Agent' => 'test' }.freeze)
    }

    assert res.decode_content, '[Bug #7924]' if Net::HTTP::HAVE_ZLIB
  end

  def _test_get__iter(http)
    buf = ''
    res = http.get('/') {|s| buf << s }
    assert_kind_of Net::HTTPResponse, res
    # assert_kind_of String, res.body
    unless self.is_a?(TestNetHTTP_v1_2_chunked)
      assert_not_nil res['content-length']
      assert_equal $test_net_http_data.size, res['content-length'].to_i
    end
    assert_equal $test_net_http_data_type, res['Content-Type']
    assert_equal $test_net_http_data.size, buf.size
    assert_equal $test_net_http_data, buf
    # assert_equal $test_net_http_data.size, res.body.size
    # assert_equal $test_net_http_data, res.body
  end

  def _test_get__chunked(http)
    buf = ''
    res = http.get('/') {|s| buf << s }
    assert_kind_of Net::HTTPResponse, res
    # assert_kind_of String, res.body
    unless self.is_a?(TestNetHTTP_v1_2_chunked)
      assert_not_nil res['content-length']
      assert_equal $test_net_http_data.size, res['content-length'].to_i
    end
    assert_equal $test_net_http_data_type, res['Content-Type']
    assert_equal $test_net_http_data.size, buf.size
    assert_equal $test_net_http_data, buf
    # assert_equal $test_net_http_data.size, res.body.size
    # assert_equal $test_net_http_data, res.body
  end

  def test_get__break
    i = 0
    start {|http|
      http.get('/') do |str|
        i += 1
        break
      end
    }
    assert_equal 1, i
    @log_tester = nil # server may encount ECONNRESET
  end

  def test_get__implicit_start
    res = new().get('/')
    assert_kind_of Net::HTTPResponse, res
    assert_kind_of String, res.body
    unless self.is_a?(TestNetHTTP_v1_2_chunked)
      assert_not_nil res['content-length']
    end
    assert_equal $test_net_http_data_type, res['Content-Type']
    assert_equal $test_net_http_data.size, res.body.size
    assert_equal $test_net_http_data, res.body
  end

  def test_get__crlf
    start {|http|
      assert_raise(ArgumentError) do
        http.get("\r")
      end
      assert_raise(ArgumentError) do
        http.get("\n")
      end
    }
  end

  def test_get2
    start {|http|
      http.get2('/') {|res|
        EnvUtil.suppress_warning do
          assert_kind_of Net::HTTPResponse, res
          assert_kind_of Net::HTTPResponse, res.header
        end

        unless self.is_a?(TestNetHTTP_v1_2_chunked)
          assert_not_nil res['content-length']
        end
        assert_equal $test_net_http_data_type, res['Content-Type']
        assert_kind_of String, res.body
        assert_kind_of String, res.entity
        assert_equal $test_net_http_data.size, res.body.size
        assert_equal $test_net_http_data, res.body
        assert_equal $test_net_http_data, res.entity
      }
    }
  end

  def test_post
    start {|http|
      _test_post__base http
    }
    start {|http|
      _test_post__file http
    }
    start {|http|
      _test_post__no_data http
    }
  end

  def _test_post__base(http)
    uheader = {}
    uheader['Accept'] = 'application/octet-stream'
    uheader['Content-Type'] = 'application/x-www-form-urlencoded'
    data = 'post data'
    res = http.post('/', data, uheader)
    assert_kind_of Net::HTTPResponse, res
    assert_kind_of String, res.body
    assert_equal data, res.body
    assert_equal data, res.entity
  end

  def _test_post__file(http)
    data = 'post data'
    f = StringIO.new
    http.post('/', data, {'content-type' => 'application/x-www-form-urlencoded'}, f)
    assert_equal data, f.string
  end

  def _test_post__no_data(http)
    unless self.is_a?(TestNetHTTP_v1_2_chunked)
      EnvUtil.suppress_warning do
        data = nil
        res = http.post('/', data)
        assert_not_equal '411', res.code
      end
    end
  end

  def test_s_post
    url = "http://#{config('host')}:#{config('port')}/?q=a"
    res = Net::HTTP.post(
            URI.parse(url),
            "a=x")
    assert_equal "application/octet-stream", res["Content-Type"]
    assert_equal "a=x", res.body
    assert_equal url, res["X-request-uri"]

    res = Net::HTTP.post(
              URI.parse(url),
              "hello world",
              "Content-Type" => "text/plain; charset=US-ASCII")
    assert_equal "text/plain; charset=US-ASCII", res["Content-Type"]
    assert_equal "hello world", res.body
  end

  def test_s_post_form
    url = "http://#{config('host')}:#{config('port')}/"
    res = Net::HTTP.post_form(
              URI.parse(url),
              "a" => "x")
    assert_equal ["a=x"], res.body.split(/[;&]/).sort

    res = Net::HTTP.post_form(
              URI.parse(url),
              "a" => "x",
              "b" => "y")
    assert_equal ["a=x", "b=y"], res.body.split(/[;&]/).sort

    res = Net::HTTP.post_form(
              URI.parse(url),
              "a" => ["x1", "x2"],
              "b" => "y")
    assert_equal url, res['X-request-uri']
    assert_equal ["a=x1", "a=x2", "b=y"], res.body.split(/[;&]/).sort

    res = Net::HTTP.post_form(
              URI.parse(url + '?a=x'),
              "b" => "y")
    assert_equal url + '?a=x', res['X-request-uri']
    assert_equal ["b=y"], res.body.split(/[;&]/).sort
  end

  def test_patch
    start {|http|
      _test_patch__base http
    }
  end

  def _test_patch__base(http)
    uheader = {}
    uheader['Accept'] = 'application/octet-stream'
    uheader['Content-Type'] = 'application/x-www-form-urlencoded'
    data = 'patch data'
    res = http.patch('/', data, uheader)
    assert_kind_of Net::HTTPResponse, res
    assert_kind_of String, res.body
    assert_equal data, res.body
    assert_equal data, res.entity
  end

  def test_timeout_during_HTTP_session_write
    th = nil
    # listen for connections... but deliberately do not read
    TCPServer.open('localhost', 0) {|server|
      port = server.addr[1]

      conn = Net::HTTP.new('localhost', port)
      conn.write_timeout = EnvUtil.apply_timeout_scale(0.01)
      conn.read_timeout = EnvUtil.apply_timeout_scale(0.01) if windows?
      conn.open_timeout = EnvUtil.apply_timeout_scale(1)

      th = Thread.new do
        err = !windows? ? Net::WriteTimeout : Net::ReadTimeout
        assert_raise(err) do
          conn.post('/', "a"*50_000_000)
        end
      end
      assert th.join(EnvUtil.apply_timeout_scale(10))
    }
  ensure
    th&.kill
    th&.join
  end

  def test_timeout_during_non_chunked_streamed_HTTP_session_write
    th = nil
    # listen for connections... but deliberately do not read
    TCPServer.open('localhost', 0) {|server|
      port = server.addr[1]

      conn = Net::HTTP.new('localhost', port)
      conn.write_timeout = EnvUtil.apply_timeout_scale(0.01)
      conn.read_timeout = EnvUtil.apply_timeout_scale(0.01) if windows?
      conn.open_timeout = EnvUtil.apply_timeout_scale(1)

      req = Net::HTTP::Post.new('/')
      data = "a"*50_000_000
      req.content_length = data.size
      req['Content-Type'] = 'application/x-www-form-urlencoded'
      req.body_stream = StringIO.new(data)

      th = Thread.new do
        assert_raise(Net::WriteTimeout) { conn.request(req) }
      end
      assert th.join(10)
    }
  ensure
    th&.kill
    th&.join
  end

  def test_timeout_during_HTTP_session
    bug4246 = "expected the HTTP session to have timed out but have not. c.f. [ruby-core:34203]"

    th = nil
    # listen for connections... but deliberately do not read
    TCPServer.open('localhost', 0) {|server|
      port = server.addr[1]

      conn = Net::HTTP.new('localhost', port)
      conn.read_timeout = EnvUtil.apply_timeout_scale(0.01)
      conn.open_timeout = EnvUtil.apply_timeout_scale(1)

      th = Thread.new do
        assert_raise(Net::ReadTimeout) {
          conn.get('/')
        }
      end
      assert th.join(EnvUtil.apply_timeout_scale(10)), bug4246
    }
  ensure
    th.kill
    th.join
  end
end


module TestNetHTTP_version_1_2_methods

  def test_request
    start {|http|
      _test_request__GET http
      _test_request__QUERY http
      _test_request__accept_encoding http
      _test_request__file http
      # _test_request__range http   # WEBrick does not support Range: header.
      _test_request__HEAD http
      _test_request__POST http
      _test_request__uri http
      _test_request__uri_host http
    }
    start {|http|
      _test_request__stream_body http
    }
  end

  def _test_request__GET(http)
    req = Net::HTTP::Get.new('/')
    http.request(req) {|res|
      assert_kind_of Net::HTTPResponse, res
      assert_kind_of String, res.body
      unless self.is_a?(TestNetHTTP_v1_2_chunked)
        assert_not_nil res['content-length']
        assert_equal $test_net_http_data.size, res['content-length'].to_i
      end
      assert_equal $test_net_http_data.size, res.body.size
      assert_equal $test_net_http_data, res.body

      assert res.decode_content, 'Bug #7831' if Net::HTTP::HAVE_ZLIB
    }
  end

  def _test_request__QUERY(http)
    data = 'query data'
    req = Net::HTTP::Query.new('/')
    req['Accept'] = $test_net_http_data_type
    req['Content-Type'] = 'application/x-www-form-urlencoded'
    http.request(req, data) {|res|
      assert_kind_of Net::HTTPResponse, res
      unless self.is_a?(TestNetHTTP_v1_2_chunked)
        assert_equal data.size, res['content-length'].to_i
      end
      assert_kind_of String, res.body
      assert_equal data, res.body
    }
  end

  def _test_request__accept_encoding(http)
    req = Net::HTTP::Get.new('/', 'accept-encoding' => 'deflate')
    http.request(req) {|res|
      assert_kind_of Net::HTTPResponse, res
      assert_kind_of String, res.body
      unless self.is_a?(TestNetHTTP_v1_2_chunked)
        assert_not_nil res['content-length']
        assert_equal $test_net_http_data.size, res['content-length'].to_i
      end
      assert_equal $test_net_http_data.size, res.body.size
      assert_equal $test_net_http_data, res.body

      assert_not_predicate res, :decode_content, 'Bug #7831' if Net::HTTP::HAVE_ZLIB
    }
  end

  def _test_request__file(http)
    req = Net::HTTP::Get.new('/')
    http.request(req) {|res|
      assert_kind_of Net::HTTPResponse, res
      unless self.is_a?(TestNetHTTP_v1_2_chunked)
        assert_not_nil res['content-length']
        assert_equal $test_net_http_data.size, res['content-length'].to_i
      end
      f = StringIO.new("".force_encoding("ASCII-8BIT"))
      res.read_body f
      assert_equal $test_net_http_data.bytesize, f.string.bytesize
      assert_equal $test_net_http_data.encoding, f.string.encoding
      assert_equal $test_net_http_data, f.string
    }
  end

  def _test_request__range(http)
    req = Net::HTTP::Get.new('/')
    req['range'] = 'bytes=0-5'
    assert_equal $test_net_http_data[0,6], http.request(req).body
  end

  def _test_request__HEAD(http)
    req = Net::HTTP::Head.new('/')
    http.request(req) {|res|
      assert_kind_of Net::HTTPResponse, res
      unless self.is_a?(TestNetHTTP_v1_2_chunked)
        assert_not_nil res['content-length']
        assert_equal $test_net_http_data.size, res['content-length'].to_i
      end
      assert_nil res.body
    }
  end

  def _test_request__POST(http)
    data = 'post data'
    req = Net::HTTP::Post.new('/')
    req['Accept'] = $test_net_http_data_type
    req['Content-Type'] = 'application/x-www-form-urlencoded'
    http.request(req, data) {|res|
      assert_kind_of Net::HTTPResponse, res
      unless self.is_a?(TestNetHTTP_v1_2_chunked)
        assert_equal data.size, res['content-length'].to_i
      end
      assert_kind_of String, res.body
      assert_equal data, res.body
    }
  end

  def _test_request__stream_body(http)
    req = Net::HTTP::Post.new('/')
    data = $test_net_http_data
    req.content_length = data.size
    req['Content-Type'] = 'application/x-www-form-urlencoded'
    req.body_stream = StringIO.new(data)
    res = http.request(req)
    assert_kind_of Net::HTTPResponse, res
    assert_kind_of String, res.body
    assert_equal data.size, res.body.size
    assert_equal data, res.body
  end

  def _test_request__path(http)
    uri = URI 'https://hostname.example/'
    req = Net::HTTP::Get.new('/')

    res = http.request(req)

    assert_kind_of URI::Generic, req.uri

    assert_not_equal uri, req.uri

    assert_equal uri, res.uri

    assert_not_same uri,     req.uri
    assert_not_same req.uri, res.uri
  end

  def _test_request__uri(http)
    uri = URI 'https://hostname.example/'
    req = Net::HTTP::Get.new(uri)

    res = http.request(req)

    assert_kind_of URI::Generic, req.uri

    assert_not_equal uri, req.uri

    assert_equal req.uri, res.uri

    assert_not_same uri,     req.uri
    assert_not_same req.uri, res.uri
  end

  def _test_request__uri_host(http)
    uri = URI 'http://other.example/'

    req = Net::HTTP::Get.new(uri)
    req['host'] = 'hostname.example'

    res = http.request(req)

    assert_kind_of URI::Generic, req.uri

    assert_equal URI("http://hostname.example:#{http.port}"), res.uri
  end

  def test_send_request
    start {|http|
      _test_send_request__GET http
      _test_send_request__QUERY http
      _test_send_request__HEAD http
      _test_send_request__POST http
    }
  end

  def _test_send_request__GET(http)
    res = http.send_request('GET', '/')
    assert_kind_of Net::HTTPResponse, res
    unless self.is_a?(TestNetHTTP_v1_2_chunked)
      assert_equal $test_net_http_data.size, res['content-length'].to_i
    end
    assert_kind_of String, res.body
    assert_equal $test_net_http_data, res.body
  end

  def _test_send_request__QUERY(http)
    data = 'aaabbb cc ddddddddddd lkjoiu4j3qlkuoa'
    res = http.send_request('QUERY', '/', data, 'content-type' => 'application/x-www-form-urlencoded')
    assert_kind_of Net::HTTPResponse, res
    unless self.is_a?(TestNetHTTP_v1_2_chunked)
      assert_equal data.size, res['content-length'].to_i
    end
    assert_kind_of String, res.body
    assert_equal data, res.body
  end

  def _test_send_request__HEAD(http)
    res = http.send_request('HEAD', '/')
    assert_kind_of Net::HTTPResponse, res
    unless self.is_a?(TestNetHTTP_v1_2_chunked)
      assert_not_nil res['content-length']
      assert_equal $test_net_http_data.size, res['content-length'].to_i
    end
    assert_nil res.body
  end

  def _test_send_request__POST(http)
    data = 'aaabbb cc ddddddddddd lkjoiu4j3qlkuoa'
    res = http.send_request('POST', '/', data, 'content-type' => 'application/x-www-form-urlencoded')
    assert_kind_of Net::HTTPResponse, res
    assert_kind_of String, res.body
    assert_equal data.size, res.body.size
    assert_equal data, res.body
  end

  def test_set_form
    require 'tempfile'
    Tempfile.create('ruby-test') {|file|
      file << "\u{30c7}\u{30fc}\u{30bf}"
      data = [
        ['name', 'Gonbei Nanashi'],
        ['name', "\u{540d}\u{7121}\u{3057}\u{306e}\u{6a29}\u{5175}\u{885b}"],
        ['s"i\o', StringIO.new("\u{3042 3044 4e9c 925b}")],
        ["file", file, filename: "ruby-test"]
      ]
      expected = <<"__EOM__".gsub(/\n/, "\r\n")
--<boundary>
Content-Disposition: form-data; name="name"

Gonbei Nanashi
--<boundary>
Content-Disposition: form-data; name="name"

\xE5\x90\x8D\xE7\x84\xA1\xE3\x81\x97\xE3\x81\xAE\xE6\xA8\xA9\xE5\x85\xB5\xE8\xA1\x9B
--<boundary>
Content-Disposition: form-data; name="s\\"i\\\\o"

\xE3\x81\x82\xE3\x81\x84\xE4\xBA\x9C\xE9\x89\x9B
--<boundary>
Content-Disposition: form-data; name="file"; filename="ruby-test"
Content-Type: application/octet-stream

\xE3\x83\x87\xE3\x83\xBC\xE3\x82\xBF
--<boundary>--
__EOM__
      start {|http|
        _test_set_form_urlencoded(http, data.reject{|k,v|!v.is_a?(String)})
      }
      start {|http|
        @server.mount('/', lambda {|req, res| res.body = req.body })
        _test_set_form_multipart(http, false, data, expected)
      }
      start {|http|
        @server.mount('/', lambda {|req, res| res.body = req.body })
        _test_set_form_multipart(http, true, data, expected)
      }
    }
  end

  def _test_set_form_urlencoded(http, data)
    req = Net::HTTP::Post.new('/')
    req.set_form(data)
    res = http.request req
    assert_equal "name=Gonbei+Nanashi&name=%E5%90%8D%E7%84%A1%E3%81%97%E3%81%AE%E6%A8%A9%E5%85%B5%E8%A1%9B", res.body
  end

  def _test_set_form_multipart(http, chunked_p, data, expected)
    data.each{|k,v|v.rewind rescue nil}
    req = Net::HTTP::Post.new('/')
    req.set_form(data, 'multipart/form-data')
    req['Transfer-Encoding'] = 'chunked' if chunked_p
    res = http.request req
    body = res.body
    assert_match(/\A--(?<boundary>\S+)/, body)
    /\A--(?<boundary>\S+)/ =~ body
    expected = expected.gsub(/<boundary>/, boundary)
    assert_equal(expected, body)
  end

  def test_set_form_with_file
    require 'tempfile'
    Tempfile.create('ruby-test') {|file|
      file.binmode
      file << $test_net_http_data
      filename = File.basename(file.to_path)
      data = [['file', file]]
      expected = <<"__EOM__".gsub(/\n/, "\r\n")
--<boundary>
Content-Disposition: form-data; name="file"; filename="<filename>"
Content-Type: application/octet-stream

<data>
--<boundary>--
__EOM__
      expected.sub!(/<filename>/, filename)
      expected.sub!(/<data>/, $test_net_http_data)
      start {|http|
        @server.mount('/', lambda {|req, res| res.body = req.body })
        data.each{|k,v|v.rewind rescue nil}
        req = Net::HTTP::Post.new('/')
        req.set_form(data, 'multipart/form-data')
        res = http.request req
        body = res.body
        header, _ = body.split(/\r\n\r\n/, 2)
        assert_match(/\A--(?<boundary>\S+)/, body)
        /\A--(?<boundary>\S+)/ =~ body
        expected = expected.gsub(/<boundary>/, boundary)
        assert_match(/^--(?<boundary>\S+)\r\n/, header)
        assert_match(
          /^Content-Disposition: form-data; name="file"; filename="#{filename}"\r\n/,
          header)
        assert_equal(expected, body)

        # TODO: test with chunked
        # data.each{|k,v|v.rewind rescue nil}
        # req['Transfer-Encoding'] = 'chunked'
        # res = http.request req
        # assert_equal(expected, res.body)
      }
    }
  end

  def test_set_form_multipart_crlf_injection
    build = ->(data, opt = {}) {
      req = Net::HTTP::Post.new('/')
      req.set_form(data, 'multipart/form-data')
      out = +''
      req.send(:encode_multipart_form_data, out, req.instance_variable_get(:@body_data), opt)
    }
    assert_raise(ArgumentError) { build.call([["foo\r\nX-Injected: 1", 'v']]) }
    assert_raise(ArgumentError) { build.call([['f', 'v']], boundary: "abc\r\nX-Injected: 1") }
    assert_raise(ArgumentError) { build.call([['f', 'v', {filename: "a\r\nX-Injected: 1"}]]) }
    assert_raise(ArgumentError) do
      build.call([['f', 'v', {filename: 'a', content_type: "text/plain\r\nX-Injected: 1"}]])
    end
    assert_nothing_raised do
      build.call([['f', 'v', {filename: 'a', content_type: :"text/plain"}]])
    end
  end
end

class TestNetHTTP_v1_2 < Test::Unit::TestCase
  CONFIG = {
    'host' => '127.0.0.1',
    'proxy_host' => nil,
    'proxy_port' => nil,
  }

  include TestNetHTTPUtils
  include TestNetHTTP_version_1_1_methods
  include TestNetHTTP_version_1_2_methods

  def new
    Net::HTTP.version_1_2
    super
  end

  def test_send_large_POST_request
    start {|http|
      data = ' '*6000000
      res = http.send_request('POST', '/', data, 'content-type' => 'application/x-www-form-urlencoded')
      assert_kind_of Net::HTTPResponse, res
      assert_kind_of String, res.body
      assert_equal data.size, res.body.size
      assert_equal data, res.body
    }
  end
end

class TestNetHTTP_v1_2_chunked < Test::Unit::TestCase
  CONFIG = {
    'host' => '127.0.0.1',
    'proxy_host' => nil,
    'proxy_port' => nil,
    'chunked' => true,
  }

  include TestNetHTTPUtils
  include TestNetHTTP_version_1_1_methods
  include TestNetHTTP_version_1_2_methods

  def new
    Net::HTTP.version_1_2
    super
  end

  def test_chunked_break
    assert_nothing_raised("[ruby-core:29229]") {
      start {|http|
        http.request_get('/') {|res|
          res.read_body {|chunk|
            break
          }
        }
      }
    }
  end
end

class TestNetHTTPContinue < Test::Unit::TestCase
  CONFIG = {
    'host' => '127.0.0.1',
    'proxy_host' => nil,
    'proxy_port' => nil,
    'chunked' => true,
  }

  include TestNetHTTPUtils

  def logfile
    @debug = StringIO.new('')
  end

  def mount_proc(&block)
    @server.mount('/continue', block.to_proc)
  end

  def test_expect_continue
    mount_proc {|req, res|
      req.continue
      res.body = req.query['body']
    }
    start {|http|
      uheader = {'content-type' => 'application/x-www-form-urlencoded', 'expect' => '100-continue'}
      http.continue_timeout = 0.2
      http.request_post('/continue', 'body=BODY', uheader) {|res|
        assert_equal('BODY', res.read_body)
      }
    }
    assert_match(/Expect: 100-continue/, @debug.string)
    assert_match(/HTTP\/1.1 100 continue/, @debug.string)
  end

  def test_expect_continue_timeout
    mount_proc {|req, res|
      sleep 0.2
      req.continue # just ignored because it's '100'
      res.body = req.query['body']
    }
    start {|http|
      uheader = {'content-type' => 'application/x-www-form-urlencoded', 'expect' => '100-continue'}
      http.continue_timeout = 0
      http.request_post('/continue', 'body=BODY', uheader) {|res|
        assert_equal('BODY', res.read_body)
      }
    }
    assert_match(/Expect: 100-continue/, @debug.string)
    assert_match(/HTTP\/1.1 100 continue/, @debug.string)
  end

  def test_expect_continue_error
    mount_proc {|req, res|
      res.status = 501
      res.body = req.query['body']
    }
    start {|http|
      uheader = {'content-type' => 'application/x-www-form-urlencoded', 'expect' => '100-continue'}
      http.continue_timeout = 0
      http.request_post('/continue', 'body=ERROR', uheader) {|res|
        assert_equal('ERROR', res.read_body)
      }
    }
    assert_match(/Expect: 100-continue/, @debug.string)
    assert_not_match(/HTTP\/1.1 100 continue/, @debug.string)
  end

  def test_expect_continue_error_before_body
    @log_tester = nil
    mount_proc {|req, res|
      raise TestNetHTTPUtils::Forbidden
    }
    start {|http|
      uheader = {'content-type' => 'application/x-www-form-urlencoded', 'content-length' => '5', 'expect' => '100-continue'}
      http.continue_timeout = 1 # allow the server to respond before sending
      http.request_post('/continue', 'data', uheader) {|res|
        assert_equal(res.code, '403')
      }
    }
    assert_match(/Expect: 100-continue/, @debug.string)
    assert_not_match(/HTTP\/1.1 100 continue/, @debug.string)
  end

  def test_expect_continue_error_while_waiting
    mount_proc {|req, res|
      res.status = 501
      res.body = req.query['body']
    }
    start {|http|
      uheader = {'content-type' => 'application/x-www-form-urlencoded', 'expect' => '100-continue'}
      http.continue_timeout = 0.5
      http.request_post('/continue', 'body=ERROR', uheader) {|res|
        assert_equal('ERROR', res.read_body)
      }
    }
    assert_match(/Expect: 100-continue/, @debug.string)
    assert_not_match(/HTTP\/1.1 100 continue/, @debug.string)
  end
end

class TestNetHTTPExpectContinueRegression < Test::Unit::TestCase
  # A stream that records every read Net::HTTP performs on the request body.
  class RecordingBody
    attr_reader :reads

    def initialize(content)
      @io = StringIO.new(content)
      @reads = []
    end

    def readpartial(*args)
      record(:readpartial)
      @io.readpartial(*args)
    end

    def read(*args)
      record(:read)
      @io.read(*args)
    end

    def first_read_at
      @reads.first && @reads.first[:at]
    end

    private

    def record(kind)
      @reads << {
        at: Process.clock_gettime(Process::CLOCK_MONOTONIC),
        kind: kind,
      }
    end
  end

  # Proves the body writer never ran by failing if Net::HTTP reads at all.
  class UnreadableBody
    def readpartial(*)
      raise 'body was read during early rejection'
    end

    def read(*)
      raise 'body was read during early rejection'
    end
  end

  # A scripted HTTP/1.1 keep-alive server.  It records the request line,
  # headers, body, and timestamps so tests can assert what actually crossed
  # the wire and when the client consumed its request body.
  class ScriptedServer
    attr_reader :port, :requests, :connections, :error

    def initialize(request_count, &handler)
      @request_count = request_count
      @handler = handler
      @requests = []
      @connections = 0
      @error = nil
      @listener = TCPServer.new('127.0.0.1', 0)
      @port = @listener.addr[1]
    end

    def start
      @thread = Thread.new do
        begin
          while @requests.length < @request_count
            socket = @listener.accept
            @connections += 1
            begin
              while @requests.length < @request_count
                exchange = Exchange.read(socket)
                break unless exchange
                @requests << exchange
                @handler.call(exchange, @requests.length - 1)
              end
            ensure
              socket.close
            end
          end
        rescue => exception
          @error = exception
        ensure
          @listener.close unless @listener.closed?
        end
      end
      self
    end

    def join(timeout)
      unless @thread.join(timeout)
        raise "scripted server did not finish"
      end
      raise @error if @error
      self
    end

    def shutdown
      @thread&.kill
      @thread&.join
      @listener.close unless @listener.closed?
    end

    class Exchange
      attr_reader :method, :path, :request_line, :headers, :raw_headers,
                  :headers_at, :body, :body_at, :continue_at,
                  :status, :response

      def self.read(socket)
        request_line = socket.gets
        return nil if request_line.nil? || request_line.strip.empty?

        raw_headers = +''
        headers = {}
        while (line = socket.gets)
          break if line.strip.empty?
          raw_headers << line
          key, value = line.split(':', 2)
          headers[key.downcase] = value.strip if key && value
        end

        new(socket, request_line, headers, raw_headers)
      end

      def initialize(socket, request_line, headers, raw_headers)
        @socket = socket
        @request_line = request_line
        @method, @path, _version = request_line.split(' ', 3)
        @headers = headers
        @raw_headers = raw_headers
        @headers_at = monotonic
        @body = nil
        @body_at = nil
        @continue_at = nil
      end

      def send_continue
        # Record before writing so a concurrent client read cannot appear to
        # precede the consent from the server's point of view.
        @continue_at = monotonic
        @socket.write("HTTP/1.1 100 Continue\r\n\r\n")
      end

      def read_body
        length = Integer(@headers.fetch('content-length'))
        data = +''.b
        while data.bytesize < length
          chunk = @socket.readpartial(length - data.bytesize)
          @body_at ||= monotonic
          data << chunk
        end
        @body = data
      end

      def respond(status, body = '')
        @status = status
        @response = body
        reason = status == 200 ? 'OK' : status == 403 ? 'Forbidden' : 'Error'
        out = +"HTTP/1.1 #{status} #{reason}\r\n"
        out << "Content-Type: text/plain\r\n"
        out << "Content-Length: #{body.bytesize}\r\n"
        out << "\r\n"
        out << body
        @socket.write(out)
      end

      private

      def monotonic
        Process.clock_gettime(Process::CLOCK_MONOTONIC)
      end
    end
  end

  BODY_DATA = ('import-body-' * 8_192).b

  def setup
    @servers = []
    @http = nil
  end

  def teardown
    @http&.finish if @http&.started?
    @servers.each(&:shutdown)
  end

  def start_http(server, continue_timeout)
    http = Net::HTTP.new('127.0.0.1', server.port)
    http.open_timeout = scaled_timeout(2)
    http.read_timeout = scaled_timeout(5)
    http.continue_timeout = continue_timeout
    http.start
    http
  end

  def scaled_timeout(seconds)
    defined?(EnvUtil) ? EnvUtil.apply_timeout_scale(seconds) : seconds
  end

  def request_for(path, data, body)
    request = Net::HTTP::Post.new(path,
      'content-type' => 'application/octet-stream',
      'expect' => '100-continue')
    request.content_length = data.bytesize
    request.body_stream = body
    request
  end

  def with_timeout(seconds = 10)
    Timeout.timeout(scaled_timeout(seconds)) { yield }
  end

  def add_server(server)
    @servers << server
    server.start
  end

  def assert_header_contract(exchange, data)
    assert_equal 'POST', exchange.method
    assert_equal '100-continue', exchange.headers['expect']
    assert_equal data.bytesize.to_s, exchange.headers['content-length']
    assert_equal 'application/octet-stream', exchange.headers['content-type']
    assert_match(/^Expect: 100-continue\r$/, exchange.raw_headers)
    assert_match(/^Content-Length: #{data.bytesize}\r$/, exchange.raw_headers)
  end

  def test_consent_waits_for_100_then_streams_body
    server = add_server(ScriptedServer.new(2) {|exchange, index|
      if index == 0
        sleep scaled_timeout(0.1)
      end
      exchange.send_continue
      exchange.read_body
      exchange.respond(200, index == 0 ? 'accepted' : 'reused')
    })

    body = RecordingBody.new(BODY_DATA)
    @http = start_http(server, scaled_timeout(1))
    response = with_timeout {
      @http.request(request_for('/import', BODY_DATA, body))
    }

    assert_equal '200', response.code
    assert_equal 'accepted', response.body

    reused_body = RecordingBody.new('second-import'.b)
    reused = with_timeout {
      @http.request(request_for('/import/next', 'second-import'.b, reused_body))
    }
    assert_equal '200', reused.code
    assert_equal 'reused', reused.body

    server.join(scaled_timeout(5))
    assert_equal 1, server.connections, 'expected keep-alive connection reuse'

    consented = server.requests[0]
    assert_header_contract(consented, BODY_DATA)
    assert_equal '/import', consented.path
    assert_equal BODY_DATA, consented.body
    assert_not_nil consented.continue_at
    assert_operator body.first_read_at, :>=, consented.headers_at
    assert_operator body.first_read_at, :>=, consented.continue_at,
                    'request body must be read only after 100 Continue'

    next_request = server.requests[1]
    assert_header_contract(next_request, 'second-import'.b)
    assert_equal '/import/next', next_request.path
    assert_equal 'second-import'.b, next_request.body
    assert_not_empty reused_body.reads
  end

  def test_early_rejection_does_not_touch_body_and_keeps_next_request_distinct
    server = add_server(ScriptedServer.new(3) {|exchange, index|
      if index < 2
        exchange.respond(403, 'denied')
      else
        exchange.send_continue
        exchange.read_body
        exchange.respond(200, 'reused')
      end
    })

    body = RecordingBody.new(BODY_DATA)
    @http = start_http(server, scaled_timeout(1))
    response = with_timeout {
      @http.request(request_for('/import/rejected', BODY_DATA, body))
    }

    assert_equal '403', response.code
    assert_equal 'denied', response.body
    assert_empty body.reads, 'an early rejection must not read the request body'

    denied_data = 'do-not-send'.b
    unreadable = UnreadableBody.new
    denied = with_timeout {
      @http.request(request_for('/import/rejected-twice', denied_data, unreadable))
    }
    assert_equal '403', denied.code

    second_data = ('second-import-' * 512).b
    second_body = RecordingBody.new(second_data)
    reused = with_timeout {
      @http.request(request_for('/import/after-rejection', second_data, second_body))
    }
    assert_equal '200', reused.code
    assert_equal 'reused', reused.body

    server.join(scaled_timeout(5))
    assert_equal 1, server.connections, 'expected the rejected connection to be reused'

    rejected = server.requests[0]
    assert_header_contract(rejected, BODY_DATA)
    assert_equal '/import/rejected', rejected.path
    assert_nil rejected.body
    assert_nil rejected.body_at

    second_request = server.requests[1]
    assert_equal 'POST', second_request.method
    assert_equal '/import/rejected-twice', second_request.path,
                 'a second rejected request must keep its own framing'
    assert_equal denied_data.bytesize.to_s, second_request.headers['content-length']
    assert_nil second_request.body

    next_request = server.requests[2]
    assert_equal 'POST', next_request.method
    assert_equal '/import/after-rejection', next_request.path,
                 'the next request must not be confused with an unsent rejected body'
    assert_equal second_data.bytesize.to_s, next_request.headers['content-length']
    assert_equal second_data, next_request.body
    assert_not_empty second_body.reads
  end

  def test_timeout_falls_back_to_sending_body_after_continue_timeout
    # continue_timeout is a truthy seconds value: Net::HTTP waits at most that
    # long for 100 Continue, then sends the body anyway.  A nil value disables
    # the wait; 0 is still truthy and performs only a nonblocking readability
    # check.  This test pins the positive-timeout fallback.
    continue_timeout = scaled_timeout(0.25)

    server = add_server(ScriptedServer.new(2) {|exchange, index|
      if index == 0
        exchange.read_body
        exchange.respond(200, 'after-timeout')
      else
        exchange.send_continue
        exchange.read_body
        exchange.respond(200, 'reused')
      end
    })

    body = RecordingBody.new(BODY_DATA)
    @http = start_http(server, continue_timeout)
    response = with_timeout(10) {
      @http.request(request_for('/import/slow', BODY_DATA, body))
    }

    assert_equal '200', response.code
    assert_equal 'after-timeout', response.body

    second_data = 'after-timeout-reuse'.b
    second_body = RecordingBody.new(second_data)
    reused = with_timeout {
      @http.request(request_for('/import/slow/next', second_data, second_body))
    }
    assert_equal '200', reused.code
    assert_equal 'reused', reused.body

    server.join(scaled_timeout(5))
    assert_equal 1, server.connections, 'expected keep-alive connection reuse'

    timed_out = server.requests[0]
    assert_header_contract(timed_out, BODY_DATA)
    assert_equal '/import/slow', timed_out.path
    assert_nil timed_out.continue_at
    assert_equal BODY_DATA, timed_out.body
    assert_not_nil body.first_read_at
    assert_operator body.first_read_at, :>=, timed_out.headers_at,
                    'the body must not be read while waiting for consent'
    waited = body.first_read_at - timed_out.headers_at
    assert_operator waited, :>=, continue_timeout * 0.75,
                    'the client should wait for continue_timeout after headers'
    assert_operator waited, :<, continue_timeout + scaled_timeout(1),
                    'the client should not wait far beyond continue_timeout'

    next_request = server.requests[1]
    assert_equal '/import/slow/next', next_request.path
    assert_equal second_data, next_request.body
    assert_not_empty second_body.reads
  end
end

class TestNetHTTPSwitchingProtocols < Test::Unit::TestCase
  CONFIG = {
    'host' => '127.0.0.1',
    'proxy_host' => nil,
    'proxy_port' => nil,
    'chunked' => true,
  }

  include TestNetHTTPUtils

  def logfile
    @debug = StringIO.new('')
  end

  def mount_proc(&block)
    @server.mount('/continue', block.to_proc)
  end

  def test_info
    mount_proc {|req, res|
      req.instance_variable_get(:@socket) << "HTTP/1.1 101 Switching Protocols\r\n\r\n"
      res.body = req.query['body']
    }
    start {|http|
      http.continue_timeout = 0.2
      http.request_post('/continue', 'body=BODY',
                        'content-type' => 'application/x-www-form-urlencoded') {|res|
        assert_equal('BODY', res.read_body)
      }
    }
    assert_match(/HTTP\/1.1 101 Switching Protocols/, @debug.string)
  end
end

class TestNetHTTPInformationalResponses < Test::Unit::TestCase
  CONFIG = {
    'host' => '127.0.0.1',
    'proxy_host' => nil,
    'proxy_port' => nil,
  }

  include TestNetHTTPUtils

  def mount_informational(count)
    @server.mount('/info', proc {|req, res|
      count.times { req.continue }
      res.body = 'BODY'
    })
  end

  def test_informational_responses
    mount_informational 3
    start {|http|
      res = http.get('/info')
      assert_equal('BODY', res.body)
    }
  end

  def test_max_informational_responses
    mount_informational Net::HTTPResponse::MAX_INFORMATIONAL_RESPONSES
    start {|http|
      res = http.get('/info')
      assert_equal('BODY', res.body)
    }
  end

  def test_too_many_informational_responses
    mount_informational Net::HTTPResponse::MAX_INFORMATIONAL_RESPONSES + 1
    start {|http|
      assert_raise(Net::HTTPBadResponse) {
        http.get('/info')
      }
    }
  end
end

class TestNetHTTPKeepAlive < Test::Unit::TestCase
  CONFIG = {
    'host' => '127.0.0.1',
    'proxy_host' => nil,
    'proxy_port' => nil,
    'RequestTimeout' => 1,
  }

  include TestNetHTTPUtils

  def test_keep_alive_get_auto_reconnect
    start {|http|
      res = http.get('/')
      http.keep_alive_timeout = 1
      assert_kind_of Net::HTTPResponse, res
      assert_kind_of String, res.body
      sleep 1.5
      assert_nothing_raised {
        res = http.get('/')
      }
      assert_kind_of Net::HTTPResponse, res
      assert_kind_of String, res.body
    }
  end

  def test_server_closed_connection_auto_reconnect
    start {|http|
      res = http.get('/')
      http.keep_alive_timeout = 5
      assert_kind_of Net::HTTPResponse, res
      assert_kind_of String, res.body
      sleep 1.5
      assert_nothing_raised {
        # Net::HTTP should detect the closed connection before attempting the
        # request, since post requests cannot be retried.
        res = http.post('/', 'query=foo', 'content-type' => 'application/x-www-form-urlencoded')
      }
      assert_kind_of Net::HTTPResponse, res
      assert_kind_of String, res.body
    }
  end

  def test_keep_alive_get_auto_retry
    start {|http|
      res = http.get('/')
      http.keep_alive_timeout = 5
      assert_kind_of Net::HTTPResponse, res
      assert_kind_of String, res.body
      sleep 1.5
      res = http.get('/')
      assert_kind_of Net::HTTPResponse, res
      assert_kind_of String, res.body
    }
  end

  def test_keep_alive_reset_on_new_connection
    # Using debug log output on accepting connection:
    #
    #   "[2021-04-29 20:36:46] DEBUG accept: 127.0.0.1:50674\n"
    @log_tester = nil
    @logger_level = :debug

    start {|http|
      res = http.get('/')
      http.keep_alive_timeout = 1
      assert_kind_of Net::HTTPResponse, res
      assert_kind_of String, res.body
      http.finish
      assert_equal 1, @log.grep(/accept/i).size

      sleep 1.5
      http.start
      res = http.get('/')
      assert_kind_of Net::HTTPResponse, res
      assert_kind_of String, res.body
      assert_equal 2, @log.grep(/accept/i).size
    }
  end

  class MockSocket
    attr_reader :count
    def initialize(success_after: nil)
      @success_after = success_after
      @count = 0
    end
    def close
    end
    def closed?
    end
    def write(_)
    end
    def readuntil(terminator, ignore_eof = false, limit: nil)
      raise "unexpected terminator #{terminator.dump}" unless terminator == "\n"
      # A header read ends the headers at once. Every other read is the
      # status line of a fresh attempt, which is what count measures.
      return "" if ignore_eof
      @count += 1
      if @success_after && @success_after <= @count
        "HTTP/1.1 200 OK\n"
      else
        raise Errno::ECONNRESET
      end
    end
    def read_all(_)
    end
  end

  def test_http_retry_success
    start {|http|
      socket = MockSocket.new(success_after: 10)
      http.instance_variable_get(:@socket).close
      http.instance_variable_set(:@socket, socket)
      assert_equal 0, socket.count
      http.max_retries = 10
      res = http.get('/')
      assert_equal 10, socket.count
      assert_kind_of Net::HTTPResponse, res
      assert_kind_of String, res.body
    }
  end

  def test_http_retry_failed
    start {|http|
      socket = MockSocket.new
      http.instance_variable_get(:@socket).close
      http.instance_variable_set(:@socket, socket)
      http.max_retries = 10
      assert_raise(Errno::ECONNRESET){ http.get('/') }
      assert_equal 11, socket.count
    }
  end

  def test_http_retry_failed_with_block
    start {|http|
      http.max_retries = 10
      called = 0
      assert_raise(Errno::ECONNRESET){ http.get('/'){called += 1; raise Errno::ECONNRESET} }
      assert_equal 1, called
    }
    @log_tester = nil
  end

  def test_keep_alive_server_close
    def @server.run(sock)
      sock.close
    end

    start {|http|
      assert_raise(EOFError, Errno::ECONNRESET, IOError) {
        http.get('/')
      }
    }
  end
end

class TestNetHTTPLocalBind < Test::Unit::TestCase
  CONFIG = {
    'host' => 'localhost',
    'proxy_host' => nil,
    'proxy_port' => nil,
  }

  include TestNetHTTPUtils

  def test_bind_to_local_host
    @server.mount_proc('/show_ip') { |req, res| res.body = req.remote_ip }

    http = Net::HTTP.new(config('host'), config('port'))
    http.local_host = Addrinfo.tcp(config('host'), config('port')).ip_address
    assert_not_nil(http.local_host)
    assert_nil(http.local_port)

    res = http.get('/show_ip')
    assert_equal(http.local_host, res.body)
  end

  def test_bind_to_local_port
    @server.mount_proc('/show_port') { |req, res| res.body = req.peeraddr[1].to_s }

    http = Net::HTTP.new(config('host'), config('port'))
    http.local_host = Addrinfo.tcp(config('host'), config('port')).ip_address
    http.local_port = Addrinfo.tcp(config('host'), 0).bind {|s|
      s.local_address.ip_port.to_s
    }
    assert_not_nil(http.local_host)
    assert_not_nil(http.local_port)

    res = http.get('/show_port')
    assert_equal(http.local_port, res.body)
  end
end

class TestNetHTTPForceEncoding < Test::Unit::TestCase
  CONFIG = {
    'host' => 'localhost',
    'proxy_host' => nil,
    'proxy_port' => nil,
  }

  include TestNetHTTPUtils

  def fe_request(force_enc, content_type=nil)
    @server.mount_proc('/fe') do |req, res|
      res['Content-Type'] = content_type if content_type
      res.body = "hello\u1234"
    end

    http = Net::HTTP.new(config('host'), config('port'))
    http.local_host = Addrinfo.tcp(config('host'), config('port')).ip_address
    assert_not_nil(http.local_host)
    assert_nil(http.local_port)

    http.response_body_encoding = force_enc
    http.get('/fe')
  end

  def test_response_body_encoding_false
    res = fe_request(false)
    assert_equal("hello\u1234".b, res.body)
    assert_equal(Encoding::ASCII_8BIT, res.body.encoding)
  end

  def test_response_body_encoding_true_without_content_type
    res = fe_request(true)
    assert_equal("hello\u1234".b, res.body)
    assert_equal(Encoding::ASCII_8BIT, res.body.encoding)
  end

  def test_response_body_encoding_true_with_content_type
    res = fe_request(true, 'text/html; charset=utf-8')
    assert_equal("hello\u1234", res.body)
    assert_equal(Encoding::UTF_8, res.body.encoding)
  end

  def test_response_body_encoding_string_without_content_type
    res = fe_request('utf-8')
    assert_equal("hello\u1234", res.body)
    assert_equal(Encoding::UTF_8, res.body.encoding)
  end

  def test_response_body_encoding_encoding_without_content_type
    res = fe_request(Encoding::UTF_8)
    assert_equal("hello\u1234", res.body)
    assert_equal(Encoding::UTF_8, res.body.encoding)
  end
end

class TestNetHTTPPartialResponse < Test::Unit::TestCase
  CONFIG = {
    'host' => '127.0.0.1',
    'proxy_host' => nil,
    'proxy_port' => nil,
  }

  include TestNetHTTPUtils

  def test_partial_response
    str = "0123456789"
    @server.mount_proc('/') do |req, res|
      res.status = 200
      res['Content-Type'] = 'text/plain'

      res.body = str
      res['Content-Length'] = str.length + 1
    end
    @server.mount_proc('/show_ip') { |req, res| res.body = req.remote_ip }

    http = Net::HTTP.new(config('host'), config('port'))
    res = http.get('/')
    assert_equal(str, res.body)

    http = Net::HTTP.new(config('host'), config('port'))
    http.ignore_eof = false
    assert_raise(EOFError) {http.get('/')}
  end
end

class TestNetHTTPInRactor < Test::Unit::TestCase
  CONFIG = {
    'host' => '127.0.0.1',
    'proxy_host' => nil,
    'proxy_port' => nil,
  }

  include TestNetHTTPUtils

  def test_get
    assert_ractor(<<~RUBY, require: 'net/http')
      expected = #{$test_net_http_data.dump}.b
      ret = Ractor.new {
        host = #{config('host').dump}
        port = #{config('port')}
        Net::HTTP.start(host, port) { |http|
          res = http.get('/')
          res.body
        }
      }.value
      assert_equal expected, ret
    RUBY
  end
end if defined?(Ractor) && Ractor.method_defined?(:value)
