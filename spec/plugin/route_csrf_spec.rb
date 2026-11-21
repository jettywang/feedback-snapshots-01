require_relative "../spec_helper"

begin
  require 'cgi/escape'
rescue LoadError
  require 'cgi'
end

describe "route_csrf plugin" do 
  include CookieJar

  def route_csrf_app(opts={}, &block)
    app(:bare) do
      send(*DEFAULT_SESSION_ARGS) unless opts[:no_sessions_plugin]
      plugin(:route_csrf, opts, &opts[:block])
      route do |r|
        check_csrf! unless env['SKIP']
        r.post('foo'){'f'}
        r.post('bar'){'b'}
        r.get "token", String do |s|
          csrf_token("/#{s}")
        end
        instance_exec(r, &block) if block
      end
    end
  end

  it "allows all GET requests and allows POST requests only if they have a correct token for the path" do
    route_csrf_app
    token = body("/token/foo")
    token.length.must_equal 84
    body("/foo", "REQUEST_METHOD"=>'POST', 'rack.input'=>rack_input("_csrf=#{Rack::Utils.escape(token)}")).must_equal 'f'
    proc{body("/bar", "REQUEST_METHOD"=>'POST', 'rack.input'=>rack_input("_csrf=#{Rack::Utils.escape(token)}"))}.must_raise Roda::RodaPlugins::RouteCsrf::InvalidToken
    proc{body("/foo", "REQUEST_METHOD"=>'PUT', 'rack.input'=>rack_input("_csrf=#{Rack::Utils.escape(token)}"))}.must_raise Roda::RodaPlugins::RouteCsrf::InvalidToken

    token = body("/token/bar")
    token.length.must_equal 84
    body("/bar", "REQUEST_METHOD"=>'POST', 'rack.input'=>rack_input("_csrf=#{Rack::Utils.escape(token)}")).must_equal 'b'
    proc{body("/foo", "REQUEST_METHOD"=>'POST', 'rack.input'=>rack_input("_csrf=#{Rack::Utils.escape(token)}"))}.must_raise Roda::RodaPlugins::RouteCsrf::InvalidToken
    proc{body("/bar", "REQUEST_METHOD"=>'DELETE', 'rack.input'=>rack_input("_csrf=#{Rack::Utils.escape(token)}"))}.must_raise Roda::RodaPlugins::RouteCsrf::InvalidToken

    # Additional failure cases

    proc{body("/bar", "REQUEST_METHOD"=>'POST', 'rack.input'=>rack_input)}.must_raise Roda::RodaPlugins::RouteCsrf::InvalidToken

    proc{body("/bar", "REQUEST_METHOD"=>'POST', 'rack.input'=>rack_input("_csrf=#{Rack::Utils.escape(token)}a"))}.must_raise Roda::RodaPlugins::RouteCsrf::InvalidToken

    t2 = token.dup
    t2.setbyte(1, t2.getbyte(1) ^ 1)
    proc{body("/bar", "REQUEST_METHOD"=>'POST', 'rack.input'=>rack_input("_csrf=#{Rack::Utils.escape(t2)}"))}.must_raise Roda::RodaPlugins::RouteCsrf::InvalidToken

    t2 = token.dup
    t2.setbyte(61, t2.getbyte(61) ^ 1)
    proc{body("/bar", "REQUEST_METHOD"=>'POST', 'rack.input'=>rack_input("_csrf=#{Rack::Utils.escape(t2)}"))}.must_raise Roda::RodaPlugins::RouteCsrf::InvalidToken

    t2 = token.dup
    t2[1] = '|'
    proc{body("/bar", "REQUEST_METHOD"=>'POST', 'rack.input'=>rack_input("_csrf=#{Rack::Utils.escape(t2)}"))}.must_raise Roda::RodaPlugins::RouteCsrf::InvalidToken
  end

  it "supports overriding csrf_request_method to change how the request method is determined" do
    route_csrf_app{"f"}
    token = body("/token/f")
    body("/f").must_equal "f"
    app.send(:define_method, :csrf_request_method){"POST"}
    proc{body("/f", 'rack.input'=>rack_input(""))}.must_raise Roda::RodaPlugins::RouteCsrf::InvalidToken
    body("/f", "QUERY_STRING"=>"_csrf=#{Rack::Utils.escape(token)}", 'rack.input'=>rack_input("")).must_equal 'f'
  end

  it "supports :check_request_methods option" do
    route_csrf_app(:check_request_methods=>[])
    body("/foo", "REQUEST_METHOD"=>'POST', 'rack.input'=>rack_input("")).must_equal 'f'
    route_csrf_app(:check_request_methods=>["POST"])
    token = body("/token/foo")
    body("/foo", "REQUEST_METHOD"=>'POST', 'rack.input'=>rack_input("_csrf=#{Rack::Utils.escape(token)}")).must_equal 'f'
    proc{body("/bar", "REQUEST_METHOD"=>'POST', 'rack.input'=>rack_input("_csrf=#{Rack::Utils.escape(token)}"))}.must_raise Roda::RodaPlugins::RouteCsrf::InvalidToken
  end

  it "supports :exempt_request_methods option" do
    route_csrf_app(:exempt_request_methods=>["POST"])
    body("/foo", "REQUEST_METHOD"=>'POST', 'rack.input'=>rack_input("")).must_equal 'f'
    route_csrf_app(:exempt_request_methods=>["GET"])
    token = body("/token/foo")
    body("/foo", "REQUEST_METHOD"=>'POST', 'rack.input'=>rack_input("_csrf=#{Rack::Utils.escape(token)}")).must_equal 'f'
    proc{body("/bar", "REQUEST_METHOD"=>'POST', 'rack.input'=>rack_input("_csrf=#{Rack::Utils.escape(token)}"))}.must_raise Roda::RodaPlugins::RouteCsrf::InvalidToken
  end

  it "supports :require_request_specific_tokens => false option to allow non-request-specific tokens" do
    route_csrf_app(:require_request_specific_tokens=>false){csrf_token}
    token = body("/token/foo")
    token.length.must_equal 84
    body("/foo", "REQUEST_METHOD"=>'POST', 'rack.input'=>rack_input("_csrf=#{Rack::Utils.escape(token)}")).must_equal 'f'
    proc{body("/bar", "REQUEST_METHOD"=>'POST', 'rack.input'=>rack_input("_csrf=#{Rack::Utils.escape(token)}"))}.must_raise Roda::RodaPlugins::RouteCsrf::InvalidToken

    token = body
    token.length.must_equal 84
    body("/foo", "REQUEST_METHOD"=>'POST', 'rack.input'=>rack_input("_csrf=#{Rack::Utils.escape(token)}")).must_equal 'f'
    body("/bar", "REQUEST_METHOD"=>'POST', 'rack.input'=>rack_input("_csrf=#{Rack::Utils.escape(token)}")).must_equal 'b'
  end

  it "allows tokens submitted in both parameter and HTTP header if :check_header option is true" do
    route_csrf_app(:check_header=>true)
    token = body("/token/foo")
    token.length.must_equal 84
    body("/foo", "REQUEST_METHOD"=>'POST', 'rack.input'=>rack_input("_csrf=#{Rack::Utils.escape(token)}")).must_equal 'f'
    body("/foo", "REQUEST_METHOD"=>'POST', 'rack.input'=>rack_input, 'HTTP_X_CSRF_TOKEN'=>token).must_equal 'f'
    proc{body("/bar", "REQUEST_METHOD"=>'POST', 'rack.input'=>rack_input("_csrf=#{Rack::Utils.escape(token)}"))}.must_raise Roda::RodaPlugins::RouteCsrf::InvalidToken
    proc{body("/foo", "REQUEST_METHOD"=>'PUT', 'rack.input'=>rack_input, 'HTTP_X_CSRF_TOKEN'=>token)}.must_raise Roda::RodaPlugins::RouteCsrf::InvalidToken
  end

  it "allows tokens submitted in only HTTP header if :check_header option is :only" do
    route_csrf_app(:check_header=>:only)
    token = body("/token/foo")
    token.length.must_equal 84
    body("/foo", "REQUEST_METHOD"=>'POST', 'rack.input'=>rack_input, 'HTTP_X_CSRF_TOKEN'=>token).must_equal 'f'
    proc{body("/foo", "REQUEST_METHOD"=>'POST', 'rack.input'=>rack_input("_csrf=#{Rack::Utils.escape(token)}"))}.must_raise Roda::RodaPlugins::RouteCsrf::InvalidToken
    proc{body("/bar", "REQUEST_METHOD"=>'POST', 'rack.input'=>rack_input("_csrf=#{Rack::Utils.escape(token)}"))}.must_raise Roda::RodaPlugins::RouteCsrf::InvalidToken
    proc{body("/foo", "REQUEST_METHOD"=>'PUT', 'rack.input'=>rack_input, 'HTTP_X_CSRF_TOKEN'=>token)}.must_raise Roda::RodaPlugins::RouteCsrf::InvalidToken
  end

  it "allows tokens specified via :token option to check_csrf" do
    app(:bare) do
      send(*DEFAULT_SESSION_ARGS) unless opts[:no_sessions_plugin]
      plugin(:route_csrf)
      route do |r|
        check_csrf!(:token=>env['TOKEN'])
        r.post('foo'){'f'}
        r.get "token", String do |s|
          csrf_token("/#{s}")
        end
      end
    end
    token = body("/token/foo")
    token.length.must_equal 84
    body("/foo", "REQUEST_METHOD"=>'POST', 'TOKEN'=>token).must_equal 'f'
    proc{body("/foo", "REQUEST_METHOD"=>'POST', 'TOKEN'=>token+'1')}.must_raise Roda::RodaPlugins::RouteCsrf::InvalidToken
  end

  it "allows configuring CSRF failure action with :csrf_failure => :empty_403 option" do
    route_csrf_app(:csrf_failure=>:empty_403)
    body("/foo", "REQUEST_METHOD"=>'POST', 'rack.input'=>rack_input("_csrf=#{Rack::Utils.escape(body("/token/foo"))}")).must_equal 'f'
    req("/foo", "REQUEST_METHOD"=>'POST', 'rack.input'=>rack_input).must_equal [403, {RodaResponseHeaders::CONTENT_TYPE=>'text/html', RodaResponseHeaders::CONTENT_LENGTH=>'0'}, []]
  end

  deprecated "allows configuring CSRF failure action with :csrf_failure => :clear_session option" do
    route_csrf_app(:csrf_failure=>:clear_session){session.inspect}
    body("/foo", "REQUEST_METHOD"=>'POST', 'rack.input'=>rack_input("_csrf=#{Rack::Utils.escape(body("/token/foo"))}")).must_equal 'f'
    body("/b", "REQUEST_METHOD"=>'POST', 'rack.input'=>rack_input("_csrf=#{Rack::Utils.escape(body('/token/a'))}")).must_equal '{}'
  end

  it "allows configuring CSRF failure action with :csrf_failure => proc option" do
    route_csrf_app(:csrf_failure=>proc{|r| r.path + '2'})
    body("/foo", "REQUEST_METHOD"=>'POST', 'rack.input'=>rack_input("_csrf=#{Rack::Utils.escape(body("/token/foo"))}")).must_equal 'f'
    body("/foo", "REQUEST_METHOD"=>'POST', 'rack.input'=>rack_input).must_equal '/foo2'
  end

  it "allows configuring CSRF failure action via a plugin block" do
    route_csrf_app(:block=>proc{|r| r.path + '2'})
    body("/foo", "REQUEST_METHOD"=>'POST', 'rack.input'=>rack_input("_csrf=#{Rack::Utils.escape(body("/token/foo"))}")).must_equal 'f'
    body("/foo", "REQUEST_METHOD"=>'POST', 'rack.input'=>rack_input).must_equal '/foo2'
  end

  it "allows plugin block to integrate with route_block_args plugin" do
    app(:bare) do
      send(*DEFAULT_SESSION_ARGS)
      plugin :route_block_args do
        [request, request.path, response]
      end
      plugin(:route_csrf){|r, path, res| res.write(path); res.write('2')}
      route do |r, path, res|
        check_csrf!
        r.post('foo'){'f'}
        r.get "token", String do |s|
          csrf_token("/#{s}")
        end
      end
    end
    body("/foo", "REQUEST_METHOD"=>'POST', 'rack.input'=>rack_input("_csrf=#{Rack::Utils.escape(body("/token/foo"))}")).must_equal 'f'
    body("/foo", "REQUEST_METHOD"=>'POST', 'rack.input'=>rack_input).must_equal '/foo2'
  end

  it "raises Error if configuring plugin with invalid :csrf_failure option" do
    route_csrf_app(:csrf_failure=>:foo)
    proc{body("/foo", "REQUEST_METHOD"=>'POST', 'rack.input'=>rack_input)}.must_raise Roda::RodaError
  end

  it "raises Error if configuring plugin with block and :csrf_failure option" do
    proc{route_csrf_app(:block=>proc{|r| r.path + '2'}, :csrf_failure=>:raise)}.must_raise Roda::RodaError
  end

  deprecated "supports check_csrf! :csrf_failure option as a Proc" do
    pr = proc{env['BAD'] == '1' ? 't' : 'f'}
    route_csrf_app{check_csrf!(:csrf_failure=>pr); ''}
    token = body("/token/foo")
    body("SKIP"=>"1", "BAD"=>'1', "REQUEST_METHOD"=>'POST', 'rack.input'=>rack_input("_csrf=#{Rack::Utils.escape(token)}")).must_equal 't'
    body("SKIP"=>"1", "BAD"=>'0', "REQUEST_METHOD"=>'POST', 'rack.input'=>rack_input("_csrf=#{Rack::Utils.escape(token)}")).must_equal 'f'
  end

  it "supports valid_csrf? method" do
    route_csrf_app{valid_csrf?.to_s}
    body("/a", "REQUEST_METHOD"=>'POST', 'rack.input'=>rack_input("_csrf=#{Rack::Utils.escape(body("/token/a"))}")).must_equal 'true'
    body("/a", "REQUEST_METHOD"=>'POST', 'SKIP'=>'1', 'rack.input'=>rack_input("_csrf=#{Rack::Utils.escape(body("/token/b"))}")).must_equal 'false'
  end

  it "supports valid_csrf? method" do
    route_csrf_app do
      check_csrf!{'nope'}
      'yep'
    end
    body("/a", "REQUEST_METHOD"=>'POST', 'SKIP'=>'1', 'rack.input'=>rack_input("_csrf=#{Rack::Utils.escape(body("/token/a"))}")).must_equal 'yep'
    body("/a", "REQUEST_METHOD"=>'POST', 'SKIP'=>'1', 'rack.input'=>rack_input("_csrf=#{Rack::Utils.escape(body("/token/b"))}")).must_equal 'nope'
  end

  it "supports use_request_specific_csrf_tokens? method" do
    route_csrf_app{use_request_specific_csrf_tokens?.to_s}
    body.must_equal 'true'
    route_csrf_app(:require_request_specific_tokens=>false){use_request_specific_csrf_tokens?.to_s}
    body.must_equal 'false'
  end

  it "supports csrf_field method" do
    route_csrf_app{csrf_field}
    body.must_equal '_csrf'
    route_csrf_app(:field=>'foo'){csrf_field}
    body.must_equal 'foo'
  end

  it "supports csrf_header method" do
    route_csrf_app{csrf_header}
    body.must_equal 'X-CSRF-Token'
    route_csrf_app(:header=>'Foo'){csrf_header}
    body.must_equal 'Foo'
  end

  it "supports csrf_metatag method" do
    route_csrf_app(:require_request_specific_tokens=>false){csrf_metatag}
    body =~ /\A<meta name="_csrf" content="([+\/0-9A-Za-z]{84})" \/>\z/
    body("/foo", "REQUEST_METHOD"=>'POST', 'rack.input'=>rack_input("_csrf=#{Rack::Utils.escape($1)}")).must_equal 'f'

    route_csrf_app(:require_request_specific_tokens=>false, :field=>'foo'){csrf_metatag}
    body =~ /\A<meta name="foo" content="([+\/0-9A-Za-z]{84})" \/>\z/
    body("/bar", "REQUEST_METHOD"=>'POST', 'rack.input'=>rack_input("foo=#{Rack::Utils.escape($1)}")).must_equal 'b'
  end

  it "supports csrf_tag method" do
    route_csrf_app(:require_request_specific_tokens=>false){csrf_tag}
    body =~ /\A<input type="hidden" name="_csrf" value="([+\/0-9A-Za-z]{84})" \/>\z/
    body("/foo", "REQUEST_METHOD"=>'POST', 'rack.input'=>rack_input("_csrf=#{Rack::Utils.escape($1)}")).must_equal 'f'

    route_csrf_app(:require_request_specific_tokens=>false, :field=>'foo'){csrf_tag}
    body =~ /\A<input type="hidden" name="foo" value="([+\/0-9A-Za-z]{84})" \/>\z/
    body("/foo", "REQUEST_METHOD"=>'POST', 'rack.input'=>rack_input("foo=#{Rack::Utils.escape($1)}")).must_equal 'f'

    route_csrf_app{csrf_tag('/foo')}
    body =~ /\A<input type="hidden" name="_csrf" value="([+\/0-9A-Za-z]{84})" \/>\z/
    token = $1
    body("/foo", "REQUEST_METHOD"=>'POST', 'rack.input'=>rack_input("_csrf=#{Rack::Utils.escape(token)}")).must_equal 'f'
    proc{body("/bar", "REQUEST_METHOD"=>'POST', 'rack.input'=>rack_input("_csrf=#{Rack::Utils.escape(token)}"))}.must_raise Roda::RodaPlugins::RouteCsrf::InvalidToken
    proc{body("/foo", "REQUEST_METHOD"=>'PUT', 'rack.input'=>rack_input, 'QUERY_STRING'=>"_csrf=#{Rack::Utils.escape(token)}")}.must_raise Roda::RodaPlugins::RouteCsrf::InvalidToken

    route_csrf_app do |r|
      r.is 'foo', :method=>'PUT' do
        'f2'
      end
      csrf_tag('/foo', 'PUT')
    end
    body =~ /\A<input type="hidden" name="_csrf" value="([+\/0-9A-Za-z]{84})" \/>\z/
    token = $1
    body("/foo", "REQUEST_METHOD"=>'PUT', 'rack.input'=>rack_input, 'QUERY_STRING'=>"_csrf=#{Rack::Utils.escape(token)}").must_equal 'f2'
    proc{body("/bar", "REQUEST_METHOD"=>'PUT', 'rack.input'=>rack_input, 'QUERY_STRING'=>"_csrf=#{Rack::Utils.escape(token)}")}.must_raise Roda::RodaPlugins::RouteCsrf::InvalidToken
    proc{body("/foo", "REQUEST_METHOD"=>'POST', 'rack.input'=>rack_input("_csrf=#{Rack::Utils.escape(token)}"))}.must_raise Roda::RodaPlugins::RouteCsrf::InvalidToken
  end

  it "supports csrf_formaction_tag method" do
    route_csrf_app{csrf_formaction_tag('/foo')}
    body =~ /\A<input type="hidden" name="([^"]+)" value="([+\/0-9A-Za-z]{84})" \/>\z/
    field = CGI.unescapeHTML($1)
    token = $2
    body("/foo", "REQUEST_METHOD"=>'POST', 'rack.input'=>rack_input("#{Rack::Utils.escape(field)}=#{Rack::Utils.escape(token)}")).must_equal 'f'
    proc{body("/bar", "REQUEST_METHOD"=>'POST', 'rack.input'=>rack_input("#{Rack::Utils.escape(field)}=#{Rack::Utils.escape(token)}"))}.must_raise Roda::RodaPlugins::RouteCsrf::InvalidToken
    proc{body("/foo", "REQUEST_METHOD"=>'PUT', 'rack.input'=>rack_input, 'QUERY_STRING'=>"#{Rack::Utils.escape(field)}=#{Rack::Utils.escape(token)}")}.must_raise Roda::RodaPlugins::RouteCsrf::InvalidToken

    route_csrf_app do |r|
      r.is 'foo', :method=>'PUT' do
        'f2'
      end
      csrf_formaction_tag('/foo', 'PUT')
    end
    body =~ /\A<input type="hidden" name="([^"]+)" value="([+\/0-9A-Za-z]{84})" \/>\z/
    field = CGI.unescapeHTML($1)
    token = $2
    body("/foo", "REQUEST_METHOD"=>'PUT', 'rack.input'=>rack_input, 'QUERY_STRING'=>"#{Rack::Utils.escape(field)}=#{Rack::Utils.escape(token)}").must_equal 'f2'
    proc{body("/bar", "REQUEST_METHOD"=>'PUT', 'rack.input'=>rack_input, 'QUERY_STRING'=>"#{Rack::Utils.escape(field)}=#{Rack::Utils.escape(token)}")}.must_raise Roda::RodaPlugins::RouteCsrf::InvalidToken
    proc{body("/foo", "REQUEST_METHOD"=>'POST', 'rack.input'=>rack_input("#{Rack::Utils.escape(field)}=#{Rack::Utils.escape(token)}"))}.must_raise Roda::RodaPlugins::RouteCsrf::InvalidToken
  end

  it "supports csrf_token method" do
    route_csrf_app(:require_request_specific_tokens=>false){csrf_token}
    body("/foo", "REQUEST_METHOD"=>'POST', 'rack.input'=>rack_input("_csrf=#{Rack::Utils.escape(body)}")).must_equal 'f'

    route_csrf_app(:require_request_specific_tokens=>false, :field=>'foo'){csrf_token}
    body("/foo", "REQUEST_METHOD"=>'POST', 'rack.input'=>rack_input("foo=#{Rack::Utils.escape(body)}")).must_equal 'f'

    route_csrf_app{csrf_token('/foo')}
    token = body
    body("/foo", "REQUEST_METHOD"=>'POST', 'rack.input'=>rack_input("_csrf=#{Rack::Utils.escape(token)}")).must_equal 'f'
    proc{body("/bar", "REQUEST_METHOD"=>'POST', 'rack.input'=>rack_input("_csrf=#{Rack::Utils.escape(token)}"))}.must_raise Roda::RodaPlugins::RouteCsrf::InvalidToken
    proc{body("/foo", "REQUEST_METHOD"=>'PUT', 'rack.input'=>rack_input, 'QUERY_STRING'=>"_csrf=#{Rack::Utils.escape(token)}")}.must_raise Roda::RodaPlugins::RouteCsrf::InvalidToken

    route_csrf_app do |r|
      r.is 'foo', :method=>'PUT' do
        'f2'
      end
      csrf_token('/foo', 'PUT')
    end
    token = body
    body("/foo", "REQUEST_METHOD"=>'PUT', 'rack.input'=>rack_input, 'QUERY_STRING'=>"_csrf=#{Rack::Utils.escape(token)}").must_equal 'f2'
    proc{body("/bar", "REQUEST_METHOD"=>'PUT', 'rack.input'=>rack_input, 'QUERY_STRING'=>"_csrf=#{Rack::Utils.escape(token)}")}.must_raise Roda::RodaPlugins::RouteCsrf::InvalidToken
    proc{body("/foo", "REQUEST_METHOD"=>'POST', 'rack.input'=>rack_input("_csrf=#{Rack::Utils.escape(token)}"))}.must_raise Roda::RodaPlugins::RouteCsrf::InvalidToken
  end

  it "supports csrf_path method" do
    route_csrf_app do |r|
      r.post{r.path + '2'}
      csrf_token(csrf_path(env['CP']))
    end

    body("REQUEST_METHOD"=>'POST', 'rack.input'=>rack_input("_csrf=#{Rack::Utils.escape(body)}")).must_equal '/2'
    body("REQUEST_METHOD"=>'POST', 'rack.input'=>rack_input("_csrf=#{Rack::Utils.escape(body('CP'=>''))}")).must_equal '/2'
    body("REQUEST_METHOD"=>'POST', 'rack.input'=>rack_input("_csrf=#{Rack::Utils.escape(body('CP'=>'#foo'))}")).must_equal '/2'
    body("REQUEST_METHOD"=>'POST', 'rack.input'=>rack_input("_csrf=#{Rack::Utils.escape(body('CP'=>'?foo'))}")).must_equal '/2'

    body('/a', "REQUEST_METHOD"=>'POST', 'rack.input'=>rack_input("_csrf=#{Rack::Utils.escape(body('/a'))}")).must_equal '/a2'
    body('/a', "REQUEST_METHOD"=>'POST', 'rack.input'=>rack_input("_csrf=#{Rack::Utils.escape(body('/a', 'CP'=>''))}")).must_equal '/a2'
    body('/a', "REQUEST_METHOD"=>'POST', 'rack.input'=>rack_input("_csrf=#{Rack::Utils.escape(body('/a', 'CP'=>'?foo'))}")).must_equal '/a2'
    body('/a', "REQUEST_METHOD"=>'POST', 'rack.input'=>rack_input("_csrf=#{Rack::Utils.escape(body('/a', 'CP'=>'#foo'))}")).must_equal '/a2'

    body("REQUEST_METHOD"=>'POST', 'rack.input'=>rack_input("_csrf=#{Rack::Utils.escape(body('CP'=>'http://foo/'))}")).must_equal '/2'
    body('/a', "REQUEST_METHOD"=>'POST', 'rack.input'=>rack_input("_csrf=#{Rack::Utils.escape(body('CP'=>'https://foo/a'))}")).must_equal '/a2'
    body('/a/b', "REQUEST_METHOD"=>'POST', 'rack.input'=>rack_input("_csrf=#{Rack::Utils.escape(body('CP'=>'http://foo/a/b'))}")).must_equal '/a/b2'

    body("REQUEST_METHOD"=>'POST', 'rack.input'=>rack_input("_csrf=#{Rack::Utils.escape(body('CP'=>'/'))}")).must_equal '/2'
    body('/a', "REQUEST_METHOD"=>'POST', 'rack.input'=>rack_input("_csrf=#{Rack::Utils.escape(body('CP'=>'/a'))}")).must_equal '/a2'
    body('/a/b', "REQUEST_METHOD"=>'POST', 'rack.input'=>rack_input("_csrf=#{Rack::Utils.escape(body('CP'=>'/a/b'))}")).must_equal '/a/b2'

    body('/a', "REQUEST_METHOD"=>'POST', 'rack.input'=>rack_input("_csrf=#{Rack::Utils.escape(body('HTTPS'=>'on', 'HTTP_HOST'=>'foo.com', 'CP'=>'a'))}")).must_equal '/a2'
    body('/a', "REQUEST_METHOD"=>'POST', 'rack.input'=>rack_input("_csrf=#{Rack::Utils.escape(body('/b', 'HTTPS'=>'on', 'HTTP_HOST'=>'foo.com', 'CP'=>'a'))}")).must_equal '/a2'
    body('/b/a', "REQUEST_METHOD"=>'POST', 'rack.input'=>rack_input("_csrf=#{Rack::Utils.escape(body('/b/', 'HTTPS'=>'on', 'HTTP_HOST'=>'foo.com', 'CP'=>'a'))}")).must_equal '/b/a2'
    body('/b/a', "REQUEST_METHOD"=>'POST', 'rack.input'=>rack_input("_csrf=#{Rack::Utils.escape(body('/b/b', 'HTTPS'=>'on', 'HTTP_HOST'=>'foo.com', 'CP'=>'a'))}")).must_equal '/b/a2'
    body('/a/b', "REQUEST_METHOD"=>'POST', 'rack.input'=>rack_input("_csrf=#{Rack::Utils.escape(body('/b', 'HTTPS'=>'on', 'HTTP_HOST'=>'foo.com', 'CP'=>'a/b'))}")).must_equal '/a/b2'
    body('/b/a/b', "REQUEST_METHOD"=>'POST', 'rack.input'=>rack_input("_csrf=#{Rack::Utils.escape(body('/b/', 'HTTPS'=>'on', 'HTTP_HOST'=>'foo.com', 'CP'=>'a/b'))}")).must_equal '/b/a/b2'
    body('/b/a/b', "REQUEST_METHOD"=>'POST', 'rack.input'=>rack_input("_csrf=#{Rack::Utils.escape(body('/b/a', 'HTTPS'=>'on', 'HTTP_HOST'=>'foo.com', 'CP'=>'a/b'))}")).must_equal '/b/a/b2'
  end

  it "supports stable action identifiers shared by multiple routes" do
    sub_app = Class.new(Roda) do
      plugin :sessions, :secret=>'1'*64
      plugin :route_csrf

      route do |r|
        r.get 'profile' do
          r.csrf_action :update_profile
          csrf_tag
        end

        r.post 'profile' do
          r.csrf_action :update_profile
          check_csrf!
          'mounted-update-profile'
        end
      end
    end

    app(:bare) do
      send(*DEFAULT_SESSION_ARGS)
      plugin :route_csrf

      route do |r|
        r.on 'admin' do
          r.get 'profile' do
            r.csrf_action :update_profile
            csrf_tag
          end

          r.post 'profile' do
            r.csrf_action :update_profile
            check_csrf!
            'main-update-profile'
          end

          r.get 'settings' do
            r.csrf_action :update_settings
            csrf_tag
          end

          r.post 'settings' do
            r.csrf_action :update_settings
            check_csrf!
            'main-update-settings'
          end
        end

        r.get 'generate' do
          csrf_action_tag(:update_profile)
        end

        r.get 'legacy' do
          csrf_tag('/legacy')
        end

        r.post 'legacy' do
          check_csrf!
          'legacy-ok'
        end

        r.on 'mounted' do
          r.run sub_app
        end
      end
    end

    main_tag = body('/admin/profile')
    main_tag =~ /\A<input type="hidden" name="_csrf" value="([+\/0-9A-Za-z]{84})" \/>\z/
    main_token = $1

    body("/admin/profile", "REQUEST_METHOD"=>'POST', 'rack.input'=>rack_input("_csrf=#{Rack::Utils.escape(main_token)}")).must_equal 'main-update-profile'

    # The token for the same action is accepted by the mounted sub application,
    # even though the request path and the application handling it differ.  The
    # mounted sub application shares the parent application's session secret.
    body("/mounted/profile", "REQUEST_METHOD"=>'POST', 'rack.input'=>rack_input("_csrf=#{Rack::Utils.escape(main_token)}")).must_equal 'mounted-update-profile'

    mounted_tag = body('/mounted/profile')
    mounted_tag =~ /\A<input type="hidden" name="_csrf" value="([+\/0-9A-Za-z]{84})" \/>\z/
    mounted_token = $1

    # A token generated in the mounted sub application is accepted by the main
    # application route for the same action.
    body("/admin/profile", "REQUEST_METHOD"=>'POST', 'rack.input'=>rack_input("_csrf=#{Rack::Utils.escape(mounted_token)}")).must_equal 'main-update-profile'

    # A token generated directly for the action works on both routes.
    generate_tag = body('/generate')
    generate_tag =~ /\A<input type="hidden" name="_csrf" value="([+\/0-9A-Za-z]{84})" \/>\z/
    generate_token = $1
    body("/admin/profile", "REQUEST_METHOD"=>'POST', 'rack.input'=>rack_input("_csrf=#{Rack::Utils.escape(generate_token)}")).must_equal 'main-update-profile'
    body("/mounted/profile", "REQUEST_METHOD"=>'POST', 'rack.input'=>rack_input("_csrf=#{Rack::Utils.escape(generate_token)}")).must_equal 'mounted-update-profile'

    # A different independent action is isolated from the first action.
    settings_tag = body('/admin/settings')
    settings_tag =~ /\A<input type="hidden" name="_csrf" value="([+\/0-9A-Za-z]{84})" \/>\z/
    settings_token = $1
    body("/admin/settings", "REQUEST_METHOD"=>'POST', 'rack.input'=>rack_input("_csrf=#{Rack::Utils.escape(settings_token)}")).must_equal 'main-update-settings'
    proc{body("/admin/profile", "REQUEST_METHOD"=>'POST', 'rack.input'=>rack_input("_csrf=#{Rack::Utils.escape(settings_token)}"))}.must_raise Roda::RodaPlugins::RouteCsrf::InvalidToken
    proc{body("/mounted/profile", "REQUEST_METHOD"=>'POST', 'rack.input'=>rack_input("_csrf=#{Rack::Utils.escape(settings_token)}"))}.must_raise Roda::RodaPlugins::RouteCsrf::InvalidToken
    proc{body("/admin/settings", "REQUEST_METHOD"=>'POST', 'rack.input'=>rack_input("_csrf=#{Rack::Utils.escape(main_token)}"))}.must_raise Roda::RodaPlugins::RouteCsrf::InvalidToken

    # Forms without an action continue to use the existing path-specific rules.
    legacy_tag = body('/legacy')
    legacy_tag =~ /\A<input type="hidden" name="_csrf" value="([+\/0-9A-Za-z]{84})" \/>\z/
    legacy_token = $1
    body("/legacy", "REQUEST_METHOD"=>'POST', 'rack.input'=>rack_input("_csrf=#{Rack::Utils.escape(legacy_token)}")).must_equal 'legacy-ok'

    # Action-specific tokens and path-specific tokens are not interchangeable,
    # and a missing action never falls back to a different action.
    proc{body("/legacy", "REQUEST_METHOD"=>'POST', 'rack.input'=>rack_input("_csrf=#{Rack::Utils.escape(main_token)}"))}.must_raise Roda::RodaPlugins::RouteCsrf::InvalidToken
    proc{body("/admin/profile", "REQUEST_METHOD"=>'POST', 'rack.input'=>rack_input("_csrf=#{Rack::Utils.escape(legacy_token)}"))}.must_raise Roda::RodaPlugins::RouteCsrf::InvalidToken
  end

  it "binds action tokens to the request method" do
    app(:bare) do
      send(*DEFAULT_SESSION_ARGS)
      plugin :route_csrf

      route do |r|
        r.get 'tag' do
          csrf_action_tag(:update_profile, env['ACTION_METHOD'] || 'POST')
        end

        r.post 'matched' do
          r.csrf_action :update_profile
          check_csrf!
          'matched-post'
        end

        r.is 'matched', :method=>'PUT' do
          r.csrf_action :update_profile
          check_csrf!
          'matched-put'
        end

        r.post 'other' do
          r.csrf_action :other_action
          check_csrf!
          'other'
        end
      end
    end

    post_token = body('/tag')
    post_token =~ /value="([+\/0-9A-Za-z]{84})"/
    post_token = $1
    body("/matched", "REQUEST_METHOD"=>'POST', 'rack.input'=>rack_input("_csrf=#{Rack::Utils.escape(post_token)}")).must_equal 'matched-post'
    proc{body("/matched", "REQUEST_METHOD"=>'PUT', 'rack.input'=>rack_input, 'QUERY_STRING'=>"_csrf=#{Rack::Utils.escape(post_token)}")}.must_raise Roda::RodaPlugins::RouteCsrf::InvalidToken
    proc{body("/other", "REQUEST_METHOD"=>'POST', 'rack.input'=>rack_input("_csrf=#{Rack::Utils.escape(post_token)}"))}.must_raise Roda::RodaPlugins::RouteCsrf::InvalidToken

    put_token = body('/tag', 'ACTION_METHOD'=>'PUT')
    put_token =~ /value="([+\/0-9A-Za-z]{84})"/
    put_token = $1
    body("/matched", "REQUEST_METHOD"=>'PUT', 'rack.input'=>rack_input, 'QUERY_STRING'=>"_csrf=#{Rack::Utils.escape(put_token)}").must_equal 'matched-put'
    proc{body("/matched", "REQUEST_METHOD"=>'POST', 'rack.input'=>rack_input("_csrf=#{Rack::Utils.escape(put_token)}"))}.must_raise Roda::RodaPlugins::RouteCsrf::InvalidToken
  end

  it "does not leak a declared action from a route branch that does not match" do
    app(:bare) do
      send(*DEFAULT_SESSION_ARGS)
      plugin :route_csrf
      plugin :pass

      route do |r|
        r.on 'scope' do
          # The path matches and the block declares an action, but the branch
          # passes, so it must not leave the action declared for later branches.
          r.post 'partial/extra' do
            r.csrf_action :leaked_action
            r.pass
          end

          r.get 'partial/extra' do
            csrf_token('/scope/partial/extra')
          end

          r.post 'partial/extra' do
            check_csrf!
            'path-specific-after-passed-action'
          end
        end
      end
    end

    token = body('/scope/partial/extra')
    body("/scope/partial/extra", "REQUEST_METHOD"=>'POST', 'rack.input'=>rack_input("_csrf=#{Rack::Utils.escape(token)}")).must_equal 'path-specific-after-passed-action'
  end

  it "raises for invalid action identifiers" do
    app(:bare) do
      send(*DEFAULT_SESSION_ARGS)
      plugin :route_csrf

      route do |r|
        r.get 'invalid' do
          r.csrf_action(1)
        end

        r.post 'invalid' do
          check_csrf!(:action=>1)
        end
      end
    end

    proc{body('/invalid')}.must_raise Roda::RodaError
    proc{body('/invalid', "REQUEST_METHOD"=>'POST', 'rack.input'=>rack_input)}.must_raise Roda::RodaError
  end

  it "raises if the checked action conflicts with the action declared by the route" do
    app(:bare) do
      send(*DEFAULT_SESSION_ARGS)
      plugin :route_csrf

      route do |r|
        r.get 'tag' do
          csrf_action_tag(:declared_action)
        end

        r.post 'conflict' do
          r.csrf_action :declared_action
          check_csrf!(:action=>:other_action)
        end
      end
    end

    token = body('/tag')[/value="([^"]+)"/, 1]
    proc{body("/conflict", "REQUEST_METHOD"=>'POST', 'rack.input'=>rack_input("_csrf=#{Rack::Utils.escape(token)}"))}.must_raise Roda::RodaError
  end

  it "supports csrf_tag with an explicit action and valid_csrf_action?" do
    app(:bare) do
      send(*DEFAULT_SESSION_ARGS)
      plugin :route_csrf

      route do |r|
        r.get 'tag' do
          csrf_tag(:action=>:update_profile)
        end

        r.post 'check' do
          valid_csrf_action?(:update_profile).to_s
        end

        r.post 'check-other' do
          valid_csrf_action?(:other_action).to_s
        end

        r.post 'consume' do
          r.csrf_action :update_profile
          check_csrf!
          'consumed'
        end
      end
    end

    token = body('/tag')[/value="([^"]+)"/, 1]
    body("/consume", "REQUEST_METHOD"=>'POST', 'rack.input'=>rack_input("_csrf=#{Rack::Utils.escape(token)}")).must_equal 'consumed'

    body("/check", "REQUEST_METHOD"=>'POST', 'rack.input'=>rack_input("_csrf=#{Rack::Utils.escape(token)}")).must_equal 'true'
    body("/check-other", "REQUEST_METHOD"=>'POST', 'rack.input'=>rack_input("_csrf=#{Rack::Utils.escape(token)}")).must_equal 'false'
  end

  it "does not accept non-request-specific tokens for a declared action" do
    app(:bare) do
      send(*DEFAULT_SESSION_ARGS)
      plugin :route_csrf, :require_request_specific_tokens=>false

      route do |r|
        r.get 'tag' do
          # A token that is not specific to a request or action.
          csrf_metatag[/content="([^"]+)"/, 1]
        end

        r.get 'action-tag' do
          csrf_action_tag(:update_profile)
        end

        r.post 'consume' do
          r.csrf_action :update_profile
          check_csrf!
          'consumed'
        end

        r.post 'legacy' do
          check_csrf!
          'legacy'
        end
      end
    end

    unbound_token = body('/tag')
    action_token = body('/action-tag')[/value="([^"]+)"/, 1]

    # Without a declared action, the legacy behavior allows the unbound token.
    body("/legacy", "REQUEST_METHOD"=>'POST', 'rack.input'=>rack_input("_csrf=#{Rack::Utils.escape(unbound_token)}")).must_equal 'legacy'

    # With a declared action, the unbound token is not accepted.
    proc{body("/consume", "REQUEST_METHOD"=>'POST', 'rack.input'=>rack_input("_csrf=#{Rack::Utils.escape(unbound_token)}"))}.must_raise Roda::RodaPlugins::RouteCsrf::InvalidToken

    body("/consume", "REQUEST_METHOD"=>'POST', 'rack.input'=>rack_input("_csrf=#{Rack::Utils.escape(action_token)}")).must_equal 'consumed'
  end

begin
  require 'rack/csrf'
rescue LoadError
  warn "rack_csrf not installed, skipping route_csrf plugin test for rack_csrf upgrade"
else
  it "supports upgrades from existing rack_csrf token" do
    route_csrf_app(:upgrade_from_rack_csrf_key=>'csrf.token', :no_sessions_plugin=>true) do |r|
      r.get 'clear' do
        session.clear
        ''
      end
      Rack::Csrf.token(env)
    end
    app.use(*DEFAULT_SESSION_MIDDLEWARE_ARGS)
    app.use Rack::Csrf, :skip=>['POST:/foo', 'POST:/bar'], :raise=>true
    token = body
    token.length.wont_equal 84
    body("/foo", "REQUEST_METHOD"=>'POST', 'rack.input'=>rack_input("_csrf=#{Rack::Utils.escape(token)}")).must_equal 'f'
    body("/bar", "REQUEST_METHOD"=>'POST', 'rack.input'=>rack_input("_csrf=#{Rack::Utils.escape(token)}")).must_equal 'b'
    body('/clear').must_equal ''
    proc{body("/foo", "REQUEST_METHOD"=>'POST', 'rack.input'=>rack_input("_csrf=#{Rack::Utils.escape(token)}"))}.must_raise Roda::RodaPlugins::RouteCsrf::InvalidToken
    proc{body("/bar", "REQUEST_METHOD"=>'POST', 'rack.input'=>rack_input("_csrf=#{Rack::Utils.escape(token)}"))}.must_raise Roda::RodaPlugins::RouteCsrf::InvalidToken
  end
end
end
