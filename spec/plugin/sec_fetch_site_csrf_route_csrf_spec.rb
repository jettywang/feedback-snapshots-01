require_relative "../spec_helper"

describe "sec_fetch_site_csrf and route_csrf plugins combined" do
  include CookieJar

  def combined_app(sec_fetch_opts={})
    app(:bare) do
      send(*DEFAULT_SESSION_ARGS)
      plugin :route_csrf
      plugin :sec_fetch_site_csrf, sec_fetch_opts.merge(:allow_missing=>true)
      route do |r|
        check_csrf! unless env['HTTP_SEC_FETCH_SITE']
        check_sec_fetch_site!

        r.get "actions" do
          (session['actions'] || []).join(',')
        end

        r.get "token" do
          csrf_token('/action')
        end

        r.post "action" do
          (session['actions'] ||= []) << 'action'
          "created"
        end

        "ok"
      end
    end
  end

  it "allows GET requests without CSRF tokens or Fetch Metadata for all clients" do
    combined_app
    body.must_equal 'ok'
    body('/', 'HTTP_SEC_FETCH_SITE'=>'none').must_equal 'ok'
    body('/', 'HTTP_SEC_FETCH_SITE'=>'cross-site').must_equal 'ok'
    body('/actions').must_equal ''
    body('/token').wont_be_empty
    body('/actions').must_equal ''
  end

  it "uses the route_csrf token check for clients not sending Fetch Metadata" do
    combined_app
    token = body('/token')

    proc{body('/action', "REQUEST_METHOD"=>'POST', 'rack.input'=>rack_input)}.must_raise Roda::RodaPlugins::RouteCsrf::InvalidToken
    proc{body('/action', "REQUEST_METHOD"=>'POST', 'rack.input'=>rack_input("_csrf=bad"))}.must_raise Roda::RodaPlugins::RouteCsrf::InvalidToken
    body('/actions').must_equal ''

    body('/action', "REQUEST_METHOD"=>'POST', 'rack.input'=>rack_input("_csrf=#{Rack::Utils.escape(token)}")).must_equal 'created'
    body('/actions').must_equal 'action'
  end

  it "uses the sec_fetch_site_csrf origin policy for clients sending Fetch Metadata" do
    combined_app
    token = body('/token')

    body('/action', "REQUEST_METHOD"=>'POST', 'HTTP_SEC_FETCH_SITE'=>'same-origin', 'rack.input'=>rack_input).must_equal 'created'
    body('/actions').must_equal 'action'

    proc{body('/action', "REQUEST_METHOD"=>'POST', 'HTTP_SEC_FETCH_SITE'=>'none', 'rack.input'=>rack_input)}.must_raise Roda::RodaPlugins::SecFetchSiteCsrf::CsrfFailure
    proc{body('/action', "REQUEST_METHOD"=>'POST', 'HTTP_SEC_FETCH_SITE'=>'same-site', 'rack.input'=>rack_input)}.must_raise Roda::RodaPlugins::SecFetchSiteCsrf::CsrfFailure
    proc{body('/action', "REQUEST_METHOD"=>'POST', 'HTTP_SEC_FETCH_SITE'=>'cross-site', 'rack.input'=>rack_input("_csrf=#{Rack::Utils.escape(token)}"))}.must_raise Roda::RodaPlugins::SecFetchSiteCsrf::CsrfFailure
    body('/actions').must_equal 'action'
  end

  it "allows same-site submissions without tokens when the origin policy allows them" do
    combined_app(:allow_same_site=>true)
    body('/action', "REQUEST_METHOD"=>'POST', 'HTTP_SEC_FETCH_SITE'=>'same-site', 'rack.input'=>rack_input).must_equal 'created'
    proc{body('/action', "REQUEST_METHOD"=>'POST', 'HTTP_SEC_FETCH_SITE'=>'cross-site', 'rack.input'=>rack_input)}.must_raise Roda::RodaPlugins::SecFetchSiteCsrf::CsrfFailure
    body('/actions').must_equal 'action'
  end

  it "ends untrusted Fetch Metadata requests with the configured failure action" do
    combined_app(:csrf_failure=>:empty_403)
    req('/action', "REQUEST_METHOD"=>'POST', 'HTTP_SEC_FETCH_SITE'=>'cross-site', 'rack.input'=>rack_input).must_equal [403, {RodaResponseHeaders::CONTENT_TYPE=>'text/html', RodaResponseHeaders::CONTENT_LENGTH=>'0'}, []]
    body('/actions').must_equal ''
  end
end
