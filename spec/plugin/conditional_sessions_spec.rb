require_relative "../spec_helper"

describe "conditional_sessions plugin" do 
  include CookieJar

  before do
    allow = @allow = String.new('f')
    app(:bare) do
      plugin :conditional_sessions, :secret=>'1'*64 do
        allow != 'f'
      end

      route do |r|
        r.get('s', String, String){|k, v| v.force_encoding('UTF-8'); session[k] = v}
        r.get('g',  String){|k| session[k].to_s}
        r.get('cat'){r.session_created_at.to_i.to_s}
        r.get('uat'){r.session_updated_at.to_i.to_s}
        r.get('cs'){clear_session.to_s}
        r.get('ps', String, String){|k, v| r.persist_session(response.headers, k => v); env.delete("rack.session"); nil}
        ''
      end
    end
  end

  it "allows sessions if allowed" do
    @allow.replace('t')
    body('/s/foo/bar').must_equal 'bar'
    body('/g/foo').must_equal 'bar'
    body('/cat').to_i.must_be(:>=, Time.now.to_i - 1)
    body('/uat').to_i.must_be(:>=, Time.now.to_i - 1)

    body('/s/foo/baz').must_equal 'baz'
    body('/g/foo').must_equal 'baz'

    body('/ps/foo/quux').must_equal ''
    body('/g/foo').must_equal 'quux'

    body('/cs').must_equal ''
    body('/g/foo').must_equal ''
  end

  it "raises on session if sessions not allowed" do
    proc{body('/s/foo/bar')}.must_raise Roda::RodaError
  end

  it "raises on session_created_at if sessions not allowed" do
    proc{body('/cat')}.must_raise Roda::RodaError
  end

  it "raises on session_updated_at if sessions not allowed" do
    proc{body('/uat')}.must_raise Roda::RodaError
  end

  it "has clear_session do nothing if sessions are not alowed" do
    @allow.replace('t')
    body('/s/foo/bar').must_equal 'bar'
    @allow.replace('f')
    body('/cs').must_equal ''
    @allow.replace('t')
    body('/g/foo').must_equal 'bar'
  end

  it "has persist_session do nothing if sessions are not alowed" do
    @allow.replace('t')
    body('/s/foo/bar').must_equal 'bar'
    @allow.replace('f')
    body('/ps/foo/quux').must_equal ''
    @allow.replace('t')
    body('/g/foo').must_equal 'bar'
  end

  it "raises if no_sessions! is called after the session is loaded" do
    app(:bare) do
      plugin :conditional_sessions, :secret=>'1'*64 do
        true
      end

      route do |r|
        r.get('late'){session; r.no_sessions!; 'late'}
        r.get('meta'){[r.sessionless?, r.session_loaded?, r.session_persist_called?, r.session_persisted?].inspect}
      end
    end

    proc{body('/late')}.must_raise Roda::RodaError
  end

  it "only evaluates the conditional block for requests not marked sessionless" do
    evaluations = @evaluations = []
    app(:bare) do
      plugin :conditional_sessions, :secret=>'1'*64 do
        evaluations << path_info
        true
      end

      route do |r|
        r.get('mark'){r.no_sessions!; [r.sessionless?, r.use_sessions?].inspect}
        r.get('check'){[r.sessionless?, r.use_sessions?, r.session_loaded?].inspect}
        ''
      end
    end

    body('/mark').must_equal '[true, false]'
    body('/check').must_equal '[false, true, false]'
    evaluations.must_equal ['/check']
  end

  it "exposes persist_session call and effect through request env" do
    app(:bare) do
      plugin :conditional_sessions, :secret=>'1'*64 do
        true
      end

      route do |r|
        r.get('set', String, String){|k, v| session[k] = v; 'set'}
        r.get('ps', String, String) do |k, v|
          r.persist_session(response.headers, k => v)
          [r.session_persist_called?, r.session_persisted?].inspect
        end
      end
    end

    _, h, b = req('/ps/foo/bar')
    b.join.must_equal '[true, true]'
    h[RodaResponseHeaders::SET_COOKIE].wont_be_nil

    _, h, b = req('/set/foo/baz')
    b.join.must_equal 'set'
    h[RodaResponseHeaders::SET_COOKIE].wont_be_nil
  end

  it "considers an outer app's loaded session as loaded in a nested app" do
    inner = app(:bare) do
      plugin :conditional_sessions, :secret=>'1'*64 do
        true
      end

      route do |r|
        r.get('loaded'){r.session_loaded?.to_s}
        r.get('late'){r.no_sessions!; 'late'}
      end
    end

    app(:bare) do
      plugin :conditional_sessions, :secret=>'1'*64 do
        true
      end

      route do |r|
        r.on('inner'){session; r.run inner}
      end
    end

    body('/inner/loaded').must_equal 'true'
    proc{body('/inner/late')}.must_raise Roda::RodaError
  end

  it "does not load or persist sessions for nested public health and preview routes" do
    health_checks = @health_checks = []
    inner = app(:bare) do
      plugin :conditional_sessions, :secret=>'1'*64 do
        true
      end

      route do |r|
        r.on('public') do
          r.on('health') do
            r.no_sessions!
            health_checks << [r.sessionless?, r.session_loaded?]
            'OK'
          end

          r.on('preview') do
            r.no_sessions!
            raise ArgumentError, 'preview failed'
          end
        end

        r.on('session') do
          r.get('set', String, String){|k, v| session[k] = v; v}
          r.get('get', String){|k| session[k].to_s}
          r.get('clear'){clear_session; 'cleared'}
        end
      end
    end
    app(:bare) do
      plugin :conditional_sessions, :secret=>'1'*64 do
        true
      end
      plugin :error_handler do |e|
        e.message
      end

      route do |r|
        r.on('app'){r.run inner}
      end
    end

    # Seed a real session cookie through the normal session route, then reuse
    # the exact cookie value on subsequent requests.  Use direct Rack envs so
    # the behavior of the cookie jar does not hide a missing Set-Cookie.
    cookie = nil
    client = lambda do |path|
      env = req_env('PATH_INFO'=>path)
      env['HTTP_COOKIE'] = cookie if cookie
      status, headers, body = @app.call(env)
      body = [].tap{|a| body.each{|part| a << part}}
      body.close if body.respond_to?(:close)
      if set = headers[RodaResponseHeaders::SET_COOKIE]
        set = set.join("\n") if set.is_a?(Array)
        cookie = set[/roda\.session=[^;\s]+/]
      end
      [status, headers, body, env]
    end

    status, h, b, _ = client.call('/app/session/set/user/alice')
    status.must_equal 200
    h[RodaResponseHeaders::SET_COOKIE].wont_be_nil
    cookie.wont_be_nil

    # Both sessionless routes are reached through two routing levels (the
    # outer `r.on('app')` and the inner `r.on('public')`) while carrying the
    # test cookie.  Neither response may set or delete the session cookie,
    # and the sessions after processing is not even called.
    status, h, b, env = client.call('/app/public/health')
    status.must_equal 200
    b.join.must_equal 'OK'
    h[RodaResponseHeaders::SET_COOKIE].must_be_nil
    health_checks.must_equal [[true, false]]
    env['roda.conditional_sessions.sessionless'].must_equal true
    env['roda.conditional_sessions.persist_called'].must_be_nil
    env['roda.conditional_sessions.persisted'].must_be_nil

    status, h, b, env = client.call('/app/public/preview')
    status.must_equal 500
    b.join.must_equal 'preview failed'
    h[RodaResponseHeaders::SET_COOKIE].must_be_nil
    env['roda.conditional_sessions.sessionless'].must_equal true
    env['roda.conditional_sessions.persist_called'].must_be_nil
    env['roda.conditional_sessions.persisted'].must_be_nil

    # Adjacent normal pages still load and update the session using the same
    # cookie, and the updated value is visible on the next request.
    status, h, b, _ = client.call('/app/session/get/user')
    b.join.must_equal 'alice'
    h[RodaResponseHeaders::SET_COOKIE].must_be_nil

    status, h, b, env = client.call('/app/session/set/user/bob')
    b.join.must_equal 'bob'
    h[RodaResponseHeaders::SET_COOKIE].wont_be_nil
    env['roda.conditional_sessions.persisted'].must_equal true

    status, h, b, _ = client.call('/app/session/get/user')
    b.join.must_equal 'bob'
  end

  it "ignores explicit persist_session and clear_session on a sessionless request" do
    app(:bare) do
      plugin :conditional_sessions, :secret=>'1'*64 do
        true
      end

      route do |r|
        r.get('session'){session['k'] = 'v'; 'session'}
        r.get('health') do
          r.no_sessions!
          r.persist_session(response.headers, 'k' => 'v')
          clear_session
          [r.session_persist_called?, r.session_persisted?, r.session_loaded?].inspect
        end
      end
    end

    _, h, b = req('/session')
    h[RodaResponseHeaders::SET_COOKIE].wont_be_nil
    cookie = h[RodaResponseHeaders::SET_COOKIE]
    cookie = cookie.join("\n") if cookie.is_a?(Array)
    cookie = cookie[/roda\.session=[^;\s]+/]

    env = req_env('PATH_INFO'=>'/health', 'HTTP_COOKIE'=>cookie)
    status, h, b = @app.call(env)
    body = +''
    b.each{|part| body << part}
    b.close if b.respond_to?(:close)
    status.must_equal 200
    body.must_equal '[true, false, false]'
    h[RodaResponseHeaders::SET_COOKIE].must_be_nil
    env['roda.conditional_sessions.persist_called'].must_equal true
    env['roda.conditional_sessions.persisted'].must_be_nil
  end

  it "marks the shared request env as sessionless across nested apps" do
    inner = app(:bare) do
      plugin :conditional_sessions, :secret=>'1'*64 do
        true
      end

      route do |r|
        r.get('preview'){r.no_sessions!; 'preview'}
      end
    end

    app(:bare) do
      plugin :conditional_sessions, :secret=>'1'*64 do
        true
      end

      route do |r|
        r.get('health'){r.no_sessions!; 'health'}
        r.on('nested'){r.run inner}
        r.get('session'){session['seen'] = 'yes'; 'session'}
      end
    end

    env = req_env('PATH_INFO'=>'/health')
    @app.call(env)
    env['roda.conditional_sessions.sessionless'].must_equal true
    env['roda.conditional_sessions.persist_called'].must_be_nil
    env['roda.conditional_sessions.persisted'].must_be_nil

    env = req_env('PATH_INFO'=>'/nested/preview')
    @app.call(env)
    env['roda.conditional_sessions.sessionless'].must_equal true
    env['roda.conditional_sessions.persist_called'].must_be_nil

    env = req_env('PATH_INFO'=>'/session')
    @app.call(env)
    env['roda.conditional_sessions.persist_called'].must_equal true
    env['roda.conditional_sessions.persisted'].must_equal true
  end
end
