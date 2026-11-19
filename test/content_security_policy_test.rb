require_relative 'test_helper'

class ContentSecurityPolicyTest < Minitest::Test
  CSP = Sinatra::Middleware::ContentSecurityPolicy
  NONCE_KEY = CSP::NONCE_ENV_KEY

  def html_app(body = 'hello')
    lambda do |env|
      [200, { 'content-type' => 'text/html' }, [body]]
    end
  end

  def build(inner, *args, **kwargs)
    CSP.new(inner, *args, **kwargs)
  end

  def request_env(path = '/')
    Rack::MockRequest.env_for(path)
  end

  def nonce_from(header)
    header[/'nonce-([^']+)'/, 1]
  end

  it 'applies a default policy when none is given' do
    _status, headers, _body = build(html_app).call(request_env)
    assert_equal "default-src 'self'", headers['content-security-policy']
  end

  it 'uses a fixed String policy verbatim on every request' do
    mw = build(html_app, "default-src 'self'; script-src cdn.example.com")
    _s1, h1, _b1 = mw.call(request_env)
    _s2, h2, _b2 = mw.call(request_env)
    assert_equal "default-src 'self'; script-src cdn.example.com", h1['content-security-policy']
    assert_equal h1['content-security-policy'], h2['content-security-policy']
  end

  it 'exposes a per-request nonce in env that matches the policy header' do
    seen = nil
    inner = lambda do |env|
      seen = env[NONCE_KEY]
      [200, { 'content-type' => 'text/html' }, ['ok']]
    end
    mw = build(inner, { script_src: [:self, :nonce] })
    _status, headers, _body = mw.call(request_env)
    refute_nil seen
    assert_match %r{\A[A-Za-z0-9+/=]+\z}, seen
    assert_include headers['content-security-policy'], "script-src 'self' 'nonce-#{seen}'"
  end

  it 'returns the same nonce on repeated env reads within one request' do
    reads = []
    inner = lambda do |env|
      2.times { reads << env[NONCE_KEY] }
      [200, { 'content-type' => 'text/html' }, ['ok']]
    end
    build(inner, { script_src: :nonce }).call(request_env)
    assert_equal 2, reads.size
    assert_equal reads.first, reads.last
  end

  it 'generates independent nonces for sequential requests' do
    seen = []
    inner = lambda do |env|
      seen << env[NONCE_KEY]
      [200, { 'content-type' => 'text/html' }, ['ok']]
    end
    mw = build(inner, { script_src: :nonce })
    2.times { mw.call(request_env) }
    assert_equal 2, seen.uniq.size
  end

  it 'does not leak nonces between interleaved requests' do
    arrivals = Queue.new
    release = Queue.new
    inner = lambda do |env|
      arrivals << env
      release.pop
      [200, { 'content-type' => 'text/html' }, [env[NONCE_KEY]]]
    end
    mw = build(inner, { script_src: :nonce })

    env_a = request_env('/a')
    env_b = request_env('/b')
    thread_a = Thread.new { mw.call(env_a) }
    arrivals.pop # A is now paused inside the app
    thread_b = Thread.new { mw.call(env_b) }
    arrivals.pop # B is now paused inside the app
    release << true << true
    _sa, headers_a, body_a = thread_a.value
    _sb, headers_b, body_b = thread_b.value

    nonce_a = env_a[NONCE_KEY]
    nonce_b = env_b[NONCE_KEY]
    refute_equal nonce_a, nonce_b
    assert_equal nonce_a, nonce_from(headers_a['content-security-policy'])
    assert_equal nonce_b, nonce_from(headers_b['content-security-policy'])
    assert_equal [nonce_a], body_a.each.to_a
    assert_equal [nonce_b], body_b.each.to_a
  end

  it 'passes streaming bodies through untouched while adding the header' do
    chunks = %w[chunk1 chunk2 chunk3]
    stream = Object.new
    stream.define_singleton_method(:each) { |&block| chunks.each(&block) }
    inner = ->(_env) { [200, { 'content-type' => 'text/html' }, stream] }
    _status, headers, body = build(inner, { script_src: :nonce }).call(request_env)
    assert_same stream, body
    assert_include headers['content-security-policy'], "'nonce-"
    assert_equal chunks, body.each.to_a
  end

  it 'leaves Cache-Control and other response headers alone' do
    inner = lambda do |_env|
      [200, { 'content-type' => 'text/html', 'cache-control' => 'public, max-age=60' }, ['ok']]
    end
    _status, headers, _body = build(inner, { script_src: :nonce }).call(request_env)
    assert_equal 'public, max-age=60', headers['cache-control']
    assert_include headers['content-security-policy'], "'nonce-"
  end

  it 'sends the policy as report-only when report_only is true' do
    _status, headers, _body = build(html_app, { default_src: :self }, report_only: true).call(request_env)
    assert_equal "default-src 'self'", headers['content-security-policy-report-only']
    refute headers.key?('content-security-policy')
  end

  it 'does not overwrite a policy already set by the application' do
    inner = lambda do |env|
      [200, { 'content-type' => 'text/html', 'content-security-policy' => "default-src 'none'" }, ['ok']]
    end
    env = request_env
    _status, headers, _body = build(inner, { script_src: :nonce }).call(env)
    assert_equal "default-src 'none'", headers['content-security-policy']
    refute_nil env[NONCE_KEY]
  end

  it 'applies the header to non-HTML responses too' do
    inner = ->(_env) { [200, { 'content-type' => 'application/json' }, ['{}']] }
    _status, headers, _body = build(inner, { default_src: :none }).call(request_env)
    assert_equal "default-src 'none'", headers['content-security-policy']
  end

  it 'lets exceptions propagate and keeps later requests independent' do
    calls = 0
    inner = lambda do |env|
      calls += 1
      raise 'boom' if calls == 1
      [200, { 'content-type' => 'text/html' }, [env[NONCE_KEY]]]
    end
    mw = build(inner, { script_src: :nonce })
    failing_env = request_env('/fail')
    assert_raises(RuntimeError) { mw.call(failing_env) }
    _status, headers, body = mw.call(request_env('/ok'))
    refute_equal failing_env[NONCE_KEY], nonce_from(headers['content-security-policy'])
    assert_equal [nonce_from(headers['content-security-policy'])], body.each.to_a
  end

  it 'serializes hash directives, keywords and valueless directives' do
    mw = build(html_app,
               { default_src: :self,
                 script_src: [:self, :unsafe_inline, 'cdn.example.com'],
                 upgrade_insecure_requests: true,
                 block_all_mixed_content: false })
    _status, headers, _body = mw.call(request_env)
    assert_equal "default-src 'self'; " \
                 "script-src 'self' 'unsafe-inline' cdn.example.com; " \
                 'upgrade-insecure-requests',
                 headers['content-security-policy']
  end

  it 'works mounted in a Sinatra app with the nonce readable from routes' do
    mock_app do
      use Sinatra::Middleware::ContentSecurityPolicy, script_src: :nonce
      get('/') { env['sinatra.csp_nonce'] }
    end
    get '/'
    assert ok?
    nonce = body
    assert_match %r{\A[A-Za-z0-9+/=]+\z}, nonce
    assert_include response.headers['content-security-policy'], "script-src 'nonce-#{nonce}'"
  end

  it 'keeps a fixed String policy byte-identical when mounted in a Sinatra app' do
    mock_app do
      use Sinatra::Middleware::ContentSecurityPolicy, "default-src 'self'"
      get('/') { 'ok' }
    end
    get '/'
    first = response.headers['content-security-policy']
    get '/'
    assert_equal "default-src 'self'", first
    assert_equal first, response.headers['content-security-policy']
  end
end
