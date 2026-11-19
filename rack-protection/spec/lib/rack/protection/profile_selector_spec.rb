# frozen_string_literal: true

RSpec.describe Rack::Protection::ProfileSelector do
  # Stands in for the mounted Rack backend: records every request it
  # receives (as the router would see it) and can be told to blow up.
  class ProfileSelectorSpecApp
    attr_reader :requests

    def initialize
      @requests = []
      @boom = false
    end

    def raise_on_next_call!
      @boom = true
    end

    def call(env)
      @requests << [env['REQUEST_METHOD'], env['SCRIPT_NAME'], env['PATH_INFO']]
      if @boom
        @boom = false
        raise 'downstream boom'
      end

      [200, { 'content-type' => 'text/html' }, ['ok']]
    end
  end

  let(:downstream) { ProfileSelectorSpecApp.new }

  let(:webhook_rule) do
    {
      paths: %w[/webhooks/stripe],
      methods: %w[POST],
      options: { except: %i[http_origin remote_token json_csrf frame_options] }
    }
  end

  let(:evil_origin) { { 'HTTP_ORIGIN' => 'https://evil.example' } }

  def build_app(default_options = {}, profiles = { webhooks: webhook_rule }, downstream_app = downstream)
    mock_app do
      use Rack::Protection::ProfileSelector, default_options, profiles
      run downstream_app
    end
  end

  it 'applies the default profile to pages and the webhook profile to webhook endpoints, interleaved' do
    build_app

    post '/webhooks/stripe', {}, evil_origin
    expect(last_response.status).to eq(200)

    post '/page', {}, evil_origin
    expect(last_response.status).to eq(403)

    post '/webhooks/stripe', {}, evil_origin
    expect(last_response.status).to eq(200)

    post '/page', {}, evil_origin
    expect(last_response.status).to eq(403)

    expect(downstream.requests).to eq([
                                        ['POST', '', '/webhooks/stripe'],
                                        ['POST', '', '/webhooks/stripe']
                                      ])
  end

  it 'runs the actual checks of the selected profile' do
    build_app

    get '/page'
    expect(last_response.headers['x-frame-options']).to eq('SAMEORIGIN')

    # GET does not match the POST-only webhook rule, so the default profile applies
    get '/webhooks/stripe'
    expect(last_response.headers['x-frame-options']).to eq('SAMEORIGIN')

    post '/webhooks/stripe'
    expect(last_response.headers['x-frame-options']).to be_nil
  end

  it 'keeps profile side effects (session handling) independent per request' do
    build_app({ reaction: :drop_session })

    page_session = { keep: 'me' }
    post '/page', {}, 'rack.session' => page_session, 'HTTP_REFERER' => 'https://evil.example/phish'
    expect(last_response.status).to eq(200) # remote token check drops the session, request continues
    expect(page_session).to be_empty

    hook_session = { keep: 'me' }
    post '/webhooks/stripe', {}, 'rack.session' => hook_session, 'HTTP_REFERER' => 'https://evil.example/phish'
    expect(last_response.status).to eq(200)
    expect(hook_session).to eq(keep: 'me')
  end

  it 'matches paths relative to the mount point, like the downstream router' do
    rule = webhook_rule
    recorder = downstream
    mock_app do
      map '/api' do
        use Rack::Protection::ProfileSelector, {}, { webhooks: rule }
        run recorder
      end
    end

    post '/api/webhooks/stripe', {}, evil_origin
    expect(last_response.status).to eq(200)

    post '/api/page', {}, evil_origin
    expect(last_response.status).to eq(403)

    post '/webhooks/stripe', {}, evil_origin
    expect(last_response.status).to eq(404)

    expect(downstream.requests).to eq([['POST', '/api', '/webhooks/stripe']])
  end

  it 'matches the effective method after Rack::MethodOverride, like the downstream router' do
    rule = webhook_rule
    recorder = downstream
    mock_app do
      use Rack::MethodOverride
      use Rack::Protection::ProfileSelector, {}, { webhooks: rule }
      run recorder
    end

    post '/webhooks/stripe', {}, evil_origin
    expect(last_response.status).to eq(200) # POST matches the webhook rule

    # an overridden method cannot keep the relaxed webhook profile
    post '/webhooks/stripe', { _method: 'PUT' }, evil_origin
    expect(last_response.status).to eq(403)

    post '/webhooks/stripe', {}, evil_origin.merge('HTTP_X_HTTP_METHOD_OVERRIDE' => 'DELETE')
    expect(last_response.status).to eq(403)

    # the selector and the router observe the same effective method
    post '/webhooks/stripe', { _method: 'PUT' }
    expect(last_response.status).to eq(200)
    expect(downstream.requests.last).to eq(['PUT', '', '/webhooks/stripe'])

    expect(downstream.requests.first).to eq(['POST', '', '/webhooks/stripe'])
  end

  it 'matches paths literally so encoded variants fall back to the default profile' do
    build_app

    post '/webhooks/stripe'
    expect(last_response.headers['x-frame-options']).to be_nil

    post '/webhooks/%73tripe'
    expect(last_response.headers['x-frame-options']).to eq('SAMEORIGIN')
    expect(downstream.requests.last).to eq(['POST', '', '/webhooks/%73tripe'])

    # even when PathTraversal would clean the variant back onto the webhook
    # route, the relaxed profile is not acquired
    post '/webhooks%2Fstripe'
    expect(last_response.headers['x-frame-options']).to eq('SAMEORIGIN')
    expect(downstream.requests.last).to eq(['POST', '', '/webhooks/stripe'])
  end

  it 'keeps both profiles intact when the downstream app raises' do
    build_app

    downstream.raise_on_next_call!
    expect { post '/webhooks/stripe', {}, evil_origin }.to raise_error('downstream boom')

    post '/page', {}, evil_origin
    expect(last_response.status).to eq(403)

    post '/webhooks/stripe', {}, evil_origin
    expect(last_response.status).to eq(200)

    post '/page', {}, evil_origin
    expect(last_response.status).to eq(403)
  end

  it 'uses the first matching profile and the default profile for unknown routes' do
    profiles = {
      special: { paths: %w[/webhooks/special], options: { except: %i[http_origin frame_options] } },
      fallback: { paths: %w[/webhooks/special /webhooks/stripe], options: { except: %i[frame_options] } }
    }
    build_app({}, profiles)

    post '/webhooks/special', {}, evil_origin
    expect(last_response.status).to eq(200) # first matching profile wins

    post '/webhooks/stripe', {}, evil_origin
    expect(last_response.status).to eq(403) # second profile keeps http_origin

    get '/webhooks/stripe'
    expect(last_response.headers['x-frame-options']).to be_nil # second profile is active

    post '/unknown', {}, evil_origin
    expect(last_response.status).to eq(403) # explicit default

    get '/unknown'
    expect(last_response.headers['x-frame-options']).to eq('SAMEORIGIN')
  end

  it 'treats an empty PATH_INFO as / like routers do' do
    recorder = ProfileSelectorSpecApp.new
    selector = described_class.new(recorder, {}, root: { paths: ['/'], options: { except: %i[frame_options] } })

    env = Rack::MockRequest.env_for('/')
    env['PATH_INFO'] = ''
    status, headers, = selector.call(env)

    expect(status).to eq(200)
    expect(headers['x-frame-options']).to be_nil
    expect(recorder.requests).to eq([['GET', '', '']])
  end

  it 'freezes the selector and its compiled rules' do
    selector = described_class.new(DummyApp, {}, webhooks: webhook_rule)

    expect(selector).to be_frozen
    rules = selector.instance_variable_get(:@profiles)
    expect(rules).to be_frozen
    rules.each do |paths, methods, _stack|
      expect(paths).to be_frozen
      expect(paths.all?(&:frozen?)).to be(true)
      expect(methods).to be_frozen
    end
  end

  it 'cannot be reconfigured by mutating the declaration after build' do
    paths = %w[/webhooks/stripe]
    methods = %w[POST]
    except = %i[http_origin frame_options]
    profiles = { webhooks: { paths: paths, methods: methods, options: { except: except } } }
    build_app({}, profiles)

    paths << '/page'
    methods.delete('POST')
    except.delete(:http_origin)

    post '/webhooks/stripe', {}, evil_origin
    expect(last_response.status).to eq(200) # webhook profile still relaxes http_origin

    post '/page', {}, evil_origin
    expect(last_response.status).to eq(403) # /page was not added to the rule

    get '/webhooks/stripe'
    expect(last_response.headers['x-frame-options']).to eq('SAMEORIGIN') # GET still does not match
  end

  it 'builds the protection stacks once, not per request' do
    build_app

    expect(Rack::Protection).not_to receive(:new)

    post '/webhooks/stripe'
    post '/page'
    get '/unknown'
  end

  it 'rejects invalid profile declarations at build time' do
    expect { described_class.new(DummyApp, {}, nil) }.to raise_error(ArgumentError, /profiles/)
    expect { described_class.new(DummyApp, {}, {}) }.to raise_error(ArgumentError, /profiles/)
    expect { described_class.new(DummyApp, {}, 'webhooks') }.to raise_error(ArgumentError, /profiles/)
    expect { described_class.new(DummyApp, {}, { w: nil }) }.to raise_error(ArgumentError, /rule/)
    expect { described_class.new(DummyApp, {}, { w: {} }) }.to raise_error(ArgumentError, /paths/)
    expect { described_class.new(DummyApp, {}, { w: { paths: [] } }) }.to raise_error(ArgumentError, /paths/)
    expect { described_class.new(DummyApp, {}, { w: { paths: '/webhooks/stripe' } }) }.to raise_error(ArgumentError, /paths/)
    expect { described_class.new(DummyApp, {}, { w: { paths: ['relative'] } }) }.to raise_error(ArgumentError, /paths/)
    expect { described_class.new(DummyApp, {}, { w: { paths: ['/w'], methods: 'POST' } }) }.to raise_error(ArgumentError, /methods/)
    expect { described_class.new(DummyApp, {}, { w: { paths: ['/w'], methods: [] } }) }.to raise_error(ArgumentError, /methods/)
    expect { described_class.new(DummyApp, {}, { w: { paths: ['/w'], bogus: 1 } }) }.to raise_error(ArgumentError, /unknown/)
    expect { described_class.new(DummyApp, {}, { w: { paths: ['/w'], options: 'x' } }) }.to raise_error(ArgumentError, /options/)
    expect { described_class.new(DummyApp, {}, { w: { paths: ['/w'], options: { profiles: {} } } }) }.to raise_error(ArgumentError, /profiles/)
    expect { described_class.new(DummyApp, 'x', { w: { paths: ['/w'] } }) }.to raise_error(ArgumentError, /default options/)
  end

  it 'is used by Rack::Protection.new when :profiles are given' do
    selector = Rack::Protection.new(DummyApp, profiles: { webhooks: webhook_rule })
    expect(selector).to be_a(described_class)

    plain = Rack::Protection.new(DummyApp)
    expect(plain).not_to be_a(described_class)
  end

  it 'works through use Rack::Protection, :profiles => ...' do
    rule = webhook_rule
    recorder = downstream
    mock_app do
      use Rack::Protection, profiles: { webhooks: rule }
      run recorder
    end

    post '/webhooks/stripe', {}, evil_origin
    expect(last_response.status).to eq(200)

    post '/page', {}, evil_origin
    expect(last_response.status).to eq(403)
  end
end
