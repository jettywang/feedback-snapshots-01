# frozen_string_literal: true

# Reproducible local stand-in for an OmniAuth OAuth strategy migration.
#
# Everything runs through real Rack env hashes (Rack::MockRequest) and the
# real OmniAuth::Strategy code in lib/. No provider network call is ever
# made: the "provider" is modelled by Provider#request_phase redirecting to
# an authorize URL and by the callback params we hand back. In test mode
# the provider is replaced entirely by OmniAuth.config.mock_auth, and this
# file makes that boundary explicit.

require 'logger'
require 'stringio'
require 'rack'
require 'rack/mock'
require 'rack/session'
require 'rack/protection'
require 'omniauth'
require 'omniauth/strategies/developer'

module Experiment
  # A single ordered record of something that happened during a request.
  Event = Struct.new(:seq, :where, :what, :detail, keyword_init: true) do
    def to_a = [where, what, detail]
  end

  # Collects the ordered hook/phase trace for one Rack call. The same
  # recorder is reachable from the strategy and from the Rack endpoints so
  # the finished table interleaves OmniAuth hooks, strategy methods, and
  # application responses in real execution order.
  class Recorder
    attr_reader :events

    def initialize
      @events = []
      @seq = 0
    end

    def log(where, what, detail = nil)
      @events << Event.new(seq: (@seq += 1), where: where, what: what, detail: detail)
    end

    def lines
      @events.map { |event| format('%2d  %-28s %-26s %s', event.seq, event.where, event.what, event.detail.to_s) }
    end
  end

  # The application behind the middleware. In the callback phase OmniAuth
  # calls this with env['omniauth.auth'] already set; that is the point at
  # which a real app's SessionsController#create would run. It records that
  # it actually received a verified auth hash and echoes a marker.
  APP = lambda do |env|
    recorder = env['experiment.recorder']
    if env['omniauth.auth']
      recorder&.log('app', 'receives omniauth.auth', "provider=#{env['omniauth.auth']['provider']} uid=#{env['omniauth.auth']['uid']}")
      [200, {'content-type' => 'text/plain'}, ["APP_OK #{env['omniauth.auth']['uid']}"]]
    else
      recorder&.log('app', 'plain passthrough', env['PATH_INFO'])
      [200, {'content-type' => 'text/plain'}, ['APP_PLAIN']]
    end
  end

  # A Rack endpoint used as the custom :form option. When configured, the
  # request phase renders this instead of redirecting to the provider.
  FORM_ENDPOINT = lambda do |env|
    env['experiment.recorder']&.log('form_endpoint', 'renders custom form', env['PATH_INFO'])
    [200, {'content-type' => 'text/html'}, ['<form>CUSTOM FORM</form>']]
  end

  # A strategy shaped like the company's custom OAuth strategies. It is
  # instrumented at every boundary that matters for the migration: the setup
  # phase, the provider redirect, the provider callback, and the auth hash.
  class Provider
    include OmniAuth::Strategy

    option :name, 'provider'
    STATE = 'state-abc-123'

    def setup_phase
      log_trace('strategy#setup_phase', 'runs')
      super
    end

    def request_phase
      log_trace('strategy#request_phase', 'builds authorize redirect')
      remember_sign_in(STATE)
      redirect("https://provider.test/oauth/authorize?state=#{STATE}&redirect_uri=#{Rack::Utils.escape(callback_url)}")
    end

    def callback_phase
      log_trace('strategy#callback_phase', 'provider params present', "state=#{request.params['state']} code=#{request.params['code']}")
      super
    end

    def callback_sign_in_key
      request.params['state']
    end

    uid { request.params['uid'] }

    info do
      {'name' => 'Ada Lovelace', 'email' => 'ada@example.org', 'nickname' => 'ada'}
    end

    credentials do
      {'token' => 'token-from-provider-code-exchange', 'expires' => true}
    end

    extra do
      {'raw_info' => {'id' => 42, 'login' => 'ada'}}
    end

    private

    def log_trace(where, what, detail = nil)
      env['experiment.recorder']&.log(where, what, detail)
    end
  end

  module Helpers
    module_function

    # Pin global config the way a Rails initializer would. The recorder is
    # wired in through the Rack env, but the OmniAuth hooks are global config,
    # so each scenario configures them and resets afterwards.
    def configure(recorder, test_mode:, validation:)
      OmniAuth.configure do |config|
        config.logger = Logger.new(nil)
        config.test_mode = test_mode
        config.allowed_hosts = ['example.org']
        config.full_host = nil
        config.path_prefix = '/auth'
        config.allowed_request_methods = %i[post]
        config.on_failure = OmniAuth::FailureEndpoint
        config.failure_raise_out_environments = []
        config.request_validation_phase = validation
        config.before_options_phase = hook(recorder, 'before_options_phase')
        config.before_request_phase = hook(recorder, 'before_request_phase')
        config.after_request_phase = hook(recorder, 'after_request_phase')
        config.before_callback_phase = hook(recorder, 'before_callback_phase')
      end
    end

    def hook(recorder, name)
      lambda { |env| recorder.log("hook:#{name}", 'runs', env['PATH_INFO']) }
    end

    # Wraps the real OmniAuth::AuthenticityTokenProtection so the trace shows
    # exactly when request_validation_phase runs and whether it accepts or
    # raises. The real rack-protection check still does the work.
    def observed_validation(recorder)
      lambda do |env|
        recorder.log('hook:request_validation_phase', 'CSRF check starts', env['PATH_INFO'])
        begin
          OmniAuth::AuthenticityTokenProtection.call(env)
          recorder.log('hook:request_validation_phase', 'CSRF check accepted', 'token matched session')
        rescue OmniAuth::AuthenticityError => e
          recorder.log('hook:request_validation_phase', 'CSRF check REJECTED', e.message)
          raise
        end
      end
    end

    def reset_config
      OmniAuth.configure do |config|
        config.test_mode = false
        config.request_validation_phase = OmniAuth::AuthenticityTokenProtection
        config.before_request_phase = nil
        config.after_request_phase = nil
        config.before_callback_phase = nil
        config.before_options_phase = nil
        config.mock_auth.delete(:provider)
        config.allowed_request_methods = %i[post]
        config.allowed_hosts = nil
      end
    end

    def csrf_session
      session = {}
      token = Rack::Protection::AuthenticityToken.token(session)
      [session, token]
    end

    # A session cookie jar shared across the request -> callback round trip.
    def cookie_session
      {'rack.session' => {}}
    end

    def env_for(path, recorder, session:, method: 'GET', params: nil, headers: {})
      env = Rack::MockRequest.env_for("http://example.org#{path}", method: method, params: params, **headers)
      env['rack.session'] = session
      env['experiment.recorder'] = recorder
      env
    end

    # Run a full middleware stack: session middleware, then the strategy,
    # then the app. Using Rack::Session::Cookie keeps the request and
    # callback honest about sharing state, while tests can also pass an
    # explicit session hash.
    def build_stack(strategy)
      app = APP
      Rack::Builder.new do
        use Rack::Session::Cookie, secret: 'experiment-secret-that-is-at-least-64-bytes-long-xxxxxx'
        use strategy
        run app
      end.to_app
    end
  end
end
