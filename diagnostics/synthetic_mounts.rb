# frozen_string_literal: true

require 'grape'

# Synthetic mounts and the diagnostic middleware behind the 404-triage
# convention in diagnostics/README.md. Two Grape APIs sit behind a
# HeaderCascade, each wrapped in a MountProbe, with a PublicFacade on top.
# Every stage records events on env[EVENTS_KEY]; Diagnostics.call runs one
# request and hands back the external answer plus the internal trace.
module Diagnostics
  EVENTS_KEY = 'diagnostics.events'

  Result = Data.define(:status, :headers, :body, :events) do
    def allow
      headers['allow']
    end

    # The stage the request stopped at, from the last event of the trace.
    def terminal_stage
      last = events.last
      last ? "#{last[:mount]}/#{last[:stage]}:#{last[:event]}" : 'none'
    end
  end

  # Hands the request to each mounted app in turn while the answer carries
  # Grape's X-Cascade: pass header -- the convention Grape's own router
  # follows. Rack::Cascade is deliberately not used here: it falls through
  # on the 404/405 *status*, which would consult the next mount after a
  # policy denial and would swallow a 405's Allow header into the next
  # mount's 404.
  class HeaderCascade
    def initialize(apps)
      @apps = apps
    end

    def call(env)
      result = nil
      last_body = nil
      @apps.each do |app|
        last_body.close if last_body.respond_to?(:close)
        result = app.call(env)
        return result unless result[1]['x-cascade'] == 'pass'

        last_body = result[2]
      end
      result
    end
  end

  # Wraps one mounted API, outside Grape's router. Records whether the
  # router produced a route candidate for the request; when it did not, the
  # request never entered the mount's identity middleware -- that fact is
  # recorded here, at the only place that can still observe it, rather than
  # inferred later from the absence of identity events.
  #
  # Also classifies the mount's answer into the stage that produced it. This
  # cannot happen in a `use` middleware: Grape::Middleware::Error sits above
  # those and renders every thrown or raised error, so an in-stack
  # middleware only ever sees responses that return normally.
  class MountProbe
    # Routing state a previous mount in the cascade may have left on the
    # shared env. Dropped before delegating, so a miss here is not read as a
    # hit there.
    STALE_ENV_KEYS = [
      Grape::Env::GRAPE_ROUTING_ARGS,
      Grape::Env::API_ENDPOINT,
      Grape::Env::API_VERSION
    ].freeze

    def initialize(app, mount:)
      @app = app
      @mount = mount
    end

    def call(env)
      events = env[EVENTS_KEY]
      return @app.call(env) unless events

      STALE_ENV_KEYS.each { |key| env.delete(key) }
      mark = events.length
      status, headers, body = @app.call(env)
      events.insert(mark, router_event(env))
      record_terminal(events, mark, env, status, headers)
      [status, headers, body]
    end

    private

    def router_event(env)
      routing_args = env[Grape::Env::GRAPE_ROUTING_ARGS]
      unless routing_args
        return { mount: @mount, stage: 'router', event: 'no_candidate',
                 detail: 'no route candidate; request never entered the identity middleware' }
      end

      route = routing_args[:route_info]
      method = route.respond_to?(:request_method) ? route.request_method : '(neutral)'
      { mount: @mount, stage: 'router', event: 'candidate_matched',
        detail: "#{method} #{route.origin}" }
    end

    # No terminal event when there was no candidate (the router event says
    # it all) or when the identity gate denied (its event is the terminal
    # one). A denied 404 carries no X-Cascade, so the cascade stops here.
    def record_terminal(events, mark, env, status, headers)
      return unless env[Grape::Env::GRAPE_ROUTING_ARGS]
      return if events[mark..].any? { |event| event[:event] == 'denied' }

      events << terminal_event(env, status, headers)
    end

    def terminal_event(env, status, headers)
      return method_event(status, headers) if status == 405 || (status == 204 && headers['allow'])
      return { mount: @mount, stage: 'endpoint', event: 'executed', detail: "answered #{status}" } if status < 400

      if status == 404 && !env[Grape::Env::API_VERSION]
        return { mount: @mount, stage: 'version', event: 'rejected',
                 detail: 'version negotiation answered 404 (x-cascade) before api.version was set' }
      end

      { mount: @mount, stage: 'endpoint', event: 'error', detail: "answered #{status}" }
    end

    def method_event(status, headers)
      event = status == 405 ? 'method_not_allowed' : 'auto_options'
      { mount: @mount, stage: 'method', event:,
        detail: "Allow confirmed: #{headers['allow']} (public Allow response header)" }
    end
  end

  # The identity middleware, mounted with `use` inside each API: it runs
  # after the router matched a candidate, ahead of the versioner and the
  # endpoint. It authenticates the operator token and applies the mount's
  # hiding policy -- a hidden path answered to an identity the policy does
  # not cover gets the same 404 an unregistered path gets, without X-Cascade,
  # so the cascade stops instead of consulting the next mount.
  class IdentityGate
    def initialize(app, mount:, hidden:, visible_to:)
      @app = app
      @mount = mount
      @hidden = hidden
      @visible_to = visible_to
    end

    def call(env)
      events = env[EVENTS_KEY]
      token = env['HTTP_X_OPERATOR_TOKEN']
      events << { mount: @mount, stage: 'identity', event: 'entered',
                  detail: token ? "token=#{token}" : 'anonymous' }

      if hidden?(env) && token != @visible_to
        events << { mount: @mount, stage: 'identity', event: 'denied',
                    detail: 'route hidden from this identity by policy; Allow suppressed with it' }
        throw :error, Grape::Exceptions::ErrorResponse.new(status: 404, message: 'Not Found')
      end

      events << { mount: @mount, stage: 'identity', event: 'allowed',
                  detail: 'policy admits this identity' }
      record_allow(env, events)
      @app.call(env)
    end

    private

    def hidden?(env)
      path = env[Grape::Env::GRAPE_NORMALIZED_PATH] || env[Rack::PATH_INFO]
      @hidden.include?(path)
    end

    # grape.allowed_methods is set only while the router's allowed-methods
    # route runs, so its presence at entry marks this pass as the 405 or
    # auto-OPTIONS answer -- the one place Allow can be read inside the
    # stack. The request method decides which of the two it will be.
    def record_allow(env, events)
      allowed_methods = env[Grape::Env::GRAPE_ALLOWED_METHODS]
      return unless allowed_methods

      events << { mount: @mount, stage: 'method', event: 'allow_readable',
                  detail: "grape.allowed_methods=#{allowed_methods.join(', ')} " \
                          '(env key lives only while the allowed-methods route runs)' }
    end
  end

  # Outermost layer. Every 404 the cascade settles on leaves with the same
  # body and no X-Cascade, so a caller cannot tell "never registered" from
  # "hidden from this identity". 405 and 204 answers pass through untouched:
  # their Allow header is public by design.
  class PublicFacade
    NOT_FOUND_BODY = 'Not Found'

    def initialize(app)
      @app = app
    end

    def call(env)
      status, headers, body = @app.call(env)
      return [status, headers, body] unless status == 404

      body.close if body.respond_to?(:close)
      headers = headers.reject { |name, _| name == 'x-cascade' || name == 'content-length' }
      headers['content-type'] = 'text/plain'
      headers['content-length'] = NOT_FOUND_BODY.bytesize.to_s
      [404, headers, [NOT_FOUND_BODY.dup]]
    end
  end

  # Mount A: path versioning. The version segment is part of the route
  # pattern, so an unregistered version never produces a candidate -- version
  # negotiation for this mount happens inside the router.
  class LedgerAPI < Grape::API
    version 'v1', using: :path
    format :json

    use Diagnostics::IdentityGate, mount: 'ledger',
                                   hidden: ['/v1/ledger/hidden'],
                                   visible_to: 'root-admin'

    get 'ledger' do
      { balance: 1024 }
    end

    get 'ledger/hidden' do
      { ledger: 'off-book' }
    end
  end

  # Mount B: param versioning. The path routes regardless of version, so a
  # rejected version stops inside the endpoint stack -- after the identity
  # middleware -- at Grape::Middleware::Versioner::Param.
  class ReportsAPI < Grape::API
    version 'v2', using: :param
    format :json

    use Diagnostics::IdentityGate, mount: 'reports',
                                   hidden: ['/reports/hidden'],
                                   visible_to: 'root-admin'

    get 'reports' do
      { reports: %w[daily weekly] }
    end

    get 'reports/hidden' do
      { report: 'pre-release' }
    end
  end

  module_function

  def app
    cascade = HeaderCascade.new([
                                  MountProbe.new(LedgerAPI, mount: 'ledger'),
                                  MountProbe.new(ReportsAPI, mount: 'reports')
                                ])
    PublicFacade.new(cascade)
  end

  # Runs one request against the mounted stack and returns the external
  # answer (post-facade) together with the internal event trace.
  def call(method, path, token: nil)
    env = Rack::MockRequest.env_for(path, method:)
    env['HTTP_X_OPERATOR_TOKEN'] = token if token
    events = []
    env[EVENTS_KEY] = events
    status, headers, body = app.call(env)
    chunks = []
    body.each { |part| chunks << part }
    body.close if body.respond_to?(:close)
    Result.new(status:, headers:, body: chunks.join, events:)
  end
end
