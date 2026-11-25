# frozen_string_literal: true

require 'base64'
require 'grape'

module AtomicReloadingExample
  SharedDefaults = Data.define(:user, :path)

  class SharedAPI < Grape::API
    format :json
  end

  Edition = Data.define(:name, :app, :realm, :password, :defaults) do
    def initialize(name:, app:, realm:, password:, defaults:)
      compiled_app = app.compile!
      super(name:, app: compiled_app, realm:, password:, defaults:)
    end

    def call(env)
      app.call(env)
    end
  end

  class Switch
    def initialize(current)
      @lock = Mutex.new
      @current = current
    end

    def current
      @lock.synchronize { @current }
    end

    def publish(candidate)
      raise ArgumentError, 'candidate must be an Edition' unless candidate.is_a?(Edition)

      @lock.synchronize { @current = candidate }
    end

    def call(env)
      edition = current
      edition.call(env)
    end
  end

  module Factory
    module_function

    def api(version:, realm:, password:, defaults:)
      Class.new(SharedAPI) do
        http_basic(realm: realm) do |user, given_password|
          user == defaults.user && given_password == password
        end

        get(defaults.path) do
          { edition: version, handler: "handler-v#{version}" }
        end
      end
    end

    def build(version:, realm:, password:, defaults:)
      app = api(version:, realm:, password:, defaults:)
      Edition.new(name: "v#{version}", app:, realm:, password:, defaults:)
    end
  end

  module Probe
    module_function

    def response(rack_app, defaults:, password: nil, user: defaults.user)
      env = Rack::MockRequest.env_for(defaults.path)
      if password
        token = Base64.strict_encode64("#{user}:#{password}")
        env['HTTP_AUTHORIZATION'] = "Basic #{token}"
      end
      rack_app.call(env)
    end

    def json_body(response)
      JSON.parse(body_text(response))
    end

    def body_text(response)
      chunks = []
      response[2].each { |chunk| chunks << chunk }
      chunks.join
    end

    def auth_realm(response)
      response[1]['www-authenticate']
    end

    def inject_one_shot_fault(base, started, release)
      original_new = base.method(:new)
      failures = 1

      base.define_singleton_method(:new) do |*args, **kwargs, &block|
        if failures.positive?
          failures -= 1
          raise 'injected local compilation error'
        end

        started.push(true)
        release.pop
        original_new.call(*args, **kwargs, &block)
      end
    end
  end

  module Verification
    module_function

    def run
      defaults = SharedDefaults[user: 'reader', path: '/ping']
      first = Factory.build(version: 1, realm: 'atomic-v1', password: 'old-secret', defaults:)
      second_api = Factory.api(version: 2, realm: 'atomic-v2', password: 'new-secret', defaults:)
      switch = Switch.new(first)
      started = Queue.new
      release = Queue.new
      Probe.inject_one_shot_fault(second_api.base_instance, started, release)

      assert_first_edition(switch, defaults)
      failed_compilation_leaves_first(second_api, switch, defaults)
      blocked_compilation_keeps_first(second_api, switch, defaults, started, release)
      publish_second_edition(second_api, switch, defaults)
      assert_shared_defaults(defaults)

      puts 'atomic reloading checks passed'
    end

    def assert_first_edition(switch, defaults)
      assert_unauthorized(switch, defaults, 'atomic-v1')
      response = Probe.response(switch, defaults:, password: 'old-secret')
      assert_handler(response, 1, 'handler-v1')

      response = Probe.response(switch, defaults:, password: 'new-secret')
      assert_status(response, 401)
    end

    def failed_compilation_leaves_first(second_api, switch, defaults)
      error = capture_error { second_api.compile! }
      raise 'expected injected compile error' unless error&.message == 'injected local compilation error'

      assert_first_edition(switch, defaults)
    end

    def blocked_compilation_keeps_first(second_api, switch, defaults, started, release)
      compiler = Thread.new { second_api.compile! }
      started.pop
      assert_first_edition(switch, defaults)

      release.push(true)
      compiler.value
    ensure
      if compiler&.alive?
        release.push(true)
        compiler.join
      end
    end

    def publish_second_edition(second_api, switch, defaults)
      second = Edition.new(
        name: 'v2',
        app: second_api,
        realm: 'atomic-v2',
        password: 'new-secret',
        defaults:
      )
      switch.publish(second)

      assert_unauthorized(switch, defaults, 'atomic-v2')
      response = Probe.response(switch, defaults:, password: 'new-secret')
      assert_handler(response, 2, 'handler-v2')

      response = Probe.response(switch, defaults:, password: 'old-secret')
      assert_status(response, 401)
    end

    def assert_shared_defaults(defaults)
      raise 'shared defaults changed' unless defaults == SharedDefaults[user: 'reader', path: '/ping']
      raise 'shared defaults are mutable' unless defaults.frozen?
      raise 'shared Grape format changed' unless SharedAPI.format == :json
    end

    def assert_unauthorized(app, defaults, realm)
      response = Probe.response(app, defaults:)
      assert_status(response, 401)
      raise "expected #{realm} challenge" unless Probe.auth_realm(response) == "Basic realm=\"#{realm}\""
    end

    def assert_handler(response, edition, handler)
      assert_status(response, 200)
      body = Probe.json_body(response)
      raise "unexpected body #{body.inspect}" unless body == { 'edition' => edition, 'handler' => handler }
    end

    def assert_status(response, status)
      return if response[0] == status

      raise "expected status #{status}, got #{response[0]}: #{Probe.body_text(response)}"
    end

    def capture_error
      yield
      nil
    rescue StandardError => error
      error
    end
  end
end

AtomicReloadingExample::Verification.run if __FILE__ == $PROGRAM_NAME
