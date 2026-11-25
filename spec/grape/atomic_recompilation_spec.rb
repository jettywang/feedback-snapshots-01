# frozen_string_literal: true

require_relative '../../examples/atomic_reloading/check'

RSpec.describe 'Atomic Grape recompilation' do
  let(:example) { AtomicReloadingExample }
  let(:defaults) { example::SharedDefaults[user: 'reader', path: '/ping'] }

  def response(app, password: nil, user: defaults.user)
    env = Rack::MockRequest.env_for(defaults.path)
    if password
      token = Base64.strict_encode64("#{user}:#{password}")
      env['HTTP_AUTHORIZATION'] = "Basic #{token}"
    end
    app.call(env)
  end

  def body(response)
    chunks = []
    response[2].each { |chunk| chunks << chunk }
    JSON.parse(chunks.join)
  end

  def expect_v1(response)
    expect(response[0]).to eq(200)
    expect(body(response)).to eq('edition' => 1, 'handler' => 'handler-v1')
  end

  def expect_v2(response)
    expect(response[0]).to eq(200)
    expect(body(response)).to eq('edition' => 2, 'handler' => 'handler-v2')
  end

  def expect_v1_protection(switch)
    unauthorized = response(switch)
    expect(unauthorized[0]).to eq(401)
    expect(unauthorized[1]['www-authenticate']).to eq('Basic realm="atomic-v1"')
    expect(response(switch, password: 'new-secret')[0]).to eq(401)
    expect_v1(response(switch, password: 'old-secret'))
  end

  def expect_v2_protection(switch)
    unauthorized = response(switch)
    expect(unauthorized[0]).to eq(401)
    expect(unauthorized[1]['www-authenticate']).to eq('Basic realm="atomic-v2"')
    expect(response(switch, password: 'old-secret')[0]).to eq(401)
    expect_v2(response(switch, password: 'new-secret'))
  end

  describe Grape::API::Instance do
    it 'keeps lazy compilation and atomically replaces a prepared instance' do
      api = Class.new(Grape::API) { get('/ping') { { edition: 1 } } }
      base = api.base_instance

      expect(base.instance_variable_get(:@instance)).to be_nil
      first = api.compile!
      expect(api.compile!).to be(first)

      api.get('/next') { { edition: 2 } }
      second = api.recompile!

      expect(second).not_to be(first)
      expect(api.compile!).to be(second)
      expect(Rack::MockRequest.new(api).get('/next').status).to eq(200)
    end

    it 'preserves the published instance when replacement compilation fails' do
      api = Class.new(Grape::API) { get('/ping') { 'ok' } }
      first = api.compile!
      base = api.base_instance
      attempts = 0

      allow(base).to receive(:new).and_wrap_original do |original|
        attempts += 1
        raise 'injected local compilation error' if attempts == 1

        original.call
      end

      expect { api.recompile! }.to raise_error(RuntimeError, 'injected local compilation error')
      expect(api.compile!).to be(first)

      recovered = api.recompile!
      expect(recovered).not_to be(first)
      expect(api.compile!).to be(recovered)
    end
  end

  describe 'small Rack application' do
    it 'prepares two editions and switches handlers and auth atomically' do
      v1 = example::Factory.build(version: 1, realm: 'atomic-v1', password: 'old-secret', defaults:)
      v2 = example::Factory.build(version: 2, realm: 'atomic-v2', password: 'new-secret', defaults:)
      switch = example::Switch.new(v1)

      expect_v1_protection(switch)

      switch.publish(v2)

      expect_v2_protection(switch)
    end

    it 'pins a published edition to its compiled Rack instance after the API recompiles' do
      v1_api = example::Factory.api(version: 1, realm: 'atomic-v1', password: 'old-secret', defaults:)
      v1 = example::Edition.new(name: 'v1', app: v1_api, realm: 'atomic-v1', password: 'old-secret', defaults:)
      switch = example::Switch.new(v1)
      compiled_app = v1.app

      v1_api.recompile!

      expect(v1.app).to be(compiled_app)
      expect(v1_api.compile!).not_to be(compiled_app)
      expect_v1_protection(switch)
    end

    it 'keeps the old route and protection after a candidate compile error and recovery' do
      v1 = example::Factory.build(version: 1, realm: 'atomic-v1', password: 'old-secret', defaults:)
      v2_api = example::Factory.api(version: 2, realm: 'atomic-v2', password: 'new-secret', defaults:)
      switch = example::Switch.new(v1)
      attempts = 0
      allow(v2_api.base_instance).to receive(:new).and_wrap_original do |original|
        attempts += 1
        raise 'injected local compilation error' if attempts == 1

        original.call
      end

      expect { v2_api.compile! }.to raise_error(RuntimeError, 'injected local compilation error')
      expect_v1_protection(switch)

      v2_api.compile!
      switch.publish(example::Edition.new(
                       name: 'v2', app: v2_api, realm: 'atomic-v2', password: 'new-secret', defaults:
                     ))

      expect_v2_protection(switch)
      expect(attempts).to eq(2)
    end

    it 'keeps the old protection when a candidate uses an unknown auth strategy' do
      v1 = example::Factory.build(version: 1, realm: 'atomic-v1', password: 'old-secret', defaults:)
      switch = example::Switch.new(v1)
      broken = Class.new(example::SharedAPI) do
        auth :missing_atomic_reload_strategy
        get('/ping') { { edition: 'broken' } }
      end

      expect { broken.compile! }.to raise_error(Grape::Exceptions::UnknownAuthStrategy)
      expect_v1_protection(switch)
    end

    it 'pins concurrent readers to the old edition while a candidate compiles' do
      v1 = example::Factory.build(version: 1, realm: 'atomic-v1', password: 'old-secret', defaults:)
      v2_api = example::Factory.api(version: 2, realm: 'atomic-v2', password: 'new-secret', defaults:)
      switch = example::Switch.new(v1)
      started = Queue.new
      release = Queue.new

      allow(v2_api.base_instance).to receive(:new).and_wrap_original do |original|
        started.push(true)
        release.pop
        original.call
      end

      compiler = Thread.new { v2_api.compile! }
      started.pop

      expect_v1_protection(switch)

      release.push(true)
      compiler.value
      switch.publish(example::Edition.new(
                       name: 'v2', app: v2_api, realm: 'atomic-v2', password: 'new-secret', defaults:
                     ))

      expect_v2_protection(switch)
    ensure
      if compiler&.alive?
        release.push(true)
        compiler.join
      end
    end

    it 'does not let a candidate change shared defaults or parent settings' do
      shared_setting = example::SharedAPI.base_instance.inheritable_setting
      before = shared_setting.to_hash
      config_keys = %i[param_builder lint warn_on_helper_overrides raise_rendering_errors raise_rescue_handler_errors allow_undeclared_params]
      grape_defaults = config_keys.to_h { |key| [key, Grape.config[key]] }

      candidate = Class.new(example::SharedAPI) do
        http_basic(realm: 'candidate') { |user, password| user == 'reader' && password == 'candidate' }
        get('/ping') { { edition: :candidate } }
      end
      candidate.compile!

      expect(shared_setting.to_hash).to eq(before)
      expect(example::SharedAPI.format).to eq(:json)
      expect(config_keys.to_h { |key| [key, Grape.config[key]] }).to eq(grape_defaults)
    end
  end
end
