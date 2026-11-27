# frozen_string_literal: true

# Probe: splitting Rack/Rails request errors vs Active Job reports into two
# Rollbar projects. It keeps the REAL entry points (Rack middleware,
# Rollbar::Delay::ActiveJob transport, Rollbar::ActiveJob rescue) and only
# stubs the HTTP sender so no network call is made.
#
# Run:
#   BUNDLE_FROZEN=true .feedback/bundle-env exec ruby -Ilib -Ispec tmp/rollbar_project_switch_probe.rb

$LOAD_PATH.unshift(File.expand_path('../lib', __dir__))

require 'active_job'
require 'rack'
require 'json'
require 'rollbar'
require 'rollbar/middleware/rack'
require 'rollbar/delay/active_job'
require 'rollbar/plugins/active_job'

ActiveJob::Base.logger = Logger.new(File::NULL)

OLD_TOKEN = 'old-project-token-aaaaaaaaaaaa'
NEW_TOKEN = 'new-project-token-bbbbbbbbbbbb'

$results = []
$checks  = 0
$failures = 0

def check(name, actual, expected)
  $checks += 1
  ok = (actual == expected)
  $failures += 1 unless ok
  line = format('  [%s] %-58s expected=%p actual=%p',
                ok ? 'PASS' : 'FAIL', name, expected, actual)
  $results << line
  puts line
end

def banner(title)
  puts
  puts '=' * 78
  puts title
  puts '=' * 78
end

# ---------------------------------------------------------------------------
# Stub the ONLY the transport: record which token each send used, plus whether
# the payload carried its own top-level access_token. No HTTP is performed.
# ---------------------------------------------------------------------------
# Global send log. A send can be performed by the root notifier, a request
# child notifier, or a per-thread notifier, so we record the sender's identity
# alongside the token it used. No HTTP is performed.
$sends = []

class Rollbar::Notifier
  def do_post(uri, body, config_token)
    parsed = JSON.parse(body)
    $sends << {
      :sender_object_id  => object_id,
      :sender_config_tok => configuration.access_token,
      :header_token      => config_token,
      :payload_token     => parsed['access_token'],
      :use_payload_token => configuration.use_payload_access_token,
      :body              => parsed
    }
    Net::HTTPSuccess.new('1.1', '200', 'OK')
  end
end

def last_send
  $sends.last
end

# In-memory async handler so the generic async path needs no queue backend,
# while still exercising process_async_item -> handler.call(payload).
class CaptureAsyncHandler
  def self.call(payload)
    captured << payload
  end

  def self.captured
    @captured ||= []
  end
end

def configure(token, async:, payload_token: false, handler: nil)
  Rollbar.reconfigure do |config|
    config.enabled = true
    config.access_token = token
    config.use_async = async
    config.async_handler = handler
    config.use_payload_access_token = payload_token
    config.transmit = true
    config.endpoint = 'https://api.rollbar.com/api/1/item/'
    config.logger = Logger.new(File::NULL)
  end

  Rollbar.root_notifier.configuration
end

# ===========================================================================
banner 'PART A — Where the OLD project marker (access_token) is copied to'
# ===========================================================================
configure(OLD_TOKEN, :async => false)
root = Rollbar.root_notifier

# A request-style child notifier, exactly what Rollbar.scoped builds.
child = Rollbar.scoped(:request => { :url => '/orders/1' }) { Rollbar.notifier }

check 'root notifier holds OLD token',
      root.configuration.access_token, OLD_TOKEN
check 'child notifier copied OLD token at capture time',
      child.configuration.access_token, OLD_TOKEN
check 'child configuration is a CLONE (different object)',
      child.configuration.equal?(root.configuration), false

# A notifier a long-lived thread cached BEFORE the cutover keeps the old
# snapshot even though the root has since moved to the new project.
stale_thread_notifier = Rollbar::Notifier.new(root)

# Simulate the cutover: root notifier gets a brand-new Configuration.
new_root_config = configure(NEW_TOKEN, :async => false)

check 'root notifier now holds NEW token',
      Rollbar.root_notifier.configuration.access_token, NEW_TOKEN
check 'reconfigure replaces the root Configuration object',
      Rollbar.root_notifier.configuration.equal?(new_root_config), true
check 'held child notifier KEEPS old cloned token across cutover',
      child.configuration.access_token, OLD_TOKEN

# A fresh request after cutover reads the new root configuration.
fresh = Rollbar.scoped({}) { Rollbar.notifier }
check 'fresh child after cutover reads NEW token',
      fresh.configuration.access_token, NEW_TOKEN

check 'notifier cached by a thread BEFORE cutover keeps OLD token',
      stale_thread_notifier.configuration.access_token, OLD_TOKEN

# The per-thread notifier a fresh thread obtains AFTER cutover inherits the
# current root configuration and therefore points at the new project.
fresh_thread_notifier = Rollbar::Notifier.new(Rollbar.root_notifier)
check 'notifier built from post-cutover root reads NEW token',
      fresh_thread_notifier.configuration.access_token, NEW_TOKEN

# ===========================================================================
banner 'PART B — Three observation points (capture / enqueue / perform)'
# ===========================================================================

# ---- B1/B2: generic async, token stays in CONFIG (default) ---------------
configure(OLD_TOKEN, :async => true, :handler => CaptureAsyncHandler)
CaptureAsyncHandler.captured.clear
$sends.clear

Rollbar.error(StandardError.new('async default'))
enqueued_hash = CaptureAsyncHandler.captured.last

check 'enqueued payload is a Ruby Hash (not a JSON string)',
      enqueued_hash.is_a?(Hash), true
check 'default enqueued payload has NO top-level access_token field',
      enqueued_hash.key?('access_token'), false
check 'token at capture lives only in notifier configuration',
      Rollbar.root_notifier.configuration.access_token, OLD_TOKEN

# Cutover happens while the payload is still queued.
configure(NEW_TOKEN, :async => true, :handler => CaptureAsyncHandler)
$sends.clear
Rollbar.process_from_async_handler(enqueued_hash)

check 'perform re-reads config -> OLD queued payload sent with NEW header token',
      last_send[:header_token], NEW_TOKEN
check 'perform still sends no embedded payload token',
      last_send[:payload_token], nil

# ---- B3: async_json_payload=true enqueues a pre-built JSON STRING ---------
configure(OLD_TOKEN, :async => true, :handler => CaptureAsyncHandler)
Rollbar.configuration.async_json_payload = true
CaptureAsyncHandler.captured.clear

Rollbar.error(StandardError.new('async json string'))
enqueued_string = CaptureAsyncHandler.captured.last

check 'async_json_payload enqueues a String',
      enqueued_string.is_a?(String), true
check 'JSON string payload has no top-level access_token by default',
      JSON.parse(enqueued_string).key?('access_token'), false

configure(NEW_TOKEN, :async => true, :handler => CaptureAsyncHandler)
$sends.clear
Rollbar.process_from_async_handler(enqueued_string)

check 'string payload performed under NEW config uses NEW header token',
      last_send[:header_token], NEW_TOKEN

# ---- B4: use_payload_access_token=true BAKES the token into the payload ---
configure(OLD_TOKEN, :async => true, :handler => CaptureAsyncHandler,
                    :payload_token => true)
CaptureAsyncHandler.captured.clear

Rollbar.error(StandardError.new('payload token baked'))
baked = CaptureAsyncHandler.captured.last

check 'baked payload carries OLD token in its own field',
      baked['access_token'], OLD_TOKEN

configure(NEW_TOKEN, :async => true, :handler => CaptureAsyncHandler,
                    :payload_token => true)
$sends.clear
Rollbar.process_from_async_handler(baked)

check 'baked OLD payload is delivered with its OWN old token after cutover',
      last_send[:payload_token], OLD_TOKEN
check 'header is suppressed when use_payload_access_token is on',
      last_send[:header_token], NEW_TOKEN

# ===========================================================================
banner 'PART C — Real Active Job transport crossing the cutover'
# ===========================================================================
ActiveJob::Base.queue_adapter = :test
ActiveJob::Base.queue_adapter.enqueued_jobs.clear

configure(OLD_TOKEN, :async => false)
Rollbar.configuration.use_active_job # switches use_async on + handler
$sends.clear

Rollbar.error(StandardError.new('job queued before cutover'))

job = ActiveJob::Base.queue_adapter.enqueued_jobs.last
check 'a Rollbar::Delay::ActiveJob was enqueued',
      job[:job], Rollbar::Delay::ActiveJob

job_arg = job[:args].first
check 'Active Job argument is the payload Hash representation',
      job_arg.is_a?(Hash), true
check 'enqueued Active Job payload holds no token field by default',
      job_arg.key?('access_token'), false

# Cutover BEFORE the job performs.
configure(NEW_TOKEN, :async => false)
$sends.clear
Rollbar.process_from_async_handler(job_arg)

check 'Active Job perform under NEW config sends with NEW token',
      last_send[:header_token], NEW_TOKEN

# ===========================================================================
banner 'PART D — Real Rack entry point with a held child notifier + new error'
# ===========================================================================
configure(OLD_TOKEN, :async => false)

raising_app = ->(_env) { raise StandardError, 'boom in app' }
rack_middleware = Rollbar::Middleware::Rack.new(raising_app)

env = Rack::MockRequest.env_for('/orders/42?foo=bar',
                                'REQUEST_METHOD' => 'GET',
                                'rack.input' => StringIO.new)

# Capture the request-scoped child notifier that the middleware creates,
# simulating a request that is still in flight at cutover.
held_child = nil
orig_scoped = Rollbar.method(:scoped)
Rollbar.define_singleton_method(:scoped) do |opts = {}, cfg = {}, &block|
  held_child = Rollbar.notifier.scope(opts, cfg)
  orig_scoped.call(opts, cfg, &block)
end

begin
  rack_middleware.call(env)
rescue StandardError
  # middleware re-raises after reporting; expected
end
Rollbar.singleton_class.remove_method(:scoped)
Rollbar.define_singleton_method(:scoped, orig_scoped)

check 'Rack request child notifier captured OLD token',
      held_child.configuration.access_token, OLD_TOKEN

# Cutover while the old request object is still referenced.
configure(NEW_TOKEN, :async => false)
check 'held Rack child still resolves OLD token after cutover',
      held_child.configuration.access_token, OLD_TOKEN

# A NEW framework error callback after cutover (fresh middleware cycle builds a
# fresh child from the new root config).
$sends.clear
begin
  rack_middleware.call(env)
rescue StandardError
end

check 'new framework error after cutover reports to NEW project',
      last_send[:header_token], NEW_TOKEN
check 'new request payload contains request scope data',
      last_send[:body]['data'].key?('request'), true
check 'request scope carries the Rack URL',
      last_send[:body]['data']['request']['url'],
      'http://example.org/orders/42?foo=bar'

# ===========================================================================
banner 'PART E — Rollbar::ActiveJob rescue entry (job-side failure reporting)'
# ===========================================================================
class DemoJob < ActiveJob::Base
  include Rollbar::ActiveJob

  def perform
    raise StandardError, 'failure inside user job'
  end
end

configure(OLD_TOKEN, :async => true, :handler => CaptureAsyncHandler)
CaptureAsyncHandler.captured.clear

# Active Job's rescue_from wrapper runs through #perform_now (the path used by
# queued jobs), not on a bare #perform call.
begin
  DemoJob.perform_now
rescue StandardError
end

rescue_payload = CaptureAsyncHandler.captured.last
check 'Rollbar::ActiveJob rescue enqueued a report payload',
      rescue_payload.is_a?(Hash), true
check 'rescued report tagged with the job name in trace extra',
      rescue_payload['data'][:body][:trace][:extra][:job], 'DemoJob'
check 'rescued payload carries no embedded token (config-driven)',
      rescue_payload.key?('access_token'), false

configure(NEW_TOKEN, :async => true, :handler => CaptureAsyncHandler)
$sends.clear
Rollbar.process_from_async_handler(rescue_payload)
check 'pre-cutover rescued-job payload performs against NEW project',
      last_send[:header_token], NEW_TOKEN

# ---------------------------------------------------------------------------
puts
banner 'RESULT SUMMARY'
puts $results
puts
puts "Checks: #{$checks}  Failures: #{$failures}"
exit($failures.zero? ? 0 : 1)
