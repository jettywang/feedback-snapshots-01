# frozen_string_literal: true

# Machine-checkable migration gates. Each assertion pins one execution-boundary
# fact that a green mock-based unit test cannot establish on its own. Run with:
#   ./.feedback/bundle-env exec ruby experiment/assertions.rb
# Exits non-zero on the first failed gate, so it can gate a deploy pipeline.

$LOAD_PATH.unshift(File.expand_path('../lib', __dir__))
require_relative 'harness'

include Experiment::Helpers

$failures = 0
def check(name)
  result = yield
  status = result ? 'PASS' : 'FAIL'
  $failures += 1 unless result
  puts format('[%s] %s', status, name)
rescue StandardError => e
  $failures += 1
  puts format('[FAIL] %s raised %s: %s', name, e.class, e.message)
end

def fresh_call(strategy_class, path, session, test_mode:, method: 'POST', params: nil, options: {})
  recorder = Experiment::Recorder.new
  configure(recorder, test_mode: test_mode, validation: observed_validation(recorder))
  env = env_for(path, recorder, session: session.dup, method: method, params: params)
  status, headers, body = strategy_class.new(Experiment::APP, **options).call(env)
  [recorder, env, status, headers, body]
end

# --- Gate 1: real request phase enforces POST + CSRF, redirects to provider ---
session, token = csrf_session
recorder, env, status, headers, = fresh_call(
  Experiment::Provider, '/auth/provider', session,
  test_mode: false,
  params: {'authenticity_token' => token}
)
check('real request: valid token yields 302 to the provider') { status == 302 && headers['Location']&.start_with?('https://provider.test') }
check('real request: validation runs before before_request_phase') do
  accepted = recorder.events.index { |e| e.what == 'CSRF check accepted' }
  before_req = recorder.events.index { |e| e.where == 'hook:before_request_phase' }
  stored_params = recorder.events.index { |e| e.where == 'strategy#request_phase' }
  !accepted.nil? && !before_req.nil? && accepted < before_req && before_req < stored_params
end

# --- Gate 2: forged token is rejected and never reaches request_phase ---
session2, = csrf_session
rec2, env2, st2, h2, = fresh_call(
  Experiment::Provider, '/auth/provider', session2,
  test_mode: false,
  params: {'authenticity_token' => 'forged'}
)
check('forged token: 302 to /auth/failure with authenticity_error') do
  st2 == 302 && h2['Location']&.include?('/auth/failure') && env2['omniauth.error.type'] == :authenticity_error
end
check('forged token: request_phase never runs and no params are stored') do
  !rec2.events.any? { |e| e.where == 'strategy#request_phase' } && !session2.key?('omniauth.params')
end

# --- Gate 3: GET to the request path does not start a phase (POST-only) ---
rec3, _e3, st3, _h3, body3 = fresh_call(
  Experiment::Provider, '/auth/provider', {},
  test_mode: false, method: 'GET'
)
check('GET request path: falls through to the app, no phase hooks') do
  st3 == 200 && Array(body3).first == 'APP_PLAIN' && rec3.events.none? { |e| e.where.to_s.start_with?('hook:') }
end

# --- Gate 4: test mode reproduces the SAME auth hash without a provider ---
reset_config
rec_r = Experiment::Recorder.new
configure(rec_r, test_mode: false, validation: observed_validation(rec_r))
sess_r, tok_r = csrf_session
rreq = env_for('/auth/provider', rec_r, session: sess_r, method: 'POST', params: {'authenticity_token' => tok_r})
Experiment::Provider.new(Experiment::APP).call(rreq)
rcb = Experiment::Recorder.new
configure(rcb, test_mode: false, validation: observed_validation(rcb))
rcb_env = env_for('/auth/provider/callback?uid=42&code=c&state=state-abc-123', rcb, session: sess_r)
Experiment::Provider.new(Experiment::APP).call(rcb_env)
real_hash = rcb_env['omniauth.auth'].to_hash

reset_config
rec_t = Experiment::Recorder.new
configure(rec_t, test_mode: true, validation: observed_validation(rec_t))
OmniAuth.config.mock_auth[:provider] = OmniAuth::AuthHash.new(real_hash)
sess_t, tok_t = csrf_session
treq = env_for('/auth/provider', rec_t, session: sess_t, method: 'POST', params: {'authenticity_token' => tok_t})
Experiment::Provider.new(Experiment::APP).call(treq)
tcb = Experiment::Recorder.new
configure(tcb, test_mode: true, validation: observed_validation(tcb))
OmniAuth.config.mock_auth[:provider] = OmniAuth::AuthHash.new(real_hash)
tcb_env = env_for('/auth/provider/callback', tcb, session: sess_t)
Experiment::Provider.new(Experiment::APP).call(tcb_env)
mock_hash = tcb_env['omniauth.auth'].to_hash

check('real and test-mode callbacks produce an identical auth hash') { real_hash == mock_hash }
check('test-mode request never runs the strategy request_phase (no provider)') do
  rec_t.events.none? { |e| e.where == 'strategy#request_phase' }
end
check('real callback runs strategy#callback_phase; test-mode callback does not') do
  rcb.events.any? { |e| e.where == 'strategy#callback_phase' } &&
    tcb.events.none? { |e| e.where.to_s.include?('callback_phase') && e.where.start_with?('strategy') }
end

# --- Gate 5: test mode still enforces CSRF (the protection is not test-only bypassed) ---
sess5, = csrf_session
rec5, _e5, st5, h5, = fresh_call(
  Experiment::Provider, '/auth/provider', sess5,
  test_mode: true,
  params: {'authenticity_token' => 'forged'}
)
check('test mode: forged token still rejected (protection active under test_mode)') do
  st5 == 302 && h5['Location']&.include?('/auth/failure')
end

# --- Gate 6: a mocked failure symbol routes to on_failure, no omniauth.auth ---
reset_config
rec6 = Experiment::Recorder.new
configure(rec6, test_mode: true, validation: observed_validation(rec6))
OmniAuth.config.mock_auth[:provider] = :invalid_credentials
sess6, _tok6 = csrf_session
fenv = env_for('/auth/provider/callback', rec6, session: sess6)
Experiment::Provider.new(Experiment::APP).call(fenv)
check('mocked failure symbol: no omniauth.auth, error type recorded') do
  !fenv.key?('omniauth.auth') && fenv['omniauth.error.type'] == :invalid_credentials
end

# --- Gate 7: custom form renders and skips the provider, after hook still fires ---
sess7, tok7 = csrf_session
rec7, _e7, st7, _h7, body7 = fresh_call(
  Experiment::Provider, '/auth/provider', sess7,
  test_mode: false,
  params: {'authenticity_token' => tok7}, options: {form: Experiment::FORM_ENDPOINT}
)
check('custom form: 200 HTML, request_phase skipped, after_request_phase still runs') do
  st7 == 200 && Array(body7).first.include?('CUSTOM FORM') &&
    rec7.events.none? { |e| e.where == 'strategy#request_phase' } &&
    rec7.events.any? { |e| e.where == 'hook:after_request_phase' }
end

# --- Gate 8: unrelated path passes through with no OmniAuth phase at all ---
rec8, _e8, st8, _h8, body8 = fresh_call(
  Experiment::Provider, '/elsewhere', {},
  test_mode: false, method: 'GET'
)
check('unrelated path: straight to app, zero hooks/phases') do
  st8 == 200 && Array(body8).first == 'APP_PLAIN' && rec8.events.size == 1
end

reset_config
puts
passed = 12 - $failures
if $failures.zero?
  puts "ALL #{passed} MIGRATION CHECKS PASSED"
  exit 0
else
  puts "#{$failures} OF 12 CHECKS FAILED"
  exit 1
end
