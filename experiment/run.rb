# frozen_string_literal: true

$LOAD_PATH.unshift(File.expand_path('../lib', __dir__))
require_relative 'harness'

include Experiment::Helpers

# The exact auth hash the real callback builds, captured once and reused as
# the mock_auth identity so the two success paths can be compared for
# equality rather than for "looks similar".
def canonical_auth_hash
  OmniAuth::AuthHash.new(
    'provider' => 'provider',
    'uid' => '42',
    'info' => {'name' => 'Ada Lovelace', 'email' => 'ada@example.org', 'nickname' => 'ada'},
    'credentials' => {'token' => 'token-from-provider-code-exchange', 'expires' => true},
    'extra' => {'raw_info' => {'id' => 42, 'login' => 'ada'}}
  )
end

def banner(title)
  puts
  puts '=' * 96
  puts title
  puts '=' * 96
end

def show(recorder, status, headers, body)
  recorder.lines.each { |line| puts "  #{line}" }
  location = headers['Location'] || headers['location']
  puts "  -> RESPONSE status=#{status} location=#{location || '-'} body=#{Array(body).first.to_s[0, 40]}"
end

def call(strategy_class, env, strategy_options = {})
  recorder = env['experiment.recorder']
  strategy = strategy_class.new(Experiment::APP, **strategy_options)
  status, headers, body = strategy.call(env)
  [recorder, status, headers, body]
end

# ---------------------------------------------------------------------------
# Scenario A: REAL path, default provider redirect (no custom form).
# Request phase POST with a valid CSRF token -> 302 to provider, then the
# provider redirects back to the callback -> app receives omniauth.auth.
# ---------------------------------------------------------------------------
banner 'A. REAL PATH - request POST (valid CSRF) then provider callback'
reset_config
recorder_a = Experiment::Recorder.new
configure(recorder_a, test_mode: false, validation: observed_validation(recorder_a))
session_a, token_a = csrf_session

req_env = env_for('/auth/provider', recorder_a, session: session_a, method: 'POST',
                  params: {'authenticity_token' => token_a, 'origin' => '/dashboard'})
recorder_a.log('client', 'POST /auth/provider', 'valid authenticity_token')
_, status, headers, = call(Experiment::Provider, req_env)
show(recorder_a, status, headers, [])
puts "  session after request phase: #{session_a.keys.inspect}"

cb_recorder = Experiment::Recorder.new
configure(cb_recorder, test_mode: false, validation: observed_validation(cb_recorder))
cb_env = env_for('/auth/provider/callback?uid=42&code=exchange-code&state=state-abc-123', cb_recorder,
                 session: session_a, method: 'GET')
cb_recorder.log('client', 'GET callback', 'provider redirects back with code+state')
_, cb_status, cb_headers, cb_body = call(Experiment::Provider, cb_env)
show(cb_recorder, cb_status, cb_headers, cb_body)
real_auth = cb_env['omniauth.auth']
puts "  auth hash built by: strategy#auth_hash from provider callback params (real verification)"
puts "  real omniauth.auth class=#{real_auth.class} uid=#{real_auth['uid']} provider=#{real_auth['provider']}"

# ---------------------------------------------------------------------------
# Scenario B: TEST_MODE path. The provider never runs; mock_auth supplies
# the identity. Same request and callback URLs, same resulting auth hash.
# ---------------------------------------------------------------------------
banner 'B. TEST_MODE PATH - mock request then mock callback, same auth hash'
reset_config
recorder_b = Experiment::Recorder.new
configure(recorder_b, test_mode: true, validation: observed_validation(recorder_b))
OmniAuth.config.mock_auth[:provider] = canonical_auth_hash
session_b, token_b = csrf_session

mreq_env = env_for('/auth/provider', recorder_b, session: session_b, method: 'POST',
                   params: {'authenticity_token' => token_b})
recorder_b.log('client', 'POST /auth/provider', 'test mode')
_, mstatus, mheaders, = call(Experiment::Provider, mreq_env)
show(recorder_b, mstatus, mheaders, [])

mcb_recorder = Experiment::Recorder.new
configure(mcb_recorder, test_mode: true, validation: observed_validation(mcb_recorder))
OmniAuth.config.mock_auth[:provider] = canonical_auth_hash
mcb_env = env_for('/auth/provider/callback', mcb_recorder, session: session_b, method: 'GET')
mcb_recorder.log('client', 'GET callback', 'test mode, no provider code/state')
_, mcb_status, mcb_headers, mcb_body = call(Experiment::Provider, mcb_env)
show(mcb_recorder, mcb_status, mcb_headers, mcb_body)
mock_auth = mcb_env['omniauth.auth']
puts "  auth hash built by: OmniAuth.mock_auth_for(:provider) - injected, no provider verification"
puts "  mock omniauth.auth class=#{mock_auth.class} uid=#{mock_auth['uid']} provider=#{mock_auth['provider']}"

real_h  = real_auth.to_hash
mock_h  = mock_auth.to_hash
puts
puts "  SAME AUTH HASH? #{real_h == mock_h} (deep Hash equality across the two paths)"
puts "  real keys=#{real_h.keys.sort.inspect}"
puts "  mock keys=#{mock_h.keys.sort.inspect}"

# ---------------------------------------------------------------------------
# Scenario B2: does test mode still enforce CSRF? Forge the token in test
# mode. If validation genuinely runs, this must fail like production; if it
# is bypassed, the request still redirects - proving test green says nothing
# about the upgraded CSRF protection.
# ---------------------------------------------------------------------------
banner 'B2. TEST_MODE WITH A FORGED TOKEN - is request_validation_phase still enforced?'
reset_config
recorder_b2 = Experiment::Recorder.new
configure(recorder_b2, test_mode: true, validation: observed_validation(recorder_b2))
OmniAuth.config.mock_auth[:provider] = canonical_auth_hash
session_b2, _valid = csrf_session

forged_env = env_for('/auth/provider', recorder_b2, session: session_b2, method: 'POST',
                     params: {'authenticity_token' => 'forged-token'})
recorder_b2.log('client', 'POST /auth/provider', 'FORGED token, test mode')
_, fstatus, fheaders, = call(Experiment::Provider, forged_env)
show(recorder_b2, fstatus, fheaders, [])
puts "  => test mode still runs request_validation_phase? #{fstatus == 302 && fheaders['Location']&.include?('/auth/failure')}"

# ---------------------------------------------------------------------------
# Scenario C: custom :form. A Rack endpoint form means the request phase
# renders HTML (200) and never redirects to the provider, so request_phase
# and after_request_phase ordering relative to the form is the crux.
# ---------------------------------------------------------------------------
banner 'C. CUSTOM FORM - Rack endpoint renders 200, provider request_phase never runs'
reset_config
recorder_c = Experiment::Recorder.new
configure(recorder_c, test_mode: false, validation: observed_validation(recorder_c))
session_c, token_c = csrf_session
form_env = env_for('/auth/provider', recorder_c, session: session_c, method: 'POST',
                   params: {'authenticity_token' => token_c})
recorder_c.log('client', 'POST /auth/provider', 'form: Rack endpoint option')
_, cstatus, cheaders, cbody = call(Experiment::Provider, form_env, form: Experiment::FORM_ENDPOINT)
show(recorder_c, cstatus, cheaders, cbody)

banner 'C2. CUSTOM FORM = true - request phase calls through to the app itself'
reset_config
recorder_c2 = Experiment::Recorder.new
configure(recorder_c2, test_mode: false, validation: observed_validation(recorder_c2))
session_c2, token_c2 = csrf_session
form2_env = env_for('/auth/provider', recorder_c2, session: session_c2, method: 'POST',
                    params: {'authenticity_token' => token_c2})
recorder_c2.log('client', 'POST /auth/provider', 'form: true (underlying app renders)')
_, c2status, c2headers, c2body = call(Experiment::Provider, form2_env, form: true)
show(recorder_c2, c2status, c2headers, c2body)

# ---------------------------------------------------------------------------
# Scenario D: stop BEFORE entering the strategy.
# D1: a path that is not the strategy's -> passthrough straight to the app,
#     no request/callback phase, no hooks.
# D2: a GET to the request path -> POST-only default, so request_call? is
#     false and it falls through to the app instead of starting a phase.
# ---------------------------------------------------------------------------
banner 'D1. STOP BEFORE STRATEGY - unrelated path passes straight through'
reset_config
recorder_d1 = Experiment::Recorder.new
configure(recorder_d1, test_mode: false, validation: observed_validation(recorder_d1))
d1_env = env_for('/users/42/posts?page=2', recorder_d1, session: {}, method: 'GET')
recorder_d1.log('client', 'GET /users/42/posts', 'not an auth path')
_, d1status, d1headers, d1body = call(Experiment::Provider, d1_env)
show(recorder_d1, d1status, d1headers, d1body)

banner 'D2. STOP BEFORE STRATEGY - GET on request path with POST-only default'
reset_config
recorder_d2 = Experiment::Recorder.new
configure(recorder_d2, test_mode: false, validation: observed_validation(recorder_d2))
d2_env = env_for('/auth/provider', recorder_d2, session: {}, method: 'GET')
recorder_d2.log('client', 'GET /auth/provider', 'method not in allowed_request_methods [:post]')
_, d2status, d2headers, d2body = call(Experiment::Provider, d2_env)
show(recorder_d2, d2status, d2headers, d2body)

# ---------------------------------------------------------------------------
# Scenario E: FAILURE that proves the upgraded protection is present.
# Forged CSRF token on the real request path -> AuthenticityError -> fail!
# -> FailureEndpoint 302 to /auth/failure, before before_request_phase and
# before any provider redirect. This is the observation the test suite's
# mock identities cannot produce.
# ---------------------------------------------------------------------------
banner 'E. FAILURE - forged CSRF token rejected before the provider is touched'
reset_config
recorder_e = Experiment::Recorder.new
configure(recorder_e, test_mode: false, validation: observed_validation(recorder_e))
session_e, _valid_e = csrf_session
e_env = env_for('/auth/provider', recorder_e, session: session_e, method: 'POST',
                params: {'authenticity_token' => 'forged-token'})
recorder_e.log('client', 'POST /auth/provider', 'FORGED token, real mode')
_, estatus, eheaders, = call(Experiment::Provider, e_env)
show(recorder_e, estatus, eheaders, [])
puts "  omniauth.error.type=#{e_env['omniauth.error.type'].inspect}"
puts "  omniauth.params stored despite rejection? #{session_e.key?('omniauth.params')} (should be false)"
puts "  provider request_phase reached? #{recorder_e.events.any? { |ev| ev.where == 'strategy#request_phase' }}"

# ---------------------------------------------------------------------------
# Scenario F: test mode mocked FAILURE. mock_auth holds a Symbol, so the
# callback sets no omniauth.auth and routes through on_failure. This is the
# only "failure" the mock path can produce - it is a configured label, not a
# rejected credential, so it cannot substitute for scenario E.
# ---------------------------------------------------------------------------
banner 'F. TEST_MODE MOCKED FAILURE - Symbol mock routes to on_failure, no auth hash'
reset_config
recorder_f = Experiment::Recorder.new
configure(recorder_f, test_mode: true, validation: observed_validation(recorder_f))
OmniAuth.config.mock_auth[:provider] = :invalid_credentials
f_env = env_for('/auth/provider/callback', recorder_f, session: {}, method: 'GET')
recorder_f.log('client', 'GET callback', 'mock_auth[:provider] = :invalid_credentials')
_, fstatus2, fheaders2, fbody2 = call(Experiment::Provider, f_env)
show(recorder_f, fstatus2, fheaders2, fbody2)
puts "  omniauth.auth present? #{f_env.key?('omniauth.auth')} (should be false)"
puts "  omniauth.error.type=#{f_env['omniauth.error.type'].inspect}"

# ---------------------------------------------------------------------------
# Scenario G: OPTIONS preflight on an auth path. phase_call picks options_call
# first, returning the Allow header without entering request/callback phases.
# ---------------------------------------------------------------------------
banner 'G. OPTIONS PREFLIGHT - answered before any auth phase'
reset_config
recorder_g = Experiment::Recorder.new
configure(recorder_g, test_mode: false, validation: observed_validation(recorder_g))
g_env = env_for('/auth/provider', recorder_g, session: {}, method: 'OPTIONS')
recorder_g.log('client', 'OPTIONS /auth/provider', 'CORS preflight')
_, gstatus, gheaders, gbody = call(Experiment::Provider, g_env)
show(recorder_g, gstatus, gheaders, gbody)
puts "  Allow header=#{gheaders['Allow'].inspect}"

reset_config
puts
puts 'Done. Reset OmniAuth global config to defaults.'
