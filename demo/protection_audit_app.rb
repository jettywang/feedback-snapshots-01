# frozen-string-literal: true

# Demo of the protection_audit plugin's audit handoff.
#
# Runs three local requests against the app and prints the audit events
# recorded for each, showing that the events reflect the protection stages
# that actually ran, in order:
#
# 1. Host rejected            -> only a :host_authorization/:denied event
# 2. Host passes, token invalid -> :host_authorization/:allowed, then
#    :bearer_token/:denied
# 3. Full success             -> :host_authorization/:allowed, then
#    :bearer_token/:allowed
#
# Audit events contain only the source stage and the resulting action;
# no request content (host, token, path) is written to the audit log.
#
# Run with: ruby demo/protection_audit_app.rb

require_relative '../lib/roda'
$:.unshift(File.expand_path('../lib', __dir__))
require 'stringio'

class ProtectionAuditDemo < Roda
  AUDIT_LOG = []
  VALID_TOKEN = 'valid-demo-token'

  plugin :bearer_token
  plugin :host_authorization, 'www.example.com'
  plugin :protection_audit do |event|
    AUDIT_LOG << event
  end

  route do |r|
    check_host_authorization!

    unless r.bearer_token == VALID_TOKEN
      protection_audit_event(:bearer_token, :denied)
      response.status = 401
      next 'invalid token'
    end
    protection_audit_event(:bearer_token, :allowed)

    'ok'
  end
end

def request(host:, token: nil)
  env = {
    'REQUEST_METHOD' => 'GET',
    'SCRIPT_NAME' => '',
    'PATH_INFO' => '/',
    'QUERY_STRING' => '',
    'SERVER_NAME' => 'localhost',
    'SERVER_PORT' => '80',
    'rack.url_scheme' => 'http',
    'rack.input' => StringIO.new,
    'rack.errors' => StringIO.new,
    'HTTP_HOST' => host
  }
  env['HTTP_AUTHORIZATION'] = "Bearer #{token}" if token
  ProtectionAuditDemo.call(env)
end

cases = [
  ['host rejected', {host: 'evil.example.com', token: 'valid-demo-token'}],
  ['host passes, token invalid', {host: 'www.example.com', token: 'wrong-token'}],
  ['full success', {host: 'www.example.com', token: 'valid-demo-token'}]
]

cases.each_with_index do |(label, env), i|
  ProtectionAuditDemo::AUDIT_LOG.clear
  status, = request(**env)
  events = ProtectionAuditDemo::AUDIT_LOG.map { |e| "#{e[:source]}/#{e[:action]}" }
  puts "#{i + 1}. #{label}: HTTP #{status}, audit events: #{events.join(' -> ')}"
end
