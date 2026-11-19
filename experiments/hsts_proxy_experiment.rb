# frozen_string_literal: true
# Offline Rack experiment: HSTS (Rack::Protection::StrictTransport) behind
# TLS-terminating proxies. No sockets, no certs, no browser.
# Records: scheme / authority seen by the app, STS response header,
# and whether the sensitive business action actually ran.

$LOAD_PATH.unshift File.expand_path("../rack-protection/lib", __dir__)
require "rack"
require "rack/mock_request"
require "rack/protection/strict_transport"

BUSINESS_CALLS = []

# Terminal app: stands in for the Sinatra/Rack business endpoint.
# It only performs the sensitive action when Rack says the request is SSL.
class BankApp
  def call(env)
    req = Rack::Request.new(env)
    ran = false
    if req.ssl?
      BUSINESS_CALLS << "#{req.scheme}://#{req.authority}#{req.path_info}"
      ran = true
    end
    body = "scheme=#{req.scheme} ssl=#{req.ssl?} authority=#{req.authority} business_ran=#{ran}"
    [200, { "content-type" => "text/plain" }, [body]]
  end
end

# Edge middleware that only honors X-Forwarded-Proto from a trusted proxy
# (stand-in for proxy config / web-server real_ip rules).
class TrustedProxyFilter
  TRUSTED_PEER = "10.0.0.1"
  def initialize(app) = @app = app
  def call(env)
    unless env["REMOTE_ADDR"] == TRUSTED_PEER
      env.delete("HTTP_X_FORWARDED_PROTO")
      env.delete("HTTP_X_FORWARDED_HOST")
    end
    @app.call(env)
  end
end

def run(label, app, url, headers: {})
  res = Rack::MockRequest.new(app).get(url, headers)
  sts = res["strict-transport-security"] || "(none)"
  puts format("%-28s | STS: %-42s | %s", label, sts, res.body)
end

puts "== Chain: StrictTransport -> BankApp (no edge filter) =="
chain = Rack::Protection::StrictTransport.new(BankApp.new)

run("direct_https", chain, "https://app.example/transfer")
run("direct_http", chain, "http://app.example/transfer")
run("trusted_proxy", chain, "http://internal/transfer",
    headers: { "HTTP_X_FORWARDED_PROTO" => "https",
               "HTTP_X_FORWARDED_HOST" => "app.example",
               "REMOTE_ADDR" => "10.0.0.1" })
run("forged_forwarded", chain, "http://app.example/transfer",
    headers: { "HTTP_X_FORWARDED_PROTO" => "https",
               "REMOTE_ADDR" => "203.0.113.9" })

puts
puts "== include_subdomains: true, and a sibling subdomain request =="
chain_sub = Rack::Protection::StrictTransport.new(BankApp.new, include_subdomains: true)
run("apex https", chain_sub, "https://app.example/transfer")
run("subdomain https", chain_sub, "https://evil.app.example/transfer")

puts
puts "== Upstream already set STS header (middleware must not overwrite) =="
preset = ->(env) { [200, { "strict-transport-security" => "max-age=1" }, ["preset"]] }
run("upstream_preset", Rack::Protection::StrictTransport.new(preset), "https://app.example/")

puts
puts "== Recommended chain: TrustedProxyFilter -> StrictTransport -> BankApp =="
guarded = TrustedProxyFilter.new(Rack::Protection::StrictTransport.new(BankApp.new))
run("trusted_proxy", guarded, "http://internal/transfer",
    headers: { "HTTP_X_FORWARDED_PROTO" => "https",
               "HTTP_X_FORWARDED_HOST" => "app.example",
               "REMOTE_ADDR" => "10.0.0.1" })
run("forged_forwarded", guarded, "http://app.example/transfer",
    headers: { "HTTP_X_FORWARDED_PROTO" => "https",
               "REMOTE_ADDR" => "203.0.113.9" })

puts
puts "Business calls actually executed:"
BUSINESS_CALLS.each { |c| puts "  #{c}" }
