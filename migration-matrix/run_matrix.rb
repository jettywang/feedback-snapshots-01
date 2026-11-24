#!/usr/bin/env ruby
# frozen_string_literal: true

# Re-runnable local migration matrix for the Ruby `elastic-transport`
# implementation in this checkout.
#
# It exercises the REAL Elastic::Transport::Client / Base / Sniffer /
# Connection / Selector code, with a scripted Faraday adapter as the network
# double. No Elasticsearch cluster and no TCP port binding are required.
#
# It separates four layers:
#   configured  : the static hosts passed to Client.new
#   discovered  : candidates parsed from _nodes/http `http.publish_address`
#   pool        : Connections::Collection state (all / alive / dead)
#   selected    : the actual method+URL handed to the Faraday adapter
#                 (and the proxy peer Faraday/net-http would connect to)

ROOT = File.expand_path('..', __dir__)
$LOAD_PATH.unshift(File.join(ROOT, 'lib'))

require 'json'
require 'time'
require 'socket'
require 'fileutils'
require 'shellwords'

begin
  require 'elastic/transport'
rescue LoadError => e
  warn "Cannot load elastic/transport: #{e.message}"
  warn 'Run it with:  bash migration-matrix/run.sh'
  exit 2
end

OLD_HOST_RE = /\Aold-[a-z]\.corp\z/

def old_host?(host)
  host.to_s.match?(OLD_HOST_RE)
end

def redact_uri(value)
  return 'direct' if value.nil?

  value.to_s.gsub(%r{([a-z][a-z0-9+.-]*://)[^/@\s]+@}i, '\\1<redacted>@')
end

def nodes_body(addresses)
  nodes = {}
  addresses.each_with_index do |address, index|
    nodes["node-#{index}"] = { 'http' => { 'publish_address' => address } }
  end
  { 'nodes' => nodes }
end

# Minimal transport double used only to drive the REAL Sniffer parser.
class ParseProbeTransport
  attr_accessor :body

  def options
    {}
  end

  def perform_request(*_args)
    Elastic::Transport::Transport::Response.new(200, @body, {})
  end
end

class Ledger
  attr_reader :calls

  def initialize
    @calls = []
    @mutex = Mutex.new
  end

  def add(record)
    @mutex.synchronize { @calls << record }
  end
end

# Network double: records every request exactly where Faraday hands off to an
# adapter, then returns a scripted response or raises a connection error.
class ScriptedAdapter < Faraday::Adapter
  def initialize(app, ledger, handler)
    super(app)
    @ledger = ledger
    @handler = handler
  end

  def call(env)
    super

    proxy_options = env.request.proxy
    if proxy_options&.uri
      uri = proxy_options.uri
      proxy_peer = "#{uri.host}:#{uri.port}"
      proxy = redact_uri(uri.to_s)
      tcp_peer = proxy_peer
      wire = if env.url.scheme == 'https'
               "CONNECT #{env.url.host}:#{env.url.port} via proxy #{proxy_peer}"
             else
               "#{env.method.to_s.upcase} http://#{env.url.host}:#{env.url.port}" \
                 "#{env.url.path} via proxy #{proxy_peer} (absolute-form)"
             end
    else
      proxy = 'direct'
      proxy_peer = nil
      tcp_peer = "#{env.url.host}:#{env.url.port}"
      wire = "#{env.method.to_s.upcase} #{env.url.path} direct to " \
             "#{env.url.scheme}://#{env.url.host}:#{env.url.port}"
    end

    record = {
      seq: @ledger.calls.length + 1,
      kind: env.url.path == '/_nodes/http' ? 'discovery' : 'data',
      method: env.method.to_s.upcase,
      scheme: env.url.scheme,
      host: env.url.host,
      port: env.url.port,
      path: env.url.path,
      target: "#{env.url.host}:#{env.url.port}",
      proxy: proxy,
      proxy_peer: proxy_peer,
      tcp_peer: tcp_peer,
      wire: wire
    }
    @ledger.add(record)

    result = @handler.call(env)

    if result == :refuse
      raise Faraday::ConnectionFailed,
            "double: connection refused by #{env.url.host}:#{env.url.port}"
    end

    status = 200
    headers = { 'content-type' => 'application/json' }
    body = { ok: true }.to_json

    if result.is_a?(Hash)
      status = result[:status] || 200
      if result.key?(:text)
        body = result[:text]
        headers = { 'content-type' => 'text/plain' }
      else
        body = JSON.generate(result[:json] || { ok: true })
      end
      headers.merge!(result[:headers] || {})
    end

    save_response(env, status, body, headers, nil)
    @app.call(env)
  end
end

class MatrixRunner
  attr_reader :results, :expectation_failures

  def initialize
    @results = []
    @expectation_failures = 0
    @saved_proxy_env = {}
    @provenance = build_provenance
    silence_proxy_env!
  end

  def build_provenance
    sha = `git -C #{Shellwords.escape(ROOT)} rev-parse --short HEAD 2>/dev/null`.strip
    {
      time: Time.now.iso8601,
      ruby: RUBY_DESCRIPTION,
      faraday: Faraday::VERSION,
      elastic_transport: Elastic::Transport::VERSION,
      checkout: sha.empty? ? 'unknown' : sha,
      local_binding: probe_bind,
      ambient_proxy_env: ambient_proxy_summary
    }
  end

  def probe_bind
    server = TCPServer.new('127.0.0.1', 0)
    port = server.addr[1]
    server.close
    "available on 127.0.0.1:#{port}"
  rescue StandardError => e
    "unavailable (#{e.class}: #{e.message.to_s.split("\n").first})"
  end

  def ambient_proxy_summary
    keys = ENV.keys.grep(/proxy/i).sort
    summary = { proxy_env_keys: keys }
    # Only the standard URL-valued variables are shown, with userinfo stripped.
    # Sidecars such as *_PROXY_USERNAME / *_PROXY_PASSWORD are name-listed only.
    %w[http_proxy HTTP_PROXY https_proxy HTTPS_PROXY all_proxy ALL_PROXY
       no_proxy NO_PROXY].each do |key|
      summary[key] = redact_uri(ENV[key]) if ENV.key?(key)
    end
    summary
  end

  # Hermetic run: do not let the runner shell's proxy variables inject a proxy
  # into the non-proxy cases. P2 sets controlled values explicitly.
  def silence_proxy_env!
    ENV.keys.grep(/proxy/i).each do |key|
      @saved_proxy_env[key] = ENV.delete(key)
    end
  end

  def restore_proxy_env!
    @saved_proxy_env.each do |key, value|
      value.nil? ? ENV.delete(key) : ENV[key] = value
    end
  end

  def with_env(variables)
    saved = {}
    variables.each do |key, value|
      saved[key] = ENV.key?(key) ? ENV[key] : :__absent__
      ENV[key] = value
    end
    yield
  ensure
    saved.each do |key, value|
      if value == :__absent__
        ENV.delete(key)
      else
        ENV[key] = value
      end
    end
  end

  # ---------- output helpers ----------

  def section(title)
    puts
    puts '=' * 86
    puts title
    puts '=' * 86
  end

  def subsection(title)
    puts
    puts "-- #{title}"
  end

  def kv(label, value)
    puts "   %-13s %s" % ["#{label}:", value]
  end

  def check(case_record, name, condition, detail = nil)
    case_record[:checks] << { name: name, pass: condition ? true : false, detail: detail }
    @expectation_failures += 1 unless condition
    puts "     [#{condition ? 'PASS' : 'FAIL'}] #{name}" \
         "#{detail ? "  -- #{detail}" : ''}"
  end

  def client_for(static_hosts, ledger, handler, **options)
    Elastic::Transport::Client.new(hosts: static_hosts, **options) do |faraday|
      faraday.adapter ScriptedAdapter, ledger, handler
    end
  end

  def configured_snapshot(client)
    client.transport.hosts.map do |host|
      "#{host[:protocol] || host[:scheme] || 'http'}://#{host[:host]}:#{host[:port]}"
    end
  end

  def pool_snapshot(client)
    client.transport.connections.all.map do |connection|
      faraday_connection = connection.connection
      proxy_uri = faraday_connection.proxy&.uri if faraday_connection.respond_to?(:proxy)
      {
        oid: connection.object_id,
        host: connection.host[:host],
        port: connection.host[:port].to_i,
        key: "#{connection.host[:protocol]}://#{connection.host[:host]}:#{connection.host[:port]}",
        dead: connection.dead?,
        failures: connection.failures,
        proxy_peer: proxy_uri ? "#{proxy_uri.host}:#{proxy_uri.port}" : nil
      }
    end
  end

  def data_targets(ledger)
    ledger.calls.select { |r| r[:kind] == 'data' }.map { |r| r[:target] }
  end

  def discovery_targets(ledger)
    ledger.calls.select { |r| r[:kind] == 'discovery' }.map { |r| r[:target] }
  end

  def evaluate_gate(discovered_hosts:, pool:, selected_data:, discovery_invoked: true)
    old_discovered = discovered_hosts.any? { |host| old_host?(host) }
    old_in_pool = pool.any? { |p| old_host?(p[:host]) }
    selected_all_new = !selected_data.empty? && selected_data.all? { |t| !old_host?(t.split(':').first) }
    pool_hosts = pool.map { |p| p[:host] }.uniq
    selected_hosts = selected_data.map { |t| t.split(':').first }.uniq
    covered_cycle = selected_hosts.sort == pool_hosts.sort
    eligible = !old_discovered && !old_in_pool && selected_all_new && covered_cycle
    {
      discovery_invoked: discovery_invoked,
      no_old_discovered: !old_discovered,
      no_old_in_pool: !old_in_pool,
      selected_all_new: selected_all_new,
      full_selector_cycle_covered: covered_cycle,
      eligible_to_remove_old_config: eligible
    }
  end

  # ---------- scenarios ----------

  def run!
    print_provenance
    case_config_forms
    case_address_styles
    case_m1_static_only
    case_m2_sniff_to_new_domain
    case_m3_mixed_fleet_retention
    case_m4_dead_and_resurrect
    case_s1_scheme_downgrade
    case_f1_discovery_timeout
    case_f2_discovery_hard_error_direct
    case_f3_periodic_reload_hard_error
    case_f4_reload_on_failure_self_heal
    case_p1_explicit_proxy
    case_p2_env_proxy_no_proxy_split
    case_p3_proxy_survives_reload
    case_p4_https_connect
    print_admission
    write_outputs
    restore_proxy_env!

    puts
    puts '=' * 86
    if @expectation_failures.zero?
      puts "DRIVER RESULT: all recorded expectations matched the current implementation."
    else
      puts "DRIVER RESULT: #{@expectation_failures} expectation(s) FAILED."
    end
    puts "JSON ledger: migration-matrix/runs/latest.json"
    puts '=' * 86
    exit(@expectation_failures.zero? ? 0 : 1)
  end

  def print_provenance
    section('0. DRIVER PROVENANCE')
    @provenance.each { |key, value| kv(key.to_s, value) }
    puts '   note: proxy wire lines are derived from the Faraday adapter env (the exact'
    puts '         inputs faraday-net_http uses); loopback bind is not available here.'
  end

  # C0: legal static configuration forms normalize the same way.
  def case_config_forms
    section('1. CONFIGURED ADDRESS FORMS (Client#extract_hosts / parse_host)')
    cases = [
      ['bare host:port string', 'es-1.es.private:9200'],
      ['comma separated string', 'es-1.es.private:9200,es-2.es.private:9200'],
      ['absolute URI string', 'https://es-1.es.private:9200/base'],
      ['hash', { host: 'es-1.es.private', port: 9201, scheme: 'https' }]
    ]
    cases.each do |label, raw|
      client = Elastic::Transport::Client.new(hosts: raw)
      puts "   %-28s raw=#{raw.inspect}" % label
      client.transport.hosts.each do |host|
        puts "   #{' ' * 28} -> {scheme=#{host[:scheme].inspect} host=#{host[:host].inspect} " \
             "port=#{host[:port].inspect} path=#{host[:path].inspect}}"
      end
    end
    puts '   precedence: :hosts > :host > :url > :urls > ENV[ELASTICSEARCH_URL] > localhost:9200'
  end

  # A: every legal publish_address style the real Sniffer parser handles.
  def case_address_styles
    section('2. DISCOVERED CANDIDATES: _nodes/http publish_address STYLES (real Sniffer)')
    rows = [
      ['bare IPv4',                 '10.0.0.11:9200',                          '10.0.0.11', true],
      ['bare private FQDN',         'node-1.es.private:9200',                  'node-1.es.private', true],
      ['fqdn/ip:port (uses name)',  'node-1.es.private/10.0.0.11:9200',        'node-1.es.private', true],
      ['fqdn/[ipv6]:port',          'node-1.es.private/[2001:db8::11]:9200',   'node-1.es.private', true],
      ['bare bracketed IPv6',       '[2001:db8::11]:9200',                     '2001:db8::11', true],
      ['legacy inet[/ip:port]',     'inet[/10.0.0.11:9200]',                   '10.0.0.11', true],
      ['TRAP inet[name/ip:port]',   'inet[node-1.es.private/10.0.0.11:9200]',  'ode-1.es.private/10.0.0.11', false],
      ['TRAP inet[name:port]',      'inet[node-1.es.private:9200]',            'ode-1.es.private', false]
    ]

    probe = ParseProbeTransport.new
    sniffer = Elastic::Transport::Transport::Sniffer.new(probe)

    c = { id: 'A-styles', title: 'publish_address parsing', checks: [] }
    puts "   %-30s %-42s %-34s %s" % ['STYLE', 'INPUT', 'PARSED host', 'PORT']
    rows.each do |label, input, expected_host, usable|
      probe.body = nodes_body([input])
      parsed = sniffer.hosts.first
      puts "   %-30s %-42s %-34s %s" % [label, input, parsed[:host].inspect, parsed[:port].inspect]
      check(c, "#{label} parses to #{expected_host.inspect}", parsed[:host] == expected_host,
            usable ? 'usable candidate' : 'CURRENT IMPLEMENTATION MIS-PARSES (first char dropped / slash kept)')
    end
    @results << c

    # Five styles yield hostnames / IPv4 and build Faraday connections cleanly.
    buildable_addresses = [
      '10.0.0.11:9200',
      'node-1.es.private:9200',
      'node-1.es.private/10.0.0.11:9200',
      'node-1.es.private/[2001:db8::11]:9200',
      'inet[/10.0.0.11:9200]'
    ]
    ledger = Ledger.new
    handler = ->(_env) { { json: nodes_body(buildable_addresses) } }
    client = client_for(['http://bootstrap.corp:9200'], ledger, handler)
    client.transport.reload_connections!
    pool_hosts = client.transport.connections.all.map { |cn| cn.host[:host] }
    c2 = { id: 'A-build', title: 'hostname/IPv4 candidates build into the pool', checks: [] }
    check(c2, 'all five buildable candidates built into the pool',
          pool_hosts.sort == ['10.0.0.11', '10.0.0.11', 'node-1.es.private',
                               'node-1.es.private', 'node-1.es.private'].sort,
          pool_hosts.inspect)
    @results << c2

    # The bare bracketed IPv6 style parses to an UNBRACKETED host, but
    # __full_url / Connection#full_url interpolate it without re-bracketing,
    # so Faraday/URI reject "http://2001:db8::11:9200". One bad candidate
    # therefore makes the whole rebuild raise (it is not SnifferTimeoutError).
    v6_ledger = Ledger.new
    v6_handler = ->(_env) { { json: nodes_body(['[2001:db8::11]:9200']) } }
    v6_client = client_for(['http://bootstrap.corp:9200'], v6_ledger, v6_handler)
    v6_error = nil
    begin
      v6_client.transport.reload_connections!
    rescue StandardError => e
      v6_error = e
    end
    c4 = { id: 'A-ipv6-build', title: 'bare IPv6 candidate is not re-bracketed when building the URL', checks: [] }
    check(c4, 'reload raises a URI/Faraday argument error for unbracketed IPv6',
          v6_error.is_a?(URI::InvalidURIError) ||
            v6_error.is_a?(Faraday::Error) ||
            (v6_error && v6_error.cause.is_a?(URI::InvalidURIError)),
          v6_error ? "#{v6_error.class}: #{v6_error.message[0, 80]}" : 'no error')
    puts "   [ipv6] #{v6_error.class}: #{v6_error.message[0, 100]}" if v6_error
    @results << c4

    # What happens to the mis-parsed inet[name/ip] trap on a real reload?
    trap_ledger = Ledger.new
    trap_handler = ->(_env) { { json: nodes_body(['inet[node-1.es.private/10.0.0.11:9200]']) } }
    trap_client = client_for(['http://bootstrap.corp:9200'], trap_ledger, trap_handler)
    begin
      trap_client.transport.reload_connections!
      hosts = trap_client.transport.connections.all.map { |cn| cn.host[:host] }
      puts "   [trap] reload built hosts=#{hosts.inspect}"
      c3 = { id: 'A-trap-reload', title: 'mis-parsed inet name does not reach the private name', checks: [] }
      check(c3, 'reload never yields intended node-1.es.private',
            hosts.none? { |h| h == 'node-1.es.private' }, hosts.inspect)
      @results << c3
    rescue StandardError => e
      puts "   [trap] reload raised #{e.class}: #{e.message[0, 90]}"
      c3 = { id: 'A-trap-reload', title: 'mis-parsed inet address breaks reload', checks: [] }
      check(c3, "reload errors with #{e.class}", true, e.message[0, 90])
      @results << c3
    end
  end

  def case_m1_static_only
    section('3. MIGRATION TIMELINE: configured vs discovered vs selected')
    c = { id: 'M1', title: 'sniffing disabled (default): static hosts never change', checks: [] }
    ledger = Ledger.new
    handler = ->(_env) { { json: { ok: true } } }
    raw = ['http://old-a.corp:9200', 'http://old-b.corp:9200']
    client = client_for(raw, ledger, handler)

    c[:configured] = configured_snapshot(client)
    4.times { client.perform_request('GET', 'ping') }
    c[:calls] = ledger.calls
    c[:selected_data] = data_targets(ledger)

    kv('M1 configured', c[:configured].join(', '))
    kv('M1 discovered', '(sniff never invoked by client; reload_connections defaults to false)')
    kv('M1 selected', c[:selected_data].join(' -> '))
    check(c, 'no discovery request was made', discovery_targets(ledger).empty?)
    check(c, 'round-robin alternates old-a / old-b',
          c[:selected_data] == ['old-a.corp:9200', 'old-b.corp:9200',
                                'old-a.corp:9200', 'old-b.corp:9200'])
    check(c, '100% of requests still target the OLD domain',
          c[:selected_data].all? { |t| old_host?(t.split(':').first) })
    c[:gate] = evaluate_gate(discovered_hosts: [], pool: pool_snapshot(client),
                             selected_data: c[:selected_data], discovery_invoked: false)
    c[:verdict] = 'Long-lived processes with sniffing off keep using the old targets until restart/redeploy.'
    puts "   verdict: #{c[:verdict]}"
    @results << c
  end

  def case_m2_sniff_to_new_domain
    c = { id: 'M2', title: 'sniff adopts the new private publish addresses', checks: [] }
    ledger = Ledger.new
    new_addresses = ['node-1.es.private:9200', 'node-2.es.private:9200', 'node-3.es.private:9200']
    handler = lambda do |env|
      env.url.path == '/_nodes/http' ? { json: nodes_body(new_addresses) } : { json: { ok: true } }
    end
    raw = ['http://old-a.corp:9200', 'http://old-b.corp:9200']
    client = client_for(raw, ledger, handler)

    c[:configured] = configured_snapshot(client)
    c[:pool_before] = pool_snapshot(client)
    client.transport.reload_connections!
    c[:discovered_list] = new_addresses.map { |a| a.split(':').first }
    c[:pool_after] = pool_snapshot(client)
    3.times { client.perform_request('GET', 'ping') }
    c[:calls] = ledger.calls
    c[:selected_data] = data_targets(ledger)

    kv('M2 configured', c[:configured].join(', '))
    kv('M2 discovered', new_addresses.join(', '))
    kv('M2 pool after', c[:pool_after].map { |p| p[:key] }.join(', '))
    kv('M2 discovery rode on', discovery_targets(ledger).join(', '))
    kv('M2 selected', c[:selected_data].join(' -> '))
    check(c, 'old connections removed after reload',
          c[:pool_after].none? { |p| old_host?(p[:host]) })
    check(c, 'a full cycle selects only NEW private hosts',
          c[:selected_data].all? { |t| t.include?('.es.private') } &&
            c[:selected_data].uniq.size == 3)
    c[:gate] = evaluate_gate(discovered_hosts: c[:discovered_list],
                             pool: c[:pool_after], selected_data: c[:selected_data])
    c[:verdict] = 'Once discovery publishes only new names and a reload runs, real targets move to the private domain.'
    puts "   verdict: #{c[:verdict]}"
    @results << c
  end

  def case_m3_mixed_fleet_retention
    c = { id: 'M3', title: 'mixed rollout: old publish address + == retention + persisted selector', checks: [] }
    ledger = Ledger.new
    mixed = ['new-1.es.private:9200', 'new-2.es.private:9200', 'old-c.corp:9200']
    handler = lambda do |env|
      env.url.path == '/_nodes/http' ? { json: nodes_body(mixed) } : { json: { ok: true } }
    end
    raw = ['http://old-a.corp:9200', 'http://old-c.corp:9200']
    client = client_for(raw, ledger, handler)

    collection_oid_before = client.transport.connections.object_id
    old_c_oid_before = client.transport.connections.all.find { |x| x.host[:host] == 'old-c.corp' }.object_id
    client.transport.reload_connections!
    collection_oid_after = client.transport.connections.object_id
    old_c = client.transport.connections.all.find { |x| x.host[:host] == 'old-c.corp' }
    c[:pool_after] = pool_snapshot(client)
    3.times { client.perform_request('GET', 'ping') }
    c[:calls] = ledger.calls
    c[:selected_data] = data_targets(ledger)
    c[:discovered_list] = mixed.map { |a| a.split(':').first }

    kv('M3 pool after', c[:pool_after].map { |p| "#{p[:host]}(oid=#{p[:oid]})" }.join(', '))
    kv('M3 selected', c[:selected_data].join(' -> '))
    check(c, 'same Connections::Collection/selector reused by rebuild',
          collection_oid_before == collection_oid_after)
    check(c, 'equal old-c connection object physically retained',
          old_c && old_c.object_id == old_c_oid_before)
    check(c, 'old-a (absent from discovery) removed',
          c[:pool_after].none? { |p| p[:host] == 'old-a.corp' })
    check(c, 'retained old-c is still selected within the round-robin cycle',
          c[:selected_data].any? { |t| t.start_with?('old-c.corp:') },
          c[:selected_data].join(' -> '))
    c[:gate] = evaluate_gate(discovered_hosts: c[:discovered_list],
                             pool: c[:pool_after], selected_data: c[:selected_data])
    c[:verdict] = 'Not-yet-migrated nodes keep publishing old targets, and equal keys keep their physical session.'
    puts "   verdict: #{c[:verdict]}"
    @results << c
  end

  def case_m4_dead_and_resurrect
    c = { id: 'M4', title: 'dead connections are retried on the same old key (resurrect / all-dead fallback)', checks: [] }
    ledger = Ledger.new
    handler = ->(_env) { { json: { ok: true } } }
    client = client_for(['http://old-a.corp:9200', 'http://old-b.corp:9200'], ledger, handler)

    old_a = client.transport.connections.all.find { |x| x.host[:host] == 'old-a.corp' }
    old_a.dead!
    selected_while_one_dead = 3.times.map do
      client.transport.connections.get_connection.host[:host]
    end
    check(c, 'selector skips dead old-a while old-b is alive',
          selected_while_one_dead.all? { |h| h == 'old-b.corp' },
          selected_while_one_dead.inspect)

    # Simulate the exponential resurrect backoff having elapsed. The selector
    # cursor persists, so assert the resurrected old-a comes back within a cycle.
    old_a.instance_variable_set(:@dead_since, Time.now - 120)
    old_a.resurrect!
    cycle = 2.times.map { client.transport.connections.get_connection.host[:host] }
    check(c, 'old-a becomes alive and returns to rotation on the SAME old key',
          !old_a.dead? && cycle.sort == ['old-a.corp', 'old-b.corp'], cycle.inspect)

    client.transport.connections.all.each(&:dead!)
    fallback = client.transport.connections.get_connection
    check(c, 'when all are dead the collection falls back to least-failures (still an old target)',
          fallback.dead? && old_host?(fallback.host[:host]), fallback.host[:host])
    c[:verdict] = 'Dead old entries never change hostname; resurrect and all-dead fallback retry the old target.'
    puts "   verdict: #{c[:verdict]}"
    @results << c
  end

  def case_s1_scheme_downgrade
    section('4. SCHEME DECISION FOR SNIFFED CANDIDATES')
    c = { id: 'S1', title: 'https static host without :scheme option rebuilds sniffed nodes as http', checks: [] }
    ledger = Ledger.new
    handler = lambda do |env|
      env.url.path == '/_nodes/http' ? { json: nodes_body(['node-1.es.private:9200']) } : { json: { ok: true } }
    end
    client = client_for(['https://bootstrap.corp:9200'], ledger, handler)
    client.transport.reload_connections!
    pool = pool_snapshot(client)
    client.perform_request('GET', 'ping')
    actual_scheme = ledger.calls.last[:scheme]
    kv('S1 pool', pool.map { |p| p[:key] }.join(', '))
    kv('S1 actual scheme', actual_scheme)
    check(c, 'sniffed pool protocol falls back to DEFAULT_PROTOCOL http',
          pool.first[:key].start_with?('http://node-1.es.private'), pool.first[:key])
    check(c, 'data request actually goes out as cleartext http in the double', actual_scheme == 'http')
    c[:verdict] = 'publish_address has no scheme; pass scheme: "https" explicitly for TLS clusters (base.rb:165).'
    puts "   verdict: #{c[:verdict]}"
    @results << c

    c2 = { id: 'S2', title: 'scheme: https keeps sniffed connections on https', checks: [] }
    ledger2 = Ledger.new
    client2 = client_for(['https://bootstrap.corp:9200'], ledger2, handler, scheme: 'https')
    client2.transport.reload_connections!
    pool2 = pool_snapshot(client2)
    client2.perform_request('GET', 'ping')
    check(c2, 'sniffed pool uses https', pool2.first[:key].start_with?('https://node-1.es.private'),
          pool2.first[:key])
    check(c2, 'actual request scheme is https', ledger2.calls.last[:scheme] == 'https')
    puts "   [S2] #{pool2.first[:key]} scheme=#{ledger2.calls.last[:scheme]}"
    @results << c2
  end

  def case_f1_discovery_timeout
    section('5. DISCOVERY UNAVAILABLE')
    c = { id: 'F1', title: 'sniffer timeout is rescued: last-known pool is retained', checks: [] }
    ledger = Ledger.new
    handler = lambda do |_env|
      sleep 0.4
      { json: { ok: true } }
    end
    client = client_for(['http://old-a.corp:9200'], ledger, handler, sniffer_timeout: 0.05)
    started = Time.now
    client.transport.reload_connections!
    elapsed = Time.now - started
    client.perform_request('GET', 'ping')
    c[:calls] = ledger.calls
    kv('F1 elapsed', format('%.3fs', elapsed))
    kv('F1 discovery target', discovery_targets(ledger).join(', '))
    kv('F1 selected after timeout', data_targets(ledger).join(', '))
    check(c, 'timeout aborted quickly (< 0.3s)', elapsed < 0.3, format('%.3fs', elapsed))
    check(c, 'pool still contains old-a',
          client.transport.connections.all.map { |x| x.host[:host] } == ['old-a.corp'])
    check(c, 'data request still served by retained old-a',
          data_targets(ledger).last == 'old-a.corp:9200')
    @results << c
  end

  def case_f2_discovery_hard_error_direct
    c = { id: 'F2', title: 'hard discovery error on direct reload!: raises, keeps pool, marks probe dead', checks: [] }
    ledger = Ledger.new
    handler = ->(env) { env.url.path == '/_nodes/http' ? :refuse : { json: { ok: true } } }
    client = client_for(['http://old-a.corp:9200', 'http://old-b.corp:9200'], ledger, handler)
    raised = nil
    begin
      client.transport.reload_connections!
    rescue StandardError => e
      raised = e
    end
    check(c, 'reload_connections! raises Elastic::Transport::Transport::Error',
          raised.is_a?(Elastic::Transport::Transport::Error), raised&.class&.name)
    dead = client.transport.connections.dead.map { |x| x.host[:host] }
    check(c, 'the discovery-selected connection is marked dead', dead == ['old-a.corp'], dead.inspect)
    ledger.calls.clear
    response = client.perform_request('GET', 'ping')
    check(c, 'a later data request is still served by the other old host',
          response.status == 200 && data_targets(ledger) == ['old-b.corp:9200'],
          data_targets(ledger).inspect)
    c[:verdict] = 'Only SnifferTimeoutError is rescued inside reload_connections!; hard errors propagate.'
    puts "   verdict: #{c[:verdict]}"
    @results << c
  end

  def case_f3_periodic_reload_hard_error
    c = { id: 'F3', title: 'hard discovery error during periodic reload fails the triggering user request', checks: [] }
    ledger = Ledger.new
    handler = ->(env) { env.url.path == '/_nodes/http' ? :refuse : { json: { ok: true } } }
    client = client_for(['http://old-a.corp:9200', 'http://old-b.corp:9200'], ledger, handler,
                        reload_connections: 2)
    first = client.perform_request('GET', 'ping')
    second_error = nil
    begin
      client.perform_request('GET', 'ping')
    rescue StandardError => e
      second_error = e
    end
    paths = ledger.calls.map { |r| "#{r[:kind]}:#{r[:path]}" }
    check(c, 'first request succeeds', first.status == 200)
    check(c, 'second request (counter hits reload threshold) raises Transport::Error',
          second_error.is_a?(Elastic::Transport::Transport::Error), second_error&.class&.name)
    check(c, "the user's /ping on the failing request never reached an adapter",
          paths == ['data:/ping', 'discovery:/_nodes/http'], paths.inspect)
    c[:verdict] = 'A fast hard failure of _nodes/http on the reload path is NOT swallowed (only timeout is).'
    puts "   verdict: #{c[:verdict]}"
    @results << c
  end

  def case_f4_reload_on_failure_self_heal
    c = { id: 'F4', title: 'reload_on_failure: dead old bootstrap triggers discovery then retry on new pool', checks: [] }
    ledger = Ledger.new
    new_addresses = ['new-1.es.private:9200', 'new-2.es.private:9200']
    handler = lambda do |env|
      if env.url.path == '/_nodes/http'
        { json: nodes_body(new_addresses) }
      elsif env.url.host.start_with?('old-')
        :refuse
      else
        { json: { ok: true } }
      end
    end
    client = client_for(['http://old-a.corp:9200', 'http://old-b.corp:9200'], ledger, handler,
                        reload_on_failure: true)
    response = client.perform_request('GET', 'ping')
    chain = ledger.calls.map { |r| "#{r[:host]}#{r[:path]}" }
    kv('F4 chain', chain.join('  ->  '))
    check(c, 'request ultimately succeeds', response.status == 200)
    check(c, 'chain is old-a data fail -> discovery on old-b -> retry on a NEW host',
          chain[0] == 'old-a.corp/ping' &&
            chain[1] == 'old-b.corp/_nodes/http' &&
            chain[2].end_with?('.es.private/ping'),
          chain.inspect)
    check(c, 'final target is private domain',
          ledger.calls.last[:host].end_with?('.es.private'))
    c[:verdict] = 'Keep one reachable old bootstrap long enough to serve _nodes/http publishing the new names.'
    puts "   verdict: #{c[:verdict]}"
    @results << c
  end

  def case_p1_explicit_proxy
    section('6. PROXY MATRIX (logical authority vs real TCP peer)')
    c = { id: 'P1', title: 'explicit transport_options proxy: same proxy peer, selected authorities differ', checks: [] }
    ledger = Ledger.new
    handler = ->(_env) { { json: { ok: true } } }
    proxy = 'http://proxy.corp:3128'
    client = client_for(['http://node-1.es.private:9200', 'http://node-2.es.private:9200'],
                        ledger, handler, transport_options: { proxy: proxy })
    2.times { client.perform_request('GET', 'ping') }
    c[:calls] = ledger.calls
    ledger.calls.each { |r| kv('P1 request', "#{r[:wire]}  | configured proxy=#{r[:proxy]}") }
    pool_proxies = pool_snapshot(client).map { |p| p[:proxy_peer] }.uniq
    check(c, 'every Faraday connection carries the explicit proxy', pool_proxies == ['proxy.corp:3128'],
          pool_proxies.inspect)
    check(c, 'adapter saw the proxy on every request',
          ledger.calls.all? { |r| r[:proxy_peer] == 'proxy.corp:3128' })
    check(c, 'authority still follows the round-robin selected host',
          ledger.calls.map { |r| r[:host] } == ['node-1.es.private', 'node-2.es.private'])
    @results << c
  end

  def case_p2_env_proxy_no_proxy_split
    c = { id: 'P2', title: 'ambient env proxy + no_proxy splits new (direct) vs old (proxy) targets', checks: [] }
    ledger = Ledger.new
    handler = ->(_env) { { json: { ok: true } } }
    with_env(
      'http_proxy' => 'http://env-proxy.corp:8080',
      'HTTP_PROXY' => 'http://env-proxy.corp:8080',
      'no_proxy' => '.es.private',
      'NO_PROXY' => '.es.private'
    ) do
      client = client_for(['http://node-1.es.private:9200', 'http://old-a.corp:9200'], ledger, handler)
      2.times { client.perform_request('GET', 'ping') }
    end
    c[:calls] = ledger.calls
    ledger.calls.each { |r| kv('P2 request', "#{r[:host]} -> proxy=#{r[:proxy_peer] || 'none (DIRECT)'}") }
    by_host = ledger.calls.to_h { |r| [r[:host], r[:proxy_peer]] }
    check(c, 'new private host matches no_proxy and goes direct', by_host['node-1.es.private'].nil?)
    check(c, 'old corp host does NOT match no_proxy and uses env proxy',
          by_host['old-a.corp'] == 'env-proxy.corp:8080', by_host['old-a.corp'].inspect)
    c[:verdict] = 'If only the new domain is in NO_PROXY, old and new take different paths during migration.'
    puts "   verdict: #{c[:verdict]}"
    @results << c
  end

  def case_p3_proxy_survives_reload
    c = { id: 'P3', title: 'proxy option is reapplied to sniff-rebuilt connections', checks: [] }
    ledger = Ledger.new
    mixed = ['new-1.es.private:9200', 'old-c.corp:9200']
    handler = lambda do |env|
      env.url.path == '/_nodes/http' ? { json: nodes_body(mixed) } : { json: { ok: true } }
    end
    client = client_for(['http://old-c.corp:9200'], ledger, handler,
                        transport_options: { proxy: 'http://proxy.corp:3128' })
    client.transport.reload_connections!
    pool = pool_snapshot(client)
    client.perform_request('GET', 'ping')
    check(c, 'all rebuilt connections (new and retained old) point at the same proxy peer',
          pool.all? { |p| p[:proxy_peer] == 'proxy.corp:3128' },
          pool.map { |p| [p[:host], p[:proxy_peer]] }.inspect)
    check(c, 'recorded request used the proxy', ledger.calls.last[:proxy_peer] == 'proxy.corp:3128')
    @results << c
  end

  def case_p4_https_connect
    c = { id: 'P4', title: 'https via proxy: TCP peer is proxy, CONNECT authority is the selected host', checks: [] }
    ledger = Ledger.new
    handler = ->(_env) { { json: { ok: true } } }
    client = client_for(['https://node-1.es.private:9200'], ledger, handler,
                        transport_options: { proxy: 'http://proxy.corp:3128' })
    client.perform_request('GET', 'ping')
    record = ledger.calls.last
    kv('P4 scheme/authority', "#{record[:scheme]}://#{record[:target]}")
    kv('P4 tcp peer', record[:tcp_peer])
    kv('P4 wire double', record[:wire])
    check(c, 'TCP/TLS connection is opened to the proxy peer', record[:tcp_peer] == 'proxy.corp:3128')
    check(c, 'proxy CONNECT authority carries the NEW private name',
          record[:wire].include?('CONNECT node-1.es.private:9200'))
    c[:verdict] = 'TLS runs to the CONNECT authority; under normal PKI validation the new name must be in the cert SAN.'
    puts "   verdict: #{c[:verdict]}"
    @results << c
  end

  def print_admission
    section('7. ADMISSION GATES (automatable subset)')
    fmt = "   %-4s %-11s %-11s %-11s %-9s %-9s"
    puts fmt % ['CASE', 'no-old-disc', 'no-old-pool', 'sel-all-new', 'cycle-cov', 'TEARDOWN']
    @results.select { |r| r[:gate] }.each do |record|
      gate = record[:gate]
      disc = gate[:discovery_invoked] == false ? 'n/a' : (gate[:no_old_discovered] ? 'yes' : 'NO')
      pool = gate[:no_old_in_pool] ? 'yes' : 'NO'
      sel_new = gate[:selected_all_new] ? 'yes' : 'NO'
      cycle = gate[:full_selector_cycle_covered] ? 'yes' : 'NO'
      verdict = gate[:eligible_to_remove_old_config] ? 'ALLOWED' : 'BLOCKED'
      puts fmt % [record[:id], disc, pool, sel_new, cycle, verdict]
    end
    puts <<~CHECKLIST

      Fleet-wide admission before deleting old config / DNS / listeners:
        [ ] every node's _nodes/http publish_address parses to the new private name
            (no bare old IP, no old FQDN, no legacy inet[name/ip:port] trap)
        [ ] scheme pinned (https) and certificate SAN + chain valid for new names
        [ ] every client workload (all replicas/versions/cron jobs) restarted with
            new static hosts, OR confirmed to have sniff-reloaded an all-new pool
        [ ] a full selector cycle per client shows 100% new authorities
        [ ] proxy / flow / server access logs show ZERO old authorities over a soak
            window covering: rollout + reload interval + keep-alive idle + resurrect
            backoff (60s * 2**(failures-1)) and DNS TTL
        [ ] NO_PROXY / egress / firewall rules for the private domain verified
        [ ] discovery (_nodes/http) highly available: only a timeout is tolerated,
            a fast hard error on a reload path can fail the triggering request (F3)
    CHECKLIST
  end

  def write_outputs
    dir = File.join(__dir__, 'runs')
    FileUtils.mkdir_p(dir)
    payload = {
      provenance: @provenance,
      generated_at: Time.now.iso8601,
      expectation_failures: @expectation_failures,
      cases: @results
    }
    json = JSON.pretty_generate(payload)
    latest = File.join(dir, 'latest.json')
    File.write(latest, json)
    stamp = File.join(dir, "matrix-#{Time.now.strftime('%Y%m%d-%H%M%S')}.json")
    File.write(stamp, json)
  end
end

MatrixRunner.new.run!
