# frozen_string_literal: true

require 'ipaddr'

RSpec.describe Rack::Protection::IPSpoofing do
  it_behaves_like 'any rack application'

  it 'accepts requests without X-Forward-For header' do
    get('/', {}, 'HTTP_CLIENT_IP' => '1.2.3.4', 'HTTP_X_REAL_IP' => '4.3.2.1')
    expect(last_response).to be_ok
  end

  it 'accepts requests with proper X-Forward-For header' do
    get('/', {}, 'HTTP_CLIENT_IP' => '1.2.3.4',
                 'HTTP_X_FORWARDED_FOR' => '192.168.1.20, 1.2.3.4, 127.0.0.1')
    expect(last_response).to be_ok
  end

  it 'denies requests where the client spoofs X-Forward-For but not the IP' do
    get('/', {}, 'HTTP_CLIENT_IP' => '1.2.3.4', 'HTTP_X_FORWARDED_FOR' => '1.2.3.5')
    expect(last_response).not_to be_ok
  end

  it 'denies requests where the client spoofs the IP but not X-Forward-For' do
    get('/', {}, 'HTTP_CLIENT_IP' => '1.2.3.5',
                 'HTTP_X_FORWARDED_FOR' => '192.168.1.20, 1.2.3.4, 127.0.0.1')
    expect(last_response).not_to be_ok
  end

  it 'denies requests where IP and X-Forward-For are spoofed but not X-Real-IP' do
    get('/', {},
        'HTTP_CLIENT_IP' => '1.2.3.5',
        'HTTP_X_FORWARDED_FOR' => '1.2.3.5',
        'HTTP_X_REAL_IP' => '1.2.3.4')
    expect(last_response).not_to be_ok
  end

  describe 'reverse proxy access contract' do
    def build_app(trusted_proxies: nil)
      middleware_options = {}
      middleware_options[:trusted_proxies] = trusted_proxies unless trusted_proxies.nil?

      Rack::Builder.new do
        use Rack::Head
        use Rack::Config do |e|
          e['rack.session'] ||= {}
          e['probe.remote_addr'] = e['REMOTE_ADDR']
          e['probe.app_seen'] = true
        end
        use Rack::Protection::IPSpoofing, middleware_options
        run DummyApp
      end.to_app
    end

    def probe(app, env)
      status, headers, body = app.call(env)
      [status, headers, body.to_a.join, env]
    end

    def request(remote_addr, headers = {})
      {
        'REQUEST_METHOD' => 'GET',
        'PATH_INFO' => '/',
        'REMOTE_ADDR' => remote_addr,
        'rack.session' => {}
      }.merge(headers)
    end

    def evidence(env)
      env['rack.protection.ip_spoofing']
    end

    def expect_accepted(result, client_ip:, source:, peer_trusted: true, reason: nil)
      status, _headers, _body, env = result
      expect(status).to eq(200)
      expect(evidence(env)[:client_ip]).to eq(client_ip)
      expect(evidence(env)[:client_ip_source]).to eq(source)
      expect(evidence(env)[:peer_trusted]).to eq(peer_trusted)
      expect(evidence(env)[:accepted]).to be(true)
      expect(evidence(env)[:reason]).to eq(reason) if reason
      expect(env['rack.protection.client_ip']).to eq(client_ip)
    end

    def expect_denied(result, client_ip:, source:, reason:)
      status, headers, body, env = result
      expect(status).to eq(403)
      expect(headers['content-type']).to eq('text/plain')
      expect(body).to eq('Forbidden')
      expect(evidence(env)[:client_ip]).to eq(client_ip)
      expect(evidence(env)[:client_ip_source]).to eq(source)
      expect(evidence(env)[:accepted]).to be(false)
      expect(evidence(env)[:reason]).to eq(reason)
      expect(env['rack.protection.client_ip']).to eq(client_ip)
    end

    let(:trusted_proxies) { ['10.0.0.1', '10.0.0.2', '127.0.0.1'] }

    it 'derives the client from a trusted multi-hop X-Forwarded-For chain' do
      app = build_app(trusted_proxies: trusted_proxies)
      env = request('10.0.0.1', 'HTTP_X_FORWARDED_FOR' => '192.0.2.10, 10.0.0.2')

      expect_accepted(probe(app, env), client_ip: '192.0.2.10', source: :x_forwarded_for,
                                        reason: :trusted_forwarded_chain)
      expect(evidence(env)[:trusted_proxies]).to eq(['10.0.0.1', '10.0.0.2'])
      expect(evidence(env)[:adopted_chain]).to eq(['192.0.2.10', '10.0.0.2', '10.0.0.1'])
    end

    it 'does not reject a legitimate multi-hop chain because it contains proxy addresses' do
      app = build_app(trusted_proxies: trusted_proxies)
      env = request('10.0.0.1', 'HTTP_X_FORWARDED_FOR' => '192.0.2.10, 10.0.0.2, 10.0.0.1')

      expect_accepted(probe(app, env), client_ip: '192.0.2.10', source: :x_forwarded_for)
    end

    it 'denies a forged private-address chain from an untrusted peer' do
      app = build_app(trusted_proxies: trusted_proxies)
      env = request('203.0.113.9',
                    'HTTP_X_FORWARDED_FOR' => '10.1.2.3, 10.0.0.2',
                    'HTTP_X_REAL_IP' => '10.1.2.3')

      result = probe(app, env)
      expect_denied(result, client_ip: '203.0.113.9', source: :remote_addr, reason: :untrusted_peer)
      expect(evidence(env)[:peer_trusted]).to be(false)
      expect(evidence(env)[:adopted_chain]).to eq(['203.0.113.9'])
    end

    it 'ignores forwarding headers from an untrusted peer without raising errors' do
      app = build_app(trusted_proxies: trusted_proxies)
      env = request('198.51.100.20', 'HTTP_X_FORWARDED_FOR' => '192.0.2.10, 10.0.0.1')

      expect_denied(probe(app, env), client_ip: '198.51.100.20', source: :remote_addr,
                                     reason: :untrusted_peer)
    end

    it 'prefers the Forwarded header over X-Forwarded-For, as Rack does' do
      app = build_app(trusted_proxies: trusted_proxies)
      env = request('10.0.0.1',
                    'HTTP_FORWARDED' => 'for=192.0.2.10;proto=https, for=10.0.0.2',
                    'HTTP_X_FORWARDED_FOR' => '192.0.2.10, 10.0.0.2')

      expect_accepted(probe(app, env), client_ip: '192.0.2.10', source: :forwarded,
                                        reason: :trusted_forwarded_chain)
      expect(evidence(env)[:forwarded_source]).to eq(:forwarded)
    end

    it 'denies when Forwarded and X-Forwarded-For name different clients' do
      app = build_app(trusted_proxies: trusted_proxies)
      env = request('10.0.0.1',
                    'HTTP_FORWARDED' => 'for=192.0.2.10',
                    'HTTP_X_FORWARDED_FOR' => '198.51.100.7')

      expect_denied(probe(app, env), client_ip: '10.0.0.1', source: :remote_addr,
                                     reason: :inconsistent_forwarded_headers)
      expect(evidence(env)[:consistent]).to be(false)
    end

    it 'denies when X-Real-IP is not present in the forwarding chain' do
      app = build_app(trusted_proxies: trusted_proxies)
      env = request('10.0.0.1',
                    'HTTP_X_FORWARDED_FOR' => '192.0.2.10, 10.0.0.2',
                    'HTTP_X_REAL_IP' => '192.0.2.99')

      expect_denied(probe(app, env), client_ip: '10.0.0.1', source: :remote_addr,
                                     reason: :inconsistent_forwarded_headers)
    end

    it 'accepts matching X-Real-IP and Client-IP corroboration' do
      app = build_app(trusted_proxies: trusted_proxies)
      env = request('10.0.0.1',
                    'HTTP_X_FORWARDED_FOR' => '192.0.2.10, 10.0.0.2',
                    'HTTP_X_REAL_IP' => '192.0.2.10',
                    'HTTP_CLIENT_IP' => '192.0.2.10')

      expect_accepted(probe(app, env), client_ip: '192.0.2.10', source: :x_forwarded_for)
      expect(evidence(env)[:consistent]).to be(true)
    end

    it 'denies malformed forwarding addresses from a trusted peer' do
      app = build_app(trusted_proxies: trusted_proxies)
      env = request('10.0.0.1', 'HTTP_X_FORWARDED_FOR' => '192.0.2.10, unknown')

      expect_denied(probe(app, env), client_ip: '10.0.0.1', source: :remote_addr,
                                     reason: :invalid_forwarded_address)
    end

    it 'accepts a Forwarded header that carries no for parameter' do
      app = build_app(trusted_proxies: trusted_proxies)
      env = request('10.0.0.1', 'HTTP_FORWARDED' => 'proto=https;host=example.test')

      expect_accepted(probe(app, env), client_ip: '10.0.0.1', source: :remote_addr,
                                        reason: :no_client_address_claim)
    end

    it 'treats an untrusted peer with only proto/host Forwarded data as a plain request' do
      app = build_app(trusted_proxies: trusted_proxies)
      env = request('203.0.113.9', 'HTTP_FORWARDED' => 'proto=https')

      expect_accepted(probe(app, env), client_ip: '203.0.113.9', source: :remote_addr,
                                        peer_trusted: false, reason: :no_client_address_claim)
    end

    it 'falls back to Rack::Request.ip_filter when trusted_proxies is not configured' do
      app = build_app
      env = request('127.0.0.1', 'HTTP_X_FORWARDED_FOR' => '192.0.2.10, 10.0.0.2')

      expect_accepted(probe(app, env), client_ip: '192.0.2.10', source: :x_forwarded_for)
    end

    it 'uses the immediate peer when all hop addresses are trusted proxies' do
      app = build_app(trusted_proxies: trusted_proxies)
      env = request('10.0.0.1', 'HTTP_X_FORWARDED_FOR' => '10.0.0.2')

      expect_accepted(probe(app, env), client_ip: '10.0.0.2', source: :x_forwarded_for)
    end

    it 'records evidence without changing the adopted address on repeated calls' do
      app = build_app(trusted_proxies: trusted_proxies)
      env = request('10.0.0.1', 'HTTP_X_FORWARDED_FOR' => '192.0.2.10, 10.0.0.2')

      first = probe(app, env)
      second = probe(app, env)

      expect(first[0]).to eq(200)
      expect(second[0]).to eq(200)
      expect(evidence(env)[:client_ip]).to eq('192.0.2.10')
      expect(evidence(env)[:adopted_chain]).to eq(['192.0.2.10', '10.0.0.2', '10.0.0.1'])
    end

    it 'does not leak configuration between instances' do
      trusting_app = build_app(trusted_proxies: trusted_proxies)
      strict_app = build_app(trusted_proxies: ['10.0.0.9'])

      trusting_env = request('10.0.0.1', 'HTTP_X_FORWARDED_FOR' => '192.0.2.10')
      strict_env = request('10.0.0.1', 'HTTP_X_FORWARDED_FOR' => '192.0.2.10')

      expect(probe(trusting_app, trusting_env)[0]).to eq(200)
      strict_result = probe(strict_app, strict_env)
      expect(strict_result[0]).to eq(403)
      expect(evidence(strict_env)[:peer_trusted]).to be(false)

      expect(probe(trusting_app, request('10.0.0.1', 'HTTP_X_FORWARDED_FOR' => '192.0.2.11'))[0]).to eq(200)
    end

    it 'honours Rack::Request.forwarded_priority when it prefers X-Forwarded-For' do
      previous = Rack::Request.forwarded_priority
      Rack::Request.forwarded_priority = %i[x_forwarded forwarded]
      app = build_app(trusted_proxies: trusted_proxies)
      env = request('10.0.0.1',
                    'HTTP_FORWARDED' => 'for=192.0.2.10, for=10.0.0.9',
                    'HTTP_X_FORWARDED_FOR' => '192.0.2.10, 10.0.0.2')

      expect_accepted(probe(app, env), client_ip: '192.0.2.10', source: :x_forwarded_for)
    ensure
      Rack::Request.forwarded_priority = previous
    end

    it 'still denies conflicting headers when priority prefers one of them' do
      previous = Rack::Request.forwarded_priority
      Rack::Request.forwarded_priority = %i[x_forwarded forwarded]
      app = build_app(trusted_proxies: trusted_proxies)
      env = request('10.0.0.1',
                    'HTTP_FORWARDED' => 'for=198.51.100.1',
                    'HTTP_X_FORWARDED_FOR' => '192.0.2.10')

      expect_denied(probe(app, env), client_ip: '10.0.0.1', source: :remote_addr,
                                     reason: :inconsistent_forwarded_headers)
    ensure
      Rack::Request.forwarded_priority = previous
    end

    it 'supports IPAddr, CIDR string and Regexp trusted proxy entries' do
      app = build_app(trusted_proxies: [IPAddr.new('10.0.0.0/8'), '192.0.2.0/24', /\A127\.0\.0\.1\z/])
      env = request('10.0.0.1', 'HTTP_X_FORWARDED_FOR' => '198.51.100.7, 192.0.2.1')

      expect_accepted(probe(app, env), client_ip: '198.51.100.7', source: :x_forwarded_for)
    end

    it 'normalizes IPv6 forwarding addresses and ports' do
      app = build_app(trusted_proxies: trusted_proxies)
      env = request('10.0.0.1',
                    'HTTP_X_FORWARDED_FOR' => '[2001:db8::1]:4444, 10.0.0.2')

      expect_accepted(probe(app, env), client_ip: '2001:db8::1', source: :x_forwarded_for)
      expect(evidence(env)[:adopted_chain].first).to eq('2001:db8::1')
    end

    it 'denies forwarding headers when trusted_proxies is an empty list' do
      app = build_app(trusted_proxies: [])
      env = request('10.0.0.1', 'HTTP_X_FORWARDED_FOR' => '192.0.2.10')

      expect_denied(probe(app, env), client_ip: '10.0.0.1', source: :remote_addr,
                                     reason: :untrusted_peer)
    end

    it 'accepts a trusted peer without forwarding headers using REMOTE_ADDR' do
      app = build_app(trusted_proxies: trusted_proxies)
      env = request('10.0.0.1')

      expect_accepted(probe(app, env), client_ip: '10.0.0.1', source: :remote_addr,
                                        reason: :no_client_address_claim)
    end
  end
end
