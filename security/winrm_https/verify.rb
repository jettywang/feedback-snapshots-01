#!/usr/bin/env ruby
# Runs local WinRM HTTPS policy experiments against real OpenSSL/HTTPClient
# code paths, using generated certificates and socketpair TLS peers.
#
# Run through the pinned runtime:
#   /opt/homebrew/opt/ruby@3.3/bin/ruby .feedback/run.rb exec ruby \
#     -Ilib security/winrm_https/verify.rb
#
# Exit status is 0 only when every expectation below is confirmed. ACCEPT and
# REJECT are observations; UNEXPECTED means the observation contradicted the
# expectation being tested. Anything the sandbox cannot reach is listed in
# README.md instead of being asserted here.

# The harness must not inherit the sandbox's egress proxy: HTTPClient would
# otherwise proxy the socketpair "connection" and never reach the TLS peer.
ENV.keys.grep(/_proxy\z/i).each { |name| ENV.delete(name) }

require 'openssl'
require 'socket'
require 'tmpdir'
require 'winrm'
require_relative 'lib/pki_fixtures'
require_relative 'lib/tls_peer'

module WinRMHttps
  ENDPOINT = 'https://winrm.corp.example:5986/wsman'.freeze

  Result = Struct.new(:group, :name, :outcome, :detail, keyword_init: true)

  # Drives the real WinRM transport end to end: ssl_peer_fingerprint_verification!,
  # HTTPClient's TLS handshake/hostname check, the POST, and the post-response
  # peer certificate comparison.
  class Case
    attr_reader :rows

    def initialize
      @rows = []
    end

    def run(group:, name:, peer:, transport_opts: {}, ssl_config_callback: nil, requests: 1, expected:)
      peer_double = TLSPeer.new(peer.fetch(:cert), peer.fetch(:key))
      transport = transport_for(transport_opts)
      if ssl_config_callback
        transport.instance_variable_get(:@httpcli).ssl_config.verify_callback = ssl_config_callback
      end
      outcome, detail = attempt(transport, peer_double, requests)
      outcome = :unexpected if outcome != expected
      @rows << Result.new(group: group, name: name, outcome: outcome, detail: detail)
      @rows.last
    end

    private

    def transport_for(transport_opts)
      WinRM::HTTP::BasicAuthSSL.new(ENDPOINT, 'user', 'password', transport_opts)
    end

    def attempt(transport, peer_double, requests)
      peer_double.serve do
        requests.times { transport.send_request('<Envelope/>') }
      end
      [:accepted, "HTTP #{peer_double.requests} request(s), handshakes=#{peer_double.handshakes}"]
    rescue StandardError => e
      [:rejected, "#{e.class}: #{e.message.to_s.lines.first.to_s.strip}"]
    end
  end

  class Harness
    def initialize
      @world = PKI.world
      @case = Case.new
      @failures = 0
    end

    def run
      option_matrix
      fingerprint_cases
      rotation_between_connections
      trust_cases
      rotation_cases
      precedence_cases
      callback_cases
      report
    end

    private

    def w
      @world
    end

    def fp(cert, digest: OpenSSL::Digest::SHA1)
      PKI.fingerprint(cert, digest: digest)
    end

    # Which transports even read the TLS options. These checks inspect the
    # constructed transport; they do not need a peer.
    def option_matrix
      group = 'which transports read the TLS options'
      custom = OpenSSL::X509::Store.new
      custom.add_cert(w[:other_root])
      opts = { ssl_peer_fingerprint: fp(w[:good]), ca_trust_path: w[:paths][:root],
               cert_store: custom, no_ssl_peer_verification: true }

      plain = WinRM::HTTP::HttpPlaintext.new('http://winrm.corp.example:5985/wsman', 'u', 'p', opts)
      record(group, 'plaintext ignores ssl_peer_fingerprint',
             plain.instance_variable_get(:@ssl_peer_fingerprint).nil?)
      record(group, 'plaintext still applies no_ssl_peer_verification to its client',
             plain.instance_variable_get(:@httpcli).ssl_config.verify_mode == OpenSSL::SSL::VERIFY_NONE)

      %i[basic client_cert].each do |kind|
        transport = if kind == :basic
                      WinRM::HTTP::BasicAuthSSL.new(ENDPOINT, 'u', 'p', opts)
                    else
                      WinRM::HTTP::ClientCertAuthSSL.new(
                        ENDPOINT, w[:paths][:self_signed], w[:paths][:self_signed], nil, opts
                      )
                    end
        config = transport.instance_variable_get(:@httpcli).ssl_config
        record(group, "#{kind} transport reads ssl_peer_fingerprint",
               transport.instance_variable_get(:@ssl_peer_fingerprint) == fp(w[:good]))
        record(group, "#{kind} transport applies the explicit VERIFY_NONE",
               config.verify_mode == OpenSSL::SSL::VERIFY_NONE)
      end
    end

    def record(group, name, ok)
      @case.rows << Result.new(group: group, name: name,
                               outcome: ok ? :observed : :unexpected,
                               detail: ok ? 'confirmed' : 'NOT as expected')
    end

    def fingerprint_cases
      group = 'ssl_peer_fingerprint binds to the leaf presented at handshake'
      green = { cert: w[:good], key: w[:good_key] }
      @case.run(group: group, name: 'matching SHA-1 fingerprint is accepted',
                peer: green, transport_opts: { ssl_peer_fingerprint: fp(w[:good]) },
                expected: :accepted)
      @case.run(group: group, name: 'fingerprint of a different certificate is rejected',
                peer: green, transport_opts: { ssl_peer_fingerprint: fp(w[:rogue]) },
                expected: :rejected)
      @case.run(group: group, name: 'uppercase fingerprint is accepted (casecmp)',
                peer: green, transport_opts: { ssl_peer_fingerprint: fp(w[:good]).upcase },
                expected: :accepted)
      @case.run(group: group, name: 'SHA-256 fingerprint never matches (library hashes SHA-1)',
                peer: green, transport_opts: { ssl_peer_fingerprint: fp(w[:good], digest: OpenSSL::Digest::SHA256) },
                expected: :rejected)
      @case.run(group: group, name: 'colon-separated fingerprint never matches',
                peer: green, transport_opts: { ssl_peer_fingerprint: fp(w[:good]).scan(/../).join(':') },
                expected: :rejected)

      untrusted_group = 'fingerprint mode disables the PKI, not the pin'
      @case.run(group: untrusted_group, name: 'expired certificate with a matching pin is accepted',
                peer: { cert: w[:expired], key: w[:expired_key] },
                transport_opts: { ssl_peer_fingerprint: fp(w[:expired]) }, expected: :accepted)
      @case.run(group: untrusted_group, name: 'self-signed certificate with a matching pin is accepted',
                peer: { cert: w[:self_signed], key: w[:self_signed_key] },
                transport_opts: { ssl_peer_fingerprint: fp(w[:self_signed]) }, expected: :accepted)
      @case.run(group: untrusted_group, name: 'wrong hostname with a matching pin is accepted',
                peer: { cert: w[:wrong_host], key: w[:wrong_host_key] },
                transport_opts: { ssl_peer_fingerprint: fp(w[:wrong_host]) }, expected: :accepted)
      @case.run(group: untrusted_group, name: 'pin plus no_ssl_peer_verification still pins',
                peer: { cert: w[:wrong_host], key: w[:wrong_host_key] },
                transport_opts: { ssl_peer_fingerprint: fp(w[:wrong_host]),
                                  no_ssl_peer_verification: true }, expected: :accepted)
    end

    # The pin is checked on the preflight socket and again on the response.
    # This shows both halves: a rotated certificate is caught before the SOAP
    # body is sent, and a server that changes identity after the first
    # connection is caught after the POST.
    def rotation_between_connections
      group = 'certificate rotation during a session'
      green = { cert: [w[:good], w[:good]], key: [w[:good_key], w[:good_key]] }
      @case.run(group: group, name: 'pin preflight: rotated certificate rejected before POST',
                peer: { cert: [w[:rogue], w[:good]], key: [w[:rogue_key], w[:good_key]] },
                transport_opts: { ssl_peer_fingerprint: fp(w[:good]) }, expected: :rejected)
      @case.run(group: group, name: 'pin response: rotated certificate rejected after POST',
                peer: { cert: [w[:good], w[:rogue]], key: [w[:good_key], w[:rogue_key]] },
                transport_opts: { ssl_peer_fingerprint: fp(w[:good]) }, expected: :rejected)
      @case.run(group: group, name: 'CA trust re-verifies each new connection (second request rotated to rogue)',
                peer: { cert: [w[:good], w[:rogue]], key: [w[:good_key], w[:rogue_key]] },
                transport_opts: { cert_store: trust_store }, requests: 2, expected: :rejected)
      @case.run(group: group, name: 'CA trust accepts renewal from the same CA across requests',
                peer: { cert: [w[:good], w[:good]], key: [w[:good_key], w[:good_key]] },
                transport_opts: { cert_store: trust_store }, requests: 2, expected: :accepted)
    end

    def trust_store
      store = OpenSSL::X509::Store.new
      store.add_cert(w[:root])
      store
    end

    def trust_cases
      group = 'CA trust keeps chain and hostname checks'
      store = trust_store
      @case.run(group: group, name: 'CA-issued leaf with matching hostname is accepted',
                peer: { cert: w[:good], key: w[:good_key] },
                transport_opts: { cert_store: store }, expected: :accepted)
      @case.run(group: group, name: 'CA-issued leaf for the wrong hostname is rejected',
                peer: { cert: w[:wrong_host], key: w[:wrong_host_key] },
                transport_opts: { cert_store: store }, expected: :rejected)
      @case.run(group: group, name: 'expired CA-issued leaf is rejected',
                peer: { cert: w[:expired], key: w[:expired_key] },
                transport_opts: { cert_store: store }, expected: :rejected)
      @case.run(group: group, name: 'self-signed certificate is rejected by CA trust',
                peer: { cert: w[:self_signed], key: w[:self_signed_key] },
                transport_opts: { cert_store: store }, expected: :rejected)
      @case.run(group: group, name: 'certificate from another CA is rejected',
                peer: { cert: w[:rogue], key: w[:rogue_key] },
                transport_opts: { cert_store: store }, expected: :rejected)
      @case.run(group: group, name: 'no_ssl_peer_verification accepts a rogue certificate',
                peer: { cert: w[:rogue], key: w[:rogue_key] },
                transport_opts: { cert_store: store, no_ssl_peer_verification: true },
                expected: :accepted)

      @case.run(group: group, name: 'ca_trust_path file is used as a trust anchor',
                peer: { cert: w[:good], key: w[:good_key] },
                transport_opts: { ca_trust_path: w[:paths][:root] }, expected: :accepted)
      @case.run(group: group, name: 'ca_trust_path replaces the bundled public CA store',
                peer: { cert: w[:rogue], key: w[:rogue_key] },
                transport_opts: { ca_trust_path: w[:paths][:root] }, expected: :rejected)
    end

    def rotation_cases
      group = 'rotation: several certificates, one profile'
      @case.run(group: group, name: 'CA profile accepts old and new leaf from one CA',
                peer: { cert: w[:good], key: w[:good_key] },
                transport_opts: { ca_trust_path: w[:paths][:root] }, expected: :accepted)

      bundle = File.join(w[:dir], 'self-signed-bundle.pem')
      File.write(bundle, w[:self_signed].to_pem + w[:rotated].to_pem)
      @case.run(group: group, name: 'single PEM with two self-signed certs, first entry',
                peer: { cert: w[:self_signed], key: w[:self_signed_key] },
                transport_opts: { ca_trust_path: bundle }, expected: :accepted)
      @case.run(group: group, name: 'single PEM with two same-subject self-signed certs, second entry',
                peer: { cert: w[:rotated], key: w[:rotated_key] },
                transport_opts: { ca_trust_path: bundle }, expected: :rejected)

      roots = File.join(w[:dir], 'two-roots.pem')
      File.write(roots, w[:root].to_pem + w[:other_root].to_pem)
      @case.run(group: group, name: 'PEM bundle with two CA roots, first root leaf',
                peer: { cert: w[:good], key: w[:good_key] },
                transport_opts: { ca_trust_path: roots }, expected: :accepted)
      @case.run(group: group, name: 'PEM bundle with two CA roots, second root leaf',
                peer: { cert: w[:rogue], key: w[:rogue_key] },
                transport_opts: { ca_trust_path: roots }, expected: :accepted)

      distinct = File.join(w[:dir], 'self-signed-distinct.pem')
      other_subject, other_subject_key = PKI.self_signed(
        cn: 'winrm-standby.corp.example', san: 'DNS:winrm.corp.example', serial: 9003
      )
      File.write(distinct, w[:self_signed].to_pem + other_subject.to_pem)
      @case.run(group: group, name: 'single PEM with distinct subjects, second entry',
                peer: { cert: other_subject, key: other_subject_key },
                transport_opts: { ca_trust_path: distinct }, expected: :accepted)

      @case.run(group: group, name: 'fingerprint accepts exactly one leaf',
                peer: { cert: w[:rotated], key: w[:rotated_key] },
                transport_opts: { ssl_peer_fingerprint: fp(w[:self_signed]) }, expected: :rejected)

      # V_FLAG_PARTIAL_CHAIN lets a leaf act as its own anchor even when it is
      # not self-signed, and lets several leaves with the same subject coexist.
      partial = OpenSSL::X509::Store.new
      partial.add_cert(w[:self_signed])
      partial.add_cert(w[:rotated])
      partial.flags = OpenSSL::X509::V_FLAG_PARTIAL_CHAIN
      @case.run(group: group, name: 'PARTIAL_CHAIN store, first same-subject leaf',
                peer: { cert: w[:self_signed], key: w[:self_signed_key] },
                transport_opts: { cert_store: partial }, expected: :accepted)
      @case.run(group: group, name: 'PARTIAL_CHAIN store, rotated same-subject leaf',
                peer: { cert: w[:rotated], key: w[:rotated_key] },
                transport_opts: { cert_store: partial }, expected: :accepted)
      self_signed_wrong_host, self_signed_wrong_host_key = PKI.self_signed(
        cn: 'other.corp.example', san: 'DNS:other.corp.example', serial: 9100
      )
      partial_host = OpenSSL::X509::Store.new
      partial_host.add_cert(w[:self_signed])
      partial_host.add_cert(self_signed_wrong_host)
      partial_host.flags = OpenSSL::X509::V_FLAG_PARTIAL_CHAIN
      @case.run(group: group, name: 'PARTIAL_CHAIN store still rejects wrong hostname',
                peer: { cert: self_signed_wrong_host, key: self_signed_wrong_host_key },
                transport_opts: { cert_store: partial_host }, expected: :rejected)

      partial_expired = OpenSSL::X509::Store.new
      partial_expired.add_cert(w[:expired])
      partial_expired.flags = OpenSSL::X509::V_FLAG_PARTIAL_CHAIN
      @case.run(group: group, name: 'PARTIAL_CHAIN store still rejects an expired leaf',
                peer: { cert: w[:expired], key: w[:expired_key] },
                transport_opts: { cert_store: partial_expired }, expected: :rejected)

      partial_ca = OpenSSL::X509::Store.new
      partial_ca.add_cert(w[:root])
      partial_ca.flags = OpenSSL::X509::V_FLAG_PARTIAL_CHAIN
      @case.run(group: group, name: 'PARTIAL_CHAIN store keeps CA-issued leaf valid',
                peer: { cert: w[:good], key: w[:good_key] },
                transport_opts: { cert_store: partial_ca }, expected: :accepted)
    end

    def precedence_cases
      group = 'option precedence'
      custom = OpenSSL::X509::Store.new
      custom.add_cert(w[:other_root])
      @case.run(group: group, name: 'cert_store wins over ca_trust_path (custom root accepted)',
                peer: { cert: w[:rogue], key: w[:rogue_key] },
                transport_opts: { ca_trust_path: w[:paths][:root], cert_store: custom },
                expected: :accepted)
      @case.run(group: group, name: 'cert_store wins over ca_trust_path (file root ignored)',
                peer: { cert: w[:good], key: w[:good_key] },
                transport_opts: { ca_trust_path: w[:paths][:root], cert_store: custom },
                expected: :rejected)
      @case.run(group: group, name: 'pin wins over cert_store for a matching untrusted leaf',
                peer: { cert: w[:wrong_host], key: w[:wrong_host_key] },
                transport_opts: { ssl_peer_fingerprint: fp(w[:wrong_host]), cert_store: custom },
                expected: :accepted)
    end

    # WinRM exposes no verify_callback option. These rows reach into the
    # transport's HTTPClient to show the two properties that matter if an
    # operator patches one in: an accept-all callback disables chain
    # verification, but not the hostname check, and a raising callback fails
    # closed.
    def callback_cases
      group = 'verify_callback behaviour (not a WinRM option)'
      store = trust_store
      accept_all = proc { |_ok, _ctx| true }

      @case.run(group: group, name: 'accept-all callback accepts an untrusted chain',
                peer: { cert: w[:rogue], key: w[:rogue_key] },
                transport_opts: { cert_store: store },
                ssl_config_callback: accept_all, expected: :accepted)
      @case.run(group: group, name: 'accept-all callback does not disable the hostname check',
                peer: { cert: w[:wrong_host], key: w[:wrong_host_key] },
                transport_opts: { cert_store: store },
                ssl_config_callback: accept_all, expected: :rejected)
      @case.run(group: group, name: 'raising callback fails closed',
                peer: { cert: w[:good], key: w[:good_key] },
                transport_opts: { cert_store: store },
                ssl_config_callback: ->(_ok, _ctx) { raise 'boom' }, expected: :rejected)
    end

    def report
      rows = @case.rows
      width = rows.map { |row| row.name.length }.max
      rows.group_by(&:group).each do |group, group_rows|
        puts "\n== #{group} =="
        group_rows.each do |row|
          status = case row.outcome
                   when :accepted then 'ACCEPT'
                   when :rejected then 'REJECT'
                   when :observed then 'OK'
                   else 'UNEXPECTED'
                   end
          @failures += 1 if row.outcome == :unexpected
          printf("  %-8s %-#{width}s  %s\n", status, row.name, row.detail)
        end
      end
      puts
      puts "Scenarios: #{rows.size}, unexpected: #{@failures}"
      puts "Fixture directory (deleted on exit): #{w[:dir]}"
      @failures.zero?
    end
  end
end

exit(WinRMHttps::Harness.new.run ? 0 : 1)
