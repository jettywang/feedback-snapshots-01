#!/usr/bin/env ruby
# Generates config/cases.yml: a runnable comparison of WinRM HTTPS option
# combinations, plus the transport each resolves to.
#
# Run through the pinned runtime:
#   /opt/homebrew/opt/ruby@3.3/bin/ruby .feedback/run.rb exec ruby \
#     -Ilib security/winrm_https/config_matrix.rb
require 'yaml'
require 'openssl'
require 'fileutils'
require 'winrm'
require_relative 'lib/pki_fixtures'

world = WinRMHttps::PKI.world
internal_store = OpenSSL::X509::Store.new
internal_store.add_cert(world[:root])
sha1 = WinRMHttps::PKI.fingerprint(world[:good])
bundle = File.join(world[:dir], 'rotation-bundle.pem')
File.write(bundle, world[:self_signed].to_pem + world[:rotated].to_pem)

base = {
  'endpoint' => 'https://winrm.corp.example:5986/wsman',
  'user' => 'svc_winrm',
  'password' => 'REPLACE_ME'
}

cases = {
  'A_public_or_internal_ca' => {
    'why' => 'Default verification. Chain, expiry and hostname all checked.',
    'options' => base.merge('transport' => 'ssl', 'cert_store' => 'OpenSSL::X509::Store with internal root'),
    'resolves_to' => 'BasicAuthSSL / HttpNegotiate over TLS',
    'keeps' => %w[chain expiry hostname]
  },
  'B_ca_trust_path' => {
    'why' => 'Same as A but the internal root comes from a PEM file.',
    'options' => base.merge('transport' => 'ssl', 'ca_trust_path' => world[:paths][:root]),
    'resolves_to' => 'BasicAuthSSL / HttpNegotiate over TLS',
    'keeps' => %w[chain expiry hostname],
    'note' => 'Replaces the bundled public CA store; it does not add to it.'
  },
  'C_fingerprint_sha1' => {
    'why' => 'Pin a single self-signed leaf. No chain, expiry or hostname check.',
    'options' => base.merge('transport' => 'ssl', 'ssl_peer_fingerprint' => sha1,
                            'ca_trust_path' => world[:paths][:root]),
    'resolves_to' => 'BasicAuthSSL / HttpNegotiate over TLS',
    'keeps' => %w[pin],
    'drops' => %w[chain expiry hostname],
    'note' => 'SHA-1 lowercase hex of the leaf DER; the library cannot accept SHA-256.'
  },
  'D_self_signed_anchor' => {
    'why' => 'Trust a self-signed leaf as an anchor; keeps expiry and hostname.',
    'options' => base.merge('transport' => 'ssl', 'ca_trust_path' => world[:paths][:self_signed]),
    'resolves_to' => 'BasicAuthSSL / HttpNegotiate over TLS',
    'keeps' => %w[pin expiry hostname],
    'drops' => %w[chain]
  },
  'E_basic_auth_only' => {
    'why' => 'Force Basic auth over TLS instead of Negotiate.',
    'options' => base.merge('transport' => 'ssl', 'basic_auth_only' => true,
                            'ca_trust_path' => world[:paths][:root]),
    'resolves_to' => 'BasicAuthSSL',
    'keeps' => %w[chain expiry hostname]
  },
  'F_client_certificate' => {
    'why' => 'Mutual TLS; user/password replaced by a client certificate.',
    'options' => base.reject { |k, _| %w[user password].include?(k) }
                      .merge('transport' => 'ssl', 'client_cert' => '/path/client.pem',
                             'client_key' => '/path/client.key', 'ca_trust_path' => world[:paths][:root]),
    'resolves_to' => 'ClientCertAuthSSL',
    'keeps' => %w[chain expiry hostname]
  },
  'G_no_peer_verification' => {
    'why' => 'Compatibility escape hatch. Not recommended.',
    'options' => base.merge('transport' => 'ssl', 'no_ssl_peer_verification' => true),
    'resolves_to' => 'BasicAuthSSL / HttpNegotiate over TLS',
    'keeps' => [],
    'drops' => %w[chain expiry hostname pin],
    'note' => 'Any certificate is accepted; authentication still happens, but the server is unauthenticated.'
  },
  'H_rotation_bundle' => {
    'why' => 'Two self-signed leaves during a rollover, one PEM.',
    'options' => base.merge('transport' => 'ssl', 'ca_trust_path' => bundle),
    'resolves_to' => 'BasicAuthSSL / HttpNegotiate over TLS',
    'keeps' => %w[expiry hostname],
    'drops' => %w[chain],
    'note' => 'Bundled leaves must have distinct subjects; same-subject entries collapse to the first.'
  }
}

# Verify each case builds a transport and record the class. Errors are data.
cases.each_value do |entry|
  begin
    opts = entry['options'].transform_keys(&:to_sym)
    opts = opts.merge(logger: Logger.new(IO::NULL))
    opts[:transport] = opts[:transport].to_sym
    opts[:realm] = 'CONTOSO.EXAMPLE' if opts[:transport] == :kerberos
    opts[:service] = 'HTTP' if opts[:transport] == :kerberos
    opts[:cert_store] = internal_store if opts[:cert_store]
    transport = WinRM::HTTP::TransportFactory.new.create_transport(opts)
    entry['built_transport_class'] = transport.class.name
  rescue StandardError => e
    entry['built_transport_class'] = "ERROR: #{e.class}: #{e.message.lines.first.strip}"
  end
end

path = File.expand_path('config/cases.yml', __dir__)
FileUtils.mkdir_p(File.dirname(path))
File.write(path, YAML.dump('generated_by' => 'security/winrm_https/config_matrix.rb',
                           'fixture_notice' => 'Fixture paths and fingerprints are per-run; regenerate before use.',
                           'cases' => cases))
puts "wrote #{path} (#{cases.size} cases)"
cases.each { |name, entry| puts format('  %-24s %s', name, entry['built_transport_class']) }


# Replace per-run fixture paths with placeholders so the file is a template,
# not a record of a deleted temporary directory.
text = File.read(path)
text = text.gsub(world[:dir], '/etc/winrm-fixtures')
text = text.gsub(sha1, '<sha1-of-leaf-der>')
File.write(path, text)
puts 'rewrote fixture paths as placeholders'
