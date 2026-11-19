# Local certificate fixture factory. Everything is generated in a temporary
# directory at runtime; no private key is written into the repository.
require 'openssl'
require 'tmpdir'

module WinRMHttps
  module PKI
    module_function

    def key(bits = 2048)
      OpenSSL::PKey::RSA.new(bits)
    end

    def base_cert(subject:, key:, issuer_cert:, issuer_key:, serial:, not_before:, not_after:)
      cert = OpenSSL::X509::Certificate.new
      cert.version = 2
      cert.serial = serial
      cert.subject = OpenSSL::X509::Name.parse(subject)
      cert.issuer = issuer_cert ? issuer_cert.subject : cert.subject
      cert.public_key = key.public_key
      cert.not_before = not_before
      cert.not_after = not_after
      factory = OpenSSL::X509::ExtensionFactory.new
      factory.subject_certificate = cert
      factory.issuer_certificate = issuer_cert || cert
      [cert, factory]
    end

    def ca(cn:, key:, serial: rand(1 << 31), not_before: Time.now - 60, not_after: Time.now + 86_400)
      cert, factory = base_cert(
        subject: "/CN=#{cn}", key: key, issuer_cert: nil, issuer_key: key,
        serial: serial, not_before: not_before, not_after: not_after
      )
      cert.add_extension factory.create_extension('basicConstraints', 'CA:TRUE', true)
      cert.add_extension factory.create_extension('keyUsage', 'keyCertSign,cRLSign', true)
      cert.add_extension factory.create_extension('subjectKeyIdentifier', 'hash', false)
      cert.sign(key, OpenSSL::Digest::SHA256.new)
      cert
    end

    def leaf(cn:, ca:, ca_key:, san: nil, serial: rand(1 << 31),
             not_before: Time.now - 60, not_after: Time.now + 86_400)
      cert_key = key
      cert, factory = base_cert(
        subject: "/CN=#{cn}", key: cert_key, issuer_cert: ca, issuer_key: ca_key,
        serial: serial, not_before: not_before, not_after: not_after
      )
      cert.add_extension factory.create_extension('basicConstraints', 'CA:FALSE', true)
      cert.add_extension factory.create_extension('keyUsage', 'digitalSignature,keyEncipherment', true)
      cert.add_extension factory.create_extension('extendedKeyUsage', 'serverAuth')
      cert.add_extension factory.create_extension('subjectAltName', san) if san
      cert.sign(ca_key, OpenSSL::Digest::SHA256.new)
      [cert, cert_key]
    end

    def self_signed(cn:, san: nil, serial: rand(1 << 31),
                    not_before: Time.now - 60, not_after: Time.now + 86_400)
      cert_key = key
      cert, factory = base_cert(
        subject: "/CN=#{cn}", key: cert_key, issuer_cert: nil, issuer_key: cert_key,
        serial: serial, not_before: not_before, not_after: not_after
      )
      cert.add_extension factory.create_extension('basicConstraints', 'CA:FALSE', true)
      cert.add_extension factory.create_extension('keyUsage', 'digitalSignature,keyEncipherment', true)
      cert.add_extension factory.create_extension('extendedKeyUsage', 'serverAuth')
      cert.add_extension factory.create_extension('subjectAltName', san) if san
      cert.sign(cert_key, OpenSSL::Digest::SHA256.new)
      [cert, cert_key]
    end

    def fingerprint(cert, digest: OpenSSL::Digest::SHA1)
      OpenSSL::Digest.hexdigest(digest.new.name, cert.to_der)
    end

    # Builds the fixture set used by every scenario.
    def world
      dir = Dir.mktmpdir('winrm-https')
      ca_key = key
      root = ca(cn: 'Contoso WinRM Root CA', key: ca_key)
      other_ca_key = key
      other_root = ca(cn: 'Rogue Root CA', key: other_ca_key)

      good, good_key = leaf(cn: 'winrm.corp.example', ca: root, ca_key: ca_key,
                            san: 'DNS:winrm.corp.example')
      wrong_host, wrong_host_key = leaf(cn: 'other.corp.example', ca: root, ca_key: ca_key,
                                        san: 'DNS:other.corp.example')
      expired, expired_key = leaf(cn: 'winrm.corp.example', ca: root, ca_key: ca_key,
                                  san: 'DNS:winrm.corp.example',
                                  not_before: Time.now - 7200, not_after: Time.now - 3600)
      rogue, rogue_key = leaf(cn: 'winrm.corp.example', ca: other_root, ca_key: other_ca_key,
                              san: 'DNS:winrm.corp.example')
      self_signed_cert, self_signed_key = self_signed(
        cn: 'winrm.corp.example', san: 'DNS:winrm.corp.example'
      )
      rotated, rotated_key = self_signed(
        cn: 'winrm.corp.example', san: 'DNS:winrm.corp.example', serial: 9002
      )

      paths = {
        root: write(dir, 'root.pem', root.to_pem),
        other_root: write(dir, 'other-root.pem', other_root.to_pem),
        self_signed: write(dir, 'self-signed.pem', self_signed_cert.to_pem)
      }

      {
        dir: dir,
        paths: paths,
        ca_key: ca_key, root: root,
        other_ca_key: other_ca_key, other_root: other_root,
        good: good, good_key: good_key,
        wrong_host: wrong_host, wrong_host_key: wrong_host_key,
        expired: expired, expired_key: expired_key,
        rogue: rogue, rogue_key: rogue_key,
        self_signed: self_signed_cert, self_signed_key: self_signed_key,
        rotated: rotated, rotated_key: rotated_key
      }
    end

    def write(dir, name, content)
      path = File.join(dir, name)
      File.write(path, content)
      path
    end
    private_class_method :write
  end
end
