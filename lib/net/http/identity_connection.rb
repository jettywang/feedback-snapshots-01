# frozen_string_literal: true

require_relative '../http'

module Net
  class HTTP
    # A client-certificate identity used for mutual TLS.
    #
    # A +ClientIdentity+ pairs the approved X.509 certificate with its
    # private key so that a read-only service can authenticate the caller.
    # The private key is held only in memory and is never rendered through
    # the public readers of this class: callers verify the presented
    # identity from the certificate (subject, serial number, fingerprint),
    # which contains public material only.
    #
    # The certificate is checked against the expected (CSR-approved)
    # certificate at load time and the private key is checked against the
    # certificate, so a mismatched or tampered identity fails loudly before
    # any socket is opened.
    class ClientIdentity
      # Raised when an identity cannot be loaded or does not match the
      # certificate that was approved for the request.
      class LoadError < Net::ProtocolError
      end

      class MismatchError < LoadError
      end

      # Loads an identity from PEM strings.
      #
      # +certificate_pem+ is the PEM-encoded X.509 certificate, +key_pem+
      # the PEM-encoded private key, and +approved_pem+ (optional) the
      # PEM-encoded certificate that the certificate request was approved
      # for. When +approved_pem+ is given, the presented certificate must be
      # byte-identical to it (compared on the DER encoding) or
      # ClientIdentity::MismatchError is raised.
      def self.from_pem(certificate_pem, key_pem, approved_pem: nil)
        cert =
          begin
            OpenSSL::X509::Certificate.new(certificate_pem)
          rescue => e
            raise LoadError, "failed to parse client certificate: #{e.message}"
          end
        key =
          begin
            OpenSSL::PKey.read(key_pem)
          rescue => e
            raise LoadError, "failed to parse private key: #{e.message}"
          end
        new(cert, key, approved_pem && OpenSSL::X509::Certificate.new(approved_pem))
      end

      # Loads an identity from file paths. The private key is read once and
      # kept in memory; its contents are not exposed after loading.
      def self.from_files(certificate_path, key_path, approved_path: nil)
        cert = read_certificate(certificate_path, 'client certificate')
        key =
          begin
            OpenSSL::PKey.read(File.binread(key_path))
          rescue => e
            raise LoadError, "failed to load private key #{key_path}: #{e.message}"
          end
        approved = approved_path && read_certificate(approved_path, 'approved certificate')
        new(cert, key, approved)
      end

      def self.read_certificate(path, label) # :nodoc:
        OpenSSL::X509::Certificate.new(File.binread(path))
      rescue => e
        raise LoadError, "failed to load #{label} #{path}: #{e.message}"
      end
      private_class_method :read_certificate

      def initialize(certificate, key, approved_certificate = nil)
        unless certificate.is_a?(OpenSSL::X509::Certificate)
          raise LoadError, 'certificate must be an OpenSSL::X509::Certificate'
        end
        unless key.respond_to?(:sign) && key.respond_to?(:private?)
          raise LoadError, 'key must be an OpenSSL private key'
        end
        raise LoadError, 'the given key is not a private key' unless key.private?

        if approved_certificate && certificate.to_der != approved_certificate.to_der
          raise MismatchError,
                'presented certificate does not match the approved certificate ' \
                "(presented serial #{certificate.serial}, approved serial #{approved_certificate.serial})"
        end

        unless certificate.check_private_key(key)
          raise MismatchError,
                'private key does not match the client certificate'
        end

        @certificate = certificate
        @key = key
        @fingerprint = OpenSSL::Digest::SHA256.hexdigest(certificate.to_der)
      end

      # The X.509 certificate presented during the TLS handshake (public
      # material; safe to share).
      attr_reader :certificate

      # SHA-256 fingerprint, as a lowercase hex string, of the DER-encoded
      # certificate. This is the stable public identifier of the identity.
      attr_reader :fingerprint

      # Certificate subject as an RFC 2253 string, e.g. +CN=alice+.
      def subject
        certificate.subject.to_s
      end

      # Certificate serial number.
      def serial
        certificate.serial
      end

      # The certificate's public key in PEM. Public material only.
      def public_key_pem
        certificate.public_key.to_pem
      end

      # True when this identity's certificate matches +other_certificate+
      # (compared on the DER encoding). Never inspects private material.
      def certificate_for?(other_certificate)
        certificate.to_der == OpenSSL::X509::Certificate.new(other_certificate).to_der
      end

      # Applies this identity to a Net::HTTP instance so that the next
      # TLS handshake presents it. Returns the same instance.
      def apply!(http)
        http.use_ssl = true
        http.cert = @certificate
        http.key = @key
        http
      end

      def inspect
        "#<#{self.class} subject=#{subject.inspect} serial=#{serial} fingerprint=#{fingerprint}>"
      end
      alias to_s inspect
    end

    # Builds Net::HTTP connections that present a chosen client-certificate
    # identity over mutual TLS.
    #
    # Each call to #connection (or #start) selects the identity for that
    # single connection before any socket is opened and returns a fresh
    # Net::HTTP instance, so concurrent connections never share mutable SSL
    # state and rotating an identity cannot affect an in-flight connection.
    class IdentityConnection
      # Raised when the requested identity is unknown to the constructor.
      class IdentityNotFound < Net::ProtocolError
      end

      # +default_options+ are applied to every built connection (for example
      # +cert_store:+ for the CA used to verify the read-only service).
      def initialize(address, port = nil, default_options = {})
        @address = address
        @port = port
        @default_options = default_options.dup
        @identities = {}
      end

      # Registers an identity under +name+. The name is what callers pass to
      # #connection to select "who" the call is made as.
      def register(name, identity)
        unless identity.is_a?(ClientIdentity)
          raise ClientIdentity::LoadError,
                'identity must be a Net::HTTP::ClientIdentity'
        end
        @identities[name.to_sym] = identity
        self
      end

      # Returns the registered identity without exposing its private key.
      def identity(name)
        @identities.fetch(name.to_sym) do
          raise IdentityNotFound, "no client identity registered as #{name.inspect}"
        end
      end

      def identities
        @identities.keys
      end

      # Builds a fresh, not-yet-started Net::HTTP that presents the identity
      # registered as +name+. The identity is selected here, before the
      # connection is established.
      def connection(name, options = {})
        id = identity(name)
        http = Net::HTTP.new(@address, @port)
        apply_options(http, @default_options)
        apply_options(http, options)
        id.apply!(http)
        http
      end

      # Builds and starts a connection as +name+, yielding it and closing it
      # when the block returns. The block's value is returned.
      def start(name, options = {}, &block)
        connection(name, options).start(&block)
      end

      private

      # Assigns only options that Net::HTTP understands; cert/key are owned
      # by the selected identity and cannot be overridden per call.
      def apply_options(http, options)
        options.each do |key, value|
          next if %i[cert key use_ssl].include?(key.to_sym)
          setter = "#{key}="
          unless http.respond_to?(setter)
            raise ArgumentError, "unknown Net::HTTP option: #{key.inspect}"
          end
          http.public_send(setter, value)
        end
      end
    end
  end
end
