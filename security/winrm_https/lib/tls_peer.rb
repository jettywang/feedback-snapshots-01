# Test double for the network edge.
#
# The sandbox cannot bind a listening socket, so a real TCP listener is not an
# option. Instead each "connection" is a connected Socket.pair, and a genuine
# OpenSSL::SSL::SSLSocket runs the server side of a real TLS handshake with a
# generated certificate. Redirecting TCPSocket.new to that socketpair lets the
# unmodified HTTPClient (and therefore the unmodified WinRM transport) perform
# its own handshake, chain verification, and hostname check. Nothing in the
# verification path is stubbed: only the socket source is.
require 'socket'
require 'openssl'

module WinRMHttps
  class TLSPeer
    RESPONSE = '<?xml version="1.0"?><Envelope xmlns="http://www.w3.org/2003/05/soap-envelope">' \
               '<Body></Body></Envelope>'.freeze

    attr_reader :handshakes, :requests

    # certs/keys may be arrays: the Nth TLS connection is terminated with the
    # Nth certificate. That lets a test rotate the certificate between the
    # preflight connection and the SOAP POST.
    def initialize(cert, key)
      @certs = Array(cert)
      @keys = Array(key)
      @handshakes = 0
      @requests = 0
    end

    def serve
      original = TCPSocket.method(:new)
      peer = self
      TCPSocket.define_singleton_method(:new) do |_host, _port, *_rest|
        TLSPeer.server_socket(peer)
      end
      yield
    ensure
      TCPSocket.define_singleton_method(:new, original) if original
    end

    def self.server_socket(peer)
      index = peer.handshakes
      client, server = Socket.pair(:UNIX, :STREAM, 0)
      context = OpenSSL::SSL::SSLContext.new
      context.cert = peer.cert_for(index)
      context.key = peer.key_for(index)
      tls = OpenSSL::SSL::SSLSocket.new(server, context)
      Thread.new do
        begin
          tls.accept
          peer.bump_handshake
          read_request(tls)
          peer.bump_request
          tls.write(http_response)
          tls.flush
        rescue StandardError
          nil
        ensure
          tls.close rescue nil
        end
      end
      client
    end

    def cert_for(index)
      @certs[[index, @certs.length - 1].min]
    end

    def key_for(index)
      @keys[[index, @keys.length - 1].min]
    end

    def bump_handshake
      @handshakes += 1
    end

    def bump_request
      @requests += 1
    end

    def self.read_request(tls)
      loop do
        line = tls.gets
        break if line.nil? || line == "\r\n"
      end
    end

    def self.http_response
      "HTTP/1.1 200 OK\r\nContent-Type: application/soap+xml\r\n" \
        "Content-Length: #{RESPONSE.bytesize}\r\nConnection: close\r\n\r\n#{RESPONSE}"
    end
  end
end
