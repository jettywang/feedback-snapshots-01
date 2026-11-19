require 'openssl'
require 'logger'

# Deterministic NTLM-like session and HTTP doubles used by the negotiate
# transport specs. The session deliberately exposes the same sealing and
# signing operations the transport uses, without starting a WinRM service or
# relying on a real authentication exchange.
module NegotiateTestSupport
  SIGNING_KEY = 'winrm-test-server-signing-key'.b
  STREAM_KEY = 'winrm-test-server-sealing-key'.b
  VERSION_MAGIC = "\x01\x00\x00\x00".b
  ZERO_SEQUENCE = "\x00\x00\x00\x00".b

  class FixedSession
    def seal_message(message)
      crypt(message, :client)
    end

    def sign_message(message)
      signature(message, ZERO_SEQUENCE)
    end

    def unseal_message(message)
      crypt(message, :server)
    end

    def verify_signature(signature, message)
      expected = signature(message, ZERO_SEQUENCE)
      return false unless signature.bytesize == expected.bytesize

      result = 0
      signature.bytes.zip(expected.bytes) { |a, b| result |= a ^ b }
      result.zero?
    end

    def server_signature(message, sequence = ZERO_SEQUENCE)
      signature(message, sequence)
    end

    private

    def signature(message, sequence)
      digest = OpenSSL::HMAC.digest('SHA256', SIGNING_KEY, message.to_s.b)
      "#{VERSION_MAGIC}#{digest.byteslice(0, 8)}#{sequence}".b
    end

    def crypt(message, _direction)
      message.to_s.b.bytes.each_with_index.map { |byte, index| byte ^ keystream_byte(index) }.pack('C*')
    end

    def keystream_byte(index)
      block = index / 32
      offset = index % 32
      OpenSSL::Digest.digest('SHA256', "#{STREAM_KEY}#{[block].pack('Q>')}".b).getbyte(offset)
    end
  end

  # Minimal stand-in for Net::NTLM::Client. Calling init_context without a
  # challenge discards the session, matching rubyntlm's reset semantics.
  class FixedClient
    attr_reader :session

    def initialize(session = FixedSession.new)
      @session = session
    end

    def session=(session)
      @session = session
    end

    def init_context(_challenge = nil, _channel_binding = nil)
      @session = nil
      nil
    end
  end

  class FakeResponse
    attr_reader :body, :status, :header, :peer_cert

    def initialize(body:, status: 200, content_type: nil)
      @body = body
      @status = status
      @peer_cert = nil
      @header = {}
      @header['Content-Type'] = [content_type] if content_type
    end

    def status_code
      status
    end
  end

  class FakeHttpClient
    attr_reader :requests

    def initialize(responses)
      @responses = Array(responses)
      @requests = []
    end

    def post(endpoint, body, headers)
      @requests << { endpoint: endpoint, body: body, headers: headers }
      response = @responses.shift
      raise "unexpected HTTP request ##{@requests.length}" if response.nil?

      response
    end
  end

  module_function

  # Builds a valid multipart/encrypted NTLM response body around the given
  # plaintext. Options let individual specs break exactly one layer.
  def sealed_response_body(plaintext, options = {})
    session = options.fetch(:session, FixedSession.new)
    boundary = options.fetch(:boundary, 'Encrypted Boundary')
    declared_length = options.fetch(:original_content_length, plaintext.bytesize)
    signature_length = options.fetch(:signature_length, 16)
    signature = options.fetch(:signature) { session.server_signature(plaintext) }
    sealed = options.fetch(:sealed_message) { session.send(:crypt, plaintext, :server) }
    protocol = options.fetch(:protocol, 'application/HTTP-SPNEGO-session-encrypted')
    original_type = options.fetch(:original_content_type, 'application/soap+xml;charset=UTF-8')

    payload = [signature_length].pack('V') + signature + sealed
    "--#{boundary}\r\n" \
      "Content-Type: #{protocol}\r\n" \
      "OriginalContent: type=#{original_type};Length=#{declared_length}\r\n" \
      "--#{boundary}\r\n" \
      "Content-Type: application/octet-stream\r\n" \
      "#{payload}--#{boundary}--\r\n"
  end

  def multipart_content_type(boundary: 'Encrypted Boundary',
                             protocol: 'application/HTTP-SPNEGO-session-encrypted')
    "multipart/encrypted;protocol=\"#{protocol}\";boundary=\"#{boundary}\""
  end

  def build_transport(endpoint: 'http://example.test:5985/wsman', session: FixedSession.new,
                      responses: [], logger: quiet_logger)
    transport = WinRM::HTTP::HttpNegotiate.new(
      endpoint, 'user', 'pass',
      logger: logger,
      user_agent: 'WinRM test',
      receive_timeout: 30
    )
    client = FixedClient.new(session)
    transport.instance_variable_set(:@ntlmcli, client)
    transport.instance_variable_set(:@httpcli, FakeHttpClient.new(responses))
    [transport, client]
  end

  def quiet_logger
    Logger.new(IO::NULL, level: Logger::WARN)
  end
end
