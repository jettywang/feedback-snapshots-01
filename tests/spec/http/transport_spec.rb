require 'rubyntlm'
require 'winrm/http/transport'

describe WinRM::HTTP::HttpNegotiate do
  describe '#init' do
    let(:endpoint) { 'some_endpoint' }
    let(:domain) { 'some_domain' }
    let(:user) { 'some_user' }
    let(:password) { 'some_password' }
    let(:options) { {} }

    context 'user is not domain prefixed' do
      it 'does not pass a domain to the NTLM client' do
        expect(Net::NTLM::Client).to receive(:new).with(user, password, options)
        WinRM::HTTP::HttpNegotiate.new(endpoint, user, password, options)
      end
    end

    context 'user is domain prefixed' do
      it 'passes prefixed domain to the NTLM client' do
        expect(Net::NTLM::Client).to receive(:new) do |passed_user, passed_password, passed_options|
          expect(passed_user).to eq user
          expect(passed_password).to eq password
          expect(passed_options[:domain]).to eq domain
        end
        WinRM::HTTP::HttpNegotiate.new(endpoint, "#{domain}\\#{user}", password, options)
      end
    end

    context 'option is passed with a domain' do
      let(:options) { { domain: domain } }

      it 'passes domain option to the NTLM client' do
        expect(Net::NTLM::Client).to receive(:new) do |passed_user, passed_password, passed_options|
          expect(passed_user).to eq user
          expect(passed_password).to eq password
          expect(passed_options[:domain]).to eq domain
        end
        WinRM::HTTP::HttpNegotiate.new(endpoint, user, password, options)
      end
    end
  end
end

describe 'WinRM::HTTP::HttpTransport SOAP logging' do
  let(:secret) { 'FAKE-TRANSPORT-SECRET-5c1e-do-not-log' }
  let(:password) { 'FAKE-TRANSPORT-PASSWORD-a93b-do-not-log' }
  let(:io) { StringIO.new }
  let(:logger) { Logger.new(io) }
  let(:endpoint) { URI.parse("https://user:#{password}@localhost:5986/wsman") }
  let(:transport) { WinRM::HTTP::HttpTransport.new(endpoint, logger: logger, receive_timeout: 10) }

  let(:message) do
    <<~XML
      <env:Envelope xmlns:env="http://www.w3.org/2003/05/soap-envelope"
                    xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell"
                    xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing">
        <env:Header>
          <a:MessageID>uuid:00000000-0000-0000-0000-000000000001</a:MessageID>
          <a:Action>http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Command</a:Action>
        </env:Header>
        <env:Body>
          <rsp:CommandLine CommandId="00000000-0000-0000-0000-000000000002">
            <rsp:Command>"echo #{secret}"</rsp:Command>
            <rsp:Arguments>--password=#{password}</rsp:Arguments>
          </rsp:CommandLine>
        </env:Body>
      </env:Envelope>
    XML
  end

  let(:response) do
    <<~XML
      <env:Envelope xmlns:env="http://www.w3.org/2003/05/soap-envelope"
                    xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell"
                    xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing">
        <env:Header>
          <a:RelatesTo>uuid:00000000-0000-0000-0000-000000000001</a:RelatesTo>
        </env:Header>
        <env:Body>
          <rsp:ReceiveResponse>
            <rsp:Stream Name="stdout">#{secret}</rsp:Stream>
          </rsp:ReceiveResponse>
        </env:Body>
      </env:Envelope>
    XML
  end

  before do
    logger.level = :debug
    allow(transport).to receive(:ssl_peer_fingerprint_verification!)
    body = double('http_body', content: response)
    allow(transport).to receive(:verify_ssl_fingerprint)
    @http_response = double('http_response', http_body: body, peer_cert: nil, status: 200)
    @httpcli = transport.instance_variable_get(:@httpcli)
    allow(@httpcli).to receive(:post).and_return(@http_response)
  end

  it 'logs redacted request and response with correlation ids' do
    transport.send_request(message)

    logged = io.string
    expect(logged).to include('SOAP request')
    expect(logged).to include('SOAP response')
    expect(logged).to include('message_id="uuid:00000000-0000-0000-0000-000000000001"')
    expect(logged).to include('command_id="00000000-0000-0000-0000-000000000002"')
    expect(logged).to include('REDACTED Command')
    expect(logged).to include('REDACTED Arguments')
    expect(logged).to include('REDACTED Stream')
    expect(logged).not_to include(secret)
    expect(logged).not_to include(password)
  end

  it 'sends the exact original bytes even though the log copy is redacted' do
    transport.send_request(message)

    expect(@httpcli).to have_received(:post) do |_endpoint, body, headers|
      expect(body).to eq(message)
      expect(body).not_to include('REDACTED')
      expect(body).to include(secret)
      expect(headers['Content-Length']).to eq(message.bytesize)
    end
  end

  it 'still logs a locatable summary for malformed responses' do
    malformed = "<env:Envelope xmlns:env='u'><env:Body>#{secret}"
    allow(@http_response.http_body).to receive(:content).and_return(malformed)

    expect { transport.send_request(message) }.to raise_error(WinRM::WinRMHTTPTransportError)

    logged = io.string
    expect(logged).to include('xml=unparseable')
    expect(logged).to include('line=1')
    expect(logged).not_to include(secret)
  end

  it 'keeps logging silent below debug level' do
    logger.level = :info

    transport.send_request(message)

    expect(io.string).to be_empty
  end

  it 'reports a redaction failure without echoing the payload' do
    allow(WinRM::LogRedactor).to receive(:describe).and_raise(StandardError.new("bad #{secret}"))

    transport.send_request(message)

    expect(io.string).to include('SOAP logging failed')
    expect(io.string).not_to include(secret)
  end
end

describe 'WinRM::HTTP::HttpGSSAPI logging' do
  let(:secret) { 'FAKE-GSS-SECRET-1d2f-do-not-log' }
  let(:password) { 'FAKE-GSS-PASSWORD-77bc-do-not-log' }
  let(:io) { StringIO.new }
  let(:logger) { Logger.new(io) }
  let(:endpoint) { URI.parse("https://user:#{password}@localhost:5986/wsman") }
  let(:transport) { WinRM::HTTP::HttpGSSAPI.allocate }

  let(:message) do
    <<~XML
      <env:Envelope xmlns:env="http://www.w3.org/2003/05/soap-envelope"
                    xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell">
        <env:Body>
          <rsp:CommandLine CommandId="00000000-0000-0000-0000-000000000003">
            <rsp:Command>"echo #{secret}"</rsp:Command>
          </rsp:CommandLine>
        </env:Body>
      </env:Envelope>
    XML
  end

  let(:response_payload) do
    <<~XML
      <env:Envelope xmlns:env="http://www.w3.org/2003/05/soap-envelope"
                    xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell">
        <env:Body>
          <rsp:CommandLine CommandId="00000000-0000-0000-0000-000000000004">
            <rsp:Command>"#{secret}"</rsp:Command>
          </rsp:CommandLine>
        </env:Body>
      </env:Envelope>
    XML
  end

  before do
    require 'gssapi'
    require 'gssapi/extensions'

    logger.level = :debug
    transport.instance_variable_set(:@logger, logger)
    transport.instance_variable_set(:@endpoint, endpoint)
    transport.instance_variable_set(:@service, 'HTTP/host@REALM')
    transport.instance_variable_set(:@gsscli, double('gsscli', context: double('context')))
    transport.instance_variable_set(:@httpcli, double('httpcli'))
  end

  def buffer(value = nil, length = 0)
    Struct.new(:value, :length).new(value, length)
  end

  def iov(buffer)
    Struct.new(:type, :buffer).new(nil, buffer)
  end

  def stub_gss_buffers(*buffers)
    wrappers = buffers.map { |buf| iov(buf) }
    allow(GSSAPI::LibGSSAPI::GssIOVBufferDesc).to receive(:new).and_return(*wrappers)
    allow(FFI::MemoryPointer).to receive(:new).and_return(
      double('pointer', address: 1024, write_int: nil, read_int: 0)
    )
    allow(FFI::Pointer).to receive(:new).and_return(double('ffi pointer'))
    allow(GSSAPI::LibGSSAPI).to receive(:gss_wrap_iov)
    allow(GSSAPI::LibGSSAPI).to receive(:gss_unwrap_iov)
    wrappers
  end

  it 'logs only a length and digest summary before sealing' do
    header_buffer = buffer('header', 6)
    plaintext_buffer = buffer
    padding_buffer = buffer('pad', 3)
    stub_gss_buffers(header_buffer, plaintext_buffer, padding_buffer)

    transport.send(:winrm_encrypt, message)

    logged = io.string
    expect(logged).to include('sealing SOAP message')
    expect(logged).to include("plaintext_bytes=#{message.bytesize}")
    expect(logged).to include("plaintext_sha256=sha256:#{WinRM::LogRedactor.digest(message)}")
    expect(logged).not_to include(secret)
    expect(plaintext_buffer.value).to eq(message)
  end

  it 'logs only a length and digest summary of ciphertext before decrypting' do
    ciphertext = "\x00\x00\x00\x00#{secret}"
    data = buffer(response_payload)
    stub_gss_buffers(buffer, data, buffer)

    transport.send(:winrm_decrypt, ciphertext.dup)

    logged = io.string
    expect(logged).to include('decrypting SOAP message')
    expect(logged).to include("ciphertext_bytes=#{ciphertext.bytesize}")
    expect(logged).not_to include(secret)
  end

  it 'logs the decrypted message as redacted and returns the original plaintext' do
    data = buffer
    stub_gss_buffers(buffer, data, buffer)
    allow(GSSAPI::LibGSSAPI).to receive(:gss_unwrap_iov) { data.value = response_payload; 0 }

    result = transport.send(:winrm_decrypt, "\x00\x00\x00\x00#{secret}".dup)

    logged = io.string
    expect(logged).to include('SOAP message decrypted')
    expect(logged).to include('response-decrypted')
    expect(logged).to include("bytes=#{response_payload.bytesize}")
    expect(logged).not_to include(secret)
    expect(result).to eq(response_payload)
  end

  it 'logs the redacted request and opaque response while posting sealed bytes unchanged' do
    sealed = 'SEALED-BYTES-are-not-the-plaintext'
    allow(transport).to receive(:winrm_encrypt).and_return([0, sealed])
    httpcli = transport.instance_variable_get(:@httpcli)
    post = double('post')
    expect(httpcli).to receive(:post) do |_endpoint, body, _headers|
      expect(body).to include(sealed)
      post
    end
    response = double('response', http_body: double('body', content: response_payload))
    allow(post).to receive(:http_body).and_return(response.http_body)

    transport.send(:send_kerberos_request, message).tap do
      expect(io.string).to include('SOAP request')
      expect(io.string).to include('REDACTED Command')
      expect(io.string).to include('response-encrypted')
      expect(io.string).not_to include(secret)
    end
  end
end
