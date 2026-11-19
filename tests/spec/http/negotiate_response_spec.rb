require 'winrm/http/transport'
require_relative 'negotiate_support'

describe WinRM::HTTP::HttpNegotiate do
  include NegotiateTestSupport

  let(:soap) do
    '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">' \
      '<s:Body><ReceiveResponse><ok>true</ok></ReceiveResponse></s:Body></s:Envelope>'
  end
  let(:session) { NegotiateTestSupport::FixedSession.new }
  let(:content_type) { NegotiateTestSupport.multipart_content_type }
  let(:body) { NegotiateTestSupport.sealed_response_body(soap, session: session) }
  let(:response) { NegotiateTestSupport::FakeResponse.new(body: body, content_type: content_type) }
  let(:transport) { build_transport(session: session, responses: [response]).first }
  let(:published) { [] }

  it 'returns a parsed SOAP document for a valid sealed response' do
    doc = transport.send_request('<request/>')
    expect(doc).to be_a(REXML::Document)
    expect(doc.root.name).to eq('Envelope')
  end

  it 'does not publish the SOAP document until integrity checks pass' do
    allow(WinRM::ResponseHandler).to receive(:new).and_wrap_original do |original, xml, status|
      published << xml
      original.call(xml, status)
    end

    transport.send_request('<request/>')
    expect(published).to eq([soap])
  end

  it 'rejects a response with a bad signature before XML parsing or callbacks' do
    forged_signature = session.server_signature('other message')
    body = NegotiateTestSupport.sealed_response_body(soap, session: session, signature: forged_signature)
    response = NegotiateTestSupport::FakeResponse.new(body: body, content_type: content_type)
    transport = build_transport(session: session, responses: [response]).first
    expect(WinRM::ResponseHandler).not_to receive(:new)

    expect { transport.send_request('<request/>') { |_stdout, _stderr| published << :callback } }
      .to raise_error(WinRM::WinRMHTTPTransportError, /integrity/)
    expect(published).to be_empty
  end

  it 'rejects a truncated ciphertext before XML parsing or callbacks' do
    body = NegotiateTestSupport.sealed_response_body(
      soap, session: session, original_content_length: soap.bytesize + 4
    )
    response = NegotiateTestSupport::FakeResponse.new(body: body, content_type: content_type)
    transport = build_transport(session: session, responses: [response]).first
    expect(WinRM::ResponseHandler).not_to receive(:new)

    expect { transport.send_request('<request/>') { |_stdout, _stderr| published << :callback } }
      .to raise_error(WinRM::WinRMHTTPTransportError, /length/)
    expect(published).to be_empty
  end

  it 'rejects a plain SOAP body that forges the encrypted Content-Type' do
    response = NegotiateTestSupport::FakeResponse.new(body: soap, content_type: content_type)
    transport = build_transport(session: session, responses: [response]).first
    expect(WinRM::ResponseHandler).not_to receive(:new)

    expect { transport.send_request('<request/>') { |_stdout, _stderr| published << :callback } }
      .to raise_error(WinRM::WinRMHTTPTransportError, /Invalid NTLM encrypted response/)
    expect(published).to be_empty
  end

  it 'rejects plaintext SOAP over HTTP even with a SOAP Content-Type' do
    response = NegotiateTestSupport::FakeResponse.new(
      body: soap, content_type: 'application/soap+xml;charset=UTF-8'
    )
    transport = build_transport(endpoint: 'http://example.test:5985/wsman', session: session,
                                responses: [response]).first
    expect(WinRM::ResponseHandler).not_to receive(:new)

    expect { transport.send_request('<request/>') { |_stdout, _stderr| published << :callback } }
      .to raise_error(WinRM::WinRMHTTPTransportError)
    expect(published).to be_empty
  end

  it 'rejects a plain SOAP Content-Type carrying non-XML over HTTPS' do
    response = NegotiateTestSupport::FakeResponse.new(
      body: 'not xml at all', content_type: 'application/soap+xml;charset=UTF-8'
    )
    transport = build_transport(endpoint: 'https://example.test:5986/wsman', session: session,
                                responses: [response]).first
    expect(WinRM::ResponseHandler).not_to receive(:new)

    expect { transport.send_request('<request/>') }
      .to raise_error(WinRM::WinRMHTTPTransportError, /Invalid NTLM encrypted response/)
  end

  it 'accepts the documented OMI plaintext SOAP response over HTTPS' do
    response = NegotiateTestSupport::FakeResponse.new(
      body: soap, content_type: 'application/soap+xml;charset=UTF-8'
    )
    transport = build_transport(endpoint: 'https://example.test:5986/wsman', session: session,
                                responses: [response]).first

    doc = transport.send_request('<request/>')
    expect(doc).to be_a(REXML::Document)
    expect(doc.root.name).to eq('Envelope')
  end

  it 'renegotiates once and raises after a repeated 401' do
    response = NegotiateTestSupport::FakeResponse.new(body: '', status: 401)
    transport, client = build_transport(session: session, responses: [response, response])
    fresh = NegotiateTestSupport::FixedSession.new
    allow(transport).to receive(:init_auth) { client.session = fresh }

    expect { transport.send_request('<request/>') }
      .to raise_error(WinRM::WinRMAuthorizationError)
    expect(transport).to have_received(:init_auth).once
    expect(client.session).to be_nil
  end

  it 'renegotiates once after a 401 using a fresh session' do
    fresh = NegotiateTestSupport::FixedSession.new
    unauth = NegotiateTestSupport::FakeResponse.new(body: '', status: 401)
    retried_response = NegotiateTestSupport::FakeResponse.new(
      body: NegotiateTestSupport.sealed_response_body(soap, session: fresh),
      content_type: content_type
    )
    transport, client = build_transport(session: session, responses: [unauth, retried_response])
    allow(transport).to receive(:init_auth) { client.session = fresh }

    doc = transport.send_request('<request/>')
    expect(doc).to be_a(REXML::Document)
    expect(transport).to have_received(:init_auth).once
    expect(client.session).to equal(fresh)
  end

  it 'discards the NTLM session after an integrity failure' do
    forged_signature = session.server_signature('other message')
    response = NegotiateTestSupport::FakeResponse.new(
      body: NegotiateTestSupport.sealed_response_body(soap, session: session, signature: forged_signature),
      content_type: content_type
    )
    transport, client = build_transport(session: session, responses: [response])

    expect { transport.send_request('<request/>') }
      .to raise_error(WinRM::WinRMHTTPTransportError, /integrity/)
    expect(client.session).to be_nil
  end
end
