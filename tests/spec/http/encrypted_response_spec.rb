require 'winrm/http/encrypted_response'
require_relative 'negotiate_support'

describe WinRM::HTTP::EncryptedResponse do
  let(:soap) { '<s:Envelope><s:Body><ok>true</ok></s:Body></s:Envelope>' }
  let(:session) { NegotiateTestSupport::FixedSession.new }
  let(:body) { NegotiateTestSupport.sealed_response_body(soap, session: session) }
  let(:content_type) { NegotiateTestSupport.multipart_content_type }

  subject(:parsed) { described_class.new(body, content_type) }

  it 'extracts the boundary and OriginalContent metadata' do
    expect(parsed.boundary).to eq('Encrypted Boundary')
    expect(parsed.original_content_length).to eq(soap.bytesize)
  end

  it 'extracts a 16 byte signature and the sealed message' do
    expect(parsed.signature.bytesize).to eq(16)
    expect(parsed.sealed_message.bytesize).to eq(soap.bytesize)
    expect(session.unseal_message(parsed.sealed_message)).to eq(soap)
  end

  it 'accepts a quoted boundary with mixed case media types' do
    quoted = NegotiateTestSupport.sealed_response_body(soap, session: session)
    content_type = 'Multipart/Encrypted; Protocol="Application/HTTP-SPNEGO-Session-Encrypted"; ' \
                   'Boundary="Encrypted Boundary"'
    expect(described_class.new(quoted, content_type).boundary).to eq('Encrypted Boundary')
  end

  it 'rejects an unquoted boundary containing a quote delimiter' do
    header = 'multipart/encrypted;protocol="application/HTTP-SPNEGO-session-encrypted"; ' \
             'boundary=Encrypted Boundary'
    expect { described_class.new(body, header) }
      .to raise_error(described_class::ParseError, /boundary/)
  end

  it 'rejects a missing boundary parameter' do
    header = 'multipart/encrypted;protocol="application/HTTP-SPNEGO-session-encrypted"'
    expect { described_class.new(body, header) }
      .to raise_error(described_class::ParseError, /boundary/)
  end

  it 'rejects a body framed with a different boundary' do
    forged = NegotiateTestSupport.sealed_response_body(
      soap, session: session, boundary: 'Different Boundary'
    )
    expect { described_class.new(forged, content_type) }
      .to raise_error(described_class::ParseError, /boundary/)
  end

  it 'rejects a non multipart/encrypted Content-Type' do
    expect { described_class.new(body, 'application/soap+xml;charset=UTF-8') }
      .to raise_error(described_class::ParseError, /Content-Type/)
  end

  it 'rejects an unexpected encryption protocol' do
    header = NegotiateTestSupport.multipart_content_type(protocol: 'application/HTTP-Kerberos-session-encrypted')
    expect { described_class.new(body, header) }
      .to raise_error(described_class::ParseError, /protocol/)
  end

  it 'rejects an unexpected OriginalContent type' do
    forged = NegotiateTestSupport.sealed_response_body(
      soap, session: session, original_content_type: 'text/plain'
    )
    expect { described_class.new(forged, content_type) }
      .to raise_error(described_class::ParseError, /OriginalContent type/)
  end

  it 'rejects a non numeric OriginalContent length' do
    forged = body.sub('Length=', 'Length=abc')
    expect { described_class.new(forged, content_type) }
      .to raise_error(described_class::ParseError, /OriginalContent length/)
  end

  it 'rejects a truncated payload when OriginalContent declares more bytes' do
    forged = NegotiateTestSupport.sealed_response_body(
      soap, session: session, original_content_length: soap.bytesize + 1
    )
    expect { described_class.new(forged, content_type) }
      .to raise_error(described_class::ParseError, /length/)
  end

  it 'rejects a payload longer than OriginalContent declares' do
    forged = NegotiateTestSupport.sealed_response_body(
      soap, session: session, original_content_length: soap.bytesize - 1
    )
    expect { described_class.new(forged, content_type) }
      .to raise_error(described_class::ParseError, /length/)
  end

  it 'rejects a signature that is not 16 bytes' do
    forged = NegotiateTestSupport.sealed_response_body(
      soap, session: session, signature_length: 24
    )
    expect { described_class.new(forged, content_type) }
      .to raise_error(described_class::ParseError, /signature length/)
  end

  it 'rejects a truncated signature' do
    forged = NegotiateTestSupport.sealed_response_body(
      soap, session: session, signature: 'short'
    )
    expect { described_class.new(forged, content_type) }
      .to raise_error(described_class::ParseError)
  end

  it 'rejects content after the closing boundary' do
    forged = NegotiateTestSupport.sealed_response_body(soap, session: session) + 'smuggled'
    expect { described_class.new(forged, content_type) }
      .to raise_error(described_class::ParseError, /after NTLM multipart closing boundary/)
  end

  it 'rejects ciphertext that ends with a fabricated multipart epilogue' do
    forged = body.sub('application/octet-stream', "application/octet-stream\r\n\r\n--Encrypted Boundary--")
    expect { described_class.new(forged, content_type) }
      .to raise_error(described_class::ParseError, /length/)
  end

  it 'requires the payload part Content-Type header' do
    forged = body.sub("\r\nContent-Type: application/octet-stream\r\n", "\r\n")
    expect { described_class.new(forged, content_type) }
      .to raise_error(described_class::ParseError, /payload Content-Type/)
  end

  it 'rejects a missing closing boundary' do
    forged = body.sub("--Encrypted Boundary--\r\n", '')
    expect { described_class.new(forged, content_type) }
      .to raise_error(described_class::ParseError)
  end
end
