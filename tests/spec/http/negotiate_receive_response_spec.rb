require 'base64'
require 'winrm/http/transport'
require 'winrm/wsmv/command_output'
require 'winrm/wsmv/receive_response_reader'
require_relative 'negotiate_support'

describe 'NTLM response chain' do
  let(:shell_id) { 'F4A2622B-B842-4EB8-8A78-0225C8A993DF' }
  let(:command_id) { 'A2A2622B-B842-4EB8-8A78-0225C8A993DF' }
  let(:session) { NegotiateTestSupport::FixedSession.new }
  let(:content_type) { NegotiateTestSupport.multipart_content_type }
  let(:stdout_text) { 'verified output' }
  let(:soap) do
    "<s:Envelope xmlns:s='http://www.w3.org/2003/05/soap-envelope'>" \
      "<s:Body><rsp:ReceiveResponse xmlns:rsp='http://schemas.microsoft.com/wbem/wsman/1/windows/shell'>" \
      "<rsp:Stream Name='stdout'>#{Base64.strict_encode64(stdout_text)}</rsp:Stream>" \
      "<rsp:CommandState State='http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandState/Done'>" \
      '<rsp:ExitCode>0</rsp:ExitCode></rsp:CommandState>' \
      '</rsp:ReceiveResponse></s:Body></s:Envelope>'
  end

  let(:message) do
    WinRM::WSMV::CommandOutput.new(
      default_connection_opts,
      shell_id: shell_id,
      command_id: command_id,
      shell_uri: WinRM::WSMV::Header::RESOURCE_URI_CMD
    )
  end

  def reader_for(response)
    transport = NegotiateTestSupport.build_transport(session: session, responses: [response]).first
    WinRM::WSMV::ReceiveResponseReader.new(transport, NegotiateTestSupport.quiet_logger)
  end

  it 'delivers verified SOAP output to the reader callback' do
    response = NegotiateTestSupport::FakeResponse.new(
      body: NegotiateTestSupport.sealed_response_body(soap, session: session),
      content_type: content_type
    )
    yields = []
    output = reader_for(response).read_output(message) { |stdout, stderr| yields << [stdout, stderr] }

    expect(yields).to eq([[stdout_text, nil]])
    expect(output.stdout).to eq(stdout_text)
  end

  it 'does not invoke the callback when the signature is invalid' do
    response = NegotiateTestSupport::FakeResponse.new(
      body: NegotiateTestSupport.sealed_response_body(
        soap, session: session, signature: session.server_signature('forged')
      ),
      content_type: content_type
    )
    yields = []

    expect do
      reader_for(response).read_output(message) { |stdout, stderr| yields << [stdout, stderr] }
    end.to raise_error(WinRM::WinRMHTTPTransportError, /integrity/)
    expect(yields).to be_empty
  end

  it 'does not invoke the callback when the payload is truncated' do
    response = NegotiateTestSupport::FakeResponse.new(
      body: NegotiateTestSupport.sealed_response_body(
        soap, session: session, original_content_length: soap.bytesize + 1
      ),
      content_type: content_type
    )
    yields = []

    expect do
      reader_for(response).read_output(message) { |stdout, stderr| yields << [stdout, stderr] }
    end.to raise_error(WinRM::WinRMHTTPTransportError, /length/)
    expect(yields).to be_empty
  end

  it 'does not invoke the callback for plain SOAP disguised as encrypted' do
    response = NegotiateTestSupport::FakeResponse.new(body: soap, content_type: content_type)
    yields = []

    expect do
      reader_for(response).read_output(message) { |stdout, stderr| yields << [stdout, stderr] }
    end.to raise_error(WinRM::WinRMHTTPTransportError, /Invalid NTLM encrypted response/)
    expect(yields).to be_empty
  end
end
