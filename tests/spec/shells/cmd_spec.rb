require 'winrm/shells/cmd'

describe WinRM::Shells::Cmd do
  let(:retry_limit) { 1 }
  let(:shell_id) { 'shell_id' }
  let(:output) { 'output' }
  let(:create_shell_payload) { 'create_shell_payload' }
  let(:close_shell_payload) { 'close_shell_payload' }
  let(:cleanup_payload) { 'cleanup_payload' }
  let(:command) { 'run this command' }
  let(:arguments) { ['args'] }

  # Well-formed protocol envelopes. Each also carries a shadow node reusing
  # the target local-name in another namespace/position to prove only the
  # legitimate, correctly-namespaced node is selected.
  let(:create_shell_response) do
    <<~XML
      <s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
                  xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing"
                  xmlns:x="http://schemas.xmlsoap.org/ws/2004/09/transfer"
                  xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd"
                  xmlns:evil="http://evil.example/not-winrm">
        <s:Header><a:Action>CreateResponse</a:Action></s:Header>
        <s:Body>
          <evil:SelectorSet><evil:Selector Name="ShellId">shadow-shell</evil:Selector></evil:SelectorSet>
          <x:ResourceCreated>
            <a:ReferenceParameters>
              <w:SelectorSet>
                <w:Selector Name="ShellId">#{shell_id}</w:Selector>
              </w:SelectorSet>
            </a:ReferenceParameters>
          </x:ResourceCreated>
        </s:Body>
      </s:Envelope>
    XML
  end

  let(:command_response) do
    <<~XML
      <s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
                  xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell"
                  xmlns:evil="http://evil.example/not-winrm">
        <s:Body>
          <evil:CommandResponse><evil:CommandId>shadow-command</evil:CommandId></evil:CommandResponse>
          <rsp:CommandResponse>
            <rsp:CommandId>command_id</rsp:CommandId>
          </rsp:CommandResponse>
        </s:Body>
      </s:Envelope>
    XML
  end

  let(:connection_options) { { max_commands: 100, retry_limit: retry_limit, retry_delay: 0 } }
  let(:transport) { double('transport', send_request: nil) }

  before do
    allow_any_instance_of(WinRM::WSMV::CloseShell).to receive(:build)
      .and_return(close_shell_payload)
    allow_any_instance_of(WinRM::WSMV::CreateShell).to receive(:build)
      .and_return(create_shell_payload)
    allow_any_instance_of(WinRM::WSMV::CleanupCommand).to receive(:build)
      .and_return(cleanup_payload)
    allow_any_instance_of(WinRM::WSMV::ReceiveResponseReader).to receive(:read_output)
      .and_return(output)
    allow(transport).to receive(:send_request)
      .with(create_shell_payload)
      .and_return(REXML::Document.new(create_shell_response))
    allow(transport).to receive(:send_request)
      .with(/#{command}/)
      .and_return(REXML::Document.new(command_response))
  end

  subject { described_class.new(connection_options, transport, Logger.new(IO::NULL)) }

  describe '#run' do
    it 'opens a shell and gets shell id' do
      subject.run(command, arguments)
      expect(subject.shell_id).to eq shell_id
    end

    it 'sends create shell through transport' do
      expect(transport).to receive(:send_request).with(create_shell_payload)
      subject.run(command, arguments)
    end

    it 'returns output from generated command' do
      expect(subject.run(command, arguments)).to eq output
    end

    it 'sends command through transport' do
      expect(transport).to receive(:send_request).with(/#{command}/)
      subject.run(command, arguments)
    end

    it 'sends cleanup message through transport' do
      expect(transport).to receive(:send_request).with(cleanup_payload)
      subject.run(command, arguments)
    end
  end

  describe '#close' do
    it 'sends close shell through transport' do
      subject.run(command, arguments)
      expect(transport).to receive(:send_request).with(close_shell_payload)
      subject.close
    end

    it 'creates a shell closer with default shell uri' do
      allow(WinRM::WSMV::CloseShell).to receive(:new) do |_, opts|
        expect(opts[:shell_uri]).to be nil
      end.and_call_original
      subject.close
    end
  end
end
