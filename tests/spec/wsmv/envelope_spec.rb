require 'winrm/wsmv/envelope'

describe WinRM::WSMV::Envelope, unit: true do
  let(:shell_ns) { 'http://schemas.microsoft.com/wbem/wsman/1/windows/shell' }
  let(:evil_ns) { 'http://evil.example/not-winrm' }

  # An envelope that renames every prefix and embeds shadow nodes reusing the
  # target local-names in another namespace or a nested payload.
  let(:adversarial_envelope) do
    <<~XML
      <z:Envelope xmlns:z="http://www.w3.org/2003/05/soap-envelope"
                  xmlns:h="http://schemas.xmlsoap.org/ws/2004/08/addressing"
                  xmlns:t="http://schemas.xmlsoap.org/ws/2004/09/transfer"
                  xmlns:g="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd"
                  xmlns:r="#{shell_ns}"
                  xmlns:e="#{evil_ns}">
        <z:Header>
          <h:RelatesTo>uuid:REAL</h:RelatesTo>
          <e:RelatesTo>uuid:SHADOW</e:RelatesTo>
          <h:MessageID>uuid:REQUEST-ID</h:MessageID>
        </z:Header>
        <z:Body>
          <e:ResourceCreated><e:ReferenceParameters><g:SelectorSet>
            <g:Selector Name="ShellId">shadow-shell</g:Selector>
          </g:SelectorSet></e:ReferenceParameters></e:ResourceCreated>
          <t:ResourceCreated>
            <h:ReferenceParameters>
              <g:SelectorSet><g:Selector Name="ShellId">real-shell</g:Selector></g:SelectorSet>
            </h:ReferenceParameters>
          </t:ResourceCreated>
          <r:ReceiveResponse>
            <e:Stream Name="stdout">shadow-stream</e:Stream>
            <r:Stream Name="stdout">real-stream</r:Stream>
            <e:CommandState State="#{described_class::COMMAND_STATE_DONE}">
              <e:ExitCode>123</e:ExitCode>
            </e:CommandState>
            <r:CommandState State="#{described_class::COMMAND_STATE_DONE}">
              <r:ExitCode>7</r:ExitCode>
            </r:CommandState>
          </r:ReceiveResponse>
        </z:Body>
      </z:Envelope>
    XML
  end

  let(:doc) { REXML::Document.new(adversarial_envelope) }

  describe 'namespace and position strict selectors' do
    it 'selects the real ShellId and ignores the shadow selector' do
      expect(described_class.shell_id(doc)).to eq('real-shell')
    end

    it 'selects only shell-namespace streams' do
      expect(described_class.streams(doc).map(&:text)).to eq(['real-stream'])
    end

    it 'selects the real ExitCode and ignores the shadow exit code' do
      expect(described_class.exit_code(doc)).to eq('7')
    end

    it 'detects Done only from the shell-namespace CommandState' do
      expect(described_class.command_done?(doc)).to be(true)
    end

    it 'reads only the addressing-namespace RelatesTo' do
      expect(described_class.relates_to(doc)).to eq('uuid:REAL')
    end

    it 'is independent of namespace prefix names' do
      renamed = adversarial_envelope.gsub('xmlns:z=', 'xmlns:soap-env=')
                                     .gsub('<z:', '<soap-env:').gsub('</z:', '</soap-env:')
      expect(described_class.shell_id(REXML::Document.new(renamed))).to eq('real-shell')
    end

    it 'extracts the request MessageID' do
      expect(described_class.request_message_id(adversarial_envelope)).to eq('uuid:REQUEST-ID')
    end
  end

  describe '.command_id' do
    let(:command_doc) do
      REXML::Document.new(<<~XML)
        <s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
                    xmlns:r="#{shell_ns}" xmlns:e="#{evil_ns}">
          <s:Body>
            <e:CommandResponse><e:CommandId>shadow-command</e:CommandId></e:CommandResponse>
            <r:CommandResponse><r:CommandId>real-command</r:CommandId></r:CommandResponse>
          </s:Body>
        </s:Envelope>
      XML
    end

    it 'ignores a same local-name node in another namespace' do
      expect(described_class.command_id(command_doc)).to eq('real-command')
    end
  end

  describe '.max_envelope_size_kb' do
    let(:config_doc) do
      REXML::Document.new(<<~XML)
        <s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
                    xmlns:cfg="http://schemas.microsoft.com/wbem/wsman/1/config"
                    xmlns:e="#{evil_ns}">
          <s:Body>
            <e:Config><e:MaxEnvelopeSizekb>1</e:MaxEnvelopeSizekb></e:Config>
            <cfg:Config><cfg:MaxEnvelopeSizekb>512000</cfg:MaxEnvelopeSizekb></cfg:Config>
          </s:Body>
        </s:Envelope>
      XML
    end

    it 'reads only the config-namespace value' do
      expect(described_class.max_envelope_size_kb(config_doc)).to eq('512000')
    end
  end

  describe 'fault detection' do
    it 'ignores shadow and nested Fault elements' do
      shadow_doc = REXML::Document.new(<<~XML)
        <s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:e="#{evil_ns}">
          <s:Body>
            <e:Fault><e:Code><e:Value>e:Boom</e:Value></e:Code></e:Fault>
            <e:Payload><s:Fault/></e:Payload>
          </s:Body>
        </s:Envelope>
      XML
      expect(described_class.fault_children(shadow_doc)).to be_empty
      expect(described_class.wsman_fault(shadow_doc)).to be_nil
    end

    it 'parses a real Fault even when the default namespace is used' do
      fault_doc = REXML::Document.new(<<~XML)
        <Envelope xmlns="http://www.w3.org/2003/05/soap-envelope">
          <Header/>
          <Body>
            <Fault>
              <Code><Value>s:Sender</Value>
                <Subcode><Value>w:QuotaLimit</Value></Subcode>
              </Code>
              <Reason><Text xml:lang="en-US">nope</Text></Reason>
            </Fault>
          </Body>
        </Envelope>
      XML
      expect(described_class.fault_children(fault_doc)).not_to be_empty
      expect(described_class.soap_fault_values(fault_doc)).to eq(
        code: 's:Sender', subcode: 'w:QuotaLimit', reason: 'nope'
      )
    end

    it 'scopes WSManFault to the Fault/Detail wsmanfault namespace' do
      fault_doc = REXML::Document.new(stubbed_response('soap_fault_v2.xml'))
      expect(described_class.wsman_fault(fault_doc).attributes['Code']).to eq('2150858778')
    end

    it 'scopes WMI error codes to the MSFT_WmiError namespace' do
      fault_doc = REXML::Document.new(stubbed_response('wmi_error_v2.xml'))
      wmi_error = described_class.wmi_error(fault_doc)
      expect(described_class.wmi_error_code(wmi_error)).to eq('2150859173')
    end
  end

  describe '.correlate!' do
    let(:response_doc) do
      REXML::Document.new(<<~XML)
        <s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
                    xmlns:h="http://schemas.xmlsoap.org/ws/2004/08/addressing">
          <s:Header><h:RelatesTo>uuid:REQUEST-ID</h:RelatesTo></s:Header>
          <s:Body/>
        </s:Envelope>
      XML
    end

    it 'accepts a matching RelatesTo' do
      expect(described_class.correlate!(response_doc, 'uuid:REQUEST-ID')).to be(response_doc)
    end

    it 'rejects a mismatched RelatesTo even in lenient mode' do
      expect do
        described_class.correlate!(response_doc, 'uuid:OTHER')
      end.to raise_error(WinRM::WinRMResponseCorrelationError)
    end

    it 'tolerates a missing RelatesTo by default for legacy endpoints' do
      legacy = REXML::Document.new(
        '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body/></s:Envelope>'
      )
      expect(described_class.correlate!(legacy, 'uuid:REQUEST-ID')).to be(legacy)
    end

    it 'rejects a missing RelatesTo in strict mode' do
      legacy = REXML::Document.new(
        '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body/></s:Envelope>'
      )
      expect do
        described_class.correlate!(legacy, 'uuid:REQUEST-ID', strict: true)
      end.to raise_error(WinRM::WinRMResponseCorrelationError)
    end

    it 'tolerates an unparseable request MessageID in lenient mode' do
      expect(described_class.correlate!(response_doc, nil)).to be(response_doc)
    end
  end
end
