require 'winrm/psrp/powershell_output_decoder'

describe WinRM::PSRP::PowershellOutputDecoder do
  let(:message_type) { WinRM::PSRP::Message::MESSAGE_TYPES[:error_record] }
  let(:data) { 'blah' }
  let(:message) do
    WinRM::PSRP::Message.new(
      'bc1bfbba-8215-4a04-b2df-7a3ac0310e16',
      message_type,
      data,
      '4218a578-0f18-4b19-82c3-46b433319126'
    )
  end

  subject { described_class.new.decode(message) }

  def render_error_stub(locals)
    template_binding = binding
    locals.each { |name, value| template_binding.local_variable_set(name, value) }
    ERB.new(stubbed_clixml('error_record.xml.erb')).result(template_binding)
  end

  context 'undecodable message type' do
    let(:message_type) { WinRM::PSRP::Message::MESSAGE_TYPES[:public_key] }

    it 'ignores message' do
      expect(subject).to be nil
    end
  end

  context 'undecodable method identifier' do
    let(:message_type) { WinRM::PSRP::Message::MESSAGE_TYPES[:pipeline_host_call] }
    let(:data) do
      "\xEF\xBB\xBF<Obj RefId=\"0\"><MS><I64 N=\"ci\">-100</I64><Obj N=\"mi\" RefId=\"1\">"\
      '<TN RefId="0"><T>System.Management.Automation.Remoting.RemoteHostMethodId</T>'\
      '<T>System.Enum</T><T>System.ValueType</T><T>System.Object</T></TN>'\
      '<ToString>WriteProgress</ToString><I32>17</I32></Obj><Obj N="mp" RefId="2">'\
      '<TN RefId="1"><T>System.Collections.ArrayList</T><T>System.Object</T></TN><LST>'\
      '<I32>7</I32><I32>0</I32><S>some_x000D__x000A_data</S></LST></Obj></MS></Obj>'
    end

    it 'ignores message' do
      expect(subject).to be nil
    end
  end

  context 'receiving pipeline output' do
    let(:message_type) { WinRM::PSRP::Message::MESSAGE_TYPES[:pipeline_output] }
    let(:data) { '<obj><S>some data</S></obj>' }

    it 'decodes output' do
      expect(subject).to eq("some data\r\n")
    end
  end

  context 'writeline with new line in middle' do
    let(:message_type) { WinRM::PSRP::Message::MESSAGE_TYPES[:pipeline_host_call] }
    let(:data) do
      "\xEF\xBB\xBF<Obj RefId=\"0\"><MS><I64 N=\"ci\">-100</I64><Obj N=\"mi\" RefId=\"1\">"\
      '<TN RefId="0"><T>System.Management.Automation.Remoting.RemoteHostMethodId</T>'\
      '<T>System.Enum</T><T>System.ValueType</T><T>System.Object</T></TN>'\
      '<ToString>WriteLine3</ToString><I32>17</I32></Obj><Obj N="mp" RefId="2">'\
      '<TN RefId="1"><T>System.Collections.ArrayList</T><T>System.Object</T></TN><LST>'\
      '<I32>7</I32><I32>0</I32><S>some_x000D__x000A_data</S></LST></Obj></MS></Obj>'
    end

    it 'decodes and replaces newline' do
      expect(subject).to eq("some\r\ndata\r\n")
    end
  end

  context 'host call text uses the shared CLIXML contract' do
    let(:message_type) { WinRM::PSRP::Message::MESSAGE_TYPES[:pipeline_host_call] }

    def host_call(payload)
      "\xEF\xBB\xBF<Obj RefId=\"0\"><MS><I64 N=\"ci\">-100</I64><Obj N=\"mi\" RefId=\"1\">"\
      '<TN RefId="0"><T>System.Management.Automation.Remoting.RemoteHostMethodId</T>'\
      '<T>System.Enum</T><T>System.ValueType</T><T>System.Object</T></TN>'\
      '<ToString>WriteLine3</ToString><I32>17</I32></Obj><Obj N="mp" RefId="2">'\
      '<TN RefId="1"><T>System.Collections.ArrayList</T><T>System.Object</T></TN><LST>'\
      "<I32>7</I32><I32>0</I32><S>#{payload}</S></LST></Obj></MS></Obj>"
    end

    it 'reassembles a surrogate pair to one supplementary code point' do
      message.data.replace(host_call('_xD83D__xDE00_'))
      expect(subject.codepoints.map { |cp| format('U+%04X', cp) })
        .to eq(%w[U+1F600 U+000D U+000A])
    end

    it 'restores a literal _x0041_ from escaped underscores in one pass' do
      message.data.replace(host_call('_x005F_x0041_x005F_'))
      expect(subject).to eq("_x0041_\r\n")
    end

    it 'replaces an unpaired surrogate instead of raising' do
      message.data.replace(host_call('_xDE00_'))
      expect(subject.valid_encoding?).to be(true)
      expect(subject.codepoints.map { |cp| format('U+%04X', cp) })
        .to eq(%w[U+FFFD U+000D U+000A])
    end
  end

  context 'receiving error record' do
    let(:message_type) { WinRM::PSRP::Message::MESSAGE_TYPES[:error_record] }
    let(:test_data_error_xml_template) do
      ERB.new(stubbed_clixml('error_record.xml.erb'))
    end
    let(:error_message) { 'an error' }
    let(:script_root) { 'script_root' }
    let(:category_message) { 'category message' }
    let(:stack_trace) { 'stack trace' }
    let(:error_id) { 'Microsoft.PowerShell.Commands.WriteErrorException' }
    let(:data) { test_data_error_xml_template.result(binding) }

    it 'decodes error record' do
      expect(subject).to match(/#{error_message}/)
    end

    it 'decodes CLIXML escapes in the error detail with the shared contract' do
      rendered = render_error_stub(
        error_message: '_xD83D__xDE00__x005F_x0041_x005F__xDE00_',
        script_root: script_root,
        category_message: category_message,
        stack_trace: stack_trace,
        error_id: error_id
      )
      message.data.replace(rendered)
      expect(subject.valid_encoding?).to be(true)
      expect(subject).to include("\u{1F600}")
      expect(subject).to include('_x0041_')
      expect(subject).to include("�")
    end
  end

  context 'receiving error record in pipeline state' do
    let(:message_type) { WinRM::PSRP::Message::MESSAGE_TYPES[:pipeline_state] }
    let(:test_data_error_xml_template) do
      ERB.new(stubbed_clixml('pipeline_state.xml.erb'))
    end
    let(:pipeline_state) { WinRM::PSRP::MessageData::PipelineState::FAILED }
    let(:error_message) { 'an error' }
    let(:category_message) { 'category message' }
    let(:error_id) { 'an error' }
    let(:data) { test_data_error_xml_template.result(binding) }

    it 'decodes error record' do
      expect(subject).to match(/#{error_message}/)
    end
  end
end
