require 'winrm/wsmv/receive_response_reader'

describe WinRM::WSMV::ReceiveResponseReader do
  let(:shell_id) { 'F4A2622B-B842-4EB8-8A78-0225C8A993DF' }
  let(:command_id) { 'A2A2622B-B842-4EB8-8A78-0225C8A993DF' }
  let(:output_message) { double('output_message', build: 'output_message') }
  let(:transport) do
    {}
  end

  subject do
    described_class.new(
      transport,
      Logger.new(IO::NULL)
    )
  end

  # Output from PowerShell endpoint and output from OMI Server endpoint
  {
    'get_command_output_response.xml.erb' => 'get_command_output_response_not_done.xml.erb',
    'get_omi_command_output_response.xml.erb' => 'get_omi_command_output_response_not_done.xml.erb'
  }.each_pair do |template, template_not_done|
    describe "#read_output for #{template}" do
      context 'response doc stdout with invalid UTF-8 characters, issue 184' do
        let(:test_data_stdout) { 'ffff' } # Base64-decodes to '}\xF7\xDF', an invalid sequence
        let(:test_data_stderr) { '' }
        let(:test_data_xml)    { ERB.new(stubbed_response(template)).result(binding) }
        let(:test_data)        { REXML::Document.new(test_data_xml) }
        let(:stdout_xpath)     { "//*[local-name() = 'Stream' and @Name = 'stdout']" }

        before do
          allow(transport).to receive(:send_request).and_return(test_data)
        end

        # OMI server messages do not appear to include stdout when CommandState/Done
        it 'does not raise an ArgumentError: invalid byte sequence in UTF-8' do
          begin
            expect do
              subject.read_output(output_message)
            end.not_to raise_error
          rescue RSpec::Expectations::ExpectationNotMetError => e
            expect(e.message).not_to include 'ArgumentError'
          end
        end

        it 'does not have an empty stdout' do
          skip('response has no stdout') if REXML::XPath.match(test_data, stdout_xpath).empty?
          expect(
            subject.read_output(output_message).stdout
          ).not_to be_empty
        end
      end

      context 'response doc stdout with valid UTF-8' do
        let(:test_data_raw)    { '✓1234-äöü' }
        let(:test_data_stdout) { Base64.encode64(test_data_raw) }
        let(:test_data_stderr) { '' }
        let(:test_data_xml)    { ERB.new(stubbed_response(template)).result(binding) }
        let(:test_data)        { REXML::Document.new(test_data_xml) }
        let(:stdout_xpath)     { "//*[local-name() = 'Stream' and @Name = 'stdout']" }

        before do
          allow(transport).to receive(:send_request).and_return(test_data)
        end

        it 'decodes to match input data' do
          skip('response has no stdout') if REXML::XPath.match(test_data, stdout_xpath).empty?
          expect(
            subject.read_output(output_message).stdout
          ).to eq(test_data_raw)
        end
      end
    end

    describe "#read_response for #{template}" do
      context 'do not wait for done state' do
        let(:test_data_raw) { 'output text' }
        let(:test_error_raw) { 'error text' }
        let(:test_data_stdout) { Base64.encode64(test_data_raw) }
        let(:test_data_stderr) { Base64.encode64(test_error_raw) }
        let(:test_data_xml)    { ERB.new(stubbed_response(template)).result(binding) }

        before do
          allow(transport).to receive(:send_request).and_return(
            REXML::Document.new(test_data_xml)
          ).once
        end

        it 'yields stream and document' do
          subject.read_response(output_message) do |stream, doc|
            expect(stream[:text]).to eq(test_data_stdout) if stream[:type] == :stdout
            expect(stream[:text]).to eq(test_data_stderr) if stream[:type] == :stderr
            expect(doc.to_s).to eq(REXML::Document.new(test_data_xml).to_s)
          end
        end
      end

      context 'wait for done state' do
        let(:test_data_raw) { 'output text' }
        let(:test_error_raw) { 'error text' }
        let(:test_data_stdout) { Base64.encode64(test_data_raw) }
        let(:test_data_stderr) { Base64.encode64(test_error_raw) }
        let(:test_data_xml_notdone) { ERB.new(stubbed_response(template_not_done)).result(binding) }
        let(:test_data_xml_done) { ERB.new(stubbed_response(template)).result(binding) }

        it 'yields streams and both documents' do
          allow(transport).to receive(:send_request).and_return(
            REXML::Document.new(test_data_xml_notdone),
            REXML::Document.new(test_data_xml_done)
          )
          times = 1

          subject.read_response(output_message, true) do |stream, doc|
            expect(stream[:text]).to eq(test_data_stdout) if stream[:type] == :stdout
            expect(stream[:text]).to eq(test_data_stderr) if stream[:type] == :stderr
            expect(doc.to_s).to eq(REXML::Document.new(test_data_xml_notdone).to_s) if times == 1
            expect(doc.to_s).to eq(REXML::Document.new(test_data_xml_done).to_s) if times > 2
            times += 1
          end
        end
      end
    end
  end

  describe 'spoofed receive response nodes' do
    let(:real_stdout) { Base64.encode64('real output') }
    let(:shadow_stdout) { Base64.encode64('shadow output') }

    let(:adversarial_response) do
      <<~XML
        <s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
                    xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell"
                    xmlns:evil="http://evil.example/not-winrm">
          <s:Body>
            <rsp:ReceiveResponse>
              <evil:Stream Name="stdout">#{shadow_stdout}</evil:Stream>
              <rsp:Stream Name="stdout">#{real_stdout}</rsp:Stream>
              <evil:CommandState
                State="http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandState/Done">
                <evil:ExitCode>123</evil:ExitCode>
              </evil:CommandState>
              <rsp:CommandState
                State="http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandState/Done">
                <rsp:ExitCode>7</rsp:ExitCode>
              </rsp:CommandState>
            </rsp:ReceiveResponse>
          </s:Body>
        </s:Envelope>
      XML
    end

    before do
      allow(transport).to receive(:send_request)
        .and_return(REXML::Document.new(adversarial_response))
    end

    it 'reads only shell-namespace streams and ignores the shadow stream' do
      seen = []
      subject.read_response(output_message, true) { |stream, _doc| seen << stream[:text] }
      expect(seen).to eq([real_stdout])
    end

    it 'uses the genuine ExitCode and ignores the shadow value' do
      output = subject.read_output(output_message)
      expect(output.exitcode).to eq(7)
    end
  end
end
