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

  def response_doc(streams: [], state: nil, exit_code: nil)
    stream_xml = streams.map do |type, text|
      "<rsp:Stream CommandId='#{command_id}' Name='#{type}'>" \
        "#{Base64.strict_encode64(text)}</rsp:Stream>"
    end.join
    state_xml =
      if state
        "<rsp:CommandState CommandId='#{command_id}' State='#{state}'>" \
          "#{exit_code.nil? ? '' : "<rsp:ExitCode>#{exit_code}</rsp:ExitCode>"}" \
          '</rsp:CommandState>'
      else
        ''
      end
    REXML::Document.new(
      "<s:Envelope xmlns:s='http://www.w3.org/2003/05/soap-envelope' " \
      "xmlns:rsp='http://schemas.microsoft.com/wbem/wsman/1/windows/shell'>" \
      "<s:Body><rsp:ReceiveResponse>#{stream_xml}#{state_xml}" \
      '</rsp:ReceiveResponse></s:Body></s:Envelope>'
    )
  end

  let(:done) { described_class::COMMAND_STATE_DONE }
  let(:running) { described_class::COMMAND_STATE_RUNNING }

  describe '#read_output terminal state handling' do
    it 'accepts a Done response that carries no stream but does carry an exit code' do
      allow(transport).to receive(:send_request).and_return(response_doc(state: done, exit_code: 7))

      output = subject.read_output(output_message)

      expect(output.stdout).to be_empty
      expect(output.exitcode).to eq(7)
    end

    it 'reads a non-zero exit code reported together with the terminal state' do
      allow(transport).to receive(:send_request).and_return(
        response_doc(streams: [[:stdout, 'partial']], state: running),
        response_doc(streams: [[:stderr, 'final']], state: done, exit_code: 9)
      )

      output = subject.read_output(output_message)

      expect(output.stdout).to eq('partial')
      expect(output.stderr).to eq('final')
      expect(output.exitcode).to eq(9)
    end

    it 'delivers the final stream batch to the callback before finishing' do
      allow(transport).to receive(:send_request).and_return(
        response_doc(streams: [[:stdout, 'first']], state: running),
        response_doc(streams: [[:stdout, 'last']], state: done, exit_code: 3)
      )
      chunks = []

      output = subject.read_output(output_message) { |chunk| chunks << chunk }

      expect(chunks).to eq([['first', nil], ['last', nil]])
      expect(output.stdout).to eq('firstlast')
      expect(output.exitcode).to eq(3)
    end

    it 'raises instead of reporting success when a response has neither state nor output' do
      allow(transport).to receive(:send_request).and_return(response_doc)

      expect { subject.read_output(output_message) }
        .to raise_error(WinRM::CommandResultUnknown) { |error|
          expect(error.reason).to eq(:missing_command_state)
          expect(error.output).to be_a(WinRM::Output)
        }
    end

    it 'raises instead of reporting success when the endpoint reports an unknown state' do
      allow(transport).to receive(:send_request).and_return(
        response_doc(
          state: 'http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandState/Broken'
        )
      )

      expect { subject.read_output(output_message) }
        .to raise_error(WinRM::CommandResultUnknown) { |error|
          expect(error.reason).to eq(:unknown_command_state)
        }
    end

    it 'keeps the output collected before an unexpected EOF and marks the result unknown' do
      allow(transport).to receive(:send_request).and_return(
        response_doc(streams: [[:stdout, 'kept']], state: running),
        nil
      )

      expect { subject.read_output(output_message) }
        .to raise_error(WinRM::CommandResultUnknown) { |error|
          expect(error.reason).to eq(:connection_lost)
          expect(error.output.stdout).to eq('kept')
        }
    end

    it 'keeps the output collected before the transport connection drops' do
      responses = [response_doc(streams: [[:stdout, 'kept']], state: running)]
      allow(transport).to receive(:send_request) do
        raise EOFError if responses.empty?

        responses.shift
      end

      expect { subject.read_output(output_message) }
        .to raise_error(WinRM::CommandResultUnknown) { |error|
          expect(error.reason).to eq(:connection_lost)
          expect(error.output.stdout).to eq('kept')
        }
    end

    it 'propagates a callback error unchanged and does not re-send the command' do
      allow(transport).to receive(:send_request).and_return(
        response_doc(streams: [[:stdout, 'first']], state: running)
      )
      error = Class.new(StandardError)
      calls = 0

      expect do
        subject.read_output(output_message) do
          calls += 1
          raise error, 'consumer failed'
        end
      end.to raise_error(error, 'consumer failed')

      expect(calls).to eq(1)
      expect(transport).to have_received(:send_request).once
    end

    it 'keeps the collected output when a non-retryable fault ends the receive loop' do
      fault = WinRM::WinRMWSManFault.new('shell is gone', '2150858843')
      responses = [response_doc(streams: [[:stdout, 'kept']], state: running)]

      allow(transport).to receive(:send_request) do
        raise fault if responses.empty?

        responses.shift
      end

      expect { subject.read_output(output_message) }
        .to raise_error(WinRM::WinRMWSManFault) { |error|
          expect(error).to be(fault)
          expect(error.output.stdout).to eq('kept')
        }
    end

    it 'keeps polling on the OperationTimeout fault instead of finishing early' do
      timeout_fault = WinRM::WinRMWSManFault.new('timeout', '2150858793')
      attempts = 0
      allow(transport).to receive(:send_request) do
        attempts += 1
        raise timeout_fault if attempts == 1

        response_doc(streams: [[:stdout, 'late']], state: done, exit_code: 6)
      end

      output = subject.read_output(output_message)

      expect(attempts).to eq(2)
      expect(output.stdout).to eq('late')
      expect(output.exitcode).to eq(6)
    end
  end

  describe 'scripted partial output, empty Done, non-zero exit and unexpected EOF' do
    it 'reports the non-zero exit code and the callback count of the completed command' do
      allow(transport).to receive(:send_request).and_return(
        response_doc(streams: [[:stdout, 'a']], state: running),
        response_doc(streams: [[:stderr, 'b']], state: running),
        response_doc(state: done, exit_code: 42)
      )
      chunks = []

      output = subject.read_output(output_message) { |chunk| chunks << chunk }

      expect(chunks.length).to eq(2)
      expect(output.stdout).to eq('a')
      expect(output.stderr).to eq('b')
      expect(output.exitcode).to eq(42)
      expect(output.exitcode).not_to eq(0)
    end

    it 'stops issuing receive requests as soon as the terminal state arrives' do
      responses = [
        response_doc(streams: [[:stdout, 'a']], state: running),
        response_doc(state: done, exit_code: 42),
        nil
      ]
      allow(transport).to receive(:send_request) { responses.shift }
      chunks = []

      output = subject.read_output(output_message) { |chunk| chunks << chunk }

      expect(output.exitcode).to eq(42)
      expect(chunks).to eq([['a', nil]])
      expect(responses).to eq([nil])
    end

    it 'does not turn an interrupted command into exit code 0' do
      allow(transport).to receive(:send_request).and_return(
        response_doc(streams: [[:stdout, 'a']], state: running),
        response_doc(state: nil),
        nil
      )
      chunks = []

      expect do
        subject.read_output(output_message) { |chunk| chunks << chunk }
      end.to raise_error(WinRM::CommandResultUnknown) { |error|
        expect(error.reason).to eq(:missing_command_state)
        expect(error.output.exitcode).to be_nil
        expect(error.output.stdout).to eq('a')
      }
      expect(chunks).to eq([['a', nil]])
    end
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
end
