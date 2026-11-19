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

  let(:output_message) { double('output_message', build: 'output_message') }
  let(:transport) { double('transport') }
  let(:logger) { Logger.new(IO::NULL) }

  subject { described_class.new(transport, logger) }

  # Builds a ReceiveResponse document. When `chunks` is a hash, each stream's
  # values are emitted grouped. When it is an array, entries must be
  # [name, chunk] pairs and are emitted in that exact order, which allows
  # stdout and stderr chunks to interleave.
  def response_xml(chunks, done: true, exitcode: 0)
    chunks = chunks.flat_map { |name, values| values.map { |value| [name, value] } } if chunks.is_a?(Hash)
    body = chunks.map do |name, value|
      "<rsp:Stream CommandId='#{command_id}' Name='#{name}'>#{value}</rsp:Stream>"
    end.join("\n")
    state_uri = 'http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandState'
    state = if done
              "<rsp:CommandState CommandId='#{command_id}' State='#{state_uri}/Done'>" \
                "<rsp:ExitCode>#{exitcode}</rsp:ExitCode></rsp:CommandState>"
            else
              "<rsp:CommandState CommandId='#{command_id}' State='#{state_uri}/Running'/>"
            end
    <<~XML
      <s:Envelope xmlns:s='http://www.w3.org/2003/05/soap-envelope'
                  xmlns:rsp='http://schemas.microsoft.com/wbem/wsman/1/windows/shell'>
        <s:Body>
          <rsp:ReceiveResponse>
            #{body}
            #{state}
          </rsp:ReceiveResponse>
        </s:Body>
      </s:Envelope>
    XML
  end

  def doc(chunks, **opts)
    REXML::Document.new(response_xml(chunks, **opts))
  end

  def b64(text)
    Base64.strict_encode64(text.b)
  end

  context 'when stream chunks split UTF-8 characters' do
    it 'returns complete text and matching callback increments' do
      stdout = "✓1234-äöü\r\n"
      stderr = "警告: €\r\n"
      # One decoded byte per chunk; stdout and stderr chunks alternate inside
      # the same response, and the second response continues both streams.
      stdout_chunks = stdout.b.bytes.map { |byte| b64(byte.chr) }
      stderr_chunks = stderr.b.bytes.map { |byte| b64(byte.chr) }
      interleaved = stdout_chunks.zip(stderr_chunks).flat_map do |out, err|
        [['stdout', out], ['stderr', err]]
      end.compact
      first = doc(interleaved[0, 8], done: false)
      second = doc(interleaved[8..-1], done: true)
      allow(transport).to receive(:send_request).and_return(first, second)

      increments = []
      output = subject.read_output(output_message) do |out, err|
        increments << [out, err]
      end

      expect(output.stdout).to eq(stdout)
      expect(output.stderr).to eq(stderr)
      expect(increments.map(&:first).compact.join).to eq(stdout)
      expect(increments.map(&:last).compact.join).to eq(stderr)
      increments.each do |out, err|
        [out, err].compact.each do |increment|
          expect(increment).to be_valid_encoding
          expect(increment).not_to include("�")
        end
      end
    end
  end

  context 'when a command ends with an incomplete character' do
    it 'scrubs only that stream and does not affect a following command' do
      allow(transport).to receive(:send_request).and_return(
        doc({ 'stdout' => [b64("\xE2\x9C".b)] }),
        doc({ 'stdout' => [b64("\x93")] })
      )

      first = subject.read_output(output_message)
      second = subject.read_output(output_message)

      expect(first.stdout).to eq("�")
      expect(second.stdout).to eq("�")
    end
  end

  context 'when each stream starts with a BOM' do
    it 'strips a BOM at the start of stdout and stderr independently' do
      bom = "\xEF\xBB\xBF".b
      allow(transport).to receive(:send_request).and_return(
        doc({ 'stdout' => [b64(bom + 'out')], 'stderr' => [b64(bom + 'err')] })
      )

      output = subject.read_output(output_message)

      expect(output.stdout).to eq('out')
      expect(output.stderr).to eq('err')
    end

    it 'keeps a BOM that is not at the start of a stream' do
      bom = "\xEF\xBB\xBF".b
      allow(transport).to receive(:send_request).and_return(
        doc({ 'stdout' => [b64('a'), b64(bom + 'b')] })
      )

      expect(subject.read_output(output_message).stdout).to eq("a﻿b")
    end
  end

  context 'when Base64 is invalid' do
    it 'raises an explicit error' do
      allow(transport).to receive(:send_request).and_return(doc({ 'stdout' => ['!!!!'] }))

      expect { subject.read_output(output_message) }.to raise_error(ArgumentError, /invalid Base64/)
    end
  end

  context 'when a fault occurs mid-command' do
    it 'raises the fault and leaves no state for the next command' do
      pending_chunk = doc({ 'stdout' => [b64("\xE2\x9C".b)] }, done: false)
      fault = WinRM::WinRMWSManFault.new('boom', '12345')
      allow(transport).to receive(:send_request).and_return(pending_chunk).and_raise(fault)

      expect { subject.read_output(output_message) }.to raise_error(WinRM::WinRMWSManFault)

      allow(transport).to receive(:send_request).and_return(doc({ 'stdout' => [b64("\x93")] }))
      expect(subject.read_output(output_message).stdout).to eq("�")
    end
  end
end
