require 'winrm'
require 'winrm/shells/power_shell'
require 'winrm/psrp/message_defragmenter'

describe WinRM::Shells::Powershell, 'sent envelope sizes' do
  let(:shell_id) { 'bc1bfbba-8215-4a04-b2df-7a3ac0310e16' }
  let(:command_id) { '4218A578-0F18-4B19-82C3-46B433319126' }
  let(:max_envelope_size_kb) { 10 }
  let(:connection_options) do
    default_connection_opts.merge(max_commands: 100, retry_limit: 1, retry_delay: 0)
  end
  let(:transport) { double('transport') }
  let(:sent_command_envelopes) { [] }

  subject { described_class.new(connection_options, transport, Logger.new(IO::NULL)) }

  def keepalive_response
    capability = WinRM::PSRP::MessageFactory.session_capability_message(shell_id)
    state = WinRM::PSRP::Message.new(
      shell_id,
      WinRM::PSRP::Message::MESSAGE_TYPES[:runspacepool_state],
      '<Obj RefId="0"><MS><I32 N="RunspaceState">2</I32></MS></Obj>'
    )
    streams = [capability, state].map do |message|
      encoded = Base64.strict_encode64(WinRM::PSRP::Fragment.new(1, message.bytes).bytes.pack('C*'))
      "<rsp:Stream Name='stdout'>#{encoded}</rsp:Stream>"
    end
    "<s:Envelope xmlns:s='http://www.w3.org/2003/05/soap-envelope'" \
      " xmlns:rsp='http://schemas.microsoft.com/wbem/wsman/1/windows/shell'>" \
      "<s:Body><rsp:ReceiveResponse>#{streams.join}</rsp:ReceiveResponse></s:Body></s:Envelope>"
  end

  def done_response
    "<s:Envelope xmlns:s='http://www.w3.org/2003/05/soap-envelope'" \
      " xmlns:rsp='http://schemas.microsoft.com/wbem/wsman/1/windows/shell'>" \
      "<s:Body><rsp:ReceiveResponse><rsp:CommandState" \
      " State='http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandState/Done'/>" \
      '</rsp:ReceiveResponse></s:Body></s:Envelope>'
  end

  before do
    allow(SecureRandom).to receive(:uuid).and_return(command_id)
    allow(transport).to receive(:send_request) do |payload|
      case payload
      when /<rsp:CommandLine|<rsp:Send[ >]/
        sent_command_envelopes << payload
        REXML::Document.new("<a xmlns:rsp='foo'><rsp:CommandId>#{command_id}</rsp:CommandId></a>")
      when /creationXml/
        REXML::Document.new("<blob Name='ShellId'>#{shell_id}</blob>")
      when %r{<w:ResourceURI[^>]*>http://schemas\.microsoft\.com/wbem/wsman/1/config</w:ResourceURI>}
        REXML::Document.new(
          "<a xmlns:cfg='f'><cfg:MaxEnvelopeSizekb>#{max_envelope_size_kb}</cfg:MaxEnvelopeSizekb></a>"
        )
      when /<rsp:DesiredStream[^>]*CommandId/
        REXML::Document.new(done_response)
      when /WSMAN_CMDSHELL_OPTION_KEEPALIVE/
        REXML::Document.new(keepalive_response)
      when %r{<rsp:Signal[ >]|<a:Action[^>]*>(?:[^<]*/)?transfer/Delete<}
        REXML::Document.new("<a/>")
      else
        raise "unexpected request: #{payload[0, 300]}"
      end
    end
  end

  after do
    subject.close if subject.shell_id
  end

  def run_command(command)
    sent_command_envelopes.clear
    subject.run(command)
  end

  def encoded_payload(envelope)
    match = %r{<rsp:(?:Arguments|Stream)[^>]*>(.*?)</rsp:(?:Arguments|Stream)>}m.match(envelope)
    Base64.strict_decode64(match[1])
  end

  def reassembled_message(envelopes)
    defragmenter = WinRM::PSRP::MessageDefragmenter.new
    fragments = envelopes.map { |envelope| encoded_payload(envelope) }
    message = nil
    fragments.each { |fragment| message = defragmenter.defragment(Base64.strict_encode64(fragment)) }
    [message, fragments]
  end

  def expected_message(command)
    full_command = command + "\r\nif (!$?) { if($LASTEXITCODE) { exit $LASTEXITCODE } else { exit 1 } }"
    WinRM::PSRP::MessageFactory.create_pipeline_message(command_id, command_id, full_command)
  end

  # The pipeline template is roughly 5.7 KB and the envelope budget is 10 KB,
  # so these lengths straddle the one/two fragment boundary.
  [520, 540, 560, 580, 586, 590, 600, 700, 900].each do |length|
    context "with a #{length}-byte command" do
      let(:command) { 'c' * length }

      it 'sends every command envelope within MaxEnvelopeSize' do
        run_command(command)
        expect(sent_command_envelopes).not_to be_empty
        sent_command_envelopes.each do |envelope|
          expect(envelope.bytesize).to be <= max_envelope_size_kb * 1024
        end
      end

      it 'reassembles the encoded fragments into the original message' do
        run_command(command)
        message, fragments = reassembled_message(sent_command_envelopes)
        original = expected_message(command)

        expect(fragments).to all(satisfy { |fragment| fragment.bytesize > WinRM::PSRP::Fragment::HEADER_SIZE })
        expect(message).not_to be_nil
        expect(message.type).to eq original.type
        expect(message.data.bytes).to eq("\xEF\xBB\xBF".b.bytes + original.data.bytes)
      end

      it 'uses full Base64 groups and never emits an empty fragment' do
        run_command(command)
        fragments = sent_command_envelopes.map { |envelope| encoded_payload(envelope) }
        fragments[0..-2].each do |fragment|
          expect(fragment.bytesize).to eq WinRM::PSRP::Fragment::HEADER_SIZE + subject.max_fragment_blob_size
        end
        expect(fragments.last.bytesize).to be > WinRM::PSRP::Fragment::HEADER_SIZE
      end
    end
  end

  context 'when the command contains non ASCII and XML special characters' do
    let(:command) { "<&> ✓äöü 'quoted' " * 30 }

    it 'still fits the envelope and round trips the original bytes' do
      run_command(command)
      sent_command_envelopes.each do |envelope|
        expect(envelope.bytesize).to be <= max_envelope_size_kb * 1024
      end

      message, = reassembled_message(sent_command_envelopes)
      expect(message.data.bytes).to eq("\xEF\xBB\xBF".b.bytes + expected_message(command).data.bytes)
    end
  end

  context 'when the envelope cannot hold even one fragment' do
    let(:max_envelope_size_kb) { 1 }

    it 'raises instead of looping or sending an oversized envelope' do
      expect { run_command('echo hi') }.to raise_error(WinRM::FragmentSizeError)
      expect(sent_command_envelopes).to be_empty
    end
  end

  context 'when the budget fits commands but not the runspace pool creation' do
    let(:max_envelope_size_kb) { 3 }

    it 'fails clearly before sending an oversized creation envelope' do
      expect { subject.run('echo hi') }.to raise_error(WinRM::FragmentSizeError) do |error|
        expect(error.actual_size).to be > 3 * 1024
        expect(error.envelope_size).to eq 3 * 1024
      end
      expect(sent_command_envelopes).to be_empty
    end
  end
end

describe WinRM::Shells::Powershell, 'blob size derivation' do
  let(:shell_id) { 'bc1bfbba-8215-4a04-b2df-7a3ac0310e16' }
  let(:connection_options) { default_connection_opts }

  subject do
    described_class.new(connection_options, double('transport'), Logger.new(IO::NULL)).tap do |shell|
      shell.instance_variable_set(:@shell_id, shell_id)
      shell.instance_variable_set(:@max_envelope_size_kb, 10)
    end
  end

  it 'derives a blob that exactly fills the envelope' do
    blob = subject.max_fragment_blob_size
    upper = WinRM::WSMV::CreatePipeline.new(
      connection_options, shell_id, shell_id,
      WinRM::PSRP::Fragment.new(1, Array.new(blob, 0x63))
    ).build
    lower = WinRM::WSMV::CreatePipeline.new(
      connection_options, shell_id, shell_id,
      WinRM::PSRP::Fragment.new(1, Array.new(blob + 1, 0x63))
    ).build

    expect(upper.bytesize).to be <= 10 * 1024
    expect(lower.bytesize).to be > 10 * 1024
  end

  it 'raises when the envelope alone does not fit' do
    subject.instance_variable_set(:@max_envelope_size_kb, 1)
    expect { subject.max_fragment_blob_size }.to raise_error(WinRM::FragmentSizeError)
  end

  it 'rejects a zero blob budget in the fragmenter' do
    expect { WinRM::PSRP::MessageFragmenter.new(0) }.to raise_error(WinRM::FragmentSizeError)
    fragmenter = WinRM::PSRP::MessageFragmenter.new(10)
    expect { fragmenter.max_blob_length = 0 }.to raise_error(WinRM::FragmentSizeError)
    expect(fragmenter.max_blob_length).to eq 10
  end

  it 'still emits one fragment for an empty message' do
    message = WinRM::PSRP::Message.new(shell_id, WinRM::PSRP::Message::MESSAGE_TYPES[:session_capability], '')
    allow(message).to receive(:bytes).and_return([])
    fragments = []
    WinRM::PSRP::MessageFragmenter.new(10).fragment(message) { |fragment| fragments << fragment }

    expect(fragments.length).to eq 1
    expect(fragments.first.start_fragment).to be true
    expect(fragments.first.end_fragment).to be true
  end
end

describe WinRM::Shells::Powershell, 'fallback budget refresh' do
  let(:shell_id) { 'bc1bfbba-8215-4a04-b2df-7a3ac0310e16' }
  let(:command_id) { '4218A578-0F18-4B19-82C3-46B433319126' }
  let(:protocol_version) { 2.1 }
  let(:transport) { double('transport') }
  let(:sent_command_envelopes) { [] }
  let(:connection_options) do
    default_connection_opts.merge(max_commands: 100, retry_limit: 1, retry_delay: 0)
  end

  subject { described_class.new(connection_options, transport, Logger.new(IO::NULL)) }

  def done_response
    "<s:Envelope xmlns:s='http://www.w3.org/2003/05/soap-envelope'" \
      " xmlns:rsp='http://schemas.microsoft.com/wbem/wsman/1/windows/shell'>" \
      "<s:Body><rsp:ReceiveResponse><rsp:CommandState" \
      " State='http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandState/Done'/>" \
      '</rsp:ReceiveResponse></s:Body></s:Envelope>'
  end

  # The session capability payload advertises protocol 2.3 by default;
  # rewrite it to the version under test.
  def capability_stream
    capability = WinRM::PSRP::MessageFactory.session_capability_message(shell_id)
    data = capability.data.gsub('2.3', protocol_version.to_s)
    message = WinRM::PSRP::Message.new(
      shell_id, WinRM::PSRP::Message::MESSAGE_TYPES[:session_capability], data
    )
    Base64.strict_encode64(WinRM::PSRP::Fragment.new(1, message.bytes).bytes.pack('C*'))
  end

  def state_stream
    state = WinRM::PSRP::Message.new(
      shell_id,
      WinRM::PSRP::Message::MESSAGE_TYPES[:runspacepool_state],
      '<Obj RefId="0"><MS><I32 N="RunspaceState">2</I32></MS></Obj>'
    )
    Base64.strict_encode64(WinRM::PSRP::Fragment.new(1, state.bytes).bytes.pack('C*'))
  end

  before do
    allow(SecureRandom).to receive(:uuid).and_return(command_id)
    allow(transport).to receive(:send_request) do |payload|
      case payload
      when /<rsp:CommandLine|<rsp:Send[ >]/
        sent_command_envelopes << payload
        REXML::Document.new("<a xmlns:rsp='foo'><rsp:CommandId>#{command_id}</rsp:CommandId></a>")
      when /creationXml/
        REXML::Document.new("<blob Name='ShellId'>#{shell_id}</blob>")
      when %r{<w:ResourceURI[^>]*>http://schemas\.microsoft\.com/wbem/wsman/1/config</w:ResourceURI>}
        raise WinRM::WinRMWSManFault.new('no access for you', '5')
      when /<rsp:DesiredStream[^>]*CommandId/
        REXML::Document.new(done_response)
      when /WSMAN_CMDSHELL_OPTION_KEEPALIVE/
        REXML::Document.new(
          "<s:Envelope xmlns:s='http://www.w3.org/2003/05/soap-envelope'" \
          " xmlns:rsp='http://schemas.microsoft.com/wbem/wsman/1/windows/shell'>" \
          "<s:Body><rsp:ReceiveResponse>" \
          "<rsp:Stream Name='stdout'>#{capability_stream}</rsp:Stream>" \
          "<rsp:Stream Name='stdout'>#{state_stream}</rsp:Stream>" \
          '</rsp:ReceiveResponse></s:Body></s:Envelope>'
        )
      when %r{<rsp:Signal[ >]|<a:Action[^>]*>(?:[^<]*/)?transfer/Delete<}
        REXML::Document.new('<a/>')
      else
        raise "unexpected request: #{payload[0, 300]}"
      end
    end
  end

  after do
    subject.close if subject.shell_id
  end

  context 'with protocol 2.1' do
    it 'uses the 150 KB default and discards the conservative budget' do
      subject.run('c' * 200_000)
      expect(subject.max_fragment_blob_size).to eq(
        (153600 - subject.send(:pipeline_envelope_overhead).bytesize) / 4 * 3 -
        WinRM::PSRP::Fragment::HEADER_SIZE
      )
      expect(sent_command_envelopes.map(&:bytesize).max).to be <= 153600
      expect(sent_command_envelopes.map(&:bytesize).max).to be > 153600 - 4
    end
  end

  context 'with protocol 2.2' do
    let(:protocol_version) { 2.2 }

    it 'recomputes the budget for 512 KB instead of reusing the old cache' do
      subject.run('c' * 600_000)
      expect(subject.max_fragment_blob_size).to eq(
        (512000 - subject.send(:pipeline_envelope_overhead).bytesize) / 4 * 3 -
        WinRM::PSRP::Fragment::HEADER_SIZE
      )
      expect(sent_command_envelopes.map(&:bytesize).max).to be <= 512000
      expect(sent_command_envelopes.map(&:bytesize).max).to be > 512000 - 4
    end
  end

  it 'does not overwrite an endpoint-reported envelope size' do
    allow(transport).to receive(:send_request)
      .with(%r{<w:ResourceURI[^>]*>http://schemas\.microsoft\.com/wbem/wsman/1/config</w:ResourceURI>})
      .and_return(
        REXML::Document.new('<a xmlns:cfg="f"><cfg:MaxEnvelopeSizekb>10</cfg:MaxEnvelopeSizekb></a>')
      )

    subject.run('c' * 2000)
    expect(subject.max_fragment_blob_size).to eq(
      (10240 - subject.send(:pipeline_envelope_overhead).bytesize) / 4 * 3 -
      WinRM::PSRP::Fragment::HEADER_SIZE
    )
  end
end
