require 'base64'
require 'logger'
require 'rexml/document'
require 'winrm/shells/power_shell'

# Helpers that unwrap the PowerShell send chain captured at the transport
# boundary: SOAP envelope -> Base64 -> PSRP fragment -> PSRP message ->
# CLIXML payload. They only decode what the gem actually emitted; the
# script is never executed and never reduced to a plain command argument.
module SendChainRecovery
  # Extracts the PSRP fragments from the captured SOAP envelopes,
  # decoding Base64 and parsing the 21 byte fragment header.
  def captured_fragments
    sent_payloads.filter_map do |payload|
      encoded = fragment_base64(REXML::Document.new(payload))
      decode_fragment(Base64.strict_decode64(encoded).bytes) if encoded
    end
  end

  def fragment_base64(envelope)
    node = REXML::XPath.first(envelope, "//*[local-name()='CommandLine']/*[local-name()='Arguments']")
    node ||= REXML::XPath.first(envelope, "//*[local-name()='Send']/*[local-name()='Stream']")
    node&.text
  end

  def decode_fragment(bytes)
    {
      message_id: bytes[0..7].pack('C*').unpack1('Q>'),
      fragment_id: bytes[8..15].pack('C*').unpack1('Q>'),
      start_fragment: (bytes[16] & 0b01) != 0,
      end_fragment: (bytes[16] & 0b10) != 0,
      declared_length: bytes[17..20].pack('C*').unpack1('L>'),
      blob: bytes[21..]
    }
  end

  def reassembled_bytes
    captured_fragments.sort_by { |fragment| fragment[:fragment_id] }.flat_map { |fragment| fragment[:blob] }
  end

  def reassembled_message
    parse_message(reassembled_bytes)
  end

  def parse_message(bytes)
    {
      destination: bytes[0..3].pack('C*').unpack1('V'),
      type: bytes[4..7].pack('C*').unpack1('V'),
      runspace_id: bytes[8..23],
      pipeline_id: bytes[24..39],
      bom: bytes[40..42],
      data: bytes[43..].pack('C*').force_encoding(Encoding::UTF_8)
    }
  end

  def recovered_command
    document = REXML::Document.new(reassembled_message[:data])
    REXML::XPath.first(document, "//S[@N='V']").text
  end

  def windows_guid_bytes(uuid)
    bytes = uuid.scan(/[0-9a-fA-F]{2}/).map { |hex| hex.to_i(16) }
    bytes[0..3].reverse + bytes[4..5].reverse + bytes[6..7].reverse + bytes[8..15]
  end

  def expected_message_bytes(script, suffix)
    WinRM::PSRP::MessageFactory.create_pipeline_message(
      runspace_id, command_id.upcase, script + suffix
    ).bytes
  end

  def transport_response(payload)
    case payload
    when /<rsp:CommandLine/
      REXML::Document.new("<r:CommandResponse xmlns:r='urn:x'><r:CommandId>#{command_id.upcase}</r:CommandId></r:CommandResponse>")
    when %r{wsman/1/config<}
      REXML::Document.new("<cfg:MaxEnvelopeSizekb xmlns:cfg='urn:x'>#{max_envelope_size_kb}</cfg:MaxEnvelopeSizekb>")
    else
      REXML::Document.new('<x/>')
    end
  end

  # The fragment length header counts bytes. A fragmenter that sliced the
  # message by characters would undercount multi byte characters and fail
  # the declared_length check below.
  def expect_valid_fragment_chain(fragments)
    expect(fragments).not_to be_empty
    expect(fragments.map { |fragment| fragment[:message_id] }.uniq.length).to eq(1)
    expect(fragments.map { |fragment| fragment[:fragment_id] }).to eq((0...fragments.length).to_a)
    fragments.each { |fragment| expect(fragment[:declared_length]).to eq(fragment[:blob].length) }
    expect(fragments.first[:start_fragment]).to be(true)
    expect(fragments.last[:end_fragment]).to be(true)
    fragments[1..-2].each do |fragment|
      expect(fragment[:start_fragment]).to be(false)
      expect(fragment[:end_fragment]).to be(false)
    end
  end

  def expect_message_metadata(message)
    expect(message[:destination]).to eq(WinRM::PSRP::Message::SERVER_DESTINATION)
    expect(message[:type]).to eq(WinRM::PSRP::Message::MESSAGE_TYPES[:create_pipeline])
    expect(message[:bom]).to eq([239, 187, 191])
    expect(message[:runspace_id]).to eq(windows_guid_bytes(runspace_id))
    expect(message[:pipeline_id]).to eq(windows_guid_bytes(command_id.upcase))
  end

  # Splits the recovered command into the user supplied script and the
  # transport suffix. XML parsers normalize CRLF to LF, so the suffix is
  # compared in normalized form here; its exact bytes are verified on the
  # wire separately.
  def expect_script_and_metadata(recovered, script, suffix)
    expect(recovered.length).to be > script.length
    expect(recovered[0...script.length]).to eq(script)
    expect(recovered[script.length..]).to eq(suffix.gsub("\r\n", "\n"))
  end
end

describe WinRM::Shells::Powershell do
  include SendChainRecovery

  let(:shell_id) { 'BC1BFBA-8215-4A04-B2DF-7A3AC0310E16' }
  let(:runspace_id) { 'D5A2622B-B842-4EB8-8A78-0225C8A993DF' }
  let(:command_id) { '4218a578-0f18-4b19-82c3-46b433319126' }
  let(:max_envelope_size_kb) { 150 }
  let(:sent_payloads) { [] }
  let(:transport) { double('transport') }
  let(:connection_opts) do
    {
      user: 'Administrator', password: 'password', endpoint: 'http://localhost:5985/wsman',
      max_envelope_size: 153600, session_id: '05A2622B-B842-4EB8-8A78-0225C8A993DF',
      operation_timeout: 60, locale: 'en-US', retry_limit: 1, retry_delay: 0
    }
  end
  # Appended to every command by the shell. It is transport metadata,
  # not part of the user supplied script.
  let(:exit_code_suffix) do
    "\r\nif (!$?) { if($LASTEXITCODE) { exit $LASTEXITCODE } else { exit 1 } }"
  end

  subject(:shell) { described_class.new(connection_opts, transport, Logger.new(IO::NULL)) }

  before do
    allow(SecureRandom).to receive(:uuid).and_return(command_id)
    allow(transport).to receive(:send_request) do |payload|
      sent_payloads << payload
      transport_response(payload)
    end
    shell.instance_variable_set(:@shell_id, shell_id)
    shell.instance_variable_set(:@runspace_id, runspace_id)
  end

  context 'with a fixed short script' do
    let(:script) { "Write-Output 'a&b <c> \"d\" 😀'" }

    before { shell.send(:send_command, script, []) }

    it 'recovers the user script code point by code point' do
      expect(recovered_command[0...script.length].codepoints).to eq(script.codepoints)
    end

    it 'recovers the user script byte for byte' do
      expect(recovered_command[0...script.length].bytes).to eq(script.bytes)
    end

    it 'keeps the exit code suffix separate from the user script' do
      expect_script_and_metadata(recovered_command, script, exit_code_suffix)
    end

    it 'emits a single create_pipeline message carrying transport metadata' do
      expect(captured_fragments.length).to eq(1)
      expect_valid_fragment_chain(captured_fragments)
      expect_message_metadata(reassembled_message)
    end

    it 'matches the independently built message byte for byte' do
      expect(reassembled_bytes).to eq(expected_message_bytes(script, exit_code_suffix))
    end

    it 'does not send the script as a plain command argument' do
      envelope = sent_payloads.find { |payload| payload.include?('<rsp:CommandLine') }
      document = REXML::Document.new(envelope)
      expect(REXML::XPath.first(document, "//*[local-name()='Command']").text).to eq('Invoke-Expression')
      expect(envelope).not_to include(script)
      arguments = REXML::XPath.first(document, "//*[local-name()='Arguments']").text
      expect { Base64.strict_decode64(arguments) }.not_to raise_error
    end

    it 'rejects a variant that escaped the script a second time' do
      expect(recovered_command[0...script.length]).not_to eq(script.encode(xml: :text))
    end
  end

  context 'with XML special characters' do
    let(:script) { %q{& < > ' " ` $} }

    before { shell.send(:send_command, script, []) }

    it 'recovers the script exactly' do
      expect_script_and_metadata(recovered_command, script, exit_code_suffix)
      expect(recovered_command[0...script.length].bytes).to eq(script.bytes)
    end

    it 'escapes &, < and > exactly once on the wire' do
      data = reassembled_message[:data]
      expect(data).to include('&amp;').and include('&lt;').and include('&gt;')
      expect(data).not_to include('&amp;amp;')
      expect(data).not_to include('&amp;lt;')
      expect(data).not_to include('&amp;gt;')
    end

    it 'leaves quotes as literal text' do
      expect(reassembled_message[:data]).not_to include('&quot;')
      expect(reassembled_message[:data]).not_to include('&apos;')
    end

    it 'produces well formed CLIXML' do
      expect { REXML::Document.new(reassembled_message[:data]) }.not_to raise_error
    end
  end

  context 'with literal entity text' do
    let(:script) { %q{&lt; &gt; &#39; &#x1F600;} }

    it 'recovers the entities literally without decoding them' do
      shell.send(:send_command, script, [])
      expect_script_and_metadata(recovered_command, script, exit_code_suffix)
    end

    it 'escapes the leading ampersands exactly once on the wire' do
      shell.send(:send_command, script, [])
      data = reassembled_message[:data]
      expect(data).to include('&amp;lt;').and include('&amp;#x1F600;')
      expect(data).not_to include('&amp;amp;')
    end
  end

  context 'with supplementary plane characters' do
    let(:script) { "Write-Output '😀 𠀀 🧑‍💻'" }

    before { shell.send(:send_command, script, []) }

    it 'recovers every code point and byte' do
      recovered = recovered_command[0...script.length]
      expect(recovered.codepoints).to eq(script.codepoints)
      expect(recovered.bytes).to eq(script.bytes)
    end

    it 'keeps the exact UTF-8 sequences on the wire' do
      expect(reassembled_message[:data]).to include(script)
    end
  end

  context 'with LF newlines' do
    let(:script) { "line1\nline2\nline3\n" }

    it 'recovers the script exactly' do
      shell.send(:send_command, script, [])
      expect_script_and_metadata(recovered_command, script, exit_code_suffix)
    end
  end

  context 'with CRLF newlines' do
    let(:script) { "line1\r\nline2\r\n" }

    before { shell.send(:send_command, script, []) }

    it 'preserves the exact CRLF bytes on the wire' do
      expect(reassembled_message[:data]).to include(script)
      expect(reassembled_bytes).to eq(expected_message_bytes(script, exit_code_suffix))
    end

    it 'recovers XML normalized LF line endings' do
      # XML parsers normalize CRLF to LF; the wire bytes above stay exact.
      expect_script_and_metadata(recovered_command, "line1\nline2\n", exit_code_suffix)
    end
  end

  context 'across fragment boundaries' do
    context 'with a small blob size' do
      let(:script) { '😀' * 100 }

      before do
        allow(shell).to receive(:max_fragment_blob_size).and_return(45)
        shell.send(:send_command, script, [])
      end

      it 'splits the message into multiple valid fragments' do
        expect(captured_fragments.length).to be > 1
        expect_valid_fragment_chain(captured_fragments)
      end

      it 'splits multi byte characters across fragment boundaries' do
        leading_blobs = captured_fragments[0..-2].map { |fragment| fragment[:blob] }
        split = leading_blobs.any? do |blob|
          !blob.pack('C*').force_encoding(Encoding::UTF_8).valid_encoding?
        end
        expect(split).to be(true)
      end

      it 'reassembles to the exact original message bytes' do
        expect(reassembled_bytes).to eq(expected_message_bytes(script, exit_code_suffix))
      end

      it 'recovers the script exactly' do
        expect_script_and_metadata(recovered_command, script, exit_code_suffix)
      end

      it 'sends continuation fragments as stdin stream metadata' do
        sends = sent_payloads.select { |payload| payload.include?('<rsp:Send') }
        expect(sends.length).to eq(captured_fragments.length - 1)
        sends.each do |payload|
          stream = REXML::XPath.first(REXML::Document.new(payload), "//*[local-name()='Stream']")
          expect(stream.attributes['Name']).to eq('stdin')
          expect(stream.attributes['CommandId']).to eq(command_id.upcase)
        end
      end
    end

    context 'with the endpoint max envelope size' do
      let(:max_envelope_size_kb) { 2 }
      let(:script) { '中' * 500 }

      it 'fragments to fit the endpoint and recovers exactly' do
        shell.send(:send_command, script, [])
        expect(captured_fragments.length).to be > 1
        expect_valid_fragment_chain(captured_fragments)
        expect_script_and_metadata(recovered_command, script, exit_code_suffix)
      end
    end
  end
end
