require 'stringio'
require 'winrm'
require 'winrm/shells/cmd'
require 'winrm/shells/power_shell'

describe 'shell diagnostic logging' do
  let(:secret) { 'FAKE-SCRIPT-SECRET-6b2a-do-not-log' }
  let(:password) { 'FAKE-SCRIPT-PASSWORD-c14d-do-not-log' }
  let(:io) { StringIO.new }
  let(:logger) { Logger.new(io) }
  let(:shell_id) { 'SHELL-SEC17-0001' }
  let(:command_id) { 'CMD-SEC17-0001' }
  let(:transport) { double('transport', send_request: nil) }
  let(:connection_options) do
    {
      endpoint: "https://user:#{password}@localhost:5986/wsman",
      max_commands: 100,
      retry_limit: 1,
      retry_delay: 0
    }
  end

  before do
    logger.level = :debug
  end

  describe 'cmd shell' do
    subject { WinRM::Shells::Cmd.new(connection_options, transport, logger) }

    before do
      allow_any_instance_of(WinRM::WSMV::CreateShell).to receive(:build).and_return('create')
      allow_any_instance_of(WinRM::WSMV::Command).to receive(:build).and_return('command')
      allow_any_instance_of(WinRM::WSMV::CleanupCommand).to receive(:build).and_return('cleanup')
      allow_any_instance_of(WinRM::WSMV::CloseShell).to receive(:build).and_return('close')
      allow_any_instance_of(WinRM::WSMV::ReceiveResponseReader).to receive(:read_output).and_return('output')
      allow(transport).to receive(:send_request).with('create')
        .and_return(REXML::Document.new("<blob Name='ShellId'>#{shell_id}</blob>"))
      allow(transport).to receive(:send_request).with('command').and_return(
        REXML::Document.new("<a><CommandId>#{command_id}</CommandId></a>")
      )
    end

    it 'logs the script only as a length and digest' do
      subject.run("echo #{secret}", ["--password=#{password}"])

      logged = io.string
      expect(logged).to include('Command created command_bytes=')
      expect(logged).to include("command_id: #{command_id}")
      expect(logged).to include("shell_id #{shell_id}")
      expect(logged).not_to include(secret)
      expect(logged).not_to include(password)
    end

    it 'keeps the wire payload unchanged after redacted logging' do
      subject.run("echo #{secret}")

      expect(transport).to have_received(:send_request).with('command')
      expect(subject.shell_id).to eq(shell_id)
    end
  end

  describe 'powershell shell' do
    subject { WinRM::Shells::Powershell.new(connection_options, transport, logger) }

    let(:message) do
      WinRM::PSRP::Message.new(
        shell_id,
        WinRM::PSRP::Message::MESSAGE_TYPES[:runspacepool_state],
        "<Obj RefId='0'><MS><I32 N='RunspaceState'>2</I32></MS></Obj>",
        command_id
      )
    end

    it 'summarizes polling messages instead of inspecting raw payloads' do
      logger.debug("[WinRM] polling for pipeline state. #{WinRM::LogRedactor.psrp_message(message)}")

      logged = io.string
      expect(logged).to include('message_type=0x00021005')
      expect(logged).to include("pipeline_id=\"#{command_id}\"")
      expect(logged).to include('data_bytes=')
      expect(logged).not_to include("Obj RefId='0'")
    end

    it 'logs PSRP data digests without the serialized content' do
      summary = WinRM::LogRedactor.psrp_message(message)

      expect(summary).to include("data_sha256=sha256:#{WinRM::LogRedactor.digest(message.data)}")
      expect(summary).not_to include('RunspaceState')
    end

    it 'redacts a pipeline command containing a planted script secret' do
      io = StringIO.new
      logger = Logger.new(io)
      logger.level = :debug
      pipeline = WinRM::PSRP::MessageFactory.create_pipeline_message(
        '11111111-1111-1111-1111-111111111111',
        '22222222-2222-2222-2222-222222222222',
        "$cred = ConvertTo-SecureString '#{secret}'"
      )

      envelope = WinRM::WSMV::CreatePipeline.new(
        connection_options, shell_id, command_id, WinRM::PSRP::Fragment.new(1, pipeline.bytes)
      ).build
      transport = WinRM::HTTP::HttpPlaintext.allocate
      transport.instance_variable_set(:@logger, logger)
      transport.send(:log_soap_message, envelope, 'request')

      expect(io.string).to include('REDACTED Arguments')
      expect(io.string).not_to include(secret)
      expect(envelope).not_to include('REDACTED')
    end
  end

  describe 'cleanup failures' do
    subject { WinRM::Shells::Cmd.new(connection_options, transport, logger) }

    it 'logs a cleanup transport error without echoing its message' do
      allow(transport).to receive(:send_request) do |payload|
        if payload == 'cleanup'
          raise WinRM::WinRMHTTPTransportError.new("failed for #{secret}", 500)
        end

        REXML::Document.new("<blob Name='ShellId'>#{shell_id}</blob>")
      end
      allow_any_instance_of(WinRM::WSMV::CreateShell).to receive(:build).and_return('create')
      allow_any_instance_of(WinRM::WSMV::CleanupCommand).to receive(:build).and_return('cleanup')

      subject.send(:open)
      subject.send(:cleanup_command, command_id)

      logged = io.string
      expect(logged).to include('returned in cleanup with error')
      expect(logged).to include('status=500')
      expect(logged).to include('message_bytes=')
      expect(logged).not_to include(secret)
    end

    it 'redacts the endpoint when opening a shell' do
      allow_any_instance_of(WinRM::WSMV::CreateShell).to receive(:build).and_return('create')
      allow_any_instance_of(WinRM::WSMV::CleanupCommand).to receive(:build).and_return('cleanup')
      allow(transport).to receive(:send_request)
        .and_return(REXML::Document.new("<blob Name='ShellId'>#{shell_id}</blob>"))

      subject.send(:open)

      expect(io.string).to include('https://[REDACTED]@localhost:5986/wsman')
      expect(io.string).not_to include(password)
    end
  end

  describe 'response handler failures' do
    it 'keeps parse location but not malformed content' do
      handler = WinRM::ResponseHandler.new("<a>#{secret}</b>", 500)

      expect { handler.parse_to_xml }.to raise_error(WinRM::WinRMHTTPTransportError) do |error|
        expect(error.message).to include('class=REXML::ParseException')
        expect(error.message).to include('line=1')
        expect(error.message).not_to include(secret)
      end
    end

    it 'summarizes a non-fault HTTP error body' do
      body = "<response>server failure #{secret}</response>"
      handler = WinRM::ResponseHandler.new(body, 500)

      expect { handler.parse_to_xml }.to raise_error(WinRM::WinRMHTTPTransportError) do |error|
        expect(error.message).to include("body_bytes=#{body.bytesize}")
        expect(error.message).to include('body_sha256=sha256:')
        expect(error.message).not_to include(secret)
      end
    end
  end

  describe 'default log level' do
    around do |example|
      previous = ENV.delete('WINRM_LOG')
      example.run
      ENV['WINRM_LOG'] = previous if previous
    end

    it 'defaults to warn and suppresses debug diagnostics' do
      expect(WinRM.default_log_level).to eq(:warn)

      log = StringIO.new
      default_logger = WinRM::CompatLogger.new(log, level: WinRM.default_log_level)
      shell = WinRM::Shells::Cmd.new(connection_options, transport, default_logger)

      shell.logger.debug("[WinRM] Command created for #{secret}")

      expect(log.string).to be_empty
    end
  end
end
