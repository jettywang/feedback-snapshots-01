require 'winrm/shells/cmd'
require 'winrm/retry_policy'

# A clock whose time only passes when advanced explicitly, so tests can
# simulate operation timeouts and retry delays without real sleeps.
class FakeClock
  def initialize
    @now = 0.0
  end

  def call
    @now
  end

  def advance(seconds)
    @now += seconds
  end
end

# A transport that records every request and replays a scripted sequence of
# responses and failures. Each script entry decides whether the request
# "reached the server" (via deliver) and what happens next, so tests can
# distinguish failures before send from failures after send and can count
# the remote operations that were actually issued.
class ScriptedTransport
  attr_reader :requests, :remote_log

  def initialize(clock: nil, advance_per_request: 0, fallback: nil)
    @script = []
    @requests = []
    @remote_log = []
    @clock = clock
    @advance_per_request = advance_per_request
    @fallback = fallback || ->(_msg) { REXML::Document.new('<ok/>') }
  end

  def script(&action)
    @script << action
    self
  end

  def send_request(message)
    @requests << message
    @clock.advance(@advance_per_request) if @clock
    action = @script.shift || @fallback
    action.call(message)
  end

  # Marks the request as delivered to the remote host
  def deliver(message)
    @remote_log << message
  end

  def requests_matching(fragment)
    @requests.select { |request| request.include?(fragment) }
  end

  def remote_matching(fragment)
    @remote_log.select { |request| request.include?(fragment) }
  end
end

describe 'unattended retry boundaries' do
  let(:shell_id) { 'shell_id' }
  let(:command_id) { 'command_id' }
  let(:command) { 'whoami' }
  let(:clock) { FakeClock.new }
  let(:sleeper) { ->(seconds) { clock.advance(seconds) } }
  let(:retry_limit) { 3 }
  let(:receive_wait_limit) { nil }
  let(:advance_per_request) { 0 }
  let(:connection_options) do
    {
      endpoint: 'http://localhost:5985/wsman',
      session_id: '05A2622B-B842-4EB8-8A78-0225C8A993DF',
      operation_timeout: 60,
      locale: 'en-US',
      max_envelope_size: 153600,
      retry_limit: retry_limit,
      retry_delay: 5,
      receive_wait_limit: receive_wait_limit,
      retry_clock: clock,
      retry_sleeper: sleeper
    }
  end
  let(:transport) { ScriptedTransport.new(clock: clock, advance_per_request: advance_per_request) }

  subject { WinRM::Shells::Cmd.new(connection_options, transport, Logger.new(IO::NULL)) }

  def shell_response
    REXML::Document.new("<blah Name='ShellId'>#{shell_id}</blah>")
  end

  def command_response
    REXML::Document.new("<a xmlns:rsp='foo'><rsp:CommandId>#{command_id}</rsp:CommandId></a>")
  end

  def receive_response(stdout: nil, done: true)
    stream = ''
    stream = "<rsp:Stream Name='stdout'>#{Base64.strict_encode64(stdout)}</rsp:Stream>" if stdout
    state = ''
    if done
      state = "<rsp:CommandState State='http://schemas.microsoft.com/wbem/wsman/1/" \
              "windows/shell/CommandState/Done'/>"
    end
    REXML::Document.new(
      "<env:Envelope xmlns:env='http://www.w3.org/2003/05/soap-envelope'>" \
      "<env:Body><rsp:ReceiveResponse xmlns:rsp='http://schemas.microsoft.com/wbem/wsman/1/windows/shell'>" \
      "#{stream}#{state}<rsp:ExitCode>0</rsp:ExitCode></rsp:ReceiveResponse></env:Body></env:Envelope>"
    )
  end

  def operation_timeout_fault
    WinRM::WinRMWSManFault.new('operation timeout', '2150858793')
  end

  def script_open_and_command
    transport.script { |msg| transport.deliver(msg) && shell_response }
    transport.script { |msg| transport.deliver(msg) && command_response }
  end

  context 'command send fails before the request is sent' do
    it 'retries within budget and delivers the command exactly once' do
      transport.script { |msg| transport.deliver(msg) && shell_response }
      transport.script { raise HTTPClient::ConnectTimeoutError } # never reaches the server
      transport.script { |msg| transport.deliver(msg) && command_response }
      transport.script { |msg| transport.deliver(msg) && receive_response(stdout: 'hello') }

      output = subject.run(command)

      expect(output.stdout).to eq 'hello'
      # two Command requests left the client, but only one remote execution
      expect(transport.requests_matching('CommandLine').length).to eq 2
      expect(transport.remote_matching('CommandLine').length).to eq 1
    end
  end

  context 'connection drops after the command request was sent' do
    it 'raises a caller-identifiable unknown status and does not replay the command' do
      transport.script { |msg| transport.deliver(msg) && shell_response }
      transport.script do |msg|
        transport.deliver(msg) # request reached the server, response is lost
        raise HTTPClient::KeepAliveDisconnected
      end

      expect { subject.run(command) }.to raise_error(WinRM::WinRMCommandDeliveryUnknownError) do |error|
        expect(error.command).to eq command
        expect(error.shell_id).to eq shell_id
        expect(error.cause).to be_a(HTTPClient::KeepAliveDisconnected)
      end
      # the command was sent exactly once and never replayed
      expect(transport.requests_matching('CommandLine').length).to eq 1
      expect(transport.remote_matching('CommandLine').length).to eq 1
    end
  end

  context 'consecutive OperationTimeout faults' do
    it 'keeps waiting legitimately and eventually succeeds' do
      script_open_and_command
      3.times { transport.script { raise operation_timeout_fault } }
      transport.script { |msg| transport.deliver(msg) && receive_response(stdout: 'late output') }

      output = subject.run(command)

      expect(output.stdout).to eq 'late output'
      expect(transport.requests_matching(':Receive').length).to eq 4
    end

    context 'with a receive wait limit' do
      let(:receive_wait_limit) { 30 }
      let(:advance_per_request) { 20 } # every request costs 20s of clock time

      it 'raises and preserves the output received so far' do
        script_open_and_command
        transport.script { |msg| transport.deliver(msg) && receive_response(stdout: 'partial', done: false) }
        transport.script { raise operation_timeout_fault } # crosses the wait deadline

        expect { subject.run(command) }.to raise_error(WinRM::WinRMReceiveRetriesExhausted) do |error|
          expect(error.output).not_to be_nil
          expect(error.output.stdout).to eq 'partial'
        end
      end
    end
  end

  context 'retry budget is shared across layers' do
    let(:retry_limit) { 2 }

    it 'does not multiply retries between shell open and receive' do
      transport.script { raise Errno::ECONNREFUSED } # open attempt 1, retry 1
      transport.script { |msg| transport.deliver(msg) && shell_response }
      transport.script { |msg| transport.deliver(msg) && command_response }
      transport.script { raise Errno::ECONNRESET } # receive 1, retry 2 (budget now exhausted)
      transport.script { raise Errno::ECONNRESET } # receive 2, budget exhausted

      expect { subject.run(command) }.to raise_error(WinRM::WinRMReceiveRetriesExhausted)

      # 2 open attempts + 1 command + 2 receive attempts: the budget of 2
      # retries was shared, not spent once per layer
      expect(transport.requests_matching(':Shell>').length).to eq 2
      expect(transport.requests_matching(':Receive').length).to eq 2
    end

    it 'preserves received output when the budget is exhausted' do
      transport.script { |msg| transport.deliver(msg) && shell_response }
      transport.script { |msg| transport.deliver(msg) && command_response }
      transport.script { |msg| transport.deliver(msg) && receive_response(stdout: 'partial out', done: false) }
      transport.script { raise Errno::ECONNRESET } # retry 1
      transport.script { raise Errno::ECONNRESET } # retry 2
      transport.script { raise Errno::ECONNRESET } # budget exhausted

      expect { subject.run(command) }.to raise_error(WinRM::WinRMReceiveRetriesExhausted) do |error|
        expect(error.output.stdout).to eq 'partial out'
      end
    end
  end
end
