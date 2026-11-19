require 'winrm/shells/base'

# Deterministic lifecycle specs for command/shell release.
#
# The transport double below records the selector values and order of every
# Signal (CleanupCommand) and Delete (CloseShell) request rather than matching
# incidental payload strings. Responses are scripted per example so the
# primary execution error, cleanup outcome and request order are reproduced
# exactly, including finalizer and re-open interleavings.
describe 'WinRM shell lifecycle' do
  # Normalised view of one outgoing SOAP request.
  class LifecycleRequest
    ACTION_PATTERN = %r{<a:Action[^>]*>([^<]+)</a:Action>}.freeze

    attr_reader :raw, :action, :shell_id, :command_id

    def self.parse(payload)
      new(payload)
    end

    def initialize(payload)
      @raw = payload
      @action = classify(payload)
      @shell_id = payload[%r{Selector Name="ShellId">([^<]+)</}m, 1]
      @command_id = payload[%r{<rsp:Signal CommandId="([^"]+)"}m, 1]
    end

    # Stable, comparable description of what was sent.
    def selector
      [@action, @shell_id, @command_id].compact.join(':')
    end

    private

    def classify(payload)
      action = payload[ACTION_PATTERN, 1].to_s
      case action
      when %r{/transfer/Create} then :create
      when %r{windows/shell/Command$} then :command
      when %r{windows/shell/Receive} then :receive
      when %r{windows/shell/Signal} then :signal
      when %r{/transfer/Delete} then :delete
      else :other
      end
    end
  end

  # Transport double that records requests and lets each example script the
  # response (or raise) for the next request of a given action.
  class LifecycleTransport
    attr_reader :requests

    def initialize
      @requests = []
      @handlers = Hash.new { |h, k| h[k] = [] }
    end

    def script(action, &handler)
      @handlers[action] << handler
      self
    end

    def send_request(payload)
      request = LifecycleRequest.parse(payload)
      @requests << request
      handler = @handlers[request.action].shift
      return handler.call(request) if handler

      default_response(request)
    end

    def selectors(action = nil)
      @requests.select { |r| action.nil? || r.action == action }.map(&:selector)
    end

    def count(action)
      @requests.count { |r| r.action == action }
    end

    def default_response(request)
      case request.action
      when :create
        REXML::Document.new("<a Name='ShellId'>#{request.shell_id || 'shell'}</a>")
      when :command
        REXML::Document.new("<a xmlns:rsp='foo'><rsp:CommandId>cmd</rsp:CommandId></a>")
      else
        REXML::Document.new('<a/>')
      end
    end
  end

  # Minimal shell implementation exposing the protected lifecycle hooks.
  class LifecycleShell < WinRM::Shells::Base
    class << self
      def close_shell(_connection_opts, transport, shell_id)
        transport.send_request(close_payload(shell_id))
      end

      def close_payload(shell_id)
        WinRM::WSMV::CloseShell.new(
          { endpoint: 'http://127.0.0.1:5985/wsman' }, shell_id: shell_id
        ).build
      end
    end

    def initialize(connection_options, transport, shell_ids = ['shell-1'])
      super(connection_options, transport, Logger.new(IO::NULL))
      @shell_ids = shell_ids
      @open_count = 0
    end

    attr_reader :open_count

    def response_reader
      @response_reader ||= WinRM::WSMV::ReceiveResponseReader.new(transport, logger)
    end

    def send_command(_command, _arguments)
      transport.send_request(
        WinRM::WSMV::Command.new(
          { endpoint: 'http://127.0.0.1:5985/wsman' },
          shell_id: shell_id,
          command: 'echo hi'
        ).build
      )
      "command-#{shell_id}"
    end

    def open_shell
      id = @shell_ids[@open_count]
      @open_count += 1
      id
    end

    def out_streams
      %w[stdout stderr]
    end
  end

  let(:connection_options) do
    { max_commands: 100, retry_limit: 1, retry_delay: 0, endpoint: 'http://127.0.0.1:5985/wsman' }
  end
  let(:transport) { LifecycleTransport.new }
  let(:shell) { LifecycleShell.new(connection_options, transport) }

  # Replaces the XML reader so the spec only exercises lifecycle behaviour.
  def stub_reader(shell, &behaviour)
    reader = double('reader')
    allow(shell).to receive(:response_reader).and_return(reader)
    allow(reader).to receive(:read_output) do |*_args, &block|
      behaviour ? behaviour.call(block) : WinRM::Output.new
    end
  end

  describe 'normal completion' do
    it 'signals the original command and leaves the shell open' do
      stub_reader(shell)
      expect(shell.run('echo hi')).to be_a(WinRM::Output)

      expect(transport.selectors).to eq(
        [
          'command:shell-1',
          'signal:shell-1:command-shell-1'
        ]
      )
      expect(transport.count(:delete)).to eq(0)
      expect(shell.shell_id).to eq('shell-1')
    end

    it 'records the successful Signal cleanup status' do
      stub_reader(shell)
      shell.run('echo hi')

      status = shell.cleanup_statuses.last
      expect(status.action).to eq(:signal)
      expect(status.shell_id).to eq('shell-1')
      expect(status).to be_ok
    end

    it 'closes the shell exactly once across repeated close calls' do
      stub_reader(shell)
      shell.run('echo hi')
      shell.close
      shell.close

      expect(transport.selectors(:delete)).to eq(['delete:shell-1'])
      expect(shell.shell_id).to be_nil
    end
  end

  describe 'output callback error' do
    it 'preserves the callback error and still signals the original command' do
      callback_error = Class.new(StandardError)
      stub_reader(shell) { |_block| raise callback_error, 'callback exploded' }

      expect { shell.run('echo hi') }.to raise_error(callback_error, 'callback exploded')

      expect(transport.selectors(:signal)).to eq(['signal:shell-1:command-shell-1'])
      expect(transport.selectors(:command).length).to eq(1)
    end

    it 'attaches already collected output and cleanup status to the error' do
      partial = WinRM::Output.new
      partial << { stdout: 'before the callback blew up' }
      callback_error = Class.new(StandardError)
      stub_reader(shell) do |_block|
        error = callback_error.new('boom')
        WinRM::FailureDetails.attach_output(error, partial)
        raise error
      end

      error = nil
      begin
        shell.run('echo hi')
      rescue callback_error => e
        error = e
      end

      expect(error.output).to eq(partial)
      expect(error.cleanup_statuses.map(&:action)).to eq([:signal])
      expect(error.cleanup_statuses.first).to be_ok
    end

    it 'never retries and re-sends the remote command for a callback fault' do
      # Use the real response reader here: it is what marks a callback error,
      # so this exercises the actual guard rather than a stubbed reader.
      output_xml = <<~XML
        <s:Envelope xmlns:s='s' xmlns:rsp='http://schemas.microsoft.com/wbem/wsman/1/windows/shell'>
          <s:Body><rsp:ReceiveResponse>
            <rsp:Stream Name='stdout' CommandId='cid'>#{['hello'].pack('m0')}</rsp:Stream>
            <rsp:CommandState CommandId='cid'
              State='http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandState/Done'>
              <rsp:ExitCode>0</rsp:ExitCode>
            </rsp:CommandState>
          </rsp:ReceiveResponse></s:Body>
        </s:Envelope>
      XML
      transport.script(:receive) { REXML::Document.new(output_xml) }

      fault_error = Class.new(WinRM::WinRMWSManFault)
      expect do
        # A callback that happens to raise a WSMan-fault-looking error must not
        # trigger the shell's reset/retry logic.
        shell.run('echo hi') { |_stdout, _stderr| raise fault_error.new('callback fault', '2150858843') }
      end.to raise_error(fault_error, /callback fault/)

      expect(transport.selectors(:command).length).to eq(1)
      expect(shell.open_count).to eq(1)
    end
  end

  describe 'authentication failure' do
    it 'keeps the authorization error when cleanup also fails' do
      stub_reader(shell) { |_block| raise WinRM::WinRMAuthorizationError, '401' }
      transport.script(:signal) do |_r|
        raise WinRM::WinRMHTTPTransportError.new('cleanup timed out', 504)
      end

      expect { shell.run('echo hi') }.to raise_error(WinRM::WinRMAuthorizationError, '401')
    end

    it 'exposes the cleanup failure alongside the authorization error' do
      stub_reader(shell) { |_block| raise WinRM::WinRMAuthorizationError, '401' }
      transport.script(:signal) do |_r|
        raise WinRM::WinRMHTTPTransportError.new('cleanup timed out', 504)
      end

      error = nil
      begin
        shell.run('echo hi')
      rescue WinRM::WinRMAuthorizationError => e
        error = e
      end

      expect(error.cleanup_errors.map(&:class)).to eq([WinRM::WinRMHTTPTransportError])
      expect(error.cleanup_statuses.map(&:outcome)).to eq([:failed])
    end
  end

  describe 'cleanup timeout' do
    it 'raises a cleanup error when a successful command cannot be terminated' do
      stub_reader(shell)
      transport.script(:signal) do |_r|
        raise WinRM::WinRMHTTPTransportError.new('gateway timeout', 504)
      end

      expect { shell.run('echo hi') }.to raise_error(WinRM::CleanupError) do |error|
        expect(error.action).to eq(:signal)
        expect(error.shell_id).to eq('shell-1')
        expect(error.original_error).to be_a(WinRM::WinRMHTTPTransportError)
      end
    end

    it 'treats an aborted Signal as an ignored outcome' do
      stub_reader(shell)
      transport.script(:signal) { |_r| raise WinRM::WinRMWSManFault.new('aborted', '995') }

      expect { shell.run('echo hi') }.not_to raise_error
      expect(shell.cleanup_statuses.last).to be_ignored
    end

    it 'raises a cleanup error when closing the shell times out and forgets the handle' do
      stub_reader(shell)
      shell.run('echo hi')
      transport.script(:delete) do |_r|
        raise WinRM::WinRMHTTPTransportError.new('timeout', 504)
      end

      expect { shell.close }.to raise_error(WinRM::CleanupError) do |error|
        expect(error.action).to eq(:delete)
        expect(error.shell_id).to eq('shell-1')
      end
      expect(shell.shell_id).to be_nil
    end

    it 'treats an already-closed shell Delete as a tolerated outcome' do
      stub_reader(shell)
      shell.run('echo hi')
      transport.script(:delete) { |_r| raise WinRM::WinRMWSManFault.new('gone', '2150858843') }

      expect { shell.close }.not_to raise_error
      expect(shell.cleanup_statuses.last).to be_ignored
    end
  end

  describe 'reopening the same shell object' do
    let(:shell) { LifecycleShell.new(connection_options, transport, %w[shell-1 shell-2]) }

    it 'binds each command cleanup to the shell that created it' do
      stub_reader(shell)
      shell.run('echo hi')
      shell.close
      shell.run('echo hi')

      # The first command targeted shell-1; reopening made the second command
      # target shell-2 rather than reusing the stale selector.
      expect(transport.selectors(:command)).to eq(%w[command:shell-1 command:shell-2])
      expect(transport.selectors(:signal)).to eq(
        [
          'signal:shell-1:command-shell-1',
          'signal:shell-2:command-shell-2'
        ]
      )
    end

    it 'does not delete a newly opened shell with the previous id' do
      stub_reader(shell)
      shell.run('echo hi')
      shell.close
      shell.run('echo hi')

      expect(transport.selectors(:delete)).to eq(['delete:shell-1'])
      expect(shell.shell_id).to eq('shell-2')
    end
  end

  describe 'finalizer and explicit close interleaving' do
    let(:shell) { LifecycleShell.new(connection_options, transport, %w[shell-1 shell-2]) }

    # Builds the exact claim-gated proc the real finalizer stores, without
    # relying on non-deterministic GC. Returns [proc, handle].
    def finalizer_proc(shell)
      handle = shell.instance_variable_get(:@shell_handle)
      LifecycleShell.install_finalizer(connection_options, transport, handle.id, handle)
    end

    # The gated proc is a no-op when the generation was already claimed, so it
    # may return nil instead of a thread.
    def run_finalizer(finalizer)
      finalizer.call&.join
    end

    it 'sends one Delete when both explicit close and the finalizer run' do
      stub_reader(shell)
      shell.run('echo hi')
      finalizer = finalizer_proc(shell)

      shell.close
      run_finalizer(finalizer)

      expect(transport.selectors(:delete)).to eq(['delete:shell-1'])
    end

    it 'does not delete a shell reopened after the finalizer captured its id' do
      stub_reader(shell)
      shell.run('echo hi')
      finalizer = finalizer_proc(shell)

      # Explicit close claims shell-1, then the object is reopened.
      shell.close
      shell.run('echo hi')

      run_finalizer(finalizer)
      expect(transport.selectors(:delete)).to eq(['delete:shell-1'])
      expect(shell.shell_id).to eq('shell-2')
    end

    it 'does not delete a shell reopened after the generation was released' do
      stub_reader(shell)
      shell.run('echo hi')

      # Simulate GC reclaiming the object while a caller still holds a handle:
      # claim and release the old generation, then reopen on the same object.
      handle = shell.instance_variable_get(:@shell_handle)
      shell.send(:take_shell_handle)
      shell.send(:release_shell_handle, handle)
      shell.send(:open)

      expect(transport.selectors(:delete)).to eq(['delete:shell-1'])
      expect(shell.shell_id).to eq('shell-2')
    end

    it 'installs a finalizer that is a no-op once close claimed the handle' do
      installed = []
      allow(ObjectSpace).to receive(:define_finalizer) do |_obj, proc_to_install|
        installed << proc_to_install
      end

      stub_reader(shell)
      shell.run('echo hi')
      expect(installed.length).to eq(1)

      shell.close
      # The proc that would run at GC must not send a second Delete.
      installed.first.call&.join
      expect(transport.selectors(:delete)).to eq(['delete:shell-1'])
    end
  end

  describe 'connection block form' do
    it 'does not let a failing close hide the block error' do
      connection = WinRM::Connection.new(
        default_connection_opts.merge(retry_limit: 1, retry_delay: 1)
      )
      shell_double = instance_double(WinRM::Shells::Cmd)
      allow(shell_double).to receive(:close)
        .and_raise(WinRM::CleanupError.new('delete failed', action: :delete, shell_id: 's'))
      allow(connection).to receive(:shell_factory)
        .and_return(double(create_shell: shell_double))

      block_error = Class.new(StandardError)
      expect do
        connection.shell(:cmd) { raise block_error, 'block failed' }
      end.to raise_error(block_error, 'block failed')
    end

    it 'raises the cleanup error when the block itself succeeded' do
      connection = WinRM::Connection.new(
        default_connection_opts.merge(retry_limit: 1, retry_delay: 1)
      )
      shell_double = instance_double(WinRM::Shells::Cmd)
      allow(shell_double).to receive(:close)
        .and_raise(WinRM::CleanupError.new('delete failed', action: :delete, shell_id: 's'))
      allow(connection).to receive(:shell_factory)
        .and_return(double(create_shell: shell_double))

      expect do
        connection.shell(:cmd) { :ok }
      end.to raise_error(WinRM::CleanupError, /delete failed/)
    end
  end

  describe 'reset after a recoverable fault' do
    let(:shell) { LifecycleShell.new(connection_options, transport, %w[shell-1 shell-2]) }

    it 'never signals the retried command against the new shell selector' do
      stub_reader(shell)
      attempts = 0
      allow(shell).to receive(:send_command) do |_command, _arguments|
        attempts += 1
        "command-shell-#{attempts}"
      end
      # The first command's output read loses the shell; the retry succeeds.
      allow(shell.response_reader).to receive(:read_output) do
        if attempts == 1
          raise WinRM::WinRMWSManFault.new('shell gone', '2150858843')
        end

        WinRM::Output.new
      end

      shell.run('echo hi')

      # The command created on shell-1 is stopped on shell-1, the retried
      # command is stopped on shell-2, and the dead shell gets no Delete.
      expect(transport.selectors(:signal)).to eq(
        [
          'signal:shell-1:command-shell-1',
          'signal:shell-2:command-shell-2'
        ]
      )
      expect(transport.count(:delete)).to eq(0)
      expect(shell.shell_id).to eq('shell-2')
    end

    it 'sends no Delete at all for the shell the server already dropped' do
      allow(shell).to receive(:send_command) do |_command, _arguments|
        raise WinRM::WinRMWSManFault.new('shell gone', '2150858843')
      end
      stub_reader(shell)

      expect { shell.run('echo hi') }.to raise_error(WinRM::WinRMWSManFault)
      expect(transport.count(:delete)).to eq(0)
      expect(shell.cleanup_statuses.last).to be_skipped
    end

    it 'signals the outstanding command on its original shell, not a reopened one' do
      # A callback failure ends the run without a retry, but the shell was
      # reopened in between: the outstanding Signal must still target the
      # original shell id, not the newly opened one.
      stub_reader(shell) do |_block|
        shell.send(:open)
        raise 'callback failed'
      end

      expect { shell.run('echo hi') }.to raise_error(RuntimeError, 'callback failed')
      expect(transport.selectors(:signal)).to eq(['signal:shell-1:command-shell-1'])
      expect(shell.shell_id).to eq('shell-2')
    end
  end
end
