describe 'Exceptions' do
  describe WinRM::WinRMAuthorizationError do
    let(:error) { WinRM::WinRMHTTPTransportError.new('Foo happened', 500) }

    it 'adds the response code to the message' do
      expect(error.message).to eq('Foo happened (500).')
    end

    it 'exposes the response code as an attribute' do
      expect(error.status_code).to eq 500
    end

    it 'is a winrm error' do
      expect(error).to be_kind_of(WinRM::WinRMError)
    end
  end

  describe WinRM::WinRMWSManFault do
    let(:error) { WinRM::WinRMWSManFault.new('fault text', 42) }

    it 'exposes the fault text as an attribute' do
      expect(error.fault_description).to eq('fault text')
    end

    it 'exposes the fault code as an attribute' do
      expect(error.fault_code).to eq 42
    end

    it 'is a winrm error' do
      expect(error).to be_kind_of(WinRM::WinRMError)
    end
  end

  describe WinRM::WinRMWMIError do
    let(:error) { WinRM::WinRMWMIError.new('message text', 77_777) }

    it 'exposes the error text as an attribute' do
      expect(error.error).to eq('message text')
    end

    it 'exposes the error code as an attribute' do
      expect(error.error_code).to eq 77_777
    end

    it 'is a winrm error' do
      expect(error).to be_kind_of(WinRM::WinRMError)
    end
  end

  describe WinRM::CleanupError do
    let(:original) { WinRM::WinRMHTTPTransportError.new('timeout', 504) }
    let(:error) do
      described_class.new(
        'could not release',
        action: :signal,
        shell_id: 'shell-1',
        command_id: 'command-1',
        original_error: original
      )
    end

    it 'exposes the action, ids and original error' do
      expect(error.action).to eq(:signal)
      expect(error.shell_id).to eq('shell-1')
      expect(error.command_id).to eq('command-1')
      expect(error.original_error).to be(original)
    end

    it 'reports the original error as its cause' do
      expect(error.cause).to be(original)
    end

    it 'is a winrm error' do
      expect(error).to be_kind_of(WinRM::WinRMError)
    end
  end

  describe WinRM::CleanupStatus do
    it 'defaults a successful request to :ok' do
      expect(described_class.new(action: :delete, shell_id: 's')).to be_ok
    end

    it 'defaults a request with an error to :failed' do
      status = described_class.new(
        action: :signal, shell_id: 's', error: RuntimeError.new('x')
      )
      expect(status).to be_failed
      expect(status.error).to be_a(RuntimeError)
    end

    it 'records tolerated and skipped outcomes' do
      expect(described_class.new(action: :signal, shell_id: 's', outcome: :ignored)).to be_ignored
      expect(described_class.new(action: :delete, shell_id: 's', outcome: :skipped)).to be_skipped
    end
  end

  describe WinRM::FailureDetails do
    it 'attaches output and accumulates cleanup statuses without changing the error' do
      error = RuntimeError.new('primary')
      output = WinRM::Output.new
      first = WinRM::CleanupStatus.new(action: :signal, shell_id: 's')
      second = WinRM::CleanupStatus.new(action: :delete, shell_id: 's', outcome: :ignored)

      described_class.attach(error, output: output, cleanup_statuses: [first])
      described_class.attach(error, cleanup_statuses: [second])

      expect(error).to be_a(RuntimeError)
      expect(error.message).to eq('primary')
      expect(error.output).to be(output)
      expect(error.cleanup_statuses).to eq([first, second])
      expect(error.cleanup_errors).to be_empty
    end

    it 'leaves a frozen exception untouched' do
      error = RuntimeError.new('frozen').freeze
      expect(described_class.attach(error, output: WinRM::Output.new)).to be(error)
    end

    it 'marks an output callback error' do
      error = RuntimeError.new('callback')
      described_class.mark_output_callback(error)
      expect(error).to be_a(WinRM::OutputCallbackError)
    end
  end
end
