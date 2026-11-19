require 'winrm'

describe WinRM::ConnectionOpts do
  describe 'receive_wait_limit' do
    it 'defaults to nil (unlimited) for backward compatibility' do
      opts = described_class.create_with_defaults(default_connection_opts)
      expect(opts[:receive_wait_limit]).to be_nil
    end

    it 'accepts a positive integer' do
      opts = described_class.create_with_defaults(
        default_connection_opts.merge(receive_wait_limit: 300)
      )
      expect(opts[:receive_wait_limit]).to eq 300
    end

    it 'rejects a non integer' do
      expect do
        described_class.create_with_defaults(
          default_connection_opts.merge(receive_wait_limit: 'never')
        )
      end.to raise_error(/receive_wait_limit must be a Integer/)
    end

    it 'rejects zero' do
      expect do
        described_class.create_with_defaults(
          default_connection_opts.merge(receive_wait_limit: 0)
        )
      end.to raise_error(/receive_wait_limit must be greater than 0/)
    end
  end
end
