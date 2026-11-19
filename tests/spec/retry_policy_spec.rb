require 'winrm/retry_policy'

describe WinRM::RetryPolicy do
  let(:clock) { FakeClock.new }
  let(:sleeps) { [] }
  let(:sleeper) { ->(seconds) { sleeps << seconds } }

  subject { described_class.new(limit: 2, delay: 5, clock: clock, sleeper: sleeper) }

  # minimal controllable clock
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

  it 'shares one budget across all consumers' do
    expect(subject.retry?).to be true
    subject.wait_for_retry
    subject.consume_retry
    expect(subject.retry?).to be false
    expect(subject.retries_used).to eq 2
    expect(subject.retries_remaining).to eq 0
  end

  it 'waits through the injectable sleeper instead of sleeping' do
    subject.wait_for_retry
    expect(sleeps).to eq [5]
  end

  it 'reads time from the injectable clock' do
    clock.advance(7)
    expect(subject.now).to eq 7
  end

  it 'classifies failures by whether the request may have been sent' do
    expect(described_class::PRE_SEND_EXCEPTIONS).to include(Errno::ECONNREFUSED)
    expect(described_class::PRE_SEND_EXCEPTIONS).to include(HTTPClient::ConnectTimeoutError)
    expect(described_class::AMBIGUOUS_EXCEPTIONS).to include(HTTPClient::ReceiveTimeoutError)
    expect(described_class::AMBIGUOUS_EXCEPTIONS).to include(HTTPClient::KeepAliveDisconnected)
    expect(described_class::PRE_SEND_EXCEPTIONS & described_class::AMBIGUOUS_EXCEPTIONS).to be_empty
  end
end
