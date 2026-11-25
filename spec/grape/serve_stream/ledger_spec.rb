# frozen_string_literal: true

describe Grape::ServeStream::Ledger do
  subject(:ledger) { described_class.new }

  describe '#deliver' do
    it 'records each line and moves the last checkpoint' do
      ledger.deliver(index: 0, bytes: 4)
      ledger.deliver(index: 1, bytes: 4, checkpoint: 2)

      expect(ledger.delivered).to eq(2)
      expect(ledger.bytes).to eq(8)
      expect(ledger.last_checkpoint).to eq(2)
    end

    it 'stamps each entry with the approved revision' do
      ledger = described_class.new(version: 'v3')

      ledger.deliver(index: 0, bytes: 1)

      expect(ledger.entries.first.version).to eq('v3')
    end
  end

  describe '#terminate' do
    it 'settles once, keeping the first terminal state' do
      ledger.terminate(:complete)
      ledger.terminate(:aborted, reason: :denied)

      expect(ledger.terminal).to eq(:complete)
      expect(ledger.reason).to be_nil
    end

    it 'takes a reason when the stream stopped' do
      ledger.terminate(:aborted, reason: :consumer_closed)

      expect(ledger.reason).to eq(:consumer_closed)
      expect(ledger).to be_terminated
    end
  end

  describe '#abort!' do
    it 'keeps the failure location of a record that could not be rendered' do
      error = ArgumentError.new('cannot render')
      error.set_backtrace(['/app/models/report.rb:42:in \'secret_column\''])

      aborted = Grape::ServeStream::StreamAborted.new(:format_error, ledger:, index: 2, status: :failed)
      ledger.abort!(aborted, cause: error, index: 2, terminal: :failed)

      expect(ledger.terminal).to eq(:failed)
      expect(ledger.reason).to eq(:format_error)
      expect(ledger.aborted_at).to eq(2)
      expect(ledger.failure).to include(index: 2, class: 'ArgumentError', message: 'cannot render')
      expect(ledger.failure[:location]).to eq('/app/models/report.rb:42')
    end

    it 'records no failure for a policy change, which is not an error' do
      ledger.abort!(Grape::ServeStream::StreamAborted.new(:policy_changed, ledger:, index: 1), index: 1)

      expect(ledger.reason).to eq(:policy_changed)
      expect(ledger.failure).to be_nil
    end
  end

  describe '#truncated?' do
    it 'is true for a stream that stopped early' do
      ledger.terminate(:aborted)

      expect(ledger).to be_truncated
    end

    it 'is false for a complete or unread response' do
      ledger.terminate(:complete)
      expect(ledger).not_to be_truncated

      unread = described_class.new
      unread.terminate(:closed_unread)
      expect(unread).not_to be_truncated
    end
  end

  describe '#policy_changed?' do
    it 'is true once the live revision differs from the approved one' do
      ledger = described_class.new(version: 'v1')

      expect(ledger).not_to be_policy_changed
      ledger.observe_policy(Grape::ServeStream::Policy.new(version: 'v2'))
      expect(ledger).to be_policy_changed
    end

    it 'is false when the policy did not name a revision' do
      ledger.observe_policy(Struct.new(:version).new(nil))

      expect(ledger).not_to be_policy_changed
    end
  end

  describe '#to_h' do
    subject(:ledger) do
      described_class.new(representation: Grape::ServeStream::Representation.new(fields: %i[id], version: 'v1'))
    end

    before do
      ledger.source_read
      ledger.deliver(index: 0, bytes: 4, checkpoint: 1)
      ledger.terminate(:complete)
      ledger.closed(by: :consumer)
    end

    it 'is a detached record of the response' do
      expect(ledger.to_h).to include(
        version: 'v1', delivered: 1, bytes: 4, terminal: :complete, closed_by: :consumer, source_reads: 1
      )
      expect(ledger.to_h[:entries]).to eq([{ index: 0, version: 'v1', bytes: 4, checkpoint: 1 }])
      expect(ledger.to_h[:representation]).to include(fields: %i[id], mode: :declared, version: 'v1')
    end
  end

  describe '.from' do
    it 'finds the ledger a request published' do
      env = { Grape::Env::JSONL_LEDGER => ledger }

      expect(described_class.from(env)).to be(ledger)
      expect(described_class.from({})).to be_nil
    end
  end
end
