require 'spec_helper'

require 'rollbar/scrub_policy'

# Thread-style fake delay handler: mirrors Rollbar::Delay::Thread by
# performing each payload in its own thread, but gates the threads so
# examples can update the scrub policy while the payloads are queued.
class FakeThreadDelay
  class << self
    def payloads
      @payloads ||= []
    end

    def threads
      @threads ||= []
    end

    def gate
      @gate ||= Queue.new
    end

    def call(payload)
      payloads << payload
      threads << ::Thread.new do
        gate.pop
        Rollbar.process_from_async_handler(payload)
      end
    end

    def drain
      threads.size.times { gate << :go }
      threads.each(&:join)
    end

    def reset
      @payloads = []
      @threads = []
      @gate = Queue.new
    end
  end
end

# Task-style fake delay handler: queues payloads like a background job
# backend and performs them on demand. Failed jobs stay in the queue so
# they can be retried, like Sidekiq/Resque would do.
class FakeTaskDelay
  class << self
    def jobs
      @jobs ||= []
    end

    def call(payload)
      jobs << payload
    end

    def perform_next
      Rollbar.process_from_async_handler(jobs.first)
      jobs.shift
    end

    def drain
      perform_next until jobs.empty?
    end

    def reset
      @jobs = []
    end
  end
end

describe 'delayed sends with versioned scrub policy' do
  let(:notifier) { Rollbar.notifier }
  let(:sent_payloads) { [] }
  let(:sent_data) do
    sent_payloads.map { |payload| payload['data'] }.reject { |data| data['internal'] }
  end

  def configure_notifier
    Rollbar.clear_notifier!

    Rollbar.reconfigure do |config|
      config.access_token = test_access_token
      config.logger = ::Logger.new(nil)
      config.use_async = true
      yield(config)
    end

    # The delayed handlers process payloads through per-thread notifiers,
    # so the send stub has to cover every notifier instance.
    allow_any_instance_of(Rollbar::Notifier).to receive(:send_body) do |_, body|
      raise 'boom' if @fail_send

      sent_payloads << Rollbar::JSON.load(body)
    end
  end

  def report_sensitive_event
    Rollbar.error('sensitive event', :api_token => 'secret123')
  end

  def mask_api_token!(options = {})
    Rollbar.configuration.update_scrub_policy(
      options.merge(:scrub_fields => Rollbar.configuration.scrub_fields + [:api_token])
    )
  end

  def enqueued_data(payload)
    Rollbar::JSON.load(Rollbar::JSON.dump(payload))['data']
  end

  before do
    @fail_send = false
    FakeThreadDelay.reset
    FakeTaskDelay.reset
  end

  describe Rollbar::ScrubPolicy do
    it 'starts unversioned and non-strict' do
      policy = Rollbar::ScrubPolicy.new

      expect(policy.version).to eq(0)
      expect(policy).not_to be_strict
    end

    it 'bumps the version and records strictness on update' do
      policy = Rollbar::ScrubPolicy.new
      policy.update
      policy.update(:strict => false)

      expect(policy.version).to eq(2)
      expect(policy).not_to be_strict
      expect(policy.updated_at).not_to be_nil
    end

    it 'stamps payloads and reads the stamped version back' do
      policy = Rollbar::ScrubPolicy.new
      payload = { 'data' => { :body => {} } }

      policy.update
      policy.stamp(payload)

      expect(payload['data']['policy_version']).to eq(1)
      expect(policy.version_of(payload)).to eq(1)
      expect(policy.version_of('data' => {})).to be_nil
    end
  end

  context 'with a thread-style delay handler' do
    before do
      configure_notifier do |config|
        config.async_handler = FakeThreadDelay
      end
    end

    it 'reprocesses queued items under a newer strict policy before sending' do
      report_sensitive_event

      expect(FakeThreadDelay.payloads.size).to eq(1)
      expect(sent_payloads).to be_empty

      queued = enqueued_data(FakeThreadDelay.payloads.first)
      expect(queued['policy_version']).to eq(0)
      expect(queued['body']['message']['extra']['api_token']).to eq('secret123')

      mask_api_token!
      expect(Rollbar.configuration.scrub_policy.version).to eq(1)

      FakeThreadDelay.drain

      expect(sent_data.size).to eq(1)
      sent = sent_data.first
      expect(sent['policy_version']).to eq(1)
      expect(sent['body']['message']['extra']['api_token']).to eq('*' * 6)
      expect(sent['body']['message']['body']).to eq('sensitive event')
    end
  end

  context 'with a task-style delay handler' do
    before do
      configure_notifier do |config|
        config.async_handler = FakeTaskDelay
      end
    end

    it 'defers stale items instead of sending them when configured to defer' do
      Rollbar.configuration.async_stale_policy = :defer

      report_sensitive_event
      mask_api_token!
      FakeTaskDelay.drain

      expect(sent_payloads).to be_empty
      expect(FakeTaskDelay.jobs).to be_empty

      report_sensitive_event
      FakeTaskDelay.drain

      expect(sent_data.size).to eq(1)
      expect(sent_data.first['policy_version']).to eq(1)
      expect(sent_data.first['body']['message']['extra']['api_token']).to eq('*' * 6)
    end

    it 'keeps failed sends in the queue and retries them under the new policy' do
      report_sensitive_event
      mask_api_token!

      @fail_send = true

      expect { FakeTaskDelay.perform_next }.to raise_error('boom')
      expect(FakeTaskDelay.jobs.size).to eq(1)
      expect(sent_payloads).to be_empty

      @fail_send = false
      FakeTaskDelay.drain

      expect(FakeTaskDelay.jobs).to be_empty
      expect(sent_data.size).to eq(1)
      expect(sent_data.first['policy_version']).to eq(1)
      expect(sent_data.first['body']['message']['extra']['api_token']).to eq('*' * 6)
    end

    it 'sends items stamped under a non-strict policy with their own version' do
      report_sensitive_event
      Rollbar.configuration.update_scrub_policy(:strict => false)
      Rollbar.error('second event')
      FakeTaskDelay.drain

      expect(sent_data.size).to eq(2)
      expect(sent_data.map { |data| data['policy_version'] }).to eq([0, 1])
    end

    context 'with async_json_payload' do
      before do
        Rollbar.configuration.async_json_payload = true
      end

      it 'reprocesses JSON payloads under a newer strict policy' do
        report_sensitive_event

        expect(FakeTaskDelay.jobs.first).to be_a(String)

        mask_api_token!
        FakeTaskDelay.drain

        expect(sent_data.size).to eq(1)
        expect(sent_data.first['policy_version']).to eq(1)
        expect(sent_data.first['body']['message']['extra']['api_token']).to eq('*' * 6)
      end
    end
  end
end
