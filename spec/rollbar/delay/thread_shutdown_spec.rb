require 'spec_helper'
require 'open3'
require 'tmpdir'
require 'fileutils'
require 'rollbar/delay/thread'

module ThreadShutdownSupport
  # A stand-in for the network layer. It blocks on demand and records every
  # payload it was asked to deliver, without any real HTTP or real time wait.
  class BlockingDelivery
    attr_reader :payloads

    def initialize
      @payloads = []
      @started = Queue.new
      @release = Queue.new
      @lock = Mutex.new
      @block_next = false
    end

    def block_next!
      @lock.synchronize { @block_next = true }
    end

    def call(payload)
      block = false

      @lock.synchronize do
        @payloads << payload
        @started << true
        block = @block_next
        @block_next = false
      end

      @release.pop if block

      true
    end

    def wait_until_started
      @started.pop
    end

    def release!
      @release << true
    end
  end

  class FailingDelivery
    attr_reader :attempts

    def initialize(error = StandardError.new('delivery failed'))
      @error = error
      @attempts = 0
      @lock = Mutex.new
    end

    def call(_payload)
      @lock.synchronize { @attempts += 1 }
      raise @error
    end
  end
end

describe 'Rollbar::Delay::Thread shutdown lifecycle' do
  subject(:handler) { Rollbar::Delay::Thread }

  let(:payload) { { 'data' => { 'uuid' => 'uuid-1' } } }
  let(:second_payload) { { 'data' => { 'uuid' => 'uuid-2' } } }

  before do
    handler.reset!
    handler.options = nil
  end

  after do
    handler.reset!
  end

  def use_delivery(delivery)
    allow(Rollbar).to receive(:process_from_async_handler) { |body| delivery.call(body) }
  end

  def wait_for_shutdown_to_start
    wait_until('shutdown never started') { handler.shutdown_in_progress? }
  end

  def wait_for_shutdown_waiter
    wait_until('shutdown never got a second caller') do
      handler.shutdown_waiters == 1
    end
  end

  def wait_until(message)
    100_000.times do
      return if yield

      Thread.pass
    end

    raise message
  end

  describe 'normal completion' do
    it 'reports every accepted report as processed with one delivery each' do
      delivery = ThreadShutdownSupport::BlockingDelivery.new
      use_delivery(delivery)

      handler.call(payload)
      handler.call(second_payload)

      receipt = handler.shutdown(:timeout => 1)

      expect(receipt.accepted_count).to eq(2)
      expect(receipt.processed_uuids).to contain_exactly('uuid-1', 'uuid-2')
      expect(receipt.unfinished_count).to eq(0)
      expect(receipt.deliveries).to eq(2)
      expect(receipt.complete?).to be(true)
      expect(receipt.timed_out?).to be(false)
      expect(receipt.status).to eq(:processed)
    end

    it 'reports the enqueue position as admission order, not completion order' do
      deliveries = Queue.new
      allow(Rollbar).to receive(:process_from_async_handler) do |body|
        deliveries << body['data']['uuid']
        true
      end

      handler.call(payload)
      handler.call(second_payload)

      receipt = handler.shutdown(:timeout => 1)

      expect(receipt.accepted.map(&:uuid)).to eq(%w[uuid-1 uuid-2])
      expect(receipt.accepted.map(&:position)).to eq([0, 1])
      expect(deliveries.size).to eq(2)
    end

    it 'keeps the enqueue position for each accepted report' do
      use_delivery(ThreadShutdownSupport::BlockingDelivery.new)

      handler.call(payload)
      handler.call(second_payload)

      entries = handler.shutdown(:timeout => 1).accepted

      expect(entries.map(&:position)).to eq([0, 1])
      expect(entries.map(&:uuid)).to eq(%w[uuid-1 uuid-2])
    end
  end

  describe 'in-flight delivery at the cutoff' do
    it 'distinguishes accepted from processing in the receipt' do
      delivery = ThreadShutdownSupport::BlockingDelivery.new
      delivery.block_next!
      use_delivery(delivery)

      handler.call(payload)
      delivery.wait_until_started

      receipt = handler.shutdown(:timeout => 0)

      expect(receipt.accepted.first.status).to eq(:unfinished)
      expect(receipt.accepted.first.stage).to eq(:processing)
      expect(receipt.processing_count).to eq(1)
      expect(receipt.counts).to include(:accepted => 1, :processing => 1,
                                        :unfinished => 1)
      expect(receipt.to_h[:unfinished].first).to include(:stage => :processing)

      delivery.release!
      handler.shutdown(:timeout => 1)
    end

    it 'keeps an unfinished marker and only sends once' do
      delivery = ThreadShutdownSupport::BlockingDelivery.new
      delivery.block_next!
      use_delivery(delivery)

      handler.call(payload)
      delivery.wait_until_started

      receipt = handler.shutdown(:timeout => 0)

      expect(receipt.accepted_count).to eq(1)
      expect(receipt.processed_count).to eq(0)
      expect(receipt.unfinished_count).to eq(1)
      expect(receipt.timed_out?).to be(true)
      expect(receipt.status).to eq(:unfinished)

      entry = receipt.unfinished.first
      expect(entry.uuid).to eq('uuid-1')
      expect(entry.stage).to eq(:processing)
      expect(entry.deliveries).to eq(1)
      expect(entry.error).to be_a(Rollbar::Delay::Thread::TimeoutError)

      expect(handler.open_reports.map(&:uuid)).to eq(%w[uuid-1])

      delivery.release!
      retry_receipt = handler.shutdown(:timeout => 1)

      expect(retry_receipt.processed_uuids).to eq(%w[uuid-1])
      expect(retry_receipt.unfinished_count).to eq(0)
      expect(handler.open_reports).to be_empty
      expect(delivery.payloads.size).to eq(1)
    end
  end

  describe 'failed delivery' do
    it 'marks the report failed with the delivery error' do
      delivery = ThreadShutdownSupport::FailingDelivery.new
      use_delivery(delivery)

      handler.call(payload)
      receipt = handler.shutdown(:timeout => 1)

      expect(receipt.processed_count).to eq(0)
      expect(receipt.failed_count).to eq(1)
      expect(receipt.failed.first.error.message).to eq('delivery failed')
      expect(receipt.status).to eq(:failed)
      expect(receipt.timed_out?).to be(false)
      expect(delivery.attempts).to eq(1)
    end
  end

  describe 'reports after shutdown' do
    it 'does not judge a later report by the previous shutdown state' do
      use_delivery(ThreadShutdownSupport::BlockingDelivery.new)

      handler.call(payload)
      first = handler.shutdown(:timeout => 1)
      expect(first.processed_uuids).to eq(%w[uuid-1])

      handler.call(second_payload)
      second = handler.shutdown(:timeout => 1)

      expect(second.generation).to be > first.generation
      expect(second.processed_uuids).to eq(%w[uuid-2])
      expect(second.processed_uuids).not_to include('uuid-1')
    end
  end

  describe 'a report accepted during shutdown' do
    it 'stays out of the old receipt and is drained by the next shutdown' do
      delivery = ThreadShutdownSupport::BlockingDelivery.new
      delivery.block_next!
      use_delivery(delivery)

      handler.call(payload)
      delivery.wait_until_started

      first_receipt = Queue.new
      first = ::Thread.new do
        first_receipt << handler.shutdown(:timeout => 5)
      end

      wait_for_shutdown_to_start

      handler.call(second_payload)
      delivery.release!
      first.join

      first_result = first_receipt.pop
      expect(first_result.processed_uuids).to eq(%w[uuid-1])
      expect(first_result.accepted.map(&:position)).to eq([0])

      second_result = handler.shutdown(:timeout => 1)
      expect(second_result.generation).to be > first_result.generation
      expect(second_result.processed_uuids).to eq(%w[uuid-2])
      expect(delivery.payloads.size).to eq(2)
    end
  end

  describe 'through Rollbar.error' do
    it 'correlates the report to the shutdown receipt by uuid' do
      delivered = Queue.new
      allow(Rollbar).to receive(:process_from_async_handler) do |body|
        data = body['data'] || body[:data]
        delivered << (data['uuid'] || data[:uuid])
        true
      end

      Rollbar.configure do |config|
        config.access_token = 'test'
        config.enabled = true
        config.use_thread(:shutdown_timeout => 1)
        config.logger = Logger.new(File::NULL)
      end

      Rollbar.error('worker failed')

      receipt = Rollbar.shutdown
      delivered_uuid = delivered.pop

      expect(receipt.accepted_count).to eq(1)
      expect(receipt.processed_uuids).to eq([delivered_uuid])
      expect(receipt.accepted.first.position).to eq(0)
      expect(receipt.deliveries).to eq(1)
    ensure
      Rollbar.clear_notifier!
    end
  end

  describe 'Rollbar.shutdown entry point' do
    it 'uses the configured async shutdown timeout' do
      delivery = ThreadShutdownSupport::BlockingDelivery.new
      delivery.block_next!
      use_delivery(delivery)

      Rollbar.configure do |config|
        config.use_thread(:shutdown_timeout => 0)
      end

      Rollbar::Delay::Thread.call(payload)
      delivery.wait_until_started

      receipt = Rollbar.shutdown

      expect(receipt).to be_a(Rollbar::Delay::Thread::ShutdownReceipt)
      expect(receipt.timed_out?).to be(true)
      expect(receipt.unfinished_uuids).to eq(%w[uuid-1])

      delivery.release!
      Rollbar::Delay::Thread.shutdown(:timeout => 1)
    ensure
      Rollbar.clear_notifier!
    end

    it 'falls back to the thread handler for use_async without a custom handler' do
      delivery = ThreadShutdownSupport::BlockingDelivery.new
      use_delivery(delivery)

      Rollbar.configure do |config|
        config.access_token = 'test'
        config.enabled = true
        config.use_async = true
        config.logger = Logger.new(File::NULL)
      end

      Rollbar.error('plain async')

      receipt = Rollbar.shutdown(:timeout => 1)

      expect(receipt).to be_a(Rollbar::Delay::Thread::ShutdownReceipt)
      expect(receipt.accepted_count).to eq(1)
      expect(receipt.processed_count).to eq(1)
    ensure
      Rollbar.clear_notifier!
    end

    it 'returns an empty receipt when the active handler has no lifecycle' do
      Rollbar.configure do |config|
        config.use_async = true
        config.async_handler = proc { |_payload| true }
      end

      receipt = Rollbar.shutdown

      expect(receipt.accepted_count).to eq(0)
      expect(receipt.complete?).to be(true)
    ensure
      Rollbar.clear_notifier!
    end

    it 'honors an explicit timeout over the configured one' do
      use_delivery(ThreadShutdownSupport::BlockingDelivery.new)

      Rollbar.configure do |config|
        config.use_thread(:shutdown_timeout => 0)
      end

      Rollbar::Delay::Thread.call(payload)

      receipt = Rollbar.shutdown(:timeout => 1)

      expect(receipt.timed_out?).to be(false)
      expect(receipt.processed_uuids).to eq(%w[uuid-1])
    ensure
      Rollbar.clear_notifier!
    end
  end

  describe 'after a forked process' do
    it 'starts an empty lifecycle so the child does not drain the parent copy' do
      use_delivery(ThreadShutdownSupport::BlockingDelivery.new)
      handler.call(payload)
      handler.shutdown(:timeout => 1)

      next unless Process.respond_to?(:fork)

      reader, writer = IO.pipe
      child = Process.fork do
        reader.close
        begin
          receipt = handler.shutdown(:timeout => 0)
          writer.write(receipt.accepted_count.to_s)
        ensure
          writer.close
        end
        exit! 0
      end

      writer.close
      count = reader.read
      reader.close
      Process.wait(child)

      expect(count).to eq('0')
    end
  end

  describe 'two concurrent shutdowns' do
    it 'share one receipt and do not duplicate deliveries' do
      delivery = ThreadShutdownSupport::BlockingDelivery.new
      delivery.block_next!
      use_delivery(delivery)

      handler.call(payload)
      delivery.wait_until_started

      first_receipt = Queue.new
      second_receipt = Queue.new

      first = ::Thread.new do
        first_receipt << handler.shutdown(:timeout => 5)
      end

      wait_for_shutdown_to_start

      second = ::Thread.new do
        second_receipt << handler.shutdown(:timeout => 5)
      end

      # Make sure the second caller is actually waiting on the same run
      # before allowing the blocked delivery to finish.
      wait_for_shutdown_waiter
      delivery.release!
      [first, second].each(&:join)

      one = first_receipt.pop
      two = second_receipt.pop

      expect(one).to be(two)
      expect(one.processed_uuids).to eq(%w[uuid-1])
      expect(delivery.payloads.size).to eq(1)
    end
  end

  describe 'normal process exit' do
    it 'reports unfinished reports on stderr without failing the process' do
      lib = File.expand_path('../../../../lib', __FILE__)

      script = <<-'RUBY'
        require 'rollbar'
        require 'rollbar/delay/thread'

        Rollbar::Delay::Thread.reset!
        $gate = Queue.new
        module Rollbar
          def self.process_from_async_handler(_payload)
            $gate.pop
            true
          end
        end

        Rollbar.configure do |config|
          config.use_thread(:shutdown_timeout => 0)
        end

        Rollbar::Delay::Thread.call('data' => { 'uuid' => 'left-behind' })
        exit 0
      RUBY

      output, status = Open3.capture2e(RbConfig.ruby, "-I#{lib}", '-e', script)

      expect(status.exitstatus).to eq(0)
      expect(output).to include('left-behind')
    end

    it 'drains accepted work without failing the process' do
      lib = File.expand_path('../../../../lib', __FILE__)
      marker = File.join(Dir.mktmpdir('rollbar-exit'), 'delivered')

      script = <<-'RUBY'
        require 'rollbar'
        require 'rollbar/delay/thread'

        Rollbar::Delay::Thread.reset!
        release = Queue.new
        $release = release
        marker = ENV.fetch('MARKER')

        module Rollbar
          def self.process_from_async_handler(_payload)
            $release.pop
            File.write(ENV.fetch('MARKER'), '1')
            true
          end
        end

        Rollbar::Delay::Thread.call('data' => { 'uuid' => 'exit-1' })

        # Runs before the library's at_exit handler (LIFO), releasing the
        # blocked report so the shutdown has real work to finish.
        at_exit { $release << true }
        exit 0
      RUBY

      output, status = Open3.capture2e(
        { 'MARKER' => marker }, RbConfig.ruby, "-I#{lib}", '-e', script
      )

      expect(status.exitstatus).to eq(0), output
      expect(File.read(marker)).to eq('1')
    ensure
      if marker && File.exist?(File.dirname(marker))
        FileUtils.remove_entry_secure(File.dirname(marker))
      end
    end
  end

  describe 'receipt serialization' do
    it 'is JSON-friendly and does not include report bodies' do
      use_delivery(ThreadShutdownSupport::BlockingDelivery.new)

      handler.call(payload)
      receipt = handler.shutdown(:timeout => 1)

      json = JSON.generate(receipt.to_h)

      expect(json).to include('uuid-1')
      expect(json).to include('"complete":true')
      expect(json).not_to include('payload')
    end
  end

  describe 'empty shutdown' do
    it 'returns a complete empty receipt when nothing was accepted' do
      receipt = handler.shutdown(:timeout => 0)

      expect(receipt.accepted_count).to eq(0)
      expect(receipt.complete?).to be(true)
      expect(receipt.timed_out?).to be(false)
    end

    it 'returns an empty receipt for the next window when nothing new arrived' do
      use_delivery(ThreadShutdownSupport::BlockingDelivery.new)

      handler.call(payload)
      first = handler.shutdown(:timeout => 1)
      second = handler.shutdown(:timeout => 1)

      expect(second).not_to be(first)
      expect(first.processed_uuids).to eq(%w[uuid-1])
      expect(second.accepted_count).to eq(0)
      expect(second.complete?).to be(true)
    end
  end
end
