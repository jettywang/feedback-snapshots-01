require 'json'

module Rollbar
  module Delay
    class Thread
      EXIT_TIMEOUT = 6

      Error        = Class.new(StandardError)
      TimeoutError = Class.new(Error)

      DEFAULT_PRIORITY = 1
      DEFAULT_SHUTDOWN_TIMEOUT = EXIT_TIMEOUT

      ACCEPTED   = :accepted
      PROCESSING = :processing
      PROCESSED  = :processed
      FAILED     = :failed
      UNFINISHED = :unfinished

      LIFECYCLE_MUTEX = Mutex.new
      LIFECYCLE_COND  = ConditionVariable.new
      RUNTIME_MUTEX   = Mutex.new

      # One report accepted by the async handler. A report moves from accepted
      # to processing, then to processed or failed. Reports still open when a
      # shutdown deadline expires are reported as unfinished without closing
      # them, so a later shutdown can wait for the same delivery again.
      class Report
        attr_reader :id, :uuid, :payload, :generation, :position
        attr_accessor :status, :stage, :error, :thread, :deliveries, :closed

        def initialize(id, uuid, payload, generation, position)
          @id = id
          @uuid = uuid
          @payload = payload
          @generation = generation
          @position = position
          @status = ACCEPTED
          @stage = ACCEPTED
          @error = nil
          @thread = nil
          @deliveries = 0
          @closed = false
        end

        def processed?
          status == PROCESSED
        end

        def failed?
          status == FAILED
        end

        def finished?
          closed
        end

        def snapshot
          ReceiptEntry.new(id, uuid, position, status, stage, error, deliveries)
        end
      end

      # An immutable view of one accepted report at the time the receipt was
      # built. It carries no payload, so a finished receipt does not retain
      # report bodies in memory.
      class ReceiptEntry
        attr_reader :id, :uuid, :position, :status, :stage, :error, :deliveries

        def initialize(id, uuid, position, status, stage, error, deliveries)
          @id = id
          @uuid = uuid
          @position = position
          @status = status
          @stage = stage
          @error = error
          @deliveries = deliveries
          freeze
        end

        def processed?
          status == PROCESSED
        end

        def failed?
          status == FAILED
        end

        def unfinished?
          status == UNFINISHED
        end

        def to_h
          {
            :id => id,
            :uuid => uuid,
            :position => position,
            :status => status,
            :stage => stage,
            :deliveries => deliveries,
            :error => error && {
              :class => error.class.name,
              :message => error.message
            }
          }
        end
      end

      # The result of closing one generation of accepted reports. +accepted+
      # is every report admitted before shutdown started, +processed+ is the
      # subset delivered successfully, +failed+ is the subset whose delivery
      # raised, and +unfinished+ is the subset still in flight at the deadline.
      class ShutdownReceipt
        attr_reader :entries, :generation, :timed_out

        def initialize(entries, generation, timed_out)
          @entries = entries.freeze
          @generation = generation
          @timed_out = timed_out
          freeze
        end

        def accepted
          entries
        end

        def processed
          entries.select(&:processed?)
        end

        def failed
          entries.select(&:failed?)
        end

        def unfinished
          entries.select(&:unfinished?)
        end

        # Unfinished entries whose delivery had already started.
        def processing
          unfinished.select { |entry| entry.stage == PROCESSING }
        end

        def deliveries
          entries.map(&:deliveries).inject(0, :+)
        end

        def accepted_count
          entries.size
        end

        def processed_count
          processed.size
        end

        def failed_count
          failed.size
        end

        def unfinished_count
          unfinished.size
        end

        def processing_count
          processing.size
        end

        def counts
          {
            :accepted => accepted_count,
            :processed => processed_count,
            :failed => failed_count,
            :unfinished => unfinished_count,
            :processing => processing_count
          }
        end

        def complete?
          failed.empty? && unfinished.empty?
        end
        def timed_out?
          timed_out
        end

        def status
          return UNFINISHED unless unfinished.empty?
          return FAILED unless failed.empty?

          PROCESSED
        end

        def uuids
          entries.map(&:uuid).compact
        end

        def processed_uuids
          processed.map(&:uuid).compact
        end

        def failed_uuids
          failed.map(&:uuid).compact
        end

        def unfinished_uuids
          unfinished.map(&:uuid).compact
        end

        def to_h
          {
            :generation => generation,
            :accepted => accepted.map(&:to_h),
            :processed => processed.map(&:to_h),
            :failed => failed.map(&:to_h),
            :unfinished => unfinished.map(&:to_h),
            :counts => counts,
            :deliveries => deliveries,
            :complete => complete?,
            :timed_out => timed_out?
          }
        end
      end

      # Reports accepted while a shutdown is running belong to the next
      # generation, so a later shutdown never judges them by the old cutoff.
      class Generation
        attr_reader :number, :reports

        def initialize(number)
          @number = number
          @reports = []
        end
      end

      class ShutdownRun
        attr_reader :generation, :deadline, :reports
        attr_accessor :receipt, :done, :waiters

        def initialize(generation, deadline, reports)
          @generation = generation
          @deadline = deadline
          @reports = reports
          @receipt = nil
          @done = false
          @waiters = 0
        end
      end

      class << self
        attr_writer :options
        attr_reader :last_shutdown_receipt

        def call(payload)
          ensure_runtime

          report = register(payload)
          thread = start_worker(report)

          LIFECYCLE_MUTEX.synchronize do
            report.thread = thread
            LIFECYCLE_COND.broadcast
          end

          thread
        rescue StandardError => e
          close_report(report, FAILED, e) if report
          raise
        end

        # Stop accepting new work into the current generation, wait up to
        # +timeout+ for every report already accepted to finish, and return a
        # snapshot. Reports accepted after this call start a new generation and
        # are not part of this receipt. Concurrent calls share the same
        # in-progress run and return the same receipt. Reports still in flight
        # at the deadline stay open, so a later shutdown can wait for them
        # again instead of trusting a stale cutoff.
        def shutdown(options = {})
          ensure_runtime

          options = { :timeout => options } if options.is_a?(Numeric)
          options ||= {}

          deadline = monotonic_now + shutdown_timeout(options)

          run, owner = acquire_shutdown_run(deadline)

          return run.receipt unless owner

          begin
            run.receipt = drain(run)
          ensure
            publish_receipt(run)
          end

          run.receipt
        end
        # Discard lifecycle state so a forked process or a test can begin with
        # an empty generation. Reports already accepted are closed as unfinished
        # without waiting for them.
        def reset!
          ensure_runtime

          LIFECYCLE_MUTEX.synchronize do
            active = @active_shutdown

            if active
              active.receipt ||= ShutdownReceipt.new(
                active.reports.map(&:snapshot),
                active.generation.number,
                true
              )
              active.done = true
            end

            @open_reports.each { |report| report.closed = true }
            @open_reports = []
            @report_sequence = 0
            @generation = Generation.new(@generation.number + 1)
            @last_shutdown_receipt = nil
            @active_shutdown = nil
            LIFECYCLE_COND.broadcast
          end

          nil
        end

        def shutdown_in_progress?
          LIFECYCLE_MUTEX.synchronize { !@active_shutdown.nil? }
        end

        # Unfinished reports from the most recent shutdown, so an operator
        # can retrieve the follow-up list without holding the receipt. The
        # count also lets callers observe coalescing without wall-clock waits.
        def open_reports
          LIFECYCLE_MUTEX.synchronize { @open_reports.dup }
        end

        def shutdown_waiters
          LIFECYCLE_MUTEX.synchronize do
            @active_shutdown ? @active_shutdown.waiters : 0
          end
        end

        def options
          @options || {}
        end

        private

        def ensure_runtime
          return if @runtime_ready && @runtime_pid == Process.pid

          RUNTIME_MUTEX.synchronize do
            return if @runtime_ready && @runtime_pid == Process.pid

            # A forked child inherits the parent's report list. Starting a
            # fresh lifecycle keeps the child from waiting on or reporting
            # another process's work.
            @generation = Generation.new(0)
            @open_reports = []
            @report_sequence = 0
            @last_shutdown_receipt = nil
            @active_shutdown = nil
            @runtime_pid = Process.pid
            @runtime_ready = true
            configure_exit_handler
          end
        end

        def configure_exit_handler
          return if @exit_handler_configured

          @exit_handler_configured = true

          at_exit do
            begin
              receipt = shutdown(:timeout => exit_timeout)
              log_unfinished_at_exit(receipt)
            rescue StandardError
              # Draining must not turn a normal process exit into a failure.
              # Callers that need the outcome use #shutdown explicitly.
              nil
            end
          end
        end

        # The at_exit drain has no caller to hand a receipt to, so it reads the
        # configured cutoff from the notifier and reports leftovers on stderr.
        def exit_timeout
          value = options[:shutdown_timeout]

          if value.nil?
            begin
              value = Rollbar.notifier.configuration.async_shutdown_timeout
            rescue StandardError
              value = nil
            end
          end

          value
        end

        def log_unfinished_at_exit(receipt)
          return unless receipt

          uuids = receipt.unfinished_uuids + receipt.failed_uuids
          return if uuids.empty?

          Kernel.warn(
            '[Rollbar] Shutdown left ' \
            "#{receipt.unfinished_count} unfinished and " \
            "#{receipt.failed_count} failed report(s) for review: " \
            "#{uuids.join(', ')}"
          )
        end

        def register(payload)
          LIFECYCLE_MUTEX.synchronize do
            @last_shutdown_receipt = nil
            @report_sequence += 1
            generation = @generation
            report = Report.new(@report_sequence, extract_uuid(payload), payload,
                                generation, @report_sequence - 1)
            generation.reports << report
            @open_reports << report
            report
          end
        end

        def start_worker(report)
          priority = options[:priority] || DEFAULT_PRIORITY

          ::Thread.new do
            begin
              ::Thread.current.priority = priority
              # A report opened after its shutdown already published a receipt
              # is still delivered; mark_processing only refuses work that was
              # explicitly closed by #reset!.
              next unless mark_processing(report)

              # Only an explicit false from the delivery path proves the
              # report was rejected. A nil return is not a failure signal.
              delivered = Rollbar.process_from_async_handler(report.payload)

              if delivered == false
                close_report(
                  report, FAILED,
                  Error.new('Rollbar did not accept the report')
                )
              else
                close_report(report, PROCESSED)
              end
            rescue StandardError => e
              # Swallow the exception as before: the original report was not
              # sent and an internal error was reported and logged. The
              # receipt records the report as failed so on-call can follow up.
              close_report(report, FAILED, e)
            end
          end
        end

        def mark_processing(report)
          LIFECYCLE_MUTEX.synchronize do
            return false if report.finished?

            report.status = PROCESSING
            report.stage = PROCESSING
            report.deliveries += 1
            LIFECYCLE_COND.broadcast
            true
          end
        end

        def close_report(report, status, error = nil)
          LIFECYCLE_MUTEX.synchronize do
            return false if report.finished?

            report.status = status
            report.stage = status
            report.error = error
            report.closed = true
            @open_reports.delete(report)
            LIFECYCLE_COND.broadcast
            true
          end
        end

        def acquire_shutdown_run(deadline)
          LIFECYCLE_MUTEX.synchronize do
            # A concurrent caller shares the active run's receipt instead of
            # starting a second drain. It must not pick up reports accepted
            # into the next generation while that run was in flight.
            active = @active_shutdown

            if active
              active.waiters += 1
              begin
                LIFECYCLE_COND.wait(LIFECYCLE_MUTEX) until active.done
              ensure
                active.waiters -= 1
              end
              return [active, false]
            end

            # The window is every report admitted since the previous cutoff,
            # including ones that already finished, plus reports from earlier
            # generations that are still in flight. That lets a later shutdown
            # wait again for work an earlier deadline abandoned.
            reports = @generation.reports + @open_reports
            run = ShutdownRun.new(@generation, deadline, reports.uniq)
            @generation = Generation.new(@generation.number + 1)
            @active_shutdown = run
            [run, true]
          end
        end

        def drain(run)
          timed_out = false

          LIFECYCLE_MUTEX.synchronize do
            loop do
              break if run.reports.all?(&:finished?)

              remaining = run.deadline - monotonic_now

              if remaining <= 0
                timed_out = true
                break
              end

              LIFECYCLE_COND.wait(LIFECYCLE_MUTEX, remaining)
            end

            run.reports.each do |report|
              next if report.finished?

              # Keep the last observed stage (:accepted or :processing) so the
              # receipt shows whether delivery had started, but report the
              # status as unfinished. The report stays open, so a later
              # shutdown can wait for the same delivery again.
              report.error ||= TimeoutError.new(
                'report did not finish before the shutdown deadline'
              )
              report.status = UNFINISHED
            end

            LIFECYCLE_COND.broadcast

            entries = run.reports.map(&:snapshot)
            ShutdownReceipt.new(entries, run.generation.number, timed_out)
          end
        end

        def publish_receipt(run)
          LIFECYCLE_MUTEX.synchronize do
            # Waiters read run.receipt, so make sure an interrupted drain
            # still yields a receipt rather than nil.
            run.receipt ||= ShutdownReceipt.new(
              run.reports.map(&:snapshot), run.generation.number, true
            )
            @last_shutdown_receipt = run.receipt
            run.done = true
            @active_shutdown = nil
            LIFECYCLE_COND.broadcast
          end
        end

        def shutdown_timeout(options)
          value = options[:timeout]
          value = options[:shutdown_timeout] if value.nil?
          value = self.options[:shutdown_timeout] if value.nil?
          value = DEFAULT_SHUTDOWN_TIMEOUT if value.nil?

          timeout = Float(value)
          return timeout if timeout >= 0

          raise ArgumentError, 'shutdown timeout must be a non-negative number'
        rescue ArgumentError, TypeError
          raise ArgumentError, 'shutdown timeout must be a non-negative number'
        end

        def monotonic_now
          Process.clock_gettime(Process::CLOCK_MONOTONIC)
        end

        def extract_uuid(payload)
          data = payload
          data = ::JSON.parse(data) if data.is_a?(String)
          return nil unless data.is_a?(Hash)

          data = data['data'] || data[:data]
          return nil unless data.is_a?(Hash)

          data['uuid'] || data[:uuid]
        rescue StandardError
          nil
        end
      end

      def priority
        self.class.options[:priority] || DEFAULT_PRIORITY
      end

      def call(payload)
        self.class.call(payload)
      end
    end
  end
end
