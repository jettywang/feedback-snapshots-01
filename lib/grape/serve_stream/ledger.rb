# frozen_string_literal: true

module Grape
  module ServeStream
    # What one streamed response actually delivered, kept after the response is
    # gone. A line stream records the representation it was approved under when
    # it starts, one entry per line handed to Rack, the terminal state it
    # reached, why it stopped, the failure location and who released the body,
    # so a caller can still account for the answer the client received.
    #
    # The ledger is a plain record: the stream writes it, and whoever holds the
    # response body -- or looks it up through the request env under
    # {Grape::Env::JSONL_LEDGER} -- reads it. {#to_h} is safe to log or hand to
    # an audit sink.
    class Ledger
      # One delivered line: its position, the representation version it was
      # rendered under, its byte size and the source checkpoint after it.
      Entry = Data.define(:index, :version, :bytes, :checkpoint)

      # The terminal states a response can reach.
      TERMINAL_STATES = %i[complete aborted failed closed_unread].freeze

      # How a stream stopped before its source was exhausted.
      ABORT_REASONS = %i[policy_changed denied format_error source_error consumer_closed consumer_error].freeze

      # Terminal states that mean the body was cut short rather than delivered
      # whole or never read.
      INCOMPLETE_STATES = %i[aborted failed].freeze

      # The notification an audit subscriber listens to.
      NOTIFICATION = 'jsonl_stream.grape'

      attr_reader :entries, :terminal, :reason, :failure, :aborted_at,
                  :closed_by, :source_reads, :source_closed_by, :last_checkpoint,
                  :live_policy_version

      def initialize(representation: nil, version: nil)
        @representation_source = representation
        @version = version || representation&.version
        @entries = []
        @terminal = nil
        @reason = nil
        @failure = nil
        @aborted_at = nil
        @closed_by = nil
        @source_reads = 0
        @source_closed_by = nil
        @last_checkpoint = nil
        @live_policy_version = nil
      end

      def version
        @version
      end

      # The disclosure the response was approved under, read from the
      # representation as it stands now: for +fields: :first+ that is the set
      # the first record locked in.
      def representation
        source = @representation_source
        source.respond_to?(:to_h) ? source.to_h : source
      end

      def delivered
        entries.size
      end

      def bytes
        entries.sum(&:bytes)
      end

      def terminated?
        !terminal.nil?
      end

      # Whether the response stopped short of the rows the source would have
      # produced: the client has a partial document it must not treat as whole.
      def truncated?
        INCOMPLETE_STATES.include?(terminal)
      end

      # Fixes the revision the response is approved under, once the first live
      # policy names one. No-op once set, so later lines keep the first answer.
      def approve(version)
        @version ||= version
      end

      def source_read
        @source_reads += 1
      end

      def source_closed(by:)
        @source_closed_by ||= by
      end

      def deliver(index:, bytes:, checkpoint: nil)
        entries << Entry.new(index:, version: @version, bytes:, checkpoint:)
        @last_checkpoint = checkpoint
      end

      # The live policy at the end of the response, when the caller gave one.
      # Compared with the version the response was approved under, so a policy
      # that changed while the body streamed is visible after the fact.
      def observe_policy(policy)
        @live_policy_version = policy.version.to_s if policy.respond_to?(:version) && !policy.version.nil?
      end

      def closed(by:)
        @closed_by ||= by
      end

      # Stops the stream at +status+. The first terminal state wins, so a
      # failure that stopped the stream stays the reason when the consumer
      # later closes the body.
      def terminate(status, reason: nil)
        return if terminated?

        @terminal = status
        @reason ||= reason
        notify
      end

      def abort!(exception, cause: nil, index: nil, terminal: :aborted)
        @reason = exception.reason
        @aborted_at = index
        @failure = failure_for(cause || exception, index) unless exception.reason == :policy_changed
        terminate(terminal)
      end

      def policy_changed?
        !@live_policy_version.nil? && @live_policy_version != @version
      end

      # @return [Hash] a detached record of this response for logs and audits.
      def to_h
        {
          representation: representation,
          version: version,
          delivered: delivered,
          bytes: bytes,
          entries: entries.map(&:to_h),
          terminal: terminal,
          truncated: truncated?,
          reason: reason,
          aborted_at: aborted_at,
          failure: failure,
          closed_by: closed_by,
          source_reads: source_reads,
          source_closed_by: source_closed_by,
          last_checkpoint: last_checkpoint,
          live_policy_version: live_policy_version,
          policy_changed: policy_changed?
        }
      end

      # The ledger this request published, if it streamed JSON Lines.
      #
      # @param env [Hash] the Rack env
      # @return [Ledger, nil]
      def self.from(env)
        env[Grape::Env::JSONL_LEDGER]
      end

      private

      def failure_for(exception, index)
        {
          index: index,
          class: exception.class.name,
          message: exception.message,
          location: location_of(exception),
          backtrace: exception.backtrace&.first(8)
        }
      end

      # The first frame outside the stream machinery, so the entry points at
      # the formatter, the record or the application code that raised.
      def location_of(exception)
        frame = exception.backtrace&.find { |line| !line.include?('/grape/serve_stream/') }
        frame&.split(':in ')&.first
      end

      def notify
        return unless ActiveSupport::Notifications.notifier.listening?(NOTIFICATION)

        ActiveSupport::Notifications.instrument(NOTIFICATION, ledger: to_h)
      end
    end
  end
end
