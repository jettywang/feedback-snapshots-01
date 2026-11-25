# frozen_string_literal: true

module Grape
  module ServeStream
    # A JSON Lines body rendered one line at a time, each through the
    # representation frozen when the response was set up.
    #
    # The body owns the disclosure decision, not the formatter: fields are
    # projected from the approved snapshot as every line is read, so a record
    # or policy changed mid-stream cannot widen or narrow a line already
    # promised. A policy that changes, a record the policy denies, a record
    # that cannot be rendered or a source that fails stops the stream and
    # leaves a terminal state in {#ledger}.
    #
    # The ledger is also written into the request env under
    # {Grape::Env::JSONL_LEDGER} and announced on the
    # {Ledger::NOTIFICATION} notification, so an audit sink can account for a
    # response whose body it never sees. A line-level failure raises
    # {StreamAborted} out of +#each+, which is the only way to tell a reader
    # past the response headers that the body was truncated.
    class JsonlBody
      # @return [Ledger]
      attr_reader :ledger
      # @return [Representation]
      attr_reader :representation

      # @param records [Enumerable] the source records, read once.
      # @param representation [Representation] the approved disclosure.
      # @param policy [#version, #permitted?, nil] the authorization frozen for
      #   this response; its revision is the one the response was approved
      #   under when the representation names none.
      # @param policy_source [#call, nil] a callable answering the *live*
      #   policy, re-read before every line so a change made while the body
      #   streams stops it at the first line beyond the approved revision.
      # @param env [Hash, nil] the request env, to publish the ledger in.
      # @param source [#checkpoint, #close, nil] the data source, when it can
      #   save the checkpoint of its own read and release itself.
      def initialize(records, representation:, policy: nil, policy_source: nil, env: nil, source: nil)
        @records = records
        @representation = representation
        @policy = policy || policy_source&.call
        @policy_source = policy_source
        @env = env
        @source = source || records
        @approved_version = representation.version || policy_version(@policy)
        @ledger = Ledger.new(representation:, version: @approved_version)
        @started = false
        @closed = false
        @source_closed = false
        @index = -1
        @consumer_failure = false
        env[Grape::Env::JSONL_LEDGER] = @ledger if env
      end

      def each(&)
        return if @closed || @started

        start
        stream_records(&)
        @ledger.terminate(:complete)
      rescue StreamAborted
        raise
      rescue StandardError => e
        raise if @consumer_failure

        # The source raised before the next record was yielded, so +@index+ is
        # the last delivered line: the record that failed is the one after it.
        record_source_failure(e, @index + 1)
        raise
      ensure
        finish
      end

      # Rack's close. A body closed before it was read is a response the
      # caller abandoned; one closed after the stream stopped early records
      # the caller as the one who released it, without changing the reason the
      # stream stopped.
      def close
        return if @closed

        @closed = true
        @ledger.closed(by: :consumer)
        close_source(:consumer)
        @ledger.terminate(:closed_unread) unless @started || @ledger.terminated?
      end

      def closed?
        @closed
      end

      private

      def start
        @started = true
        @ledger.source_read
      end

      def stream_records
        @records.each do |record|
          @index += 1
          line = line_for(record, @index)
          # A line counts as delivered the moment it is handed to Rack: the
          # consumer's break unwinds through +yield+ and never returns here.
          @ledger.deliver(index: @index, bytes: line.bytesize, checkpoint: resume_after(@index))
          begin
            yield line
          rescue StandardError
            @consumer_failure = true
            raise
          end
        end
      end

      def line_for(record, index)
        policy_now = live_policy
        check_policy!(policy_now, index)
        render(record, index, policy_now)
      end

      # A consumer that broke out of the loop, or raised while writing the
      # response, ended the stream early: say which, instead of leaving no
      # status at all. A stream that failed or completed keeps its own status.
      def finish
        unless @ledger.terminated?
          @ledger.terminate(:aborted, reason: @consumer_failure ? :consumer_error : :consumer_closed)
        end
        @ledger.source_closed(by: :stream) if close_source(:stream)
      end

      def policy_version(policy)
        policy.version if policy.respond_to?(:version)
      end

      # The policy in force for the line about to be rendered, from the live
      # source when one was given and otherwise the snapshot itself.
      def live_policy
        return @policy unless @policy_source

        @policy_source.call
      end

      def check_policy!(live, index)
        return unless live

        @ledger.observe_policy(live)
        # A response set up without a revision loses nothing by adopting the
        # first one it sees; after that every different revision is a change.
        if @approved_version.nil? && @ledger.live_policy_version
          @approved_version = @ledger.live_policy_version
          @ledger.approve(@approved_version)
          return
        end
        return unless @ledger.live_policy_version && @ledger.live_policy_version != @approved_version

        abort!(StreamAborted.new(:policy_changed, ledger: @ledger, index:))
      end

      def render(record, index, live)
        projected = @representation.project(record)
        if live.respond_to?(:permitted?) && !live.permitted?(projected)
          abort!(StreamAborted.new(:denied, ledger: @ledger, index:))
        end

        "#{Formatter::Json.call(projected, @env)}\n"
      rescue StreamAborted
        raise
      rescue StandardError => e
        abort!(StreamAborted.new(:format_error, ledger: @ledger, index:), status: :failed, cause: e)
      end

      def abort!(exception, status: :aborted, cause: nil)
        @ledger.abort!(exception, cause:, index: exception.index, terminal: status)
        raise exception
      end

      # A source that raised while being read, rather than a line that failed
      # to render. Recorded with its location, then raised as it was: a source
      # error is the application's, not the formatter's.
      def record_source_failure(exception, index)
        @ledger.abort!(
          StreamAborted.new(:source_error, ledger: @ledger, index:, status: :failed),
          cause: exception, index:, terminal: :failed
        )
      end

      # Where a resumed read should continue: the source's own checkpoint when
      # it has moved past the line just sent, and the line count otherwise. A
      # source that saves its checkpoint only after its own yield returns has
      # not advanced when a later line aborts.
      def resume_after(index)
        saved = @source.respond_to?(:checkpoint) ? @source.checkpoint : nil
        return index + 1 unless saved.is_a?(Integer) && saved > index

        saved
      rescue StandardError
        index + 1
      end

      def close_source(by)
        return false if @source_closed
        return false unless @source.respond_to?(:close)

        @source_closed = true
        @ledger.source_closed(by:)
        @source.close
        true
      end
    end
  end
end
