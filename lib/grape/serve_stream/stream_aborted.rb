# frozen_string_literal: true

module Grape
  module ServeStream
    # Raised out of a line stream that stopped before its source was exhausted:
    # the disclosure policy changed, a record the policy denies, or a record
    # that could not be rendered. The response headers and the lines already
    # yielded are on the wire by then, so the exception is how the caller
    # learns the body was truncated rather than finished.
    #
    # The exception carries the same ledger the request env holds, so a caller
    # that catches it can read what was delivered, the representation those
    # lines were approved under, the checkpoint to resume from and the failure
    # location -- without having kept the body.
    class StreamAborted < StandardError
      # @return [Symbol] one of {Ledger::ABORT_REASONS}
      attr_reader :reason
      # @return [Symbol] :aborted or :failed
      attr_reader :status
      # @return [Ledger]
      attr_reader :ledger
      # @return [Integer, nil] the index of the line that was not sent
      attr_reader :index

      def initialize(reason, ledger:, index: nil, status: :aborted)
        @reason = reason
        @status = status
        @ledger = ledger
        @index = index
        super("JSON Lines stream aborted (#{reason}) after #{ledger.delivered} line(s)")
      end

      # A detached record of the response, as {Ledger#to_h} answers it.
      def to_h
        ledger.to_h
      end
    end
  end
end
