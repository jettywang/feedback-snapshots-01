# frozen_string_literal: true

module Grape
  module ServeStream
    # Streams a source that responds to +#read(length)+ and +#close+, opening a
    # source factory only when Rack reads the body. Once a source is open it is
    # always closed: when the body is read fully, when the reader stops after
    # the first chunk or raises while streaming. A source given directly is also
    # released when the body is closed unread; a factory stays lazy and is never
    # opened just to be closed.
    class SourceBody
      # @param source [#read, #close, #call] an open readable source, or a
      #   callable that answers with one when the body is first read.
      # @param chunk_size [Integer] the maximum bytes of each chunk.
      def initialize(source, chunk_size: CHUNK_SIZE)
        lazy = source.respond_to?(:call) && !source.respond_to?(:read)
        @factory = lazy ? source : -> { source }
        @direct_source = lazy ? nil : ensure_readable(source)
        @chunk_size = chunk_size
        @closed = false
      end

      # Whether the source has been released.
      def closed?
        @closed
      end

      def each
        return if closed?

        begin
          while (chunk = open_source.read(@chunk_size))
            break if chunk.empty?

            yield chunk
          end
        ensure
          close
        end
      end

      def close
        return if closed?

        @closed = true
        # A source handed in directly is released even when the body was never
        # read; a factory stays lazy, so closing an unread body never opens it.
        @source ||= @direct_source
        @source&.close
      end

      private

      def open_source
        @source ||= ensure_readable(@factory.call)
      end

      def ensure_readable(source)
        raise ArgumentError, 'source must respond to #read and #close' unless source.respond_to?(:read) && source.respond_to?(:close)

        source
      end
    end
  end
end
